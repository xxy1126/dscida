package app

import (
	"context"
	"fmt"
	"net/http"
	"syscall"
	"time"

	"github.com/tmo/dscida/internal/control"
	"github.com/tmo/dscida/internal/runner"
	"github.com/tmo/dscida/internal/store"
)

func failSession(st *store.Store, session *store.Session, reason error) error {
	session.State = "failed"
	st.SaveSession(session)
	if session.ControlURL != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		var response map[string]any
		_ = control.New(session.ControlURL, session.ControlToken).Post(ctx, "/control/shutdown", map[string]any{}, &response, http.StatusOK)
		cancel()
	}
	if waitOrTerminate(session.IDAPID, 3*time.Second) {
		session.IDAPID = 0
		session.ControlURL = ""
		session.MCPURL = ""
		_ = st.SaveSession(session)
	}
	return reason
}

func (e *environment) failAndRecover(ctx context.Context, st *store.Store, run *runner.Runner, session *store.Session, job *store.Job, lifecycleHeld bool, reason error) error {
	if !lifecycleHeld {
		unlock, err := st.LockLifecycle(session.SessionID)
		if err != nil {
			return fmt.Errorf("job %s failed: %v; automatic recovery lock failed: %w", job.JobID, reason, err)
		}
		defer unlock()
	}
	fresh, err := st.LoadSession(session.SessionID)
	if err != nil {
		return fmt.Errorf("job %s failed: %v; automatic recovery could not reload session: %w", job.JobID, reason, err)
	}
	*session = *fresh
	if !ownsMutation(session, job.JobID) {
		return fmt.Errorf(
			"job %s failed: %v; automatic recovery skipped because the job no longer owns the session mutation slot (state %s)",
			job.JobID, reason, session.State,
		)
	}
	failure := failJob(st, session, job, reason)
	if session.CurrentGeneration <= 0 {
		return failure
	}
	recoveryTimeout := 30 * time.Minute
	if deadline, ok := ctx.Deadline(); ok {
		recoveryTimeout = time.Until(deadline)
		if recoveryTimeout <= 0 {
			return fmt.Errorf("%v; automatic recovery was not started because the command deadline expired", failure)
		}
	}
	current, recoveryErr := e.resumeCore(st, session, run, "127.0.0.1", 0, recoveryTimeout)
	logger := newLogger(st.SessionDir(session.SessionID), e.stderr)
	if recoveryErr != nil {
		session.State = "recovery_required"
		session.UncommittedMCPEdits = true
		_ = st.SaveSession(session)
		logger.event("error", "recovery", "automatic_recovery_failed", "automatic rollback to current generation failed", map[string]any{
			"session_id": session.SessionID, "job_id": job.JobID,
			"base_generation": job.BaseGeneration, "error": recoveryErr.Error(),
		})
		return fmt.Errorf("%v; automatic recovery failed: %w", failure, recoveryErr)
	}
	logger.event("info", "recovery", "automatic_recovery_completed", "session automatically restored from verified generation", map[string]any{
		"session_id": session.SessionID, "job_id": job.JobID,
		"generation": current.Generation, "ida_pid": session.IDAPID, "mcp_url": session.MCPURL,
	})
	return fmt.Errorf("%v; session automatically recovered to generation %d and is ready at %s", failure, current.Generation, session.MCPURL)
}

func ownsMutation(session *store.Session, jobID string) bool {
	return len(session.ActiveJobIDs) == 1 && session.ActiveJobIDs[0] == jobID
}

func failJob(st *store.Store, session *store.Session, job *store.Job, reason error) error {
	if fresh, err := st.LoadJob(session.SessionID, job.JobID); err == nil {
		job = fresh
	}
	if !store.IsTerminalJob(job.State) {
		job.State = "failed"
		job.Error = reason.Error()
		_ = st.SaveJob(job)
	}
	if session.ControlURL != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		var response map[string]any
		_ = control.New(session.ControlURL, session.ControlToken).Post(ctx, "/control/shutdown", map[string]any{}, &response, http.StatusOK)
		cancel()
	}
	processExited := waitOrTerminate(session.IDAPID, 3*time.Second)
	_ = st.ClearActiveJob(session, job.JobID, "recovery_required")
	if processExited {
		session.IDAPID = 0
		session.ControlURL = ""
		session.MCPURL = ""
	}
	session.UncommittedMCPEdits = true
	_ = st.SaveSession(session)
	return fmt.Errorf("job %s failed: %w", job.JobID, reason)
}

func waitOrTerminate(pid int, timeout time.Duration) bool {
	if pid <= 0 {
		return true
	}
	deadline := time.Now().Add(timeout)
	for store.ProcessAlive(pid) && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if store.ProcessAlive(pid) {
		_ = syscall.Kill(pid, syscall.SIGTERM)
	}
	deadline = time.Now().Add(5 * time.Second)
	for store.ProcessAlive(pid) && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if store.ProcessAlive(pid) {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
	deadline = time.Now().Add(2 * time.Second)
	for store.ProcessAlive(pid) && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	return !store.ProcessAlive(pid)
}

func (e *environment) resumeCore(st *store.Store, session *store.Session, run *runner.Runner, host string, port int, timeout time.Duration) (*store.Current, error) {
	current, err := st.PrepareResume(session)
	if err != nil {
		return nil, fmt.Errorf("prepare resume: %w", err)
	}
	if err := runner.CopyGenerationToWorking(current.Path, session.WorkingIDBPath); err != nil {
		session.State = "recovery_required"
		_ = st.SaveSession(session)
		return nil, fmt.Errorf("restore current generation: %w", err)
	}
	sessionDir := st.SessionDir(session.SessionID)
	pid, err := run.Launch(runner.LaunchOptions{
		SessionDir: sessionDir, DSCPath: session.DSCPath, DSCUUID: session.DSCUUID,
		ModulePath: session.MainModule, Arch: session.Architecture, ImageCount: session.ImageCount,
		WorkingIDB: session.WorkingIDBPath, Token: session.ControlToken, Host: host,
		Port: port, OpenExisting: true,
	})
	if err != nil {
		session.State = "recovery_required"
		_ = st.SaveSession(session)
		return nil, err
	}
	session.IDAPID = pid
	session.State = "analyzing_initial"
	if err := st.SaveSession(session); err != nil {
		return nil, failSession(st, session, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ready, err := runner.WaitReady(ctx, sessionDir, pid)
	if err != nil {
		return nil, failSession(st, session, fmt.Errorf("wait for resumed IDA: %w", err))
	}
	session.ControlURL = ready.ControlURL
	session.MCPURL = ready.MCPURL
	if err := st.SaveSession(session); err != nil {
		return nil, failSession(st, session, err)
	}
	if !store.SamePath(ready.IDA.IDBPath, session.WorkingIDBPath) {
		return nil, failSession(st, session, fmt.Errorf("resumed IDA opened unexpected IDB %q", ready.IDA.IDBPath))
	}
	if !sameIndexes(ready.IDA.LoadedImageIndexes, current.LoadedImageIndexes) {
		return nil, failSession(st, session, fmt.Errorf(
			"resumed loaded indexes %v do not match generation %v",
			ready.IDA.LoadedImageIndexes, current.LoadedImageIndexes,
		))
	}
	for _, index := range ready.IDA.LoadedImageIndexes {
		if index < 0 || index >= session.ImageCount {
			return nil, failSession(st, session, fmt.Errorf("resumed image index %d is out of bounds", index))
		}
	}
	if err := control.MCPHealth(ctx, ready.MCPURL); err != nil {
		return nil, failSession(st, session, fmt.Errorf("resumed MCP readiness: %w", err))
	}
	session.State = "ready"
	session.LoadedImageIndexes = append([]int(nil), current.LoadedImageIndexes...)
	session.UncommittedMCPEdits = false
	if err := st.SaveSession(session); err != nil {
		return nil, failSession(st, session, err)
	}
	return current, nil
}
