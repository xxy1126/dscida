package app

import (
	"context"
	"fmt"
	"time"

	"github.com/tmo/dscida/internal/cache"
	"github.com/tmo/dscida/internal/control"
	"github.com/tmo/dscida/internal/runner"
	"github.com/tmo/dscida/internal/store"
)

func (e *environment) add(args []string) error {
	set := flagSet("add", e.stderr)
	modulePath := set.String("module", "", "canonical DSC module path")
	root := set.String("state-dir", "", "state root")
	timeout := set.Duration("timeout", 45*time.Minute, "wait timeout")
	noWait := set.Bool("no-wait", false, "return after durable acceptance")
	jsonOutput := set.Bool("json", false, "emit JSON")
	idaPath := set.String("ida-path", "", "idat executable")
	if err := parseInterspersed(set, args); err != nil {
		return err
	}
	if err := requireArgs(set, 1, "dscida add <SESSION> --module <PATH>"); err != nil {
		return err
	}
	if *modulePath == "" {
		return fmt.Errorf("--module is required")
	}
	st, session, err := loadReadySession(*root, set.Arg(0))
	if err != nil {
		return err
	}
	cacheInfo, err := cache.Open(session.DSCPath)
	if err != nil {
		return err
	}
	if cacheInfo.UUID != session.DSCUUID {
		return fmt.Errorf("DSC UUID changed: session=%s current=%s", session.DSCUUID, cacheInfo.UUID)
	}
	module, err := cacheInfo.Exact(*modulePath)
	if err != nil {
		return err
	}
	var idat string
	if !*noWait {
		idat, err = runner.ResolveIDA(*idaPath)
		if err != nil {
			return err
		}
	}
	index := int(module.ImageIndex)
	job, err := st.NewJob(session, "add", module.ModulePath, &index)
	if err != nil {
		return err
	}
	logger := newLogger(st.SessionDir(session.SessionID), e.stderr)
	logger.event("info", "supervisor", "job_queued", "module load job durably queued", map[string]any{
		"session_id": session.SessionID, "job_id": job.JobID,
		"module_path": module.ModulePath, "image_index": index,
	})
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if err := submitJob(ctx, session, job, "/control/load-module"); err != nil {
		if err := submissionOutcome(st, job, err); err != nil {
			return err
		}
	}
	if *noWait {
		return printResult(e.stdout, *jsonOutput, map[string]any{
			"success": true, "accepted": true, "job_id": job.JobID, "session_id": session.SessionID,
		})
	}
	job, err = e.completeJob(ctx, st, &runner.Runner{IDAT: idat}, session, job)
	if err != nil {
		return err
	}
	reconcileModules(session, cacheInfo)
	if err := st.UpdateImplicitModules(session, session.ImplicitlyLoaded); err != nil {
		return err
	}
	logger.event("info", "supervisor", "module_load_committed", "module load generation committed", map[string]any{
		"session_id": session.SessionID, "job_id": job.JobID,
		"module_path": module.ModulePath, "image_index": index,
		"generation": session.CurrentGeneration,
	})
	return printResult(e.stdout, *jsonOutput, map[string]any{
		"success": true, "job_id": job.JobID, "session_id": session.SessionID,
		"module_path": module.ModulePath, "image_index": index,
		"state": job.State, "generation": session.CurrentGeneration, "mcp_url": session.MCPURL,
	})
}

func (e *environment) save(args []string) error {
	set := flagSet("save", e.stderr)
	root := set.String("state-dir", "", "state root")
	timeout := set.Duration("timeout", 45*time.Minute, "wait timeout")
	jsonOutput := set.Bool("json", false, "emit JSON")
	idaPath := set.String("ida-path", "", "idat executable")
	if err := parseInterspersed(set, args); err != nil {
		return err
	}
	if err := requireArgs(set, 1, "dscida save <SESSION>"); err != nil {
		return err
	}
	st, session, err := loadReadySession(*root, set.Arg(0))
	if err != nil {
		return err
	}
	idat, err := runner.ResolveIDA(*idaPath)
	if err != nil {
		return err
	}
	job, err := st.NewJob(session, "save", "", nil)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if err := submitJob(ctx, session, job, "/control/save"); err != nil {
		if err := submissionOutcome(st, job, err); err != nil {
			return err
		}
	}
	job, err = e.completeJob(ctx, st, &runner.Runner{IDAT: idat}, session, job)
	if err != nil {
		return err
	}
	if info, openErr := cache.Open(session.DSCPath); openErr == nil {
		reconcileModules(session, info)
		if err := st.UpdateImplicitModules(session, session.ImplicitlyLoaded); err != nil {
			return err
		}
	}
	newLogger(st.SessionDir(session.SessionID), e.stderr).event(
		"info", "supervisor", "save_committed", "database generation committed",
		map[string]any{"session_id": session.SessionID, "job_id": job.JobID, "generation": session.CurrentGeneration},
	)
	return printResult(e.stdout, *jsonOutput, map[string]any{
		"success": true, "job_id": job.JobID, "session_id": session.SessionID,
		"generation": session.CurrentGeneration, "path": session.CurrentPath,
	})
}

func (e *environment) wait(args []string) error {
	set := flagSet("wait", e.stderr)
	root := set.String("state-dir", "", "state root")
	timeout := set.Duration("timeout", 45*time.Minute, "wait timeout")
	jsonOutput := set.Bool("json", false, "emit JSON")
	idaPath := set.String("ida-path", "", "idat executable")
	if err := parseInterspersed(set, args); err != nil {
		return err
	}
	if err := requireArgs(set, 1, "dscida wait <JOB_ID>"); err != nil {
		return err
	}
	st, err := rootStore(*root)
	if err != nil {
		return err
	}
	job, err := st.FindJob(set.Arg(0))
	if err != nil {
		return err
	}
	if store.IsTerminalJob(job.State) {
		if job.State == "succeeded" {
			return printResult(e.stdout, *jsonOutput, job)
		}
		return fmt.Errorf("job %s ended in %s: %s", job.JobID, job.State, job.Error)
	}
	session, err := st.LoadSession(job.SessionID)
	if err != nil {
		return err
	}
	if job.State == "queued" {
		initialCheckpoint := job.Operation == "save" && job.BaseGeneration == 0 && session.State == "checkpointing_initial"
		if (session.State != "ready" && !initialCheckpoint) || !store.ProcessAlive(session.IDAPID) {
			return fmt.Errorf("queued job %s cannot be submitted because session is %s or IDA is not alive", job.JobID, session.State)
		}
		route := "/control/save"
		if job.Operation == "add" {
			route = "/control/load-module"
		}
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		submitErr := submitJob(ctx, session, job, route)
		cancel()
		if submitErr != nil {
			if err := submissionOutcome(st, job, submitErr); err != nil {
				return err
			}
		}
	}
	idat, err := runner.ResolveIDA(*idaPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	job, err = e.completeJob(ctx, st, &runner.Runner{IDAT: idat}, session, job)
	if err != nil {
		return err
	}
	if info, openErr := cache.Open(session.DSCPath); openErr == nil {
		reconcileModules(session, info)
		if err := st.UpdateImplicitModules(session, session.ImplicitlyLoaded); err != nil {
			return err
		}
	}
	return printResult(e.stdout, *jsonOutput, job)
}

func loadReadySession(root, id string) (*store.Store, *store.Session, error) {
	st, err := rootStore(root)
	if err != nil {
		return nil, nil, err
	}
	session, err := st.LoadSession(id)
	if err != nil {
		return nil, nil, err
	}
	if session.State != "ready" {
		return nil, nil, fmt.Errorf("session %s is %s, not ready", id, session.State)
	}
	if !store.ProcessAlive(session.IDAPID) {
		return nil, nil, fmt.Errorf("session %s IDA process %d is not alive", id, session.IDAPID)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var ping struct {
		Success bool `json:"success"`
		PID     int  `json:"pid"`
	}
	if err := control.New(session.ControlURL, session.ControlToken).Get(ctx, "/control/ping", &ping); err != nil {
		return nil, nil, fmt.Errorf("session %s control endpoint is unhealthy: %w", id, err)
	}
	if !ping.Success || ping.PID != session.IDAPID {
		return nil, nil, fmt.Errorf("session %s control endpoint PID ownership mismatch", id)
	}
	return st, session, nil
}
