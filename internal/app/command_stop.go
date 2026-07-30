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

func (e *environment) stop(args []string) error {
	set := flagSet("stop", e.stderr)
	root := set.String("state-dir", "", "state root")
	noSave := set.Bool("no-save", false, "discard changes since current generation")
	timeout := set.Duration("timeout", 45*time.Minute, "save and shutdown timeout")
	jsonOutput := set.Bool("json", false, "emit JSON")
	idaPath := set.String("ida-path", "", "idat executable")
	if err := parseInterspersed(set, args); err != nil {
		return err
	}
	if err := requireArgs(set, 1, "dscida stop <SESSION> [--no-save]"); err != nil {
		return err
	}
	st, err := rootStore(*root)
	if err != nil {
		return err
	}
	unlockLifecycle, err := st.LockLifecycle(set.Arg(0))
	if err != nil {
		return err
	}
	defer unlockLifecycle()
	session, err := st.LoadSession(set.Arg(0))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	idat, err := runner.ResolveIDA(*idaPath)
	if err != nil {
		return err
	}
	run := &runner.Runner{IDAT: idat}
	if *noSave {
		if err := st.BeginStop(session, true); err != nil {
			return err
		}
	}
	if len(session.ActiveJobIDs) > 0 && !*noSave {
		active, err := st.LoadJob(session.SessionID, session.ActiveJobIDs[0])
		if err != nil {
			return err
		}
		if _, err := e.completeJobWithLifecycle(ctx, st, run, session, active, true); err != nil {
			return err
		}
	}
	saved := false
	if !*noSave && session.State == "ready" && store.ProcessAlive(session.IDAPID) {
		job, err := st.NewJob(session, "save", "", nil)
		if err != nil {
			return err
		}
		if err := submitJob(ctx, session, job, "/control/save"); err != nil {
			if err := submissionOutcome(st, job, err); err != nil {
				return err
			}
		}
		if _, err := e.completeJobWithLifecycle(ctx, st, run, session, job, true); err != nil {
			return err
		}
		saved = true
	}
	if !*noSave {
		if err := st.BeginStop(session, false); err != nil {
			return err
		}
	}
	if store.ProcessAlive(session.IDAPID) {
		var response map[string]any
		if err := control.New(session.ControlURL, session.ControlToken).Post(ctx, "/control/shutdown", map[string]any{}, &response, http.StatusOK); err != nil {
			return err
		}
		for store.ProcessAlive(session.IDAPID) {
			select {
			case <-ctx.Done():
				_ = syscall.Kill(session.IDAPID, syscall.SIGTERM)
				time.Sleep(2 * time.Second)
				if store.ProcessAlive(session.IDAPID) {
					_ = syscall.Kill(session.IDAPID, syscall.SIGKILL)
				}
				if store.ProcessAlive(session.IDAPID) {
					return fmt.Errorf("IDA did not stop after SIGTERM/SIGKILL: %w", ctx.Err())
				}
			case <-time.After(250 * time.Millisecond):
			}
		}
	}
	for _, jobID := range session.ActiveJobIDs {
		job, loadErr := st.LoadJob(session.SessionID, jobID)
		if loadErr == nil && !store.IsTerminalJob(job.State) {
			if job.State == "queued" {
				job.State = "cancelled_before_start"
			} else {
				job.State = "interrupted_rolled_back"
			}
			job.Error = "session stopped without committing the active job"
			_ = st.SaveJob(job)
		}
	}
	session.State = "stopped"
	session.ActiveJobIDs = nil
	session.IDAPID = 0
	session.ControlURL = ""
	session.MCPURL = ""
	if err := st.SaveSession(session); err != nil {
		return err
	}
	newLogger(st.SessionDir(session.SessionID), e.stderr).event(
		"info", "supervisor", "session_stopped", "headless IDA session stopped",
		map[string]any{"session_id": session.SessionID, "generation": session.CurrentGeneration, "saved": saved},
	)
	return printResult(e.stdout, *jsonOutput, map[string]any{
		"success": true, "session_id": session.SessionID, "state": session.State,
		"generation": session.CurrentGeneration, "saved": saved,
	})
}
