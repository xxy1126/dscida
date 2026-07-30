package app

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/tmo/dscida/internal/cache"
	"github.com/tmo/dscida/internal/control"
	"github.com/tmo/dscida/internal/runner"
	"github.com/tmo/dscida/internal/store"
)

func (e *environment) start(args []string) error {
	set := flagSet("start", e.stderr)
	modulePath := set.String("module", "", "canonical DSC module path")
	sessionID := set.String("session", "", "preferred session ID")
	outputDir := set.String("output-dir", "", "state and session root")
	idaPath := set.String("ida-path", "", "idat executable or Contents/MacOS directory")
	host := set.String("mcp-host", "127.0.0.1", "loopback host")
	port := set.Int("mcp-port", 0, "MCP/control port; 0 chooses a free port")
	timeout := set.Duration("timeout", 30*time.Minute, "startup timeout")
	jsonOutput := set.Bool("json", false, "emit JSON")
	foreground := set.Bool("foreground", false, "wait until IDA exits after startup")
	resume := set.Bool("resume", false, "resume from the current immutable generation")
	replace := set.Bool("replace", false, "recoverably back up and rebuild an existing session")
	if err := parseInterspersed(set, args); err != nil {
		return err
	}
	if err := requireArgs(set, 1, "dscida start <DSC> --module <PATH>"); err != nil {
		return err
	}
	if *modulePath == "" {
		return fmt.Errorf("--module is required")
	}
	if *resume && *replace {
		return fmt.Errorf("--resume and --replace are mutually exclusive")
	}
	if *host != "127.0.0.1" && *host != "localhost" {
		return fmt.Errorf("v1 only permits a loopback --mcp-host")
	}
	if *port < 0 || *port > 65535 {
		return fmt.Errorf("invalid port: %d", *port)
	}
	cacheInfo, err := cache.Open(set.Arg(0))
	if err != nil {
		return err
	}
	module, err := cacheInfo.Exact(*modulePath)
	if err != nil {
		return err
	}
	idat, err := runner.ResolveIDA(*idaPath)
	if err != nil {
		return err
	}
	if *resume && *sessionID == "" {
		return fmt.Errorf("--resume requires --session")
	}
	if *sessionID == "" {
		*sessionID, err = store.RandomID("", 4)
		if err != nil {
			return err
		}
	}
	if !validName(*sessionID) {
		return fmt.Errorf("invalid session ID %q", *sessionID)
	}
	st, err := rootStore(*outputDir)
	if err != nil {
		return err
	}
	unlockLifecycle, err := st.LockLifecycle(*sessionID)
	if err != nil {
		return err
	}
	defer unlockLifecycle()
	if existing, loadErr := st.LoadSession(*sessionID); loadErr == nil {
		if *resume {
			if existing.DSCPath != cacheInfo.Path || existing.DSCUUID != cacheInfo.UUID ||
				existing.MainModule != module.ModulePath {
				return fmt.Errorf("resume identity does not match DSC/module arguments")
			}
			return e.resumeSession(st, existing, &runner.Runner{IDAT: idat}, *host, *port, *timeout, *jsonOutput, *foreground)
		}
		if *replace {
			backup, err := st.BackupSession(existing)
			if err != nil {
				return err
			}
			fmt.Fprintf(e.stderr, "[supervisor] previous session moved to %s\n", backup)
		} else {
			return fmt.Errorf("session already exists: %s (use --resume or --replace)", *sessionID)
		}
	} else if *resume {
		return fmt.Errorf("cannot resume session %s: %w", *sessionID, loadErr)
	}
	token, err := store.RandomID("", 32)
	if err != nil {
		return err
	}
	sessionDir := st.SessionDir(*sessionID)
	workingIDB := filepath.Join(sessionDir, "runtime", "working.i64")
	index := int(module.ImageIndex)
	session := &store.Session{
		SessionID:          *sessionID,
		State:              "loading_primary",
		DSCPath:            cacheInfo.Path,
		DSCUUID:            cacheInfo.UUID,
		Architecture:       cacheInfo.Architecture,
		MainModule:         module.ModulePath,
		ImageCount:         cacheInfo.ImageCount,
		LoadedModules:      []string{module.ModulePath},
		LoadedImageIndexes: nil,
		WorkingIDBPath:     workingIDB,
		ControlToken:       token,
	}
	if err := st.Initialize(session); err != nil {
		return err
	}
	logger := newLogger(sessionDir, e.stderr)
	logger.event("info", "supervisor", "session_created", "session metadata created", map[string]any{
		"session_id": session.SessionID, "module_path": module.ModulePath, "image_index": index,
	})
	run := &runner.Runner{IDAT: idat}
	pid, err := run.Launch(runner.LaunchOptions{
		SessionDir: sessionDir, DSCPath: cacheInfo.Path, ModulePath: module.ModulePath,
		Arch: cacheInfo.Architecture, DSCUUID: cacheInfo.UUID, ImageCount: cacheInfo.ImageCount, WorkingIDB: workingIDB,
		SessionID: session.SessionID, SessionInstanceID: session.SessionInstanceID,
		Token: token, Host: *host, Port: *port,
	})
	if err != nil {
		session.State = "failed"
		st.SaveSession(session)
		return err
	}
	session.IDAPID = pid
	session.State = "analyzing_initial"
	if err := st.SaveSession(session); err != nil {
		return err
	}
	logger.event("info", "ida", "process_started", "headless IDA started", map[string]any{"ida_pid": pid})
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	ready, err := runner.WaitReady(ctx, sessionDir, pid)
	if err != nil {
		return failSession(st, session, fmt.Errorf("wait for IDA readiness: %w (see %s)", err, filepath.Join(sessionDir, "logs")))
	}
	if ready.SessionID != session.SessionID || ready.SessionInstanceID != session.SessionInstanceID {
		return failSession(st, session, fmt.Errorf("IDA ready identity does not match session incarnation"))
	}
	if !store.SamePath(ready.IDA.IDBPath, workingIDB) {
		return failSession(st, session, fmt.Errorf("IDA opened unexpected IDB %q", ready.IDA.IDBPath))
	}
	if err := store.ValidateEndpointPair(ready.ControlURL, ready.MCPURL); err != nil {
		return failSession(st, session, fmt.Errorf("IDA ready endpoints: %w", err))
	}
	if err := validateLoadedIndexes(ready.IDA.LoadedImageIndexes, cacheInfo.ImageCount, index); err != nil {
		return failSession(st, session, err)
	}
	if err := control.MCPHealth(ctx, ready.MCPURL); err != nil {
		return failSession(st, session, fmt.Errorf("MCP readiness: %w", err))
	}
	session.ControlURL = ready.ControlURL
	session.MCPURL = ready.MCPURL
	session.LoadedImageIndexes = append([]int(nil), ready.IDA.LoadedImageIndexes...)
	reconcileModules(session, cacheInfo)
	session.State = "checkpointing_initial"
	if err := st.SaveSession(session); err != nil {
		return err
	}
	logger.event("info", "mcp", "mcp_ready", "MCP endpoint passed initialize and tools/list", map[string]any{"mcp_url": ready.MCPURL})
	job, err := st.NewJob(session, "save", "", nil)
	if err != nil {
		return err
	}
	if err := submitJob(ctx, session, job, "/control/save"); err != nil {
		if err := submissionOutcome(st, job, err); err != nil {
			return err
		}
	}
	job, err = e.completeJobWithLifecycle(ctx, st, run, session, job, true)
	if err != nil {
		return err
	}
	reconcileModules(session, cacheInfo)
	if err := st.UpdateImplicitModules(session, session.ImplicitlyLoaded); err != nil {
		return err
	}
	result := map[string]any{
		"success": true, "session_id": session.SessionID,
		"session_instance_id": session.SessionInstanceID, "state": session.State,
		"ida_pid": session.IDAPID, "module_path": module.ModulePath, "image_index": index,
		"generation": session.CurrentGeneration, "mcp_url": session.MCPURL,
		"control_url": session.ControlURL, "session_dir": sessionDir, "job_id": job.JobID,
	}
	logger.event("info", "supervisor", "session_ready", "session committed and ready", result)
	if *jsonOutput {
		if err := writeJSON(e.stdout, result); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(e.stdout, "session: %s\nmodule: %s\nIDA PID: %d\nMCP: %s\ngeneration: %d\n", session.SessionID, module.ModulePath, session.IDAPID, session.MCPURL, session.CurrentGeneration)
	}
	if *foreground {
		for store.ProcessAlive(pid) {
			time.Sleep(time.Second)
		}
	}
	return nil
}

func (e *environment) resumeSession(st *store.Store, session *store.Session, run *runner.Runner, host string, port int, timeout time.Duration, jsonOutput, foreground bool) error {
	current, err := e.resumeCore(st, session, run, host, port, timeout)
	if err != nil {
		return err
	}
	result := map[string]any{
		"success": true, "resumed": true, "session_id": session.SessionID,
		"session_instance_id": session.SessionInstanceID,
		"state":               session.State, "ida_pid": session.IDAPID, "generation": current.Generation,
		"mcp_url": session.MCPURL, "control_url": session.ControlURL,
	}
	if err := printResult(e.stdout, jsonOutput, result); err != nil {
		return err
	}
	if foreground {
		for store.ProcessAlive(session.IDAPID) {
			time.Sleep(time.Second)
		}
	}
	return nil
}
