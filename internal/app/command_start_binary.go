package app

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/tmo/dscida/internal/binaryinput"
	"github.com/tmo/dscida/internal/control"
	"github.com/tmo/dscida/internal/runner"
	"github.com/tmo/dscida/internal/store"
)

func (e *environment) startBinary(args []string) error {
	set := flagSet("start-binary", e.stderr)
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
	if err := requireArgs(set, 1, "dscida start-binary <INPUT>"); err != nil {
		return err
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
			if store.TargetKind(existing) != store.TargetBinary {
				return fmt.Errorf("binary_identity_mismatch: session is not a binary target")
			}
			canonical, err := filepath.EvalSymlinks(set.Arg(0))
			if err != nil {
				return fmt.Errorf("binary_identity_mismatch: %w", err)
			}
			canonical, _ = filepath.Abs(canonical)
			if !store.SamePath(canonical, existing.SourcePath) {
				return fmt.Errorf("binary_identity_mismatch: source path does not match session")
			}
			if err := binaryinput.Verify(binaryIdentity(existing)); err != nil {
				return err
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
	sessionDir := st.SessionDir(*sessionID)
	identity, err := binaryinput.Stage(set.Arg(0), sessionDir)
	if err != nil {
		return err
	}
	token, err := store.RandomID("", 32)
	if err != nil {
		return err
	}
	workingIDB := filepath.Join(sessionDir, "runtime", "working.i64")
	session := &store.Session{
		SessionID: *sessionID, TargetKind: store.TargetBinary, State: "loading_target",
		SourcePath: identity.SourcePath, InputPath: identity.InputPath,
		InputSHA256: identity.SHA256, InputSize: identity.Size,
		BinaryFormat: identity.Format, Architecture: identity.Architecture,
		IDAProcessor: identity.IDAProcessor, MachOUUID: identity.MachOUUID,
		WorkingIDBPath: workingIDB,
		ControlToken:   token,
	}
	if err := st.Initialize(session); err != nil {
		return err
	}
	logger := newLogger(sessionDir, e.stderr)
	logger.event("info", "supervisor", "session_created", "binary session metadata created", map[string]any{
		"session_id": session.SessionID, "source_path": session.SourcePath,
		"input_sha256": session.InputSHA256, "binary_format": session.BinaryFormat,
	})
	run := &runner.Runner{IDAT: idat}
	pid, err := run.Launch(launchOptions(session, sessionDir, *host, *port, false))
	if err != nil {
		session.State = "failed"
		_ = st.SaveSession(session)
		return err
	}
	session.IDAPID = pid
	session.State = "analyzing_initial"
	if err := st.SaveSession(session); err != nil {
		return failSession(st, session, fmt.Errorf("persist launched IDA ownership: %w", err))
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	ready, err := runner.WaitReady(ctx, sessionDir, pid)
	if err != nil {
		return failSession(st, session, fmt.Errorf("wait for IDA readiness: %w (see %s)", err, filepath.Join(sessionDir, "logs")))
	}
	if ready.SessionID != session.SessionID || ready.SessionInstanceID != session.SessionInstanceID ||
		ready.TargetKind != store.TargetBinary {
		return failSession(st, session, fmt.Errorf("IDA ready identity does not match binary session"))
	}
	if !store.SamePath(ready.IDA.IDBPath, workingIDB) || len(ready.IDA.LoadedImageIndexes) != 0 {
		return failSession(st, session, fmt.Errorf("IDA published unexpected binary database state"))
	}
	if err := store.ValidateEndpointPair(ready.ControlURL, ready.MCPURL); err != nil {
		return failSession(st, session, fmt.Errorf("IDA ready endpoints: %w", err))
	}
	if err := control.MCPHealth(ctx, ready.MCPURL); err != nil {
		return failSession(st, session, fmt.Errorf("MCP readiness: %w", err))
	}
	session.ControlURL, session.MCPURL = ready.ControlURL, ready.MCPURL
	session.State = "checkpointing_initial"
	if err := st.SaveSession(session); err != nil {
		return failSession(st, session, fmt.Errorf("persist binary checkpoint state: %w", err))
	}
	job, err := st.NewJob(session, "save", "", nil)
	if err != nil {
		return failSession(st, session, fmt.Errorf("create initial checkpoint job: %w", err))
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
	result := map[string]any{
		"success": true, "session_id": session.SessionID,
		"session_instance_id": session.SessionInstanceID, "target_kind": store.TargetBinary,
		"state": session.State, "ida_pid": session.IDAPID, "source_path": session.SourcePath,
		"input_path": session.InputPath, "input_sha256": session.InputSHA256,
		"binary_format": session.BinaryFormat, "architecture": session.Architecture,
		"generation": session.CurrentGeneration, "mcp_url": session.MCPURL,
		"control_url": session.ControlURL, "session_dir": sessionDir, "job_id": job.JobID,
	}
	logger.event("info", "supervisor", "session_ready", "binary session committed and ready", result)
	if *jsonOutput {
		if err := writeJSON(e.stdout, result); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(e.stdout, "session: %s\ntarget: binary\ninput: %s\nformat: %s\narchitecture: %s\nIDA PID: %d\nMCP: %s\ngeneration: %d\n",
			session.SessionID, session.SourcePath, session.BinaryFormat, session.Architecture,
			session.IDAPID, session.MCPURL, session.CurrentGeneration)
	}
	if *foreground {
		for store.ProcessAlive(pid) {
			time.Sleep(time.Second)
		}
	}
	return nil
}

func binaryIdentity(session *store.Session) binaryinput.Identity {
	return binaryinput.Identity{
		SourcePath: session.SourcePath, InputPath: session.InputPath,
		SHA256: session.InputSHA256, Size: session.InputSize,
		Format: session.BinaryFormat, Architecture: session.Architecture,
		IDAProcessor: session.IDAProcessor, MachOUUID: session.MachOUUID,
	}
}

func launchOptions(session *store.Session, sessionDir, host string, port int, openExisting bool) runner.LaunchOptions {
	return runner.LaunchOptions{
		SessionDir: sessionDir, SessionID: session.SessionID,
		SessionInstanceID: session.SessionInstanceID, TargetKind: store.TargetKind(session),
		DSCPath: session.DSCPath, DSCUUID: session.DSCUUID, ModulePath: session.MainModule,
		Arch: session.Architecture, ImageCount: session.ImageCount,
		SourcePath: session.SourcePath, InputPath: session.InputPath,
		InputSHA256: session.InputSHA256, InputSize: session.InputSize,
		BinaryFormat: session.BinaryFormat, MachOUUID: session.MachOUUID,
		IDAProcessor: session.IDAProcessor,
		WorkingIDB:   session.WorkingIDBPath, Token: session.ControlToken,
		Host: host, Port: port, OpenExisting: openExisting,
	}
}
