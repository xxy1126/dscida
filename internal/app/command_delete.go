package app

import (
	"fmt"
	"time"

	"github.com/tmo/dscida/internal/store"
)

func (e *environment) delete(args []string) error {
	set := flagSet("delete", e.stderr)
	root := set.String("state-dir", "", "state root")
	includeBackups := set.Bool("include-backups", false, "also quarantine verified replacement backups")
	set.Duration("timeout", 10*time.Second, "lifecycle lock wait timeout")
	jsonOutput := set.Bool("json", false, "emit JSON")
	if err := parseInterspersed(set, args); err != nil {
		return err
	}
	if err := requireArgs(set, 1, "dscida delete <SESSION> [--include-backups]"); err != nil {
		return err
	}
	sessionID := set.Arg(0)
	if !validName(sessionID) {
		return fmt.Errorf("invalid session ID %q", sessionID)
	}
	st, err := rootStore(*root)
	if err != nil {
		return err
	}
	unlockLifecycle, err := st.LockLifecycle(sessionID)
	if err != nil {
		return err
	}
	defer unlockLifecycle()
	session, err := st.LoadSession(sessionID)
	if err != nil {
		if !*includeBackups {
			return err
		}
		// Backups-only deletion: still allowed when the current session is gone.
		session = &store.Session{SessionID: sessionID, State: "stopped"}
	}
	logger := newLogger(st.SessionDir(sessionID), e.stderr)
	logger.event("info", "delete", "session_delete_started", "session deletion requested", map[string]any{
		"session_id": sessionID, "include_backups": *includeBackups,
	})
	result, err := st.DeleteSession(session, *includeBackups)
	if err != nil {
		_ = st.AppendDeleteAudit(map[string]any{
			"event": "session_delete_failed", "session_id": sessionID,
			"timestamp": time.Now().UTC().Format(time.RFC3339Nano), "error": err.Error(),
		})
		return err
	}
	if err := st.AppendDeleteAudit(map[string]any{
		"event": "session_delete_completed", "session_id": sessionID,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"current_moved": result.CurrentMoved,
		"trash_dir":     result.TrashDir,
	}); err != nil {
		return err
	}
	if *jsonOutput {
		return writeJSON(e.stdout, result)
	}
	fmt.Fprintf(e.stdout, "session: %s\ncurrent moved: %t\ntrash: %s\n", result.SessionID, result.CurrentMoved, result.TrashDir)
	for _, source := range result.Sources {
		fmt.Fprintf(e.stdout, "%s  %s  ->  %s\n", source.State, source.Name, source.Dest)
	}
	return nil
}
