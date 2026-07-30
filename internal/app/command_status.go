package app

import (
	"context"
	"fmt"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/tmo/dscida/internal/control"
	"github.com/tmo/dscida/internal/runner"
	"github.com/tmo/dscida/internal/store"
)

func (e *environment) status(args []string) error {
	set := flagSet("status", e.stderr)
	root := set.String("state-dir", "", "state root")
	jsonOutput := set.Bool("json", false, "emit JSON")
	if err := parseInterspersed(set, args); err != nil {
		return err
	}
	if err := requireArgs(set, 1, "dscida status <SESSION>"); err != nil {
		return err
	}
	st, err := rootStore(*root)
	if err != nil {
		return err
	}
	session, err := st.LoadSession(set.Arg(0))
	if err != nil {
		return err
	}
	live := store.ProcessAlive(session.IDAPID)
	controlHealthy := false
	mcpHealthy := false
	var liveStatus map[string]any
	if live && session.ControlURL != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err = control.New(session.ControlURL, session.ControlToken).Get(ctx, "/control/status", &liveStatus)
		if err == nil {
			if reportedPID, ok := liveStatus["pid"].(float64); !ok || int(reportedPID) != session.IDAPID {
				err = fmt.Errorf("control endpoint PID ownership mismatch")
			}
		}
		cancel()
		controlHealthy = err == nil
		if controlHealthy && session.MCPURL != "" {
			ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
			mcpHealthy = control.MCPHealth(ctx, session.MCPURL) == nil
			cancel()
		}
	}
	result := map[string]any{
		"session": session, "process_alive": live, "control_healthy": controlHealthy,
		"mcp_healthy": mcpHealthy, "live_status": liveStatus, "busy": len(session.ActiveJobIDs) > 0,
	}
	if *jsonOutput {
		return writeJSON(e.stdout, result)
	}
	fmt.Fprintf(e.stdout, "session: %s\ntarget: %s\nstate: %s\nprocess alive: %t\ncontrol healthy: %t\nMCP healthy: %t\ngeneration: %d\n", session.SessionID, store.TargetKind(session), session.State, live, controlHealthy, mcpHealthy, session.CurrentGeneration)
	if store.TargetKind(session) == store.TargetBinary {
		fmt.Fprintf(e.stdout, "input: %s\nformat: %s\narchitecture: %s\n", session.SourcePath, session.BinaryFormat, session.Architecture)
	}
	if session.MCPURL != "" {
		fmt.Fprintf(e.stdout, "MCP: %s\n", session.MCPURL)
	}
	if len(session.ActiveJobIDs) > 0 {
		fmt.Fprintf(e.stdout, "active job: %s\n", session.ActiveJobIDs[0])
	}
	for index, module := range session.LoadedModules {
		fmt.Fprintf(e.stdout, "module[%d]: %s\n", index, module)
	}
	for index, module := range session.ImplicitlyLoaded {
		fmt.Fprintf(e.stdout, "implicit module[%d]: %s\n", index, module)
	}
	return nil
}

func (e *environment) sessions(args []string) error {
	set := flagSet("sessions", e.stderr)
	root := set.String("state-dir", "", "state root")
	jsonOutput := set.Bool("json", false, "emit JSON")
	if err := parseInterspersed(set, args); err != nil {
		return err
	}
	if set.NArg() != 0 {
		return fmt.Errorf("usage: dscida sessions")
	}
	st, err := rootStore(*root)
	if err != nil {
		return err
	}
	sessions, err := st.ListSessions()
	if err != nil {
		return err
	}
	if *jsonOutput {
		return writeJSON(e.stdout, map[string]any{"sessions": sessions})
	}
	table := tabwriter.NewWriter(e.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "SESSION\tTARGET\tSTATE\tPID\tGENERATION\tPRIMARY")
	for _, session := range sessions {
		primary := session.MainModule
		if store.TargetKind(&session) == store.TargetBinary {
			primary = session.SourcePath
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t%d\t%d\t%s\n", session.SessionID, store.TargetKind(&session), session.State, session.IDAPID, session.CurrentGeneration, primary)
	}
	return table.Flush()
}

func (e *environment) jobs(args []string) error {
	set := flagSet("jobs", e.stderr)
	root := set.String("state-dir", "", "state root")
	jsonOutput := set.Bool("json", false, "emit JSON")
	if err := parseInterspersed(set, args); err != nil {
		return err
	}
	if err := requireArgs(set, 1, "dscida jobs <SESSION>"); err != nil {
		return err
	}
	st, err := rootStore(*root)
	if err != nil {
		return err
	}
	jobs, err := st.ListJobs(set.Arg(0))
	if err != nil {
		return err
	}
	if *jsonOutput {
		return writeJSON(e.stdout, map[string]any{"jobs": jobs})
	}
	table := tabwriter.NewWriter(e.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "JOB\tOPERATION\tSTATE\tMODULE")
	for _, job := range jobs {
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\n", job.JobID, job.Operation, job.State, job.ModulePath)
	}
	return table.Flush()
}

func (e *environment) job(args []string) error {
	set := flagSet("job", e.stderr)
	root := set.String("state-dir", "", "state root")
	jsonOutput := set.Bool("json", false, "emit JSON")
	if err := parseInterspersed(set, args); err != nil {
		return err
	}
	if err := requireArgs(set, 1, "dscida job <JOB_ID>"); err != nil {
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
	if *jsonOutput {
		return writeJSON(e.stdout, job)
	}
	fmt.Fprintf(e.stdout, "job: %s\nsession: %s\noperation: %s\nstate: %s\nmodule: %s\nerror: %s\n", job.JobID, job.SessionID, job.Operation, job.State, job.ModulePath, job.Error)
	return nil
}

func (e *environment) logs(args []string) error {
	set := flagSet("logs", e.stderr)
	root := set.String("state-dir", "", "state root")
	component := set.String("component", "dscida", "dscida, ida, stdout, or stderr")
	lines := set.Int("lines", 100, "tail line count")
	if err := parseInterspersed(set, args); err != nil {
		return err
	}
	if err := requireArgs(set, 1, "dscida logs <SESSION>"); err != nil {
		return err
	}
	st, err := rootStore(*root)
	if err != nil {
		return err
	}
	names := map[string]string{
		"dscida": "dscida.jsonl", "ida": "ida-message.log",
		"stdout": "idat.stdout.log", "stderr": "idat.stderr.log",
	}
	name, ok := names[*component]
	if !ok {
		return fmt.Errorf("unknown log component %q", *component)
	}
	return runner.Tail(filepath.Join(st.SessionDir(set.Arg(0)), "logs", name), *lines, e.stdout)
}
