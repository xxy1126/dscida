package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/tmo/dscida/internal/bridge"
	"github.com/tmo/dscida/internal/control"
	"github.com/tmo/dscida/internal/store"
)

func (e *environment) mcp(args []string) error {
	set := flagSet("mcp", e.stderr)
	root := set.String("state-dir", "", "state root")
	stdio := set.Bool("stdio", false, "serve MCP over stdio")
	follow := set.Bool("follow", false, "follow endpoint changes for the bound session")
	serverName := set.String("server-name", "", "stable upstream MCP server name")
	if err := parseInterspersed(set, args); err != nil {
		return err
	}
	if err := requireArgs(
		set, 1,
		"dscida mcp <SESSION> [--stdio] [--follow] [--server-name NAME]",
	); err != nil {
		return err
	}
	if *follow && !*stdio {
		return fmt.Errorf("--follow requires --stdio")
	}
	st, err := rootStore(*root)
	if err != nil {
		return err
	}
	sessionID := set.Arg(0)
	session, err := st.LoadSession(sessionID)
	if err != nil {
		return err
	}
	if *follow {
		if *serverName == "" {
			*serverName = "dscida_" + sessionID
		}
		if !validName(*serverName) {
			return fmt.Errorf("invalid --server-name %q", *serverName)
		}
		logPath := filepath.Join(st.SessionDir(sessionID), "logs", "mcp-proxy.log")
		logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return fmt.Errorf("open MCP bridge log: %w", err)
		}
		defer logFile.Close()
		service, err := bridge.New(bridge.Config{
			Store: st, SessionID: sessionID, ServerName: *serverName,
			Input: os.Stdin, Output: os.Stdout,
			Log: io.MultiWriter(e.stderr, logFile), PollInterval: 500 * time.Millisecond,
		})
		if err != nil {
			return err
		}
		return service.Run(context.Background())
	}
	if session.MCPURL == "" {
		return fmt.Errorf("session has no live MCP endpoint")
	}
	if !store.ProcessAlive(session.IDAPID) {
		return fmt.Errorf("session IDA process is not alive")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := control.MCPHealth(ctx, session.MCPURL); err != nil {
		cancel()
		return fmt.Errorf("session MCP endpoint is unhealthy: %w", err)
	}
	cancel()
	if !*stdio {
		fmt.Fprintln(e.stdout, session.MCPURL)
		return nil
	}
	python, err := exec.LookPath("python3.11")
	if err != nil {
		return fmt.Errorf("python3.11 required for ida-pro-mcp stdio proxy: %w", err)
	}
	command := exec.Command(python, "-m", "ida_pro_mcp.server", "--ida-rpc", session.MCPURL)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	return command.Run()
}
