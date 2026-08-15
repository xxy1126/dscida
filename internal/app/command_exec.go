package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/tmo/dscida/internal/control"
)

// maxExecScriptBytes keeps the inline source plus envelope within the sidecar's
// 64 KiB body cap.
const maxExecScriptBytes = 60 * 1024

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func (e *environment) exec(args []string) error {
	set := flagSet("exec", e.stderr)
	code := set.String("code", "", "inline IDAPython source")
	script := set.String("script", "", "path to an IDAPython script file")
	var argList stringList
	set.Var(&argList, "arg", "script argument K=V (repeatable)")
	timeout := set.Duration("timeout", 60*time.Second, "best-effort exec timeout")
	root := set.String("state-dir", "", "state root")
	jsonOutput := set.Bool("json", false, "emit JSON")
	if err := parseInterspersed(set, args); err != nil {
		return err
	}
	if err := requireArgs(set, 1, "dscida exec <SESSION> (--code CODE | --script FILE) [--arg K=V] [--timeout DURATION]"); err != nil {
		return err
	}
	if (*code == "") == (*script == "") {
		return fmt.Errorf("exactly one of --code or --script is required")
	}
	source, err := execSource(*code, *script)
	if err != nil {
		return err
	}
	scriptArgs, err := parseExecArgs(argList)
	if err != nil {
		return err
	}
	_, session, err := loadReadySession(*root, set.Arg(0))
	if err != nil {
		return err
	}
	timeoutMs := int(timeout.Milliseconds())
	if timeoutMs <= 0 {
		return fmt.Errorf("--timeout must be positive")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout+15*time.Second)
	defer cancel()
	outcome, err := control.New(session.ControlURL, session.ControlToken).ExecPython(ctx, source, scriptArgs, timeoutMs)
	if err != nil {
		return fmt.Errorf("exec-python: %w", err)
	}
	if *jsonOutput {
		payload := map[string]any{
			"success":             outcome.Success && !outcome.TimedOut,
			"session_id":          outcome.SessionID,
			"session_instance_id": outcome.SessionInstanceID,
			"pid":                 outcome.PID,
			"stdout":              outcome.Stdout,
			"error":               outcome.Error,
			"traceback":           outcome.Traceback,
			"execution_ms":        outcome.ExecutionMS,
			"timed_out":           outcome.TimedOut,
		}
		if value, valueErr := outcome.ResultValue(); valueErr != nil {
			return valueErr
		} else if value != nil {
			payload["result"] = value
		}
		if err := writeJSON(e.stdout, payload); err != nil {
			return err
		}
	} else {
		if outcome.Stdout != "" {
			fmt.Fprint(e.stdout, outcome.Stdout)
			if !strings.HasSuffix(outcome.Stdout, "\n") {
				fmt.Fprintln(e.stdout)
			}
		}
		if value, valueErr := outcome.ResultValue(); valueErr != nil {
			return valueErr
		} else if value != nil {
			encoded, _ := json.Marshal(value)
			fmt.Fprintf(e.stdout, "result: %s\n", encoded)
		}
	}
	if outcome.TimedOut {
		return fmt.Errorf("exec timed out after %s (IDA process was not killed)", timeout)
	}
	if !outcome.Success {
		if outcome.Traceback != "" {
			return fmt.Errorf("exec failed: %s\n%s", outcome.Error, outcome.Traceback)
		}
		return fmt.Errorf("exec failed: %s", outcome.Error)
	}
	return nil
}

func execSource(code, script string) (string, error) {
	if code != "" {
		return code, nil
	}
	info, err := os.Stat(script)
	if err != nil {
		return "", fmt.Errorf("read script: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("script is not a regular file: %s", script)
	}
	if info.Size() > maxExecScriptBytes {
		return "", fmt.Errorf("script exceeds %d bytes", maxExecScriptBytes)
	}
	data, err := os.ReadFile(script)
	if err != nil {
		return "", fmt.Errorf("read script: %w", err)
	}
	return string(data), nil
}

func parseExecArgs(values []string) (map[string]string, error) {
	result := make(map[string]string, len(values))
	for _, item := range values {
		key, value, found := strings.Cut(item, "=")
		if !found || key == "" {
			return nil, fmt.Errorf("invalid --arg %q (want K=V)", item)
		}
		result[key] = value
	}
	return result, nil
}
