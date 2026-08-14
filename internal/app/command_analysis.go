package app

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/tmo/dscida/internal/assets"
	"github.com/tmo/dscida/internal/control"
	"github.com/tmo/dscida/internal/store"
)

// analysisCommand describes one built-in analysis command. Every command shares
// the exec-python transport; only its flags, script template, and timeout vary.
type analysisCommand struct {
	name      string
	template  string
	timeout   time.Duration
	modifies  bool
	extraArgs int
	usage     string
	addFlags  func(set *flag.FlagSet)
	vars      func(set *flag.FlagSet) (map[string]string, error)
}

var analysisCommands = []analysisCommand{
	{
		name: "decompile", timeout: 120 * time.Second, extraArgs: 1,
		usage: "dscida decompile <SESSION> <ADDR> [--cfg]",
		addFlags: func(set *flag.FlagSet) {
			set.Bool("cfg", false, "include the control-flow-graph block list")
		},
		vars: func(set *flag.FlagSet) (map[string]string, error) {
			return map[string]string{
				"addr": set.Arg(1),
				"cfg":  boolFlag(set, "cfg"),
			}, nil
		},
	},
	{
		name: "disasm", timeout: 60 * time.Second, extraArgs: 1,
		usage: "dscida disasm <SESSION> <ADDR> [--count N] [--graph]",
		addFlags: func(set *flag.FlagSet) {
			set.Int("count", 20, "instruction count")
			set.Bool("graph", false, "include the function basic-block list")
		},
		vars: func(set *flag.FlagSet) (map[string]string, error) {
			return map[string]string{
				"addr":  set.Arg(1),
				"count": fmt.Sprintf("%d", set.Lookup("count").Value.(flag.Getter).Get()),
				"graph": boolFlag(set, "graph"),
			}, nil
		},
	},
	{
		name: "funcs", timeout: 60 * time.Second,
		usage: "dscida funcs <SESSION> [--query TEXT] [--limit N]",
		addFlags: func(set *flag.FlagSet) {
			set.String("query", "", "case-insensitive name filter")
			set.Int("limit", 0, "maximum results; 0 means all")
		},
		vars: func(set *flag.FlagSet) (map[string]string, error) {
			return map[string]string{
				"query": set.Lookup("query").Value.String(),
				"limit": fmt.Sprintf("%d", set.Lookup("limit").Value.(flag.Getter).Get()),
			}, nil
		},
	},
	{
		name: "xrefs", timeout: 60 * time.Second, extraArgs: 1,
		usage: "dscida xrefs <SESSION> <ADDR>",
		vars: func(set *flag.FlagSet) (map[string]string, error) {
			return map[string]string{"addr": set.Arg(1)}, nil
		},
	},
	{
		name: "imports", timeout: 60 * time.Second,
		usage: "dscida imports <SESSION> [--query TEXT]",
		addFlags: func(set *flag.FlagSet) {
			set.String("query", "", "case-insensitive module name filter")
		},
		vars: func(set *flag.FlagSet) (map[string]string, error) {
			return map[string]string{"query": set.Lookup("query").Value.String()}, nil
		},
	},
	{
		name: "string", timeout: 60 * time.Second, extraArgs: 1,
		usage: "dscida string <SESSION> <ADDR> [--length N]",
		addFlags: func(set *flag.FlagSet) {
			set.Int("length", 256, "maximum read length")
		},
		vars: func(set *flag.FlagSet) (map[string]string, error) {
			return map[string]string{
				"addr":   set.Arg(1),
				"length": fmt.Sprintf("%d", set.Lookup("length").Value.(flag.Getter).Get()),
			}, nil
		},
	},
	{
		name: "bytes", timeout: 60 * time.Second, extraArgs: 1,
		usage: "dscida bytes <SESSION> <ADDR> [--length N] [--hex | --text]",
		addFlags: func(set *flag.FlagSet) {
			set.Int("length", 16, "byte count")
			set.Bool("hex", false, "hex dump output")
			set.Bool("text", false, "text output")
		},
		vars: func(set *flag.FlagSet) (map[string]string, error) {
			hexFlag := set.Lookup("hex").Value.(flag.Getter).Get().(bool)
			textFlag := set.Lookup("text").Value.(flag.Getter).Get().(bool)
			if hexFlag && textFlag {
				return nil, fmt.Errorf("--hex and --text are mutually exclusive")
			}
			format := "hex"
			if textFlag {
				format = "text"
			}
			return map[string]string{
				"addr":   set.Arg(1),
				"length": fmt.Sprintf("%d", set.Lookup("length").Value.(flag.Getter).Get()),
				"format": format,
			}, nil
		},
	},
	{
		name: "find", timeout: 60 * time.Second,
		usage: "dscida find <SESSION> (--hex HEX | --text TEXT) [--from ADDR] [--to ADDR] [--count N] [--case-insensitive]",
		addFlags: func(set *flag.FlagSet) {
			set.String("hex", "", "byte pattern as hex (e.g. DE AD BE EF)")
			set.String("text", "", "UTF-8 text pattern")
			set.String("from", "", "search start address")
			set.String("to", "", "search end address")
			set.Int("count", 0, "maximum matches; 0 means all")
			set.Bool("case-insensitive", false, "case-insensitive text match")
		},
		vars: func(set *flag.FlagSet) (map[string]string, error) {
			hexText := set.Lookup("hex").Value.String()
			text := set.Lookup("text").Value.String()
			if (hexText == "") == (text == "") {
				return nil, fmt.Errorf("exactly one of --hex or --text is required")
			}
			return map[string]string{
				"hex":              hexText,
				"text":             text,
				"from":             set.Lookup("from").Value.String(),
				"to":               set.Lookup("to").Value.String(),
				"count":            fmt.Sprintf("%d", set.Lookup("count").Value.(flag.Getter).Get()),
				"case_insensitive": boolFlag(set, "case-insensitive"),
			}, nil
		},
	},
	{
		name: "survey", timeout: 60 * time.Second,
		usage: "dscida survey <SESSION>",
		vars: func(set *flag.FlagSet) (map[string]string, error) {
			return nil, nil
		},
	},
	{
		name: "rename", timeout: 30 * time.Second, modifies: true, extraArgs: 2,
		usage: "dscida rename <SESSION> <ADDR> <NAME>",
		vars: func(set *flag.FlagSet) (map[string]string, error) {
			return map[string]string{"addr": set.Arg(1), "name": set.Arg(2)}, nil
		},
	},
	{
		name: "comment", timeout: 30 * time.Second, modifies: true, extraArgs: 2,
		usage: "dscida comment <SESSION> <ADDR> <TEXT> [--append]",
		addFlags: func(set *flag.FlagSet) {
			set.Bool("append", false, "append to the existing comment")
		},
		vars: func(set *flag.FlagSet) (map[string]string, error) {
			return map[string]string{
				"addr":   set.Arg(1),
				"text":   set.Arg(2),
				"append": boolFlag(set, "append"),
			}, nil
		},
	},
	{
		name: "set-type", timeout: 30 * time.Second, modifies: true, extraArgs: 2,
		template: "set_type.py",
		usage: "dscida set-type <SESSION> <ADDR> <TYPE>",
		vars: func(set *flag.FlagSet) (map[string]string, error) {
			return map[string]string{"addr": set.Arg(1), "type": set.Arg(2)}, nil
		},
	},
	{
		name: "patch", timeout: 30 * time.Second, modifies: true, extraArgs: 2,
		usage: "dscida patch <SESSION> <ADDR> <HEX>",
		vars: func(set *flag.FlagSet) (map[string]string, error) {
			return map[string]string{"addr": set.Arg(1), "hex": set.Arg(2)}, nil
		},
	},
}

var analysisByName = func() map[string]analysisCommand {
	result := make(map[string]analysisCommand, len(analysisCommands))
	for _, command := range analysisCommands {
		result[command.name] = command
	}
	return result
}()

func boolFlag(set *flag.FlagSet, name string) string {
	if set.Lookup(name).Value.(flag.Getter).Get().(bool) {
		return "1"
	}
	return "0"
}

func builtinScript(name string, vars map[string]string) (string, error) {
	spec, ok := analysisByName[name]
	if !ok {
		return "", fmt.Errorf("unknown analysis command %q", name)
	}
	common, err := assets.Script("common.py")
	if err != nil {
		return "", err
	}
	template := spec.template
	if template == "" {
		template = spec.name + ".py"
	}
	body, err := assets.Script(template)
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(vars)
	if err != nil {
		return "", err
	}
	return "dscida_args = " + string(encoded) + "\n" + common + "\n" + body, nil
}

func (e *environment) analysisHandler(name string) func(args []string) error {
	return func(args []string) error {
		spec := analysisByName[name]
		set := flagSet(name, e.stderr)
		root := set.String("state-dir", "", "state root")
		jsonOutput := set.Bool("json", false, "emit JSON")
		if spec.addFlags != nil {
			spec.addFlags(set)
		}
		if err := parseInterspersed(set, args); err != nil {
			return err
		}
		if err := requireArgs(set, 1+spec.extraArgs, spec.usage); err != nil {
			return err
		}
		vars, err := spec.vars(set)
		if err != nil {
			return err
		}
		if vars == nil {
			vars = map[string]string{}
		}
		st, session, err := loadReadySession(*root, set.Arg(0))
		if err != nil {
			return err
		}
		vars["target_kind"] = store.TargetKind(session)
		script, err := builtinScript(name, vars)
		if err != nil {
			return err
		}
		timeoutMs := int(spec.timeout.Milliseconds())
		ctx, cancel := context.WithTimeout(context.Background(), spec.timeout+15*time.Second)
		defer cancel()
		outcome, err := control.New(session.ControlURL, session.ControlToken).ExecPython(ctx, script, nil, timeoutMs)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if err := e.printAnalysisResult(*jsonOutput, outcome); err != nil {
			return err
		}
		if outcome.TimedOut {
			return fmt.Errorf("%s timed out after %s (IDA process was not killed)", name, spec.timeout)
		}
		if !outcome.Success {
			if outcome.Traceback != "" {
				return fmt.Errorf("%s failed: %s\n%s", name, outcome.Error, outcome.Traceback)
			}
			return fmt.Errorf("%s failed: %s", name, outcome.Error)
		}
		if spec.modifies {
			session.UncommittedMCPEdits = true
			if err := st.SaveSession(session); err != nil {
				return err
			}
		}
		return nil
	}
}

func (e *environment) printAnalysisResult(jsonOutput bool, outcome *control.ExecResult) error {
	if jsonOutput {
		payload := map[string]any{
			"success":             outcome.Success && !outcome.TimedOut,
			"session_id":          outcome.SessionID,
			"session_instance_id": outcome.SessionInstanceID,
			"stdout":              outcome.Stdout,
			"error":               outcome.Error,
			"execution_ms":        outcome.ExecutionMS,
			"timed_out":           outcome.TimedOut,
		}
		if value, valueErr := outcome.ResultValue(); valueErr != nil {
			return valueErr
		} else if value != nil {
			payload["result"] = value
		}
		return writeJSON(e.stdout, payload)
	}
	if outcome.Stdout != "" {
		fmt.Fprint(e.stdout, outcome.Stdout)
		if !strings.HasSuffix(outcome.Stdout, "\n") {
			fmt.Fprintln(e.stdout)
		}
	}
	return nil
}
