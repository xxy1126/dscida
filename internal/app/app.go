package app

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/tmo/dscida/internal/store"
)

const version = "0.1.0"

type environment struct {
	stdout io.Writer
	stderr io.Writer
}

func Run(args []string, stdout, stderr io.Writer) error {
	env := &environment{stdout: stdout, stderr: stderr}
	if len(args) == 0 {
		env.usage()
		return flag.ErrHelp
	}
	switch args[0] {
	case "help", "-h", "--help":
		env.usage()
		return nil
	case "version", "--version":
		fmt.Fprintln(stdout, version)
		return nil
	case "modules":
		return env.modules(args[1:])
	case "start":
		return env.start(args[1:])
	case "start-binary":
		return env.startBinary(args[1:])
	case "add":
		return env.add(args[1:])
	case "status":
		return env.status(args[1:])
	case "sessions":
		return env.sessions(args[1:])
	case "jobs":
		return env.jobs(args[1:])
	case "job":
		return env.job(args[1:])
	case "wait":
		return env.wait(args[1:])
	case "save":
		return env.save(args[1:])
	case "stop":
		return env.stop(args[1:])
	case "mcp":
		return env.mcp(args[1:])
	case "claude":
		return env.claude(args[1:])
	case "logs":
		return env.logs(args[1:])
	case "exec":
		return env.exec(args[1:])
	case "decompile", "disasm", "funcs", "xrefs", "imports", "string",
		"bytes", "find", "survey", "rename", "comment", "set-type", "patch":
		return env.analysisHandler(args[0])(args[1:])
	case "doctor":
		return env.doctor(args[1:])
	default:
		return fmt.Errorf("unknown command %q (run dscida help)", args[0])
	}
}

func (e *environment) usage() {
	fmt.Fprintln(e.stderr, `dscida - headless DSC and standalone binary analysis for IDA Pro

Usage:
  dscida modules <DSC> [--query TEXT] [--json]
  dscida start <DSC> --module <ABSOLUTE_INSTALL_PATH> [flags]
  dscida start-binary <INPUT> [flags]
  dscida add <SESSION> --module <ABSOLUTE_INSTALL_PATH> [--no-wait]
  dscida status <SESSION> [--json]
  dscida sessions [--json]
  dscida jobs <SESSION> [--json]
  dscida job <JOB_ID> [--json]
  dscida wait <JOB_ID> [--timeout DURATION]
  dscida save <SESSION>
  dscida stop <SESSION> [--no-save]
  dscida mcp <SESSION> [--stdio] [--follow] [--server-name NAME]
  dscida claude install <SESSION> [--name NAME] [--scope local]
  dscida claude remove <SERVER_NAME> --scope <local|project|user>
  dscida claude list [--project-dir PATH] [--json]
  dscida logs <SESSION> [--component COMPONENT]
  dscida exec <SESSION> (--code CODE | --script FILE) [--arg K=V] [--timeout DURATION]
  dscida survey <SESSION>
  dscida decompile <SESSION> <ADDR> [--cfg]
  dscida disasm <SESSION> <ADDR> [--count N] [--graph]
  dscida funcs <SESSION> [--query TEXT] [--limit N]
  dscida xrefs <SESSION> <ADDR>
  dscida imports <SESSION> [--query TEXT]
  dscida string <SESSION> <ADDR> [--length N]
  dscida bytes <SESSION> <ADDR> [--length N] [--hex | --text]
  dscida find <SESSION> (--hex HEX | --text TEXT) [--from ADDR] [--to ADDR] [--count N]
  dscida rename <SESSION> <ADDR> <NAME>
  dscida comment <SESSION> <ADDR> <TEXT> [--append]
  dscida set-type <SESSION> <ADDR> <TYPE>
  dscida patch <SESSION> <ADDR> <HEX>
  dscida doctor [--probe]
  dscida doctor --probe-dsc --dsc <DSC> --module <PATH> [--add-module <PATH>]

Set DSCIDA_HOME to override the default state directory.`)
}

func flagSet(name string, stderr io.Writer) *flag.FlagSet {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(stderr)
	return set
}

// The standard flag package stops at the first positional argument, while the
// public CLI contract permits flags after DSC/session/job operands.
func parseInterspersed(set *flag.FlagSet, args []string) error {
	var options []string
	var positionals []string
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if arg == "--" {
			positionals = append(positionals, args[index+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			positionals = append(positionals, arg)
			continue
		}
		options = append(options, arg)
		name := strings.TrimLeft(arg, "-")
		if before, _, found := strings.Cut(name, "="); found {
			name = before
			continue
		}
		option := set.Lookup(name)
		if option == nil {
			continue
		}
		type boolFlag interface{ IsBoolFlag() bool }
		if value, ok := option.Value.(boolFlag); ok && value.IsBoolFlag() {
			continue
		}
		if index+1 < len(args) {
			index++
			options = append(options, args[index])
		}
	}
	return set.Parse(append(options, positionals...))
}

func requireArgs(set *flag.FlagSet, count int, usage string) error {
	if set.NArg() != count {
		return fmt.Errorf("usage: %s", usage)
	}
	return nil
}

func rootStore(root string) (*store.Store, error) {
	if root == "" {
		var err error
		root, err = store.DefaultRoot()
		if err != nil {
			return nil, err
		}
	}
	return store.New(root)
}

func validName(value string) bool {
	if value == "" || len(value) > 64 || value == "." || value == ".." {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z') && !(char >= 'A' && char <= 'Z') &&
			!(char >= '0' && char <= '9') && char != '-' && char != '_' {
			return false
		}
	}
	return true
}

func printResult(output io.Writer, asJSON bool, value any) error {
	if asJSON {
		return writeJSON(output, value)
	}
	switch item := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(item))
		for key := range item {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			fmt.Fprintf(output, "%s: %v\n", key, item[key])
		}
	default:
		return writeJSON(output, value)
	}
	return nil
}

func writeJSON(output io.Writer, value any) error {
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
