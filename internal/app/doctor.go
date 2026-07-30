package app

import (
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tmo/dscida/internal/runner"
)

func (e *environment) doctor(args []string) error {
	set := flagSet("doctor", e.stderr)
	idaPath := set.String("ida-path", "", "idat executable")
	root := set.String("state-dir", "", "state root")
	probe := set.Bool("probe", false, "probe loopback and idat version")
	probeDSC := set.Bool("probe-dsc", false, "run a disposable real DSC/IDA/MCP compatibility probe")
	dscPath := set.String("dsc", "", "DSC path for --probe-dsc")
	modulePath := set.String("module", "", "primary canonical module path for --probe-dsc")
	addModule := set.String("add-module", "", "optional second module to test incremental DSCU loading")
	keepProbe := set.Bool("keep-probe", false, "retain successful probe artifacts")
	probeTimeout := set.Duration("timeout", 30*time.Minute, "dynamic probe operation timeout")
	jsonOutput := set.Bool("json", false, "emit JSON")
	if err := parseInterspersed(set, args); err != nil {
		return err
	}
	if set.NArg() != 0 {
		return fmt.Errorf("usage: dscida doctor [flags]")
	}
	if *probeDSC && (*dscPath == "" || *modulePath == "") {
		return fmt.Errorf("--probe-dsc requires --dsc and --module")
	}
	if *addModule != "" && !*probeDSC {
		return fmt.Errorf("--add-module requires --probe-dsc")
	}
	if *probeDSC {
		*probe = true
	}
	checks := map[string]any{}
	idat, idaErr := runner.ResolveIDA(*idaPath)
	checks["idat"] = map[string]any{"ok": idaErr == nil, "path": idat, "error": errorString(idaErr)}
	st, stateErr := rootStore(*root)
	statePath := ""
	if st != nil {
		statePath = st.Root
	}
	checks["state_directory"] = map[string]any{"ok": stateErr == nil, "path": statePath, "error": errorString(stateErr)}
	python, pythonErr := exec.LookPath("python3.11")
	mcpErr := error(nil)
	if pythonErr == nil {
		command := exec.Command(python, "-c", "import ida_pro_mcp; print(ida_pro_mcp.__file__)")
		if output, err := command.CombinedOutput(); err != nil {
			mcpErr = fmt.Errorf("%v: %s", err, strings.TrimSpace(string(output)))
		} else {
			checks["ida_pro_mcp_path"] = strings.TrimSpace(string(output))
		}
	} else {
		mcpErr = pythonErr
	}
	checks["ida_pro_mcp"] = map[string]any{"ok": mcpErr == nil, "error": errorString(mcpErr)}
	probeOK := true
	if *probe {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err == nil {
			listener.Close()
		}
		probeOK = probeOK && err == nil
		checks["loopback_dynamic_port"] = map[string]any{"ok": err == nil, "error": errorString(err)}
		if idaErr == nil {
			appMarker := ".app" + string(filepath.Separator)
			appIndex := strings.Index(idat, appMarker)
			if appIndex >= 0 {
				plist := filepath.Join(idat[:appIndex+len(".app")], "Contents", "Info.plist")
				command := exec.Command("/usr/libexec/PlistBuddy", "-c", "Print:CFBundleShortVersionString", plist)
				output, versionErr := command.CombinedOutput()
				probeOK = probeOK && versionErr == nil
				checks["ida_version"] = map[string]any{
					"ok": versionErr == nil, "output": strings.TrimSpace(string(output)),
					"error": errorString(versionErr),
				}
			} else {
				probeOK = false
				checks["ida_version"] = map[string]any{"ok": false, "error": "idat is not inside an IDA .app bundle"}
			}
		}
	}
	ok := idaErr == nil && stateErr == nil && mcpErr == nil && probeOK
	var dynamicErr error
	if *probeDSC && ok {
		dynamic, err := e.runDSCProbe(*dscPath, *modulePath, *addModule, idat, *probeTimeout, *keepProbe)
		checks["dsc_runtime"] = dynamic
		dynamicErr = err
		ok = ok && err == nil && dynamic != nil && dynamic.Success
		if err != nil && dynamic != nil && probeArtifactPath(dynamic) != "" {
			fmt.Fprintf(e.stderr, "[doctor] failed probe artifacts retained at %s\n", probeArtifactPath(dynamic))
		}
	}
	note := "static checks only; use --probe-dsc with --dsc and --module for runtime DSCU validation"
	if *probeDSC {
		note = "real DSC headless loader, DSCU, MCP, snapshot validator, optional add, and cleanup were exercised"
	}
	result := map[string]any{"success": ok, "checks": checks, "note": note}
	if *jsonOutput {
		if err := writeJSON(e.stdout, result); err != nil {
			return err
		}
		if !ok {
			if dynamicErr != nil {
				return fmt.Errorf("DSC runtime probe failed: %w", dynamicErr)
			}
			return fmt.Errorf("one or more doctor checks failed")
		}
		return nil
	}
	keys := make([]string, 0, len(checks))
	for key := range checks {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintf(e.stdout, "%s: %v\n", key, checks[key])
	}
	if !ok {
		return fmt.Errorf("one or more doctor checks failed")
	}
	return nil
}
