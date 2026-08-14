package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tmo/dscida/internal/assets"
)

func TestParseExecArgs(t *testing.T) {
	result, err := parseExecArgs([]string{"name=alice", "depth=3"})
	if err != nil {
		t.Fatal(err)
	}
	if result["name"] != "alice" || result["depth"] != "3" {
		t.Fatalf("result=%v", result)
	}
	if _, err := parseExecArgs([]string{"missing-equals"}); err == nil {
		t.Fatal("expected error for malformed --arg")
	}
	if _, err := parseExecArgs([]string{"=value"}); err == nil {
		t.Fatal("expected error for empty key")
	}
}

func TestExecSourceScript(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "script.py")
	if err := os.WriteFile(path, []byte("print('hi')"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := execSource("", path)
	if err != nil {
		t.Fatal(err)
	}
	if source != "print('hi')" {
		t.Fatalf("source=%q", source)
	}
	// Inline code wins.
	source, err = execSource("print('code')", path)
	if err != nil {
		t.Fatal(err)
	}
	if source != "print('code')" {
		t.Fatalf("source=%q", source)
	}
	// Oversized scripts are rejected.
	big := strings.Repeat("x", maxExecScriptBytes+1)
	if err := os.WriteFile(path, []byte(big), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := execSource("", path); err == nil {
		t.Fatal("expected error for oversized script")
	}
}

func TestBuiltinScriptTemplates(t *testing.T) {
	for _, command := range analysisCommands {
		template := command.template
		if template == "" {
			template = command.name + ".py"
		}
		body, err := assets.Script(template)
		if err != nil {
			t.Fatalf("command %s template %s: %v", command.name, template, err)
		}
		if !strings.Contains(body, "main()") {
			t.Fatalf("template %s does not invoke main()", template)
		}
		vars := map[string]string{"addr": "0x1000"}
		combined, err := builtinScript(command.name, vars)
		if err != nil {
			t.Fatalf("builtinScript %s: %v", command.name, err)
		}
		if !strings.Contains(combined, `dscida_args = {"addr":"0x1000"}`) {
			t.Fatalf("builtinScript %s missing dscida_args header", command.name)
		}
	}
	if _, err := assets.Script("common.py"); err != nil {
		t.Fatalf("common.py: %v", err)
	}
}
