package app

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseClaudeListNamesAndScopes(t *testing.T) {
	output := "Checking MCP server health…\n" +
		"dscida_ida2: /path (stdio) - ✔ Connected\n" +
		"not a valid name: ignored\n" +
		"dscida_ida1: /path (stdio) - ✔ Connected\n"
	if got := parseClaudeListNames(output); !reflect.DeepEqual(
		got, []string{"dscida_ida1", "dscida_ida2"},
	) {
		t.Fatalf("names=%v", got)
	}
	for _, item := range []struct {
		details string
		want    string
	}{
		{"Scope: Local config (private to you in this project)", "local"},
		{"Scope: Project config (shared via .mcp.json)", "project"},
		{"Scope: User config (available in all your projects)", "user"},
	} {
		if got := parseClaudeScope(item.details); got != item.want {
			t.Fatalf("scope=%q, want %q", got, item.want)
		}
	}
}

func TestRedactClaudeDetailsEnvironmentValues(t *testing.T) {
	details := "server:\n  Environment:\n    API_TOKEN=secret\n\nTo remove this server"
	got := redactClaudeDetails(details)
	if strings.Contains(got, "secret") ||
		!strings.Contains(got, "API_TOKEN=<redacted>") {
		t.Fatalf("redacted details=%q", got)
	}
}

func TestClaudeConfigMatchesExactBridgeCommand(t *testing.T) {
	command := "/Applications/dscida"
	args := []string{
		"mcp", "ida1", "--stdio", "--follow",
		"--server-name", "dscida_ida1", "--state-dir", "/state",
	}
	details := "dscida_ida1:\n" +
		"  Scope: User config (available in all your projects)\n" +
		"  Type: stdio\n" +
		"  Command: /Applications/dscida\n" +
		"  Args: mcp ida1 --stdio --follow --server-name dscida_ida1 --state-dir /state\n" +
		"  Environment:\n"
	if !claudeConfigMatches(details, "user", command, args) {
		t.Fatal("identical bridge configuration did not match")
	}
	args[1] = "ida2"
	if claudeConfigMatches(details, "user", command, args) {
		t.Fatal("different logical session unexpectedly matched")
	}
}
