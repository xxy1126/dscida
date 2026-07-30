package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tmo/dscida/internal/store"
)

type claudeEntry struct {
	Name           string   `json:"name"`
	Scope          string   `json:"scope,omitempty"`
	OriginScopes   []string `json:"origin_scopes,omitempty"`
	ShadowedScopes []string `json:"shadowed_scopes,omitempty"`
	Details        string   `json:"details"`
	MatchesScope   bool     `json:"matches_scope"`
}

func (e *environment) claude(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: dscida claude <install|remove|list> [flags]")
	}
	switch args[0] {
	case "install":
		return e.claudeInstall(args[1:])
	case "remove":
		return e.claudeRemove(args[1:])
	case "list":
		return e.claudeList(args[1:])
	default:
		return fmt.Errorf("unknown claude command %q", args[0])
	}
}

func (e *environment) claudeInstall(args []string) error {
	set := flagSet("claude install", e.stderr)
	name := set.String("name", "", "Claude MCP server name")
	scope := set.String("scope", "local", "Claude config scope")
	projectDir := set.String("project-dir", "", "Claude project directory")
	root := set.String("state-dir", "", "state root")
	dryRun := set.Bool("dry-run", false, "print the exact operation")
	replace := set.Bool("replace", false, "replace a conflicting configuration")
	if err := parseInterspersed(set, args); err != nil {
		return err
	}
	if err := requireArgs(
		set, 1,
		"dscida claude install <SESSION> [--name NAME] [--scope SCOPE]",
	); err != nil {
		return err
	}
	if err := validateClaudeScope(*scope); err != nil {
		return err
	}
	sessionID := set.Arg(0)
	st, err := rootStore(*root)
	if err != nil {
		return err
	}
	session, err := st.LoadSession(sessionID)
	if err != nil {
		return err
	}
	if session.SchemaVersion != store.SessionSchemaVersion {
		return fmt.Errorf("session %s must be resumed or recreated before Claude install", sessionID)
	}
	if *name == "" {
		*name = "dscida_" + sessionID
	}
	if !validName(*name) {
		return fmt.Errorf("invalid Claude MCP server name %q", *name)
	}
	directory, err := canonicalDirectory(*projectDir)
	if err != nil {
		return err
	}
	claudePath, err := absoluteExecutable("claude")
	if err != nil {
		return err
	}
	dscidaPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve dscida executable: %w", err)
	}
	dscidaPath, err = filepath.Abs(dscidaPath)
	if err != nil {
		return err
	}
	serverArgs := []string{
		"mcp", sessionID, "--stdio", "--follow",
		"--server-name", *name, "--state-dir", st.Root,
	}
	addArgs := append(
		[]string{"mcp", "add", "--scope", *scope, *name, "--", dscidaPath},
		serverArgs...,
	)
	if *dryRun {
		return writeJSON(e.stdout, map[string]any{
			"directory": directory,
			"program":   claudePath,
			"arguments": addArgs,
			"mcp": map[string]any{
				"name": *name, "type": "stdio", "command": dscidaPath,
				"args": serverArgs, "scope": *scope,
			},
		})
	}

	details, exists, err := claudeGet(directory, claudePath, *name)
	if err != nil {
		return err
	}
	if exists {
		if claudeConfigMatches(details, *scope, dscidaPath, serverArgs) {
			fmt.Fprintf(e.stdout, "Claude MCP server %s is already configured identically.\n", *name)
			return nil
		}
		if !*replace {
			return fmt.Errorf(
				"Claude MCP server %s already exists with different configuration; use --replace",
				*name,
			)
		}
		existingScope := parseClaudeScope(details)
		if existingScope != *scope {
			return fmt.Errorf(
				"Claude MCP server %s is effective from %s scope; remove it explicitly "+
					"with `dscida claude remove %s --scope %s` before installing in %s scope",
				*name, existingScope, *name, existingScope, *scope,
			)
		}
		if err := runClaude(directory, claudePath, e.stdout, e.stderr,
			"mcp", "remove", "--scope", *scope, *name,
		); err != nil {
			return fmt.Errorf("remove conflicting Claude MCP server: %w", err)
		}
	}
	if err := runClaude(directory, claudePath, e.stdout, e.stderr, addArgs...); err != nil {
		return fmt.Errorf("install Claude MCP server: %w", err)
	}
	return nil
}

func (e *environment) claudeRemove(args []string) error {
	set := flagSet("claude remove", e.stderr)
	scope := set.String("scope", "", "explicit Claude config scope")
	projectDir := set.String("project-dir", "", "Claude project directory")
	dryRun := set.Bool("dry-run", false, "print the exact operation")
	if err := parseInterspersed(set, args); err != nil {
		return err
	}
	if err := requireArgs(
		set, 1,
		"dscida claude remove <SERVER_NAME> --scope <local|project|user>",
	); err != nil {
		return err
	}
	if *scope == "" {
		return fmt.Errorf("claude remove requires an explicit --scope")
	}
	if err := validateClaudeScope(*scope); err != nil {
		return err
	}
	name := set.Arg(0)
	if !validName(name) {
		return fmt.Errorf("invalid Claude MCP server name %q", name)
	}
	directory, err := canonicalDirectory(*projectDir)
	if err != nil {
		return err
	}
	claudePath, err := absoluteExecutable("claude")
	if err != nil {
		return err
	}
	commandArgs := []string{"mcp", "remove", "--scope", *scope, name}
	if *dryRun {
		return writeJSON(e.stdout, map[string]any{
			"directory": directory, "program": claudePath, "arguments": commandArgs,
		})
	}
	return runClaude(directory, claudePath, e.stdout, e.stderr, commandArgs...)
}

func (e *environment) claudeList(args []string) error {
	set := flagSet("claude list", e.stderr)
	scope := set.String("scope", "", "annotate entries outside this scope")
	projectDir := set.String("project-dir", "", "Claude project directory")
	asJSON := set.Bool("json", false, "emit JSON")
	if err := parseInterspersed(set, args); err != nil {
		return err
	}
	if err := requireArgs(set, 0, "dscida claude list [--project-dir PATH]"); err != nil {
		return err
	}
	if *scope != "" {
		if err := validateClaudeScope(*scope); err != nil {
			return err
		}
	}
	directory, err := canonicalDirectory(*projectDir)
	if err != nil {
		return err
	}
	claudePath, err := absoluteExecutable("claude")
	if err != nil {
		return err
	}
	output, err := runClaudeOutput(directory, claudePath, "mcp", "list")
	if err != nil {
		return fmt.Errorf("list Claude MCP servers: %w\n%s", err, strings.TrimSpace(output))
	}
	names := parseClaudeListNames(output)
	origins := configuredClaudeOrigins(directory)
	for name := range origins {
		if !containsString(names, name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	entries := make([]claudeEntry, 0, len(names))
	for _, name := range names {
		details, exists, getErr := claudeGet(directory, claudePath, name)
		if getErr != nil {
			return getErr
		}
		if !exists {
			continue
		}
		entryScope := parseClaudeScope(details)
		originScopes := origins[name]
		if !containsString(originScopes, entryScope) && entryScope != "" {
			originScopes = append(originScopes, entryScope)
			sort.Strings(originScopes)
		}
		var shadowed []string
		for _, origin := range originScopes {
			if origin != entryScope {
				shadowed = append(shadowed, origin)
			}
		}
		entries = append(entries, claudeEntry{
			Name: name, Scope: entryScope, OriginScopes: originScopes,
			ShadowedScopes: shadowed, Details: redactClaudeDetails(details),
			MatchesScope: *scope == "" || containsString(originScopes, *scope),
		})
	}
	if *asJSON {
		return writeJSON(e.stdout, map[string]any{
			"project_dir": directory, "scope_filter": *scope, "servers": entries,
		})
	}
	if len(entries) == 0 {
		fmt.Fprintln(e.stdout, "No MCP servers configured.")
		return nil
	}
	for index, entry := range entries {
		if index != 0 {
			fmt.Fprintln(e.stdout)
		}
		if !entry.MatchesScope {
			fmt.Fprintf(
				e.stdout,
				"%s [effective entry outside requested %s scope]\n",
				entry.Name, *scope,
			)
		}
		fmt.Fprintln(e.stdout, entry.Details)
		if len(entry.ShadowedScopes) != 0 {
			fmt.Fprintf(
				e.stdout, "  Shadowed scopes: %s\n",
				strings.Join(entry.ShadowedScopes, ", "),
			)
		}
	}
	return nil
}

func validateClaudeScope(scope string) error {
	switch scope {
	case "local", "project", "user":
		return nil
	default:
		return fmt.Errorf("invalid Claude scope %q (want local, project, or user)", scope)
	}
}

func canonicalDirectory(path string) (string, error) {
	if path == "" {
		var err error
		path, err = os.Getwd()
		if err != nil {
			return "", err
		}
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("resolve project directory: %w", err)
	}
	info, err := os.Stat(canonical)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("project directory is not a directory: %s", canonical)
	}
	return canonical, nil
}

func absoluteExecutable(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%s executable not found: %w", name, err)
	}
	return filepath.Abs(path)
}

func runClaude(
	directory, program string, stdout, stderr io.Writer, args ...string,
) error {
	command := exec.Command(program, args...)
	command.Dir = directory
	command.Stdout = stdout
	command.Stderr = stderr
	return command.Run()
}

func runClaudeOutput(directory, program string, args ...string) (string, error) {
	command := exec.Command(program, args...)
	command.Dir = directory
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	err := command.Run()
	return output.String(), err
}

func claudeGet(directory, program, name string) (string, bool, error) {
	output, err := runClaudeOutput(directory, program, "mcp", "get", name)
	if err == nil {
		return output, true, nil
	}
	if strings.Contains(output, "No MCP server named") {
		return "", false, nil
	}
	return "", false, fmt.Errorf("inspect Claude MCP server %s: %w\n%s",
		name, err, strings.TrimSpace(output))
}

func claudeConfigMatches(
	details, scope, command string, args []string,
) bool {
	return strings.Contains(details, "Scope: "+claudeScopeLabel(scope)) &&
		strings.Contains(details, "\n  Command: "+command+"\n") &&
		strings.Contains(details, "\n  Args: "+strings.Join(args, " ")+"\n")
}

func claudeScopeLabel(scope string) string {
	switch scope {
	case "local":
		return "Local config"
	case "project":
		return "Project config"
	case "user":
		return "User config"
	default:
		return ""
	}
}

func parseClaudeListNames(output string) []string {
	var names []string
	for _, line := range strings.Split(output, "\n") {
		name, _, found := strings.Cut(line, ": ")
		if found && validName(name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func parseClaudeScope(details string) string {
	for scope, label := range map[string]string{
		"local":   "Scope: Local config",
		"project": "Scope: Project config",
		"user":    "Scope: User config",
	} {
		if strings.Contains(details, label) {
			return scope
		}
	}
	return ""
}

func redactClaudeDetails(details string) string {
	lines := strings.Split(strings.TrimSpace(details), "\n")
	inEnvironment := false
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "Environment:" {
			inEnvironment = true
			continue
		}
		if !inEnvironment {
			continue
		}
		if trimmed == "" {
			inEnvironment = false
			continue
		}
		if key, _, found := strings.Cut(trimmed, "="); found {
			indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
			lines[index] = indent + key + "=<redacted>"
		}
	}
	return strings.Join(lines, "\n")
}

func configuredClaudeOrigins(directory string) map[string][]string {
	result := make(map[string][]string)
	type projectConfig struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
	}
	var global struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
		Projects   map[string]projectConfig   `json:"projects"`
	}
	if payload, err := os.ReadFile(claudeGlobalConfigPath()); err == nil &&
		json.Unmarshal(payload, &global) == nil {
		addClaudeOrigins(result, global.MCPServers, "user")
		for path, project := range global.Projects {
			if sameCanonicalDirectory(path, directory) {
				addClaudeOrigins(result, project.MCPServers, "local")
			}
		}
	}
	var project projectConfig
	if payload, err := os.ReadFile(filepath.Join(directory, ".mcp.json")); err == nil &&
		json.Unmarshal(payload, &project) == nil {
		addClaudeOrigins(result, project.MCPServers, "project")
	}
	for name := range result {
		sort.Strings(result[name])
	}
	return result
}

func claudeGlobalConfigPath() string {
	if directory := os.Getenv("CLAUDE_CONFIG_DIR"); directory != "" {
		return filepath.Join(directory, ".claude.json")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".claude.json")
}

func addClaudeOrigins(
	result map[string][]string, servers map[string]json.RawMessage, scope string,
) {
	for name := range servers {
		if validName(name) && !containsString(result[name], scope) {
			result[name] = append(result[name], scope)
		}
	}
}

func sameCanonicalDirectory(first, second string) bool {
	firstPath, firstErr := filepath.EvalSymlinks(first)
	secondPath, secondErr := filepath.EvalSymlinks(second)
	if firstErr != nil || secondErr != nil {
		return first == second
	}
	return firstPath == secondPath
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
