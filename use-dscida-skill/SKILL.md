---
name: use-dscida
description: Operate the local dscida CLI for headless IDA analysis of dyld shared cache modules. Use when Claude Code must list canonical DSC module paths, load or replace a module in the fixed ida1/ida2 sessions, add modules to the same IDA database, inspect status or logs, stop IDA without saving, or analyze through the registered dscida_ida1/dscida_ida2 MCP servers.
---

# Use dscida

Use the local executable:

```bash
DSCIDA_BIN=/Volumes/tmo/ios_firmware/apple_tools/dscida/bin/dscida
```

The two stable slots are already registered globally:

| dscida session | Claude MCP server |
|---|---|
| `ida1` | `dscida_ida1` |
| `ida2` | `dscida_ida2` |

Do not reinstall these MCP entries during normal use. A session name is a
logical IDA slot; the MCP server name is what Claude Code sees.

## Select a DSC module

Require the exact DSC file and an exact canonical module install path. If the
user provides a directory, locate candidate `dyld_shared_cache_arm64e` or
`dyld_shared_cache_arm64` files first and report ambiguity instead of guessing.

Search modules without starting IDA:

```bash
"$DSCIDA_BIN" modules "$DSC_PATH" --query "$MODULE_QUERY"
```

Use the returned absolute install path, for example:

```text
/System/Library/Frameworks/Security.framework/Security
```

If the query returns multiple plausible paths, ask the user to choose. Never
construct or shorten a module path manually.

## Choose ida1 or ida2

Honor an explicitly requested slot. Otherwise inspect current state:

```bash
"$DSCIDA_BIN" sessions --json
```

Prefer a stopped or unused slot. If both slots are active, do not stop either
one without asking which slot may be replaced.

## Replace a slot with a new DSC target

The normal workflow intentionally discards unsaved IDA changes:

1. If the selected session exists and is running, stop it with `--no-save`.
2. Start the new DSC/module under the same session name with `--replace`.
3. Verify that the session, control endpoint, and MCP endpoint are healthy.

```bash
"$DSCIDA_BIN" stop "$SESSION_ID" --no-save

"$DSCIDA_BIN" start "$DSC_PATH" \
  --module "$MODULE_PATH" \
  --session "$SESSION_ID" \
  --replace \
  --timeout 30m \
  --json

"$DSCIDA_BIN" status "$SESSION_ID" --json
```

Skip `stop` when the session does not exist or is already stopped. Keep
`--replace`; it works for both an existing session and a newly created slot.
Replacement moves the previous session to a recoverable backup and creates a
new `session_instance_id`.

Do not use `--resume` when switching to another DSC or primary module.
`--resume` is only for continuing the exact same DSC/module identity.

## Reconnect Claude after replacement

The registered name remains unchanged, but a replacement creates a new
`session_instance_id`. An MCP bridge already running in the current Claude
Code process deliberately refuses to jump to that new target.

After replacement, tell the user to run `/mcp` in the current Claude Code
session and reconnect:

- reconnect `dscida_ida1` after replacing `ida1`;
- reconnect `dscida_ida2` after replacing `ida2`.

A newly started Claude Code session connects directly. Do not run
`dscida claude install` again. Once connected, use the corresponding
`mcp__dscida_ida1__*` or `mcp__dscida_ida2__*` tools for analysis. Do not
substitute direct `curl` calls for MCP analysis tools.

If tools are unavailable, first run:

```bash
"$DSCIDA_BIN" status "$SESSION_ID" --json
"$DSCIDA_BIN" claude list --json
```

If IDA is healthy and the MCP entry is registered, request an `/mcp`
reconnect. Do not reinstall the entry as a first response.

## Add another module to the same DSC session

Only use `add` for a module from the same DSC already loaded in that session:

```bash
"$DSCIDA_BIN" add "$SESSION_ID" --module "$MODULE_PATH"
"$DSCIDA_BIN" status "$SESSION_ID" --json
```

Use canonical absolute module paths returned by `modules`. Do not use `add`
for standalone Mach-O/ELF sessions or for modules from another DSC.

## Stop a slot

Always honor the user's no-save preference:

```bash
"$DSCIDA_BIN" stop "$SESSION_ID" --no-save
```

This exits the headless IDA process and discards changes since the current
committed generation. It does not remove the session directory or the
user-scoped Claude MCP registration.

Do not kill the IDA PID directly unless `stop` has failed and the user asks
for recovery. Direct termination can leave stale session state.

## Diagnose failures

Use structured status first, then component logs:

```bash
"$DSCIDA_BIN" status "$SESSION_ID" --json
"$DSCIDA_BIN" logs "$SESSION_ID"
```

Report the selected session, DSC path, canonical module path, IDA PID, health
state, and corresponding Claude MCP server. Preserve logs and failed session
artifacts unless the user explicitly requests cleanup.
