---
name: use-dscida
description: Operate the local dscida CLI for headless IDA analysis of dyld shared cache modules and standalone binaries. Use when an agent must list canonical DSC module paths, load or replace a module in the fixed ida1/ida2 sessions, add DSC modules to the same IDA database, run built-in analysis commands (decompile, disasm, xrefs, find, survey, ...), execute arbitrary IDAPython via exec, inspect status or logs, or stop IDA without saving.
---

# Use dscida

Use the local executable:

```bash
DSCIDA_BIN=/Volumes/tmo/ios_firmware/apple_tools/dscida/bin/dscida
```

The two stable session slots are:

| dscida session | target |
|---|---|
| `ida1` | one logical IDA slot |
| `ida2` | one logical IDA slot |

A session name is a logical IDA slot; it is not a PID or port. Analysis never
goes through MCP: use `dscida exec` and the built-in analysis commands, which
run IDAPython inside the live IDA process via the authenticated control
endpoint.

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
3. Verify that the session and control endpoint are healthy.

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

## Analyze the live session

No reconnect step is needed after a replacement: the CLI resolves the current
control endpoint from session state on every invocation. Analyze with the
built-in commands (spec: `AGENT-CLI-SPEC.md`):

```bash
"$DSCIDA_BIN" survey "$SESSION_ID" --json
"$DSCIDA_BIN" funcs "$SESSION_ID" --query Security --limit 20
"$DSCIDA_BIN" decompile "$SESSION_ID" _main
"$DSCIDA_BIN" disasm "$SESSION_ID" _main --count 20
"$DSCIDA_BIN" xrefs "$SESSION_ID" 0x180123000
"$DSCIDA_BIN" imports "$SESSION_ID" --query libobjc
"$DSCIDA_BIN" string "$SESSION_ID" 0x180123000
"$DSCIDA_BIN" bytes "$SESSION_ID" 0x180123000 --length 32
"$DSCIDA_BIN" find "$SESSION_ID" --hex "cf fa ed fe" --count 5
"$DSCIDA_BIN" find "$SESSION_ID" --text "Usage" --case-insensitive
```

Addresses accept `0x` hex, decimal, or symbol names. Every command supports
`--json`. Modifying commands persist only after an explicit save:

```bash
"$DSCIDA_BIN" rename "$SESSION_ID" _main my_func
"$DSCIDA_BIN" comment "$SESSION_ID" _main "handled" --append
"$DSCIDA_BIN" set-type "$SESSION_ID" _main "int my_func(int a);"
"$DSCIDA_BIN" patch "$SESSION_ID" 0x180123000 9090
"$DSCIDA_BIN" save "$SESSION_ID"
```

Run arbitrary IDAPython when a built-in does not cover the need:

```bash
"$DSCIDA_BIN" exec "$SESSION_ID" --code 'print(hex(idaapi.get_imagebase()))'
"$DSCIDA_BIN" exec "$SESSION_ID" --script /path/script.py --arg name=alice --timeout 2m
```

`print` output is captured as `stdout`; assigning a JSON-serializable value to
the `dscida_result` global returns it as `result`; a script raising an
exception returns an error with traceback; exceeding `--timeout` returns
`timed_out: true` without killing IDA.

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
committed generation. It does not remove the session directory.

Do not kill the IDA PID directly unless `stop` has failed and the user asks
for recovery. Direct termination can leave stale session state.

## Diagnose failures

Use structured status first, then component logs:

```bash
"$DSCIDA_BIN" status "$SESSION_ID" --json
"$DSCIDA_BIN" logs "$SESSION_ID"
```

Report the selected session, DSC path, canonical module path, IDA PID, and
health state. Preserve logs and failed session artifacts unless the user
explicitly requests cleanup.
