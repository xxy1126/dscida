---
name: dscida
description: Operate headless IDA Pro sessions through the dscida CLI for reverse-engineering Apple dyld_shared_cache (DSC) modules and standalone thin Mach-O / little-endian ELF binaries. Use when a task involves IDA analysis — listing DSC module paths, opening or replacing sessions, adding more DSC modules to a session, decompiling, disassembling, finding cross-references, searching bytes or text, renaming, commenting, setting types, patching, running custom IDAPython via exec, or deciding when to save/stop/delete a session.
---

# dscida — headless IDA analysis via CLI

`dscida` runs one persistent headless IDA process per **session** and exposes a
command-line analysis surface. All analysis is driven through this CLI — no MCP,
no GUI. Everything below works from any agent shell; every command supports
`--json` for machine-readable output (logs and diagnostics go to stderr).

Resolve the binary once (adjust the path to your install):

```bash
DSCIDA_BIN=/path/to/dscida
```

## 1. Command overview

| Command | Purpose |
|---|---|
| `modules <DSC> [--query]` | List canonical module paths inside a DSC (no IDA) |
| `start <DSC> --module <PATH>` | Open a DSC session with one primary module |
| `start-binary <FILE>` | Open a standalone thin Mach-O / ELF session |
| `add <SESSION> --module <PATH>` | Load another image from the same DSC into the session |
| `status <SESSION>` / `sessions` | Live health of one / all sessions |
| `save <SESSION>` | Commit the live IDB as a verified generation |
| `stop <SESSION> [--no-save]` | Shut down IDA (pause the session) |
| `delete <SESSION> [--include-backups]` | Remove a stopped session (quarantined, recoverable) |
| `logs <SESSION>` | Tail supervisor / IDA logs |
| `analysis <decompile\|disasm\|funcs\|xrefs\|imports\|string\|bytes\|find\|survey>` | Built-in read-only analysis (Section 4) |
| `edit <rename\|comment\|set-type\|patch>` | Built-in IDB modifications, persisted via `save` (Section 4) |
| `exec <SESSION> (--code \| --script)` | Run arbitrary IDAPython (Section 5) |
| `wait <JOB_ID>` | Wait for a background mutation (`add --no-wait`) |
| `doctor [--probe]` | Environment diagnostics |

## 2. Session management

### 2.1 Naming and state

A **session name is a logical slot**, not a PID or port — e.g. `ida1`, `ida2`,
`security`. Prefer short lowercase names. The authoritative inventory is always:

```bash
"$DSCIDA_BIN" sessions --json
```

Each session is one target (one DSC primary module or one binary), one live IDA
process, and its own committed generations. Sessions are independent:
operations on one never touch another.

`status <SESSION> --json` is the single source of truth for one session. Useful
fields: `state` (`ready`, `stopped`, `failed`, `recovery_required`, …),
`process_alive`, `control_healthy`, `current_generation`, `loaded_modules`.
Only `ready` sessions accept `add`, `save`, and analysis commands.

### 2.2 Lifecycle decision table

| Situation | Do this | Why |
|---|---|---|
| Analysis is progressing; want a durable checkpoint | `save SESSION` | Commits a verified generation; `--resume` can reopen it later |
| Pausing this target; may continue later | `stop SESSION` | Frees IDA memory, keeps generations; `start --resume` restores in seconds **without re-running analysis** |
| Done for now; discard unsaved edits, keep history | `stop SESSION --no-save` | Exits IDA, keeps committed generations, drops live edits |
| Switching this slot to a new target; old analysis may matter | `stop SESSION --no-save` then `start ... --session SESSION --replace` | Old session becomes a recoverable backup; same name reused |
| Switching slots; old target is garbage | `stop SESSION --no-save` then `delete SESSION --include-backups` then `start ... --session SESSION` | Fully frees the name; no backup accumulation |
| User asks to "remove / clean up" a session | `stop SESSION --no-save` then `delete SESSION` | `delete` only accepts a durably stopped session |
| Continuing the exact same target | `start ... --session SESSION --resume` | Reopens the committed generation; never reloads changed sources |

Rules of thumb:

- **`stop` = pause** (preserves resumability). **`delete` = cleanup** (frees the
  name, quarantines to `<state-root>/trash/`, recoverable but no longer a slot).
- `delete` is intentionally strict: it fails with `session_delete_unsafe` unless
  the session is durably stopped (pid 0, no active jobs).
- `--replace` backs up the previous session and creates a **new**
  `session_instance_id`; `--resume` preserves the identity. Never `--resume` a
  different DSC/module/binary than the session was created for.

### 2.3 Standard workflows

Open a fresh slot:

```bash
"$DSCIDA_BIN" start "$DSC_PATH" --module "$MODULE_PATH" \
  --session "$SESSION_ID" --timeout 30m --json
```

Replace a slot with a new target (discard unsaved changes):

```bash
"$DSCIDA_BIN" stop "$SESSION_ID" --no-save
"$DSCIDA_BIN" start "$DSC_PATH" --module "$MODULE_PATH" \
  --session "$SESSION_ID" --replace --timeout 30m --json
"$DSCIDA_BIN" status "$SESSION_ID" --json
```

Skip `stop` when the session does not exist or is already stopped. If both
candidate slots are active, ask the user which one may be replaced — never stop
a busy session without permission.

## 3. DSC analysis workflow

### 3.1 Selecting a module

Require the exact DSC file and the exact **canonical module install path**. If
given a directory, locate candidate `dyld_shared_cache_arm64e` /
`dyld_shared_cache_arm64` files first and report ambiguity instead of guessing.

```bash
"$DSCIDA_BIN" modules "$DSC_PATH" --query "$MODULE_QUERY"
```

Use a returned absolute path verbatim, e.g.
`/System/Library/Frameworks/Security.framework/Security`. **Never construct,
shorten, or guess a module path** — if the query returns several plausible
matches, ask the user to choose.

### 3.2 Opening and adding modules

Open with exactly one primary module, then add more images from the **same DSC**
into the same IDB:

```bash
"$DSCIDA_BIN" start "$DSC_PATH" --module "$PRIMARY" --session "$SESSION_ID" --timeout 30m --json
"$DSCIDA_BIN" add "$SESSION_ID" --module "$SECONDARY" --timeout 30m --json
```

`add` rules:

- The module must come from the same DSC as the session (UUID checked).
- Only DSC sessions accept `add`; binary sessions reject it with
  `operation_not_supported_for_target`.
- Re-adding an already loaded module is idempotent (`already_loaded`).
- `add` is serial; a batch stops at the first failure, and earlier modules stay
  loaded. Use `--no-wait` + `wait <JOB_ID>` to fire-and-forget a slow add.

**Add a module when** the analysis target needs dependencies or more cache
images in the same binary context (e.g. a framework plus `libobjc`).
**Open a new session when** the target is a different DSC, a different primary
module worth analyzing on its own, or a standalone binary.

## 4. Analysis commands

### 4.1 Addressing

`<ADDR>` accepts, in order: `0x`-prefixed hexadecimal (`0x180123000`); a symbol
name resolved in IDA (`_main`, `Security::SomeFunc` — quote names with spaces);
a plain decimal integer. On failure the tool lists close symbol matches. JSON
outputs always print addresses as hexadecimal strings.

### 4.2 Read-only analysis

```bash
"$DSCIDA_BIN" analysis survey "$SESSION_ID" --json          # overview: base, processor, segments, funcs, entries
"$DSCIDA_BIN" analysis funcs "$SESSION_ID" --query Security --limit 20
"$DSCIDA_BIN" analysis decompile "$SESSION_ID" _main         # Hex-Rays pseudocode (--cfg for block list)
"$DSCIDA_BIN" analysis disasm "$SESSION_ID" _main --count 20
"$DSCIDA_BIN" analysis xrefs "$SESSION_ID" 0x180123000       # code+data refs to an address
"$DSCIDA_BIN" analysis imports "$SESSION_ID" --query libobjc
"$DSCIDA_BIN" analysis string "$SESSION_ID" 0x180123000
"$DSCIDA_BIN" analysis bytes "$SESSION_ID" 0x180123000 --length 32   # --text for raw text
"$DSCIDA_BIN" analysis find "$SESSION_ID" --hex "cf fa ed fe" --count 5
"$DSCIDA_BIN" analysis find "$SESSION_ID" --text "Usage" --case-insensitive
```

### 4.3 Modifying commands

Modifications write to the **live IDB only**; nothing is persisted until an
explicit `save` (which also clears the session's uncommitted-edits flag).

```bash
"$DSCIDA_BIN" edit rename "$SESSION_ID" _main my_func
"$DSCIDA_BIN" edit comment "$SESSION_ID" _main "handled" --append
"$DSCIDA_BIN" edit set-type "$SESSION_ID" _main "int my_func(int a);"   # function prototypes; data items may need an existing definition
"$DSCIDA_BIN" edit patch "$SESSION_ID" 0x180123000 9090
```

## 5. exec — arbitrary IDAPython

Use a built-in when it fits; use `exec` for everything else (batch analysis,
custom logic, debugger queries, signature work, …). The script runs on IDA's
main thread; `print()` is captured into `stdout`, and assigning a
JSON-serializable value to the global `dscida_result` returns it as `result`.

```bash
"$DSCIDA_BIN" exec "$SESSION_ID" --code 'print(hex(idaapi.get_imagebase()))'
"$DSCIDA_BIN" exec "$SESSION_ID" --script /path/script.py --arg name=alice --timeout 2m
```

Contract: a raising script returns `error` + `traceback` with non-zero exit; a
timeout returns `timed_out: true` **without killing IDA** (the process stays
busy until the script finishes — do not treat a timed-out exec as cancelled).
Common IDA modules (`idaapi`, `idc`, `ida_funcs`, `ida_bytes`, `ida_hexrays`,
`ida_name`, `ida_typeinf`, `ida_search`, …) are pre-imported globals.

### 5.1 Built-in template snippets (inline)

IDA Python APIs vary across IDA versions; verify before relying on version-specific calls.

```python
# List the first N function names containing a keyword
import ida_funcs, ida_ida
count = 0
fn = ida_funcs.get_next_func(ida_ida.inf_get_min_ea())
while fn is not None and count < 10:
    name = ida_funcs.get_func_name(fn.start_ea) or ""
    if "check" in name.lower():
        print("0x%x %s" % (fn.start_ea, name)); count += 1
    fn = ida_funcs.get_next_func(fn.start_ea)
```

```python
# Batch-rename addresses from a JSON mapping passed via --arg (comma-separated)
import json
mapping = json.loads(dscida_args.get("map", "{}"))
renamed = []
for text, new_name in mapping.items():
    ea = idaapi.get_name_ea(idaapi.BADADDR, text)
    if ea != idaapi.BADADDR and ida_name.set_name(ea, new_name, ida_name.SN_FORCE):
        renamed.append(text)
dscida_result = {"renamed": renamed}
```

```python
# Decompile every function in a module and keep short ones
import ida_funcs, ida_ida, ida_hexrays
if not ida_hexrays.init_hexrays_plugin():
    raise RuntimeError("no decompiler")
out = {}
fn = ida_funcs.get_next_func(ida_ida.inf_get_min_ea())
while fn is not None:
    cf = ida_hexrays.decompile(fn.start_ea)
    if cf is not None:
        text = str(cf)
        if len(text) < 2000:
            out["0x%x" % fn.start_ea] = text
    fn = ida_funcs.get_next_func(fn.start_ea)
dscida_result = {"functions": out}
```

## 6. Diagnostics

Structured status first, then logs:

```bash
"$DSCIDA_BIN" status "$SESSION_ID" --json
"$DSCIDA_BIN" logs "$SESSION_ID"                 # --component dscida|ida|stdout|stderr
"$DSCIDA_BIN" doctor --probe                     # environment readiness (no IDA/DSC needed)
```

Report the selected session, DSC path, canonical module path, IDA PID, health
state, and generation. Preserve logs and failed-session artifacts unless the
user explicitly requests cleanup. Do not kill an IDA PID directly unless
`stop` failed and the user asked for recovery.
