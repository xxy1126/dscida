# dscida Agent-CLI Specification

Status: Draft  
Branch: `feat/analysis-cli`  
Scope: Agent-friendly analysis interface on top of the existing v1 session/lifecycle model defined in `../SPEC.md`. This document **extends** the v1 protocol; it does not rewrite the safety and persistence model.

## 1. Background and goals

`dscida` v1 exposes analysis through the unmodified `ida-pro-mcp` endpoint, bridged to
Claude Code via a stable stdio MCP server. In practice the MCP bridge has operational
friction: MCP tool sets are session-scoped and cannot be hot-swapped, a replaced
session requires manual client reconnect, and every analysis capability must be
mirrored through the bridge.

This specification introduces an **agent-host-agnostic CLI analysis surface**: the
same commands, output contracts, and skill documents work from Claude Code, Codex,
DeepSeek Harness, or a plain terminal. The design deliberately avoids MCP for this
surface.

Goals:

1. **Multi-session management as the primary capability.** One CLI can list, start,
   stop, and switch between many independent IDA sessions (DSC or standalone binary),
   each with its own live IDA process, control endpoint, and committed generations.
2. **Built-in analysis commands.** Frequent IDA analysis operations (decompile,
   disassembly, xrefs, renames, comments, byte search, …) are first-class CLI
   commands. Their IDAPython implementations are shipped inside the `dscida` binary,
   so an agent never writes Python for common operations.
3. **General IDAPython execution.** `dscida exec` runs arbitrary user-supplied Python
   inside the live IDA process, returning stdout plus an optional structured result.
4. **One skill document, many hosts.** A single `SKILL.md` teaches agents how to use
   the CLI; it is placed per-host (Claude Code, DSH, Codex) without any per-host code.
5. **Deterministic, scriptable output.** Every command supports `--json` with stable
   field names; diagnostics go to stderr.

Non-goals for this iteration:

- No new MCP surface, no bridge changes. The existing `/mcp` endpoint and bridge stay
  untouched for the Claude Code MCP path.
- No debugger tooling, no assembly-level patching (`patch_asm`), no signature
  generation, no type inference batch jobs in the built-in set (available via
  `exec`).
- No changes to the v1 job/generation/validation state machine. `exec` and the
  built-in commands run on the live IDB; durability still requires `save`.

## 2. Multi-session management

A session is a logical analysis target: one persistent headless IDA process, one IDB,
one control endpoint, one MCP endpoint, and an immutable `session_instance_id`.
Sessions are independent; operations on one never affect another.

Two session kinds exist (unchanged from v1):

- **DSC sessions** (`start`): one primary module, plus incremental `add` of more
  cache images into the same IDB.
- **Binary sessions** (`start-binary`): exactly one thin Mach-O or LE ELF input opened
  by IDA's native loader. `add` is not supported for binary sessions in this
  iteration (see Open Question OQ-1).

Management commands (all already implemented in v1, listed here as the agent contract):

| Command | Purpose |
|---|---|
| `dscida sessions --json` | List all sessions with target kind, state, PID, generation |
| `dscida status <SESSION> --json` | Live health of one session (PID, control, MCP, loaded modules) |
| `dscida start <DSC> --module <PATH> --session <ID> [--replace]` | Create/replace a DSC session |
| `dscida start-binary <INPUT> --session <ID> [--replace]` | Create/replace a binary session |
| `dscida add <SESSION> --module <PATH>` | Load another DSC image into the same IDB |
| `dscida save <SESSION>` | Commit the live IDB as a new verified generation |
| `dscida stop <SESSION> [--no-save]` | Shut down IDA (optionally discarding changes) |
| `dscida logs <SESSION> [--component ...]` | Tail supervisor/IDA logs |

Multi-session workflow contract for agents:

1. Inspect `sessions --json`; a session name is a stable logical slot (e.g. `ida1`,
   `ida2`), not a PID or port.
2. To switch a slot to a new target, `stop <SESSION> --no-save` (or leave it stopped)
   then `start ... --replace` under the same name. Replacement backs up the previous
   session recoverably and issues a new `session_instance_id`.
3. Only `ready` sessions accept `add`, `save`, and analysis commands.
4. Analysis commands run on the live writable IDB; nothing is committed until `save`.

## 3. Built-in analysis commands

All built-in commands accept `<SESSION>` first and a canonical `<ADDR>` argument
(resolution rules in Section 5). Every command supports `--json`.

### 3.1 Read-only analysis

| Command | Description | v1 MCP analogue |
|---|---|---|
| `dscida decompile <SESSION> <ADDR> [--cfg]` | Hex-Rays decompilation of the function at/containing ADDR. `--cfg` adds the control-flow-graph section. | `decompile` |
| `dscida disasm <SESSION> <ADDR> [--count N] [--graph]` | Disassemble N instructions starting at ADDR (default 20). | `disasm` |
| `dscida funcs <SESSION> [--query TEXT] [--limit N]` | List functions; optional case-insensitive name filter. | `list_funcs` |
| `dscida xrefs <SESSION> <ADDR>` | Code/data references to ADDR, with direction and type. | `xrefs_to` |
| `dscida imports <SESSION> [--query TEXT]` | Import table; optional module/name filter. | `imports` |
| `dscida string <SESSION> <ADDR> [--length N]` | Read a C string at ADDR (N defaults to null-terminated). | `get_string` |
| `dscida bytes <SESSION> <ADDR> [--length N] [--hex \| --text]` | Read raw bytes at ADDR (default hex dump, N=16). | `get_bytes` |
| `dscida find <SESSION> (--hex HEX \| --text TEXT) [--from ADDR] [--to ADDR] [--count N] [--case-insensitive]` | Search the binary for a byte pattern or ASCII/UTF-8 text within an optional address range; returns matching addresses (first N, default all). | `find_bytes`, `find` |
| `dscida survey <SESSION>` | Binary/session overview: architecture, entry point, segments, function count, imports count, loader and processor, target kind and generation. | `survey_binary` |

### 3.2 Modifying commands

Modifying commands write to the **live runtime IDB only**. They never auto-commit a
generation; `dscida save` is required to persist. The session's
`uncommitted_mcp_edits_possible` flag is set (same flag MCP edits use) so `status
--json` and a later `stop` without `--no-save` reflect pending changes.

| Command | Description | v1 MCP analogue |
|---|---|---|
| `dscida rename <SESSION> <ADDR> <NAME>` | Rename the function/global at ADDR. | `rename` |
| `dscida comment <SESSION> <ADDR> <TEXT> [--append]` | Set (or append to) the comment at ADDR. | `set_comments`, `append_comments` |
| `dscida set-type <SESSION> <ADDR> <TYPE>` | Declare/set the type at ADDR (function or data). | `set_type` |
| `dscida patch <SESSION> <ADDR> <HEX> [--length N]` | Write raw bytes (hex string) at ADDR into the live IDB. Patching is a live-IDB mutation like the others: it is visible to later analysis but is not persisted until `save`. Assembly-level patching (`patch_asm`) stays deferred. | `patch` |

### 3.3 General execution

| Command | Description |
|---|---|
| `dscida exec <SESSION> (--code CODE \| --script FILE) [--arg K=V ...] [--timeout DURATION]` | Run arbitrary IDAPython inside the live IDA process (Section 4). |

### 3.4 Explicitly deferred (use `exec`)

Debugger control (`dbg_*`), assembly-level patching (`patch_asm`), signature
generation (`sigmaker`), regex search, function profiling, and stack-frame
inspection are not built-in in this iteration. Each is expressible as a short
`exec` script; a later iteration may promote the frequent ones to built-ins based
on real usage.

## 4. The `exec` channel

`exec` and every built-in command share one transport: a new authenticated control
route on the IDA-side sidecar.

### 4.1 Route

```
POST /control/exec-python
Authorization: Bearer <control token>
Content-Type: application/json
Body (max 64 KiB):
{
  "script": "<python source>",
  "timeout_ms": 60000          // optional; per-command defaults in Section 4.4
}
```

The script executes **synchronously on IDA's main thread**, the same validated
execution model used by `/control/load-module` (SPEC v1 §10). All MCP and control
requests are serialized behind it while it runs; the process is busy, not dead.
The body carries an optional `timeout_ms` (per-command defaults in Section 4.5).

### 4.2 Result contract

The sidecar returns a single JSON response (HTTP 200 on completion, HTTP 408 on
timeout):

```json
{
  "success": true,
  "session_id": "ida1",
  "session_instance_id": "...",
  "pid": 42310,
  "stdout": "…collected print() output…",
  "result": { /* JSON value of the dscida_result global, if set */ },
  "execution_ms": 12.3,
  "timed_out": false
}
```

Contract rules (taught to agents via the skill document):

- `print(...)` output is captured into `stdout` and is **not** JSON-parsed.
- A script that assigns a JSON-serializable value to the global `dscida_result`
  receives it back under `result`.
- A script that raises sets `success: false` with `error` (exception type + message)
  and `traceback`.
- On timeout the sidecar attempts to **interrupt the running script** (see below)
  and returns `timed_out: true` with `error: "exec timeout"`.

### 4.3 Timeout semantics

The timeout is a **best-effort interrupt**, implemented with a Python
`signal.alarm` timer armed on IDA's main thread before the script runs; the signal
handler raises `TimeoutError`, which unwinds the script and lets the handler return
`timed_out: true`. This works for scripts executing Python bytecode. If a script is
blocked inside a C extension (including long-running IDA APIs that do not return to
the bytecode loop), the signal only fires at the next bytecode boundary and the
handler may remain busy; in that case the response is withheld until the script
finishes and later requests queue behind it (the process is busy, not dead — same
rule as v1 mutations). The IDA process is **never killed** by a timeout. The
job-based async variant (OQ-4) is the planned fix for genuinely long scripts.

`dscida exec --timeout DURATION` overrides the default; built-in commands use the
per-command defaults in Section 4.5.

### 4.4 Security posture

v1 SPEC §11 explicitly forbids arbitrary Python evaluation ("No arbitrary Python
evaluation or script execution"). This specification **revises that clause** for the
new route, with the following bounds:

- The route is authenticated (per-session bearer token), loopback-only, and body-size
  limited (64 KiB).
- The supervisor pre-checks `--script` files: regular file, within an allowed
  directory or provided inline via `--code`; no network is implied by the channel
  itself (IDA Python may still perform network calls at the script's discretion —
  the operator is the IDA owner).
- The route is a mutation route in the same serialization domain as `load-module`
  and `save`; one database mutation at a time still holds.
- v1's `request_id`/`payload_hash` idempotency is **not** required for read-only
  scripts; mutating scripts are the caller's responsibility and should be paired with
  a `save` when durability is wanted.

### 4.5 Embedded script assets

Each built-in command is a small IDAPython template embedded into the Go binary via
`//go:embed` under `internal/assets/scripts/` (e.g. `decompile.py`, `find_bytes.py`).
The CLI renders command arguments into the template, then invokes the same exec
transport. The Go side implements **one** shared runner (`runAnalysisScript`) that all
built-in commands delegate to, so adding a command is: write the template + one thin
command binding.

Per-command default timeouts: `decompile` 120 s; `disasm`, `funcs`, `xrefs`,
`imports`, `string`, `bytes`, `find`, `survey` 60 s; `rename`, `comment`,
`set-type`, `patch` 30 s; user `exec` defaults to 60 s, overridable with
`--timeout`.

Templates are validated by `python3 -m py_compile` in CI alongside the sidecar and
validator.

## 5. Addressing conventions

`<ADDR>` accepts, in order of resolution:

1. `0x`-prefixed hexadecimal (e.g. `0x180123000`);
2. a symbol name resolved via `idaapi.get_name_ea` (e.g. `_main`,
   `Security::SomeFunc`); quote names containing spaces or special characters;
3. a plain decimal integer (treated as an absolute address).

Resolution failure returns an error listing the closest matching symbols (same
suggestion rule as `dscida modules --exact`). All JSON outputs print addresses as
hexadecimal strings (e.g. `"0x180123000"`) to avoid integer precision loss.

## 6. Output contract

- Default (human) output is a compact text form suitable for terminals and log
  capture; the exact shapes are defined per command in the skill document.
- `--json` emits one JSON document on stdout with stable field names; logs and
  diagnostics go to stderr (existing v1 convention).
- Tool results that are large (decompilation, long disassembly, many xrefs) are
  emitted in full; the skill document advises `--limit`/`--count` and range
  parameters to bound output size.

## 7. Agent skill document (host-agnostic)

One canonical skill document, `skills/dscida/SKILL.md` in this repository, teaches
any agent to operate the CLI. Its content is host-independent: session management,
built-in commands, the exec result contract, common script templates, diagnostics,
and a worked workflow (load → decompile → rename → comment → save).

Per-host placement (an installation note in the document, not code):

| Host | Location |
|---|---|
| DeepSeek Harness | `<project>/.dsh/skills/dscida/` or `~/.dsh/skills/dscida/` |
| Claude Code | `~/.claude/skills/dscida/` |
| Codex | `~/.codex/skills/dscida/` (verify exact path; see OQ-6) |

The document explicitly states that MCP bridge reconnects are **not** needed: agents
use `dscida` via their shell tool, and the CLI resolves the current endpoint itself.

## 8. Milestones and branch

Branch: `feat/analysis-cli` (created from `main`; the MCP/bridge code and the
existing `use-dscida` Claude Code skill stay untouched on `main`).

- **M1 — exec channel**: sidecar `/control/exec-python` (+ timeout, result contract,
  `dscida_result`); `control.Client` method; `dscida exec` command; SPEC §11 clause
  revision; tests (sidecar script-level + Go command-level).
- **M2 — built-in commands**: `internal/assets/scripts/*.py` templates; one shared
  Go runner; the built-in commands from Section 3 (read-only, modifying, `exec`);
  `--json` outputs; tests.
- **M3 — skill document**: `skills/dscida/SKILL.md` with full usage contract,
  templates, and per-host placement notes; repository README section.
- **M4 — (deferred) job-async exec**: long-script execution through the existing job
  state machine (`202` + durable job + `dscida wait`); out of scope until M1–M3 land.

## 9. Decision record and open questions

Resolved (2026-08, review with the operator):

- **OQ-1 — binary-session `add` (Mach-O addition): NO, confirmed.** IDA analyzes one
  file per process; a DSC module is a part of one DSC file, so adding DSC modules to
  a DSC session is legitimate. Adding a second Mach-O into a binary session would
  mean multi-file loading in one IDB and is rejected. Mach-O/ELF analysis uses
  `start-binary` sessions; multi-session management covers running several binaries
  at once.
- **OQ-2 — modifying-command durability: CONFIRMED.** `rename`/`comment`/`set-type`/
  `patch` only touch the live runtime IDB; nothing is persisted until an explicit
  `save`. The `uncommitted_mcp_edits_possible` flag is set on mutation.
- **OQ-3 — built-in set: EXPANDED.** `survey` (binary overview) and `patch` (raw
  byte writes) are added to the built-in set (Sections 3.1/3.2). `patch_asm`,
  debugger, sigmaker, and regex search remain deferred to `exec`.
- **OQ-4 — exec timeout: CONFIRMED with best-effort interrupt.** A wall-clock
  timeout is armed on IDA's main thread (`signal.alarm` + `TimeoutError`); on expiry
  the running script is interrupted when it returns to Python bytecode and the
  response reports `timed_out: true`. A script stuck inside a C extension may keep
  the handler busy; the IDA process is never killed. Job-async execution is the
  planned upgrade for genuinely long scripts (Milestone M4).
- **OQ-5 — symbol-name addressing: CONFIRMED.** `get_name_ea` resolution with
  close-match suggestions on failure.
- **OQ-6 — skill installation: DEFERRED.** The skill document is authored and kept in
  this repository; it is **not installed** into any host (DSH/Claude Code/Codex) in
  this iteration. Per-host placement notes remain in the document for later use.
