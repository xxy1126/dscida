# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

`dscida` is a macOS Go CLI that opens either selected images from an Apple `dyld_shared_cache` (DSC), or a standalone binary (thin Mach-O / LE ELF), in headless IDA Pro. It keeps one `idat` process alive per session, allows incremental DSC module loading into the same database, and exposes a command-line analysis surface for AI agents: an `exec` channel for arbitrary IDAPython plus built-in analysis commands (decompile, disasm, xrefs, find, …) backed by embedded scripts. Standalone binary sessions use IDA's native loader; DSC sessions use DSCU.

The full protocol and safety model are specified in `../SPEC.md`.

## Build and test

```bash
# Build the binary
go build -trimpath -o ./bin/dscida ./cmd/dscida

# Run the static smoke check (no IDA or DSC required)
./bin/dscida doctor --probe

# Run all Go tests with race detector
go test -race ./...

# Run vet
go vet ./...

# Verify embedded Python sidecars are syntactically valid
python3 -m py_compile internal/assets/dscida_sidecar.py internal/assets/dscida_validator.py
```

All Go tests are offline — they use temp directories and mock paths, never a real IDA or DSC.

## Three-layer architecture

1. **Go supervisor** (`cmd/dscida`, `internal/app`) — parses DSC metadata via `github.com/blacktop/ipsw/pkg/dyld` or inspects standalone binaries via `internal/binaryinput`, owns sessions/jobs/generations, launches `idat` as a child process, performs snapshot validation, and handles recovery/rollback. Sessions carry a `TargetKind` field (`dsc` or `binary`) that discriminates the validation strategy.

2. **Embedded IDAPython sidecar** (`internal/assets/dscida_sidecar.py`) — runs inside the persistent headless IDA process and serves the headless HTTP loop on IDA's main thread (reusing the installed `ida-pro-mcp` server as its transport). Serves authenticated `/control/*` routes (`/control/ping`, `/control/load-module`, `/control/save`, `/control/exec-python`, `/control/shutdown`) on a loopback port. Publishes `ready.json` to the session runtime directory when IDA finishes auto-analysis. The sidecar is compiled into the Go binary via `//go:embed`.

3. **Embedded analysis scripts** (`internal/assets/scripts/*.py`) — one IDAPython template per built-in command, compiled into the Go binary and run through the sidecar's `/control/exec-python` route. The Go supervisor never uses MCP for lifecycle mutations.

The lifecycle separation is: `agent shell → dscida exec / built-in commands → /control` (analysis and lifecycle), with the MCP tool surface unused by the CLI.

## Key packages

| Package | Role |
|---------|------|
| `cmd/dscida/main.go` | Entry point, calls `app.Run()` |
| `internal/app/app.go` | Command dispatch (`Run`), flag parsing (`parseInterspersed`), shared helpers |
| `internal/app/command_*.go` | Individual CLI commands — each parses flags, formats output, delegates to services |
| `internal/app/jobs.go` | Job completion loop (polls durable job state, finalizes validation + commit) |
| `internal/app/recovery.go` | Automatic rollback to last verified generation, session failure handling, process termination |
| `internal/app/validation.go` | Loaded-image index validation, expected-index computation, DSCU backend consistency checks |
| `internal/store/store.go` | Durable JSON state: Session, Job, Current (generation pointer), atomic writes via temp+rename, file locking |
| `internal/cache/cache.go` | Reads DSC metadata via `ipsw/pkg/dyld`, canonical module resolution, filtering |
| `internal/binaryinput/` | Stages standalone binaries as immutable SHA-256-named copies, inspects Mach-O/ELF format, rejects fat/encrypted binaries |
| `internal/runner/runner.go` | Launches headless `idat` (fresh DSC, fresh binary, and open-existing), runs separate validator processes, snapshot copying |
| `internal/control/client.go` | HTTP client for `/control/*` routes and MCP health checks (initialize + tools/list + server_health) |
| `internal/assets/assets.go` | Embeds `dscida_sidecar.py`, `dscida_validator.py`, and `scripts/*.py` via `//go:embed` |

## Safety and persistence model

Every mutation (start, add, save) goes through a durable job state machine:

1. Job is created in `queued` state and durably written to `jobs/<id>.json`.
2. Job transitions through: `queued → running_dscu → running_analysis → snapshotting → validating → committing → succeeded`.
3. On `validating`, a **separate headless `idat` process** opens a copy of the snapshot and independently verifies the target identity. For DSC sessions this means DSC UUID and loaded-image indexes. For binary sessions this means the exact input SHA-256, file size, format, and IDA processor match the session's recorded identity. This catches DSCU bugs, IDA corruption, and stale state.
4. Only after validation passes is the snapshot atomically committed as a read-only generation (`generations/NNNNNN.i64`, mode 0400) and `current.json` advanced with a SHA256 checksum.
5. If any step fails after IDA may have mutated the database, the supervisor automatically attempts rollback to the last verified generation and restarts the session endpoints. If automatic recovery fails, the session enters `recovery_required`.

**Locking:** Per-session `session.lock` (state mutations), per-job `*.finalizer.lock` (validation+commit), and a lifecycle lock `.<id>.lifecycle.lock` (stop/recovery mutual exclusion).

**Endpoint validation:** Persisted control and MCP URLs are validated on load (must be loopback HTTP with a valid TCP port, paths must be `/control` and `/mcp`).

## Flag parsing quirk

The standard Go `flag` package stops at the first positional argument. `parseInterspersed` in `app.go` manually reorders flags and positional args so that `dscida start /path/to/cache --module /Foo` works. Commands accept flags both before and after positional operands, separated by `--` if needed.

## Session state directory layout

```
DSCIDA_HOME/sessions/<id>/
  session.json          orchestration state (Session struct, includes TargetKind)
  secret.json           control token (mode 0600)
  current.json          SHA256-authenticated generation pointer
  generations/          verified read-only packed IDBs (NNNNNN.i64, mode 0400)
  inputs/               immutable SHA-256-named standalone binary copies (binary sessions only)
  runtime/              live writable IDB, ready.json, scripts/
  jobs/                 durable job records
  staging/              snapshot candidates and validator working dirs
  recovery/             prior runtime artifacts saved during rollback
  logs/                 idat stdout/stderr, IDA message log, supervisor log
```

## Environment variables

- `DSCIDA_HOME` — overrides the default state root (`~/Library/Application Support/dscida`).
- The Go supervisor passes configuration to the Python sidecar via `DSCIDA_HOST`, `DSCIDA_PORT`, `DSCIDA_SESSION_DIR`, `DSCIDA_SESSION_ID`, `DSCIDA_SESSION_INSTANCE_ID`, `DSCIDA_CONTROL_TOKEN`, `DSCIDA_TARGET_KIND`, `DSCIDA_IMAGE_COUNT`, `DSCIDA_DSC_PATH`, `DSCIDA_DSC_UUID`, `DSCIDA_MAIN_MODULE`, `DSCIDA_SOURCE_PATH`, `DSCIDA_INPUT_PATH`, `DSCIDA_INPUT_SHA256`, `DSCIDA_INPUT_SIZE`, `DSCIDA_BINARY_FORMAT`, `DSCIDA_MACHO_UUID`.
- `TVHEADLESS=1` is set on all `idat` invocations (IDA's headless mode).
- For DSC sessions, `IDA_DYLD_CACHE_MODULE` selects the primary module.
- For binary sessions, IDA uses its native loader with the staged immutable input.
