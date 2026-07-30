# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

`dscida` is a macOS Go CLI that opens selected images from an Apple `dyld_shared_cache` (DSC) in headless IDA Pro. It keeps one `idat` process alive per session, allows incremental DSC module loading into the same database, and exposes the unmodified `ida-pro-mcp` endpoint for AI-assisted reverse engineering.

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

1. **Go supervisor** (`cmd/dscida`, `internal/app`) — parses DSC metadata via `github.com/blacktop/ipsw/pkg/dyld`, owns sessions/jobs/generations, launches `idat` as a child process, performs snapshot validation, and handles recovery/rollback.

2. **Embedded IDAPython sidecar** (`internal/assets/dscida_sidecar.py`) — runs inside the persistent headless IDA process. Serves authenticated `/control/*` HTTP routes (`/control/ping`, `/control/load-module`, `/control/save`, `/control/snapshot`, `/control/shutdown`) on a loopback port. Publishes `ready.json` to the session runtime directory when IDA finishes auto-analysis. The sidecar is compiled into the Go binary via `//go:embed`.

3. **Unmodified `ida-pro-mcp`** (`/mcp` endpoint) — the stock MCP server runs in the same IDA process on the same loopback endpoint. The Go supervisor never uses MCP for DSC lifecycle operations; it only calls `/control/*` routes for that. The MCP endpoint is health-checked on startup and exposed to AI clients.

The lifecycle separation is: `AI client → /mcp` (analysis), `dscida CLI → /control` (DSC management).

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
| `internal/runner/runner.go` | Launches headless `idat` (both fresh and open-existing), runs separate validator processes, snapshot copying |
| `internal/control/client.go` | HTTP client for `/control/*` routes and MCP health checks (initialize + tools/list + server_health) |
| `internal/assets/assets.go` | Embeds `dscida_sidecar.py` and `dscida_validator.py` via `//go:embed` |

## Safety and persistence model

Every mutation (start, add, save) goes through a durable job state machine:

1. Job is created in `queued` state and durably written to `jobs/<id>.json`.
2. Job transitions through: `queued → running_dscu → running_analysis → snapshotting → validating → committing → succeeded`.
3. On `validating`, a **separate headless `idat` process** opens a copy of the snapshot and independently verifies DSC identity and loaded-image indexes match expectations. This catches DSCU bugs, IDA corruption, and stale state.
4. Only after validation passes is the snapshot atomically committed as a read-only generation (`generations/NNNNNN.i64`, mode 0400) and `current.json` advanced with a SHA256 checksum.
5. If any step fails after IDA may have mutated the database, the supervisor automatically attempts rollback to the last verified generation and restarts the MCP endpoint. If automatic recovery fails, the session enters `recovery_required`.

**Locking:** Per-session `session.lock` (state mutations), per-job `*.finalizer.lock` (validation+commit), and a lifecycle lock `.<id>.lifecycle.lock` (stop/recovery mutual exclusion).

**Endpoint validation:** Persisted control and MCP URLs are validated on load (must be loopback HTTP with a valid TCP port, paths must be `/control` and `/mcp`).

## Flag parsing quirk

The standard Go `flag` package stops at the first positional argument. `parseInterspersed` in `app.go` manually reorders flags and positional args so that `dscida start /path/to/cache --module /Foo` works. Commands accept flags both before and after positional operands, separated by `--` if needed.

## Session state directory layout

```
DSCIDA_HOME/sessions/<id>/
  session.json          orchestration state (Session struct)
  secret.json           control token (mode 0600)
  current.json          SHA256-authenticated generation pointer
  generations/          verified read-only packed IDBs (NNNNNN.i64, mode 0400)
  runtime/              live writable IDB, ready.json, scripts/
  jobs/                 durable job records
  staging/              snapshot candidates and validator working dirs
  recovery/             prior runtime artifacts saved during rollback
  logs/                 idat stdout/stderr, IDA message log
```

## Environment variables

- `DSCIDA_HOME` — overrides the default state root (`~/Library/Application Support/dscida`).
- The Go supervisor passes configuration to the Python sidecar via `DSCIDA_HOST`, `DSCIDA_PORT`, `DSCIDA_SESSION_DIR`, `DSCIDA_CONTROL_TOKEN`, `DSCIDA_IMAGE_COUNT`, `DSCIDA_DSC_PATH`, `DSCIDA_DSC_UUID`, `DSCIDA_MAIN_MODULE`.
- `TVHEADLESS=1` is set on all `idat` invocations (IDA's headless mode).
- For initial DSC loading, `IDA_DYLD_CACHE_MODULE` selects the primary module.
