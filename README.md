# dscida

`dscida` is a macOS CLI for opening selected images from an Apple
`dyld_shared_cache` in headless IDA Pro. It keeps one `idat` process alive,
allows additional DSC images to be loaded into the same database, and exposes
the unmodified `ida-pro-mcp` endpoint for AI-assisted analysis.

The DSC lifecycle does not run through MCP:

```text
dscida CLI -> authenticated private /control routes -> IDA DSCU
AI client  -> stable dscida stdio bridge -> current unmodified /mcp endpoint
```

The executable has three layers:

- the Go supervisor parses DSC metadata, owns sessions/jobs/generations, starts
  IDA, validates snapshots, and performs rollback;
- the embedded IDAPython sidecar invokes DSCU inside the persistent headless
  IDA process and serves authenticated `/control/*` routes;
- the installed, unmodified `ida-pro-mcp` serves `/mcp` for AI analysis on the
  same loopback endpoint;
- the Go MCP bridge gives Claude Code one stable, named stdio server per
  logical dscida session and follows that session when IDA restarts on a new
  PID or dynamic port.

## Requirements

- macOS
- IDA Professional 9.1 (the currently validated build)
- IDAPython and the IDA DSCU plugin
- `ida-pro-mcp` installed for IDA
- Claude Code is optional; it is required only for `dscida claude ...`
- Go 1.26 or newer to build

The `ipsw` CLI is not a runtime dependency. The public
`github.com/blacktop/ipsw/pkg/dyld` Go package is downloaded by `go mod` during
the build and compiled into `dscida`.

## Build

```bash
go build -trimpath -o ./bin/dscida ./cmd/dscida
./bin/dscida doctor --probe
```

Run the local regression suite:

```bash
go fmt ./...
go test -race ./...
go vet ./...
python3 -m py_compile \
  internal/assets/dscida_sidecar.py \
  internal/assets/dscida_validator.py
```

Run a disposable real-DSC compatibility probe:

```bash
./bin/dscida doctor --probe-dsc \
  --dsc /path/to/dyld_shared_cache_arm64e \
  --module /System/Library/Frameworks/Security.framework/Security \
  --add-module /usr/lib/system/libsystem_blocks.dylib
```

The dynamic probe exercises the headless loader, DSCU loaded-image backend,
MCP `server_health`, packed snapshot validation, optional incremental loading,
shutdown, and cleanup. Failed probes retain their isolated artifacts; successful
probes remove them unless `--keep-probe` is supplied.

## Basic workflow

List exact canonical module paths without starting IDA:

```bash
dscida modules /path/to/dyld_shared_cache_arm64e --query Security
```

Start one primary module:

```bash
dscida start /path/to/dyld_shared_cache_arm64e \
  --module /System/Library/Frameworks/Security.framework/Security
```

The result contains a session ID and an OS-assigned MCP URL. Add later modules
to the same IDA PID and database:

```bash
dscida add SESSION \
  --module /usr/lib/system/libsystem_blocks.dylib

dscida add SESSION \
  --module /usr/lib/libobjc.A.dylib \
  --no-wait

dscida wait JOB_ID
```

Inspect or hand the MCP endpoint to an AI client:

```bash
dscida status SESSION
dscida mcp SESSION
```

Run a one-shot stdio proxy that connects to the current MCP URL and exits
when stdin closes:

```bash
dscida mcp SESSION --stdio
```

Run a stable stdio MCP server that follows endpoint changes (PID, port)
and survives IDA restarts without reconfiguration:

```bash
dscida mcp SESSION --stdio --follow --server-name my_session
```

For Claude Code, install a stable per-session MCP entry:

```bash
dscida claude install SESSION --name dscida_security --scope local
dscida claude list --json
```

Claude Code then sees tools such as
`mcp__dscida_security__server_health` and
`mcp__dscida_security__decompile`. The configuration contains the logical
session name and absolute executable/state paths, not an IDA PID, dynamic
port, control token, or downstream MCP session ID.

Multiple IDA instances use separate names and bridges:

```bash
dscida claude install ida1 --name dscida_security --scope local
dscida claude install ida2 --name dscida_objc --scope local
```

Each bridge pins the session's immutable `session_instance_id`, verifies the
authenticated control identity before publishing tools and before every tool
call, and fails closed rather than routing to another healthy IDA. Normal
stop/resume preserves that identity, so the same Claude task follows a new PID
and port. During the short recovery window its tool list is temporarily empty;
after the list-change notification Claude can use the restored tools without
rewriting configuration.

Inspect the generated command without changing Claude configuration:

```bash
dscida claude install SESSION --dry-run
```

Removing an entry always requires an explicit scope and does not stop IDA:

```bash
dscida claude remove dscida_security --scope local
```

Save, stop, and later resume from the verified immutable generation:

```bash
dscida save SESSION
dscida stop SESSION

dscida start /path/to/dyld_shared_cache_arm64e \
  --module /System/Library/Frameworks/Security.framework/Security \
  --session SESSION \
  --resume
```

## Persistence and recovery

Each session contains:

```text
generations/   verified, read-only packed IDBs
runtime/       the live writable IDB
jobs/          durable operation records
staging/       snapshots and validator attempts
recovery/      prior runtime artifacts
logs/          supervisor and IDA logs
current.json   SHA256-authenticated generation pointer
session.json   orchestration state
```

Every successful start, add, and save snapshots the live IDB, reopens a copy
in a separate headless validator, independently verifies the DSC identity and
loaded-image indexes, then atomically advances `current.json`. If a mutation
fails after IDA may have changed, the MCP endpoint is taken down and the
session enters `recovery_required`; `start --resume` restores only the last
verified generation. A failed live mutation automatically attempts that
rollback and restart first; `recovery_required` remains only when the automatic
recovery itself cannot complete.

Set `DSCIDA_HOME` to change the default state root. Tests and experiments can
instead pass `--output-dir` to `start` and `--state-dir` to later commands.

## Source layout

```text
cmd/dscida/main.go             executable entry point
internal/app/app.go            command dispatch and shared CLI helpers
internal/app/command_mcp.go    mcp --stdio, --follow, and --server-name
internal/app/command_claude.go claude install, remove, and list
internal/app/command_*.go      other CLI command groups
internal/app/jobs.go           durable job completion and generation commit
internal/app/recovery.go       resume, rollback, restart, and termination
internal/app/validation.go     loaded-index and module consistency rules
internal/app/doctor.go         static diagnostics
internal/app/probe.go          disposable real-DSC runtime probe
internal/app/logging.go        structured supervisor logging
internal/cache/                DSC metadata and canonical module resolution
internal/control/              private control and MCP health clients
internal/bridge/               Go MCP stdio server, endpoint following,
                               fail-closed identity checks, SSE listener
internal/runner/               IDA launch and snapshot validator processes
internal/store/                durable session/job/generation state
internal/assets/               embedded IDAPython sidecar and validator
```

Command handlers only parse flags, format results, and call the job/recovery/
validation services. Recovery and stop share one non-reentrant lifecycle lock;
once stop has consumed a job's mutation ownership, automatic recovery cannot
restart that session.

See [SPEC.md](../SPEC.md) for the full protocol and safety model.
