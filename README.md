# dscida

`dscida` is a macOS CLI for opening either selected images from an Apple
`dyld_shared_cache`, or a standalone binary, in headless IDA Pro. It keeps one
`idat` process alive per session and exposes a **command-line analysis surface**
for AI agents: an `exec` channel runs arbitrary IDAPython inside the live IDA
process, and a set of built-in commands (decompile, disasm, xrefs, find, …) covers
common analysis without writing Python. Agents use the CLI through their shell
tool and a skill document; no MCP bridge is involved. DSC sessions can add more
cache images; standalone sessions currently support thin Mach-O and little-endian
ELF.

The lifecycle does not run through MCP:

```text
dscida CLI -> authenticated private /control routes -> IDA DSCU
agent shell -> dscida exec / built-in analysis commands -> live IDB
```

The executable has three layers:

- the Go supervisor parses DSC metadata, owns sessions/jobs/generations, starts
  IDA, validates snapshots, and performs rollback;
- the embedded IDAPython sidecar runs the headless IDA HTTP loop on IDA's main
  thread (reusing the installed `ida-pro-mcp` server as its transport) and serves
  the authenticated `/control/*` routes, including `/control/exec-python`;
- the embedded analysis-script templates (`internal/assets/scripts`) implement
  the built-in commands and are shipped inside the `dscida` binary.

## Requirements

- macOS
- IDA Professional 9.1 (the currently validated build)
- IDAPython
- the IDA DSCU plugin for DSC sessions
- `ida-pro-mcp` installed for IDA (used internally as the headless HTTP server
  transport; the MCP tool surface itself is not used by the CLI)
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

Or start a standalone thin Mach-O or ELF. IDA uses its normal native loader;
this does not involve DSCU:

```bash
dscida start-binary /absolute/path/to/binary --session binary1
```

The input is copied from an already opened file descriptor into a
SHA-256-named, read-only file inside the session before IDA starts. Unknown
formats and all fat/universal Mach-O containers are rejected rather than
waiting for an invisible loader dialog. `dscida add` is DSC-only.

The result contains a session ID, an OS-assigned control endpoint, and a
generation. Add later modules to the same IDA PID and database:

```bash
dscida add SESSION \
  --module /usr/lib/system/libsystem_blocks.dylib

dscida add SESSION \
  --module /usr/lib/libobjc.A.dylib \
  --no-wait

dscida wait JOB_ID
```

Inspect the session and its live endpoints:

```bash
dscida status SESSION
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

`stop` is a pause: it shuts down IDA, frees memory, and keeps the verified
generations so `--resume` can continue later without re-running analysis. To
remove a session entirely, `delete` quarantines it (recoverably) beneath
`<state-root>/trash/` instead of erasing it:

```bash
dscida stop SESSION --no-save
dscida delete SESSION               # move the stopped session into trash/
dscida delete SESSION --include-backups   # also quarantine --replace backups
```

`delete` only accepts a durably stopped session (pid 0, no active jobs) and
fails closed otherwise; the quarantined directory can be recovered manually
while no session with that name exists. Deleting a session frees its name, so a
later `start --session SESSION` no longer needs `--replace`.

For a standalone session:

```bash
dscida start-binary /absolute/path/to/binary \
  --session binary1 \
  --resume
```

Resume verifies that the original source still has the recorded SHA-256, then
opens only the committed IDB generation. It never reloads a changed source
into the existing database.

## Agent analysis commands (exec and built-ins)

The CLI also exposes an agent-friendly analysis surface that does not require MCP
(spec: `AGENT-CLI-SPEC.md`). Every analysis command runs IDAPython inside the
live session's IDA process; the IDAPython for the built-ins is shipped inside the
`dscida` binary, so agents never write Python for common operations. All commands
support `--json`; addresses accept `0x` hex, decimal, or symbol names.

```bash
# arbitrary IDAPython in the live IDA (print -> stdout, dscida_result -> JSON)
dscida exec SESSION --code 'print(hex(idaapi.get_imagebase()))'
dscida exec SESSION --script /path/script.py --arg name=alice --timeout 2m

# read-only analysis
dscida survey SESSION
dscida funcs SESSION --query Security --limit 20
dscida decompile SESSION _main
dscida disasm SESSION _main --count 20
dscida xrefs SESSION 0x180123000
dscida imports SESSION --query Security
dscida string SESSION 0x180123000
dscida bytes SESSION 0x180123000 --length 32
dscida find SESSION --hex "cf fa ed fe" --count 5
dscida find SESSION --text "Usage" --case-insensitive

# modifying commands touch the live IDB; run `dscida save SESSION` to persist
dscida rename SESSION _main my_func
dscida comment SESSION _main "handled" --append
dscida set-type SESSION _main "int my_func(int a);"
dscida patch SESSION 0x180123000 9090
```

Scripts run synchronously on IDA's main thread with a best-effort timeout; on
expiry the script is interrupted when it returns to Python bytecode
(`timed_out: true`), and the IDA process is never killed. Modifying commands set
the session's `uncommitted_mcp_edits_possible` flag; nothing is persisted until
an explicit `save`.

## Agent skill document

`skills/dscida/SKILL.md` is the canonical agent-facing manual: session
management contract (slot naming, state, the save/stop/delete/--replace/--resume
lifecycle decision table), the DSC module-add workflow, every built-in analysis
command, the `exec` result contract with inline IDAPython template snippets, and
diagnostics. It is host-agnostic (DeepSeek Harness, Claude Code, Codex, plain
shell) and is not installed anywhere by default — copy it into a host's skills
directory when needed (per-host paths in `AGENT-CLI-SPEC.md` §7).

## Persistence and recovery

Each session contains:

```text
generations/   verified, read-only packed IDBs
inputs/        immutable SHA-256-named standalone inputs
runtime/       the live writable IDB
jobs/          durable operation records
staging/       snapshots and validator attempts
recovery/      prior runtime artifacts
logs/          supervisor and IDA logs
current.json   SHA256-authenticated generation pointer
session.json   orchestration state
```

Deleted sessions are quarantined (not erased) beneath `<state-root>/trash/`;
`delete-audit.jsonl` at the state root records every deletion attempt.

Every successful start, add, and save snapshots the live IDB, reopens a copy
in a separate headless validator, independently verifies its target identity,
then atomically advances `current.json`. DSC validation checks the DSC identity
and loaded-image indexes. Binary validation requires both the tool-owned
identity and IDA's native input path/SHA-256/file-type/processor metadata. If a mutation
fails after IDA may have changed, the session endpoints are taken down and the
session enters `recovery_required`; `start --resume` restores only the last
verified generation. A failed live mutation automatically attempts that
rollback and restart first; `recovery_required` remains only when the automatic
recovery itself cannot complete.

Set `DSCIDA_HOME` to change the default state root. Tests and experiments can
instead pass `--output-dir` to `start` and `--state-dir` to later commands.
The canonical state root and its session directories must be owned by the
current user; `dscida` enforces mode `0700` and rejects symlinked session roots.

## Source layout

```text
cmd/dscida/main.go             executable entry point
internal/app/app.go            command dispatch and shared CLI helpers
internal/app/command_exec.go   exec (arbitrary IDAPython via /control/exec-python)
internal/app/command_analysis.go built-in analysis commands and the shared runner
internal/app/command_*.go      other CLI command groups
internal/app/jobs.go           durable job completion and generation commit
internal/app/recovery.go       resume, rollback, restart, and termination
internal/app/validation.go     loaded-index and module consistency rules
internal/app/doctor.go         static diagnostics
internal/app/probe.go          disposable real-DSC runtime probe
internal/app/logging.go        structured supervisor logging
internal/cache/                DSC metadata and canonical module resolution
internal/binaryinput/          standalone format inspection and immutable input staging
internal/control/              private control and MCP health clients
internal/runner/               IDA launch and snapshot validator processes
internal/store/                durable session/job/generation state
internal/assets/               embedded IDAPython sidecar, validator, and analysis scripts
```

Command handlers only parse flags, format results, and call the job/recovery/
validation services. Recovery and stop share one non-reentrant lifecycle lock;
once stop has consumed a job's mutation ownership, automatic recovery cannot
restart that session.

See [SPEC.md](../SPEC.md) for the full protocol and safety model.
