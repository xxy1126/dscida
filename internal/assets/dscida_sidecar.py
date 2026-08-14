"""Headless DSC lifecycle control hosted beside the unmodified IDA MCP server."""

import contextlib
import io
import json
import os
import re
import signal
import threading
import time
import traceback
from datetime import datetime, timezone
from urllib.parse import urlparse

import ida_auto
import ida_funcs
import ida_ida
import ida_idp
import ida_kernwin
import ida_loader
import ida_nalt
import ida_netnode
import ida_pro
import ida_segment
import idaapi
import idc
from ida_mcp import IdaMcpHttpRequestHandler, MCP_SERVER


HOST = os.environ.get("DSCIDA_HOST", "127.0.0.1")
PORT = int(os.environ.get("DSCIDA_PORT", "0"))
SESSION_DIR = os.path.realpath(os.environ["DSCIDA_SESSION_DIR"])
SESSION_ID = os.environ["DSCIDA_SESSION_ID"]
SESSION_INSTANCE_ID = os.environ["DSCIDA_SESSION_INSTANCE_ID"]
READY_PATH = os.path.join(SESSION_DIR, "runtime", "ready.json")
TOKEN = os.environ["DSCIDA_CONTROL_TOKEN"]
TARGET_KIND = os.environ.get("DSCIDA_TARGET_KIND", "dsc") or "dsc"
DSC_PATH = os.path.realpath(os.environ.get("DSCIDA_DSC_PATH", ""))
DSC_UUID = os.environ.get("DSCIDA_DSC_UUID", "")
MAIN_MODULE = os.environ.get("DSCIDA_MAIN_MODULE", "")
SOURCE_PATH = os.path.realpath(os.environ.get("DSCIDA_SOURCE_PATH", ""))
INPUT_PATH = os.path.realpath(os.environ.get("DSCIDA_INPUT_PATH", ""))
INPUT_SHA256 = os.environ.get("DSCIDA_INPUT_SHA256", "")
INPUT_SIZE = int(os.environ.get("DSCIDA_INPUT_SIZE", "0"))
BINARY_FORMAT = os.environ.get("DSCIDA_BINARY_FORMAT", "")
ARCHITECTURE = os.environ.get("DSCIDA_ARCHITECTURE", "")
IDA_PROCESSOR = os.environ.get("DSCIDA_IDA_PROCESSOR", "")
MACHO_UUID = os.environ.get("DSCIDA_MACHO_UUID", "")
JOB_ID_RE = re.compile(r"^job-[0-9a-f]{16,64}$")
MAX_BODY = 65536
TERMINAL_STATES = {
    "succeeded",
    "failed",
    "interrupted_rolled_back",
    "outcome_unknown_live",
    "cancelled_before_start",
}
ALLOWED_TRANSITIONS = {
    "queued": {
        "running_dscu",
        "snapshotting",
        "failed",
        "cancelled_before_start",
        "outcome_unknown_live",
    },
    "running_dscu": {
        "running_analysis",
        "succeeded",
        "failed",
        "interrupted_rolled_back",
        "outcome_unknown_live",
    },
    "running_analysis": {
        "snapshotting",
        "failed",
        "interrupted_rolled_back",
        "outcome_unknown_live",
    },
    "snapshotting": {
        "validating",
        "failed",
        "interrupted_rolled_back",
        "outcome_unknown_live",
    },
}


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def log(event, **fields):
    detail = " ".join(f"{key}={value!r}" for key, value in fields.items())
    print(f"[dscida-sidecar] {event} {detail}".rstrip(), flush=True)


def write_json_atomic(path, payload):
    parent = os.path.dirname(path)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    temporary = f"{path}.tmp.{os.getpid()}.{threading.get_ident()}"
    with open(temporary, "w", encoding="utf-8") as stream:
        json.dump(payload, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    directory_fd = os.open(parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def job_path(job_id):
    if not isinstance(job_id, str) or not JOB_ID_RE.fullmatch(job_id):
        raise ValueError("invalid job_id")
    return os.path.join(SESSION_DIR, "jobs", f"{job_id}.json")


def read_job(job_id):
    path = job_path(job_id)
    with open(path, "r", encoding="utf-8") as stream:
        record = json.load(stream)
    if record.get("job_id") != job_id:
        raise ValueError("job record identity mismatch")
    return path, record


def update_job(job_id, state, **fields):
    path, record = read_job(job_id)
    previous = record.get("state")
    if previous in TERMINAL_STATES:
        raise RuntimeError(f"terminal job cannot transition from {previous}")
    if state != previous and state not in ALLOWED_TRANSITIONS.get(previous, set()):
        raise RuntimeError(f"invalid job transition {previous} -> {state}")
    record.update(fields)
    record["state"] = state
    record["updated_at"] = utc_now()
    record["ida_pid"] = os.getpid()
    write_json_atomic(path, record)
    log("job_phase", job_id=job_id, state=state)
    return record


def loaded_image_indices():
    if TARGET_KIND != "dsc":
        return "not_applicable", []
    try:
        import ida_dscu

        service = ida_dscu.get_dscu_svc()
        count = int(os.environ.get("DSCIDA_IMAGE_COUNT", "0"))
        return "ida_dscu", [
            index for index in range(count) if service.is_image_loaded(index)
        ]
    except (ImportError, AttributeError):
        node = ida_netnode.netnode("$ dscu")
        values = []
        index = node.altfirst("m")
        while index != ida_netnode.BADNODE:
            values.append(int(index))
            index = node.altnext(index, "m")
        return "netnode:$ dscu/m", values


def ensure_database_identity():
    node = ida_netnode.netnode()
    node.create("$ dscida")
    if TARGET_KIND == "dsc":
        expected = (
            DSC_PATH,
            DSC_UUID,
            MAIN_MODULE,
            SESSION_ID,
            SESSION_INSTANCE_ID,
        )
        for index, value in enumerate(expected):
            existing = node.supstr(index)
            if existing and existing != value:
                raise RuntimeError(
                    f"dscida database identity mismatch at field {index}: "
                    f"{existing!r} != {value!r}"
                )
            node.supset(index, value)
    identity = target_identity()
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    existing = node.supstr(10)
    if existing and existing != encoded:
        raise RuntimeError("dscida tagged database identity mismatch")
    node.supset(10, encoded)


def native_input_metadata():
    digest = ida_nalt.retrieve_input_file_sha256()
    return {
        "input_path": os.path.realpath(ida_nalt.get_input_file_path()),
        "input_sha256": bytes(digest).hex(),
        "filetype": int(ida_ida.inf_get_filetype()),
        "processor": ida_idp.get_idp_name(),
    }


def target_identity():
    common = {
        "target_kind": TARGET_KIND,
        "session_id": SESSION_ID,
        "session_instance_id": SESSION_INSTANCE_ID,
    }
    if TARGET_KIND == "binary":
        common.update(
            {
                "source_path": SOURCE_PATH,
                "input_path": INPUT_PATH,
                "input_sha256": INPUT_SHA256,
                "input_size": INPUT_SIZE,
                "binary_format": BINARY_FORMAT,
                "architecture": ARCHITECTURE,
                "ida_processor": IDA_PROCESSOR,
                "macho_uuid": MACHO_UUID,
            }
        )
    else:
        common.update(
            {
                "dsc_path": DSC_PATH,
                "dsc_uuid": DSC_UUID,
                "main_module": MAIN_MODULE,
            }
        )
    return common


def snapshot():
    function_count = 0
    function = ida_funcs.get_next_func(0)
    while function is not None:
        function_count += 1
        function = ida_funcs.get_next_func(function.start_ea)
    backend, indexes = loaded_image_indices()
    return {
        "kernel_version": idaapi.get_kernel_version(),
        "is_idaq": bool(ida_kernwin.is_idaq()),
        "root_filename": ida_nalt.get_root_filename(),
        "idb_path": idc.get_idb_path(),
        "imagebase": hex(idaapi.get_imagebase()),
        "function_count": function_count,
        "segment_count": ida_segment.get_segm_qty(),
        "thread_id": threading.get_ident(),
        "loaded_image_backend": backend,
        "loaded_image_indices": indexes,
        "native_input": native_input_metadata(),
    }


def load_module(module_path, image_index):
    if not isinstance(module_path, str) or not module_path.startswith("/"):
        raise ValueError("module must be an absolute DSC install path")
    if not isinstance(image_index, int) or image_index < 0:
        raise ValueError("image_index must be a non-negative integer")
    _, before = loaded_image_indices()
    if image_index in before:
        return {"changed": False, "state": "already_loaded", "snapshot": snapshot()}
    node = idaapi.netnode()
    node.create("$ dscu")
    node.supset(2, module_path)
    plugin_result = bool(idaapi.load_and_run_plugin("dscu", 1))
    ida_auto.auto_wait()
    _, after = loaded_image_indices()
    if image_index not in after:
        raise RuntimeError(
            f"DSCU returned {plugin_result}, but image index {image_index} is absent"
        )
    return {
        "changed": True,
        "state": "loaded",
        "plugin_result": plugin_result,
        "snapshot": snapshot(),
    }


def snapshot_path(job_id):
    return os.path.join(SESSION_DIR, "staging", f"{job_id}.snapshot.i64")


def save_snapshot(job_id):
    path = snapshot_path(job_id)
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    if os.path.exists(path):
        raise RuntimeError(f"snapshot already exists: {path}")
    if not ida_loader.save_database(path, ida_loader.DBFL_COMP):
        raise RuntimeError("ida_loader.save_database returned false")
    return path


def _exec_timeout_handler(signum, frame):
    raise TimeoutError("exec timeout")


def execute_python(script, args, timeout_ms):
    """Run a script synchronously on IDA's main thread with a best-effort alarm.

    The script sees the common IDA modules as globals, a ``dscida_args`` dict,
    and may assign a JSON-serializable ``dscida_result`` global. print() output
    is captured. On timeout the alarm handler raises TimeoutError which unwinds
    the script when it returns to the bytecode loop; the IDA process is never
    killed.
    """
    started = time.monotonic()
    buffer = io.StringIO()
    environment = {
        "__name__": "__dscida_exec__",
        "dscida_result": None,
        "dscida_args": args or {},
    }
    import ida_auto
    import ida_bytes
    import ida_entry
    import ida_funcs
    import ida_hexrays
    import ida_idp
    import ida_nalt
    import ida_name
    import ida_netnode
    import ida_search
    import ida_segment
    import ida_typeinf
    import ida_ua
    import ida_xref
    import idaapi
    import idc

    for module in (
        ida_auto, ida_bytes, ida_entry, ida_funcs, ida_hexrays,
        ida_idp, ida_nalt, ida_name, ida_netnode, ida_search,
        ida_segment, ida_typeinf, ida_ua, ida_xref, idaapi, idc,
    ):
        environment[module.__name__] = module
    timed_out = False
    error = ""
    traceback_text = ""
    result = None
    previous = None
    if timeout_ms and timeout_ms > 0 and threading.current_thread() is threading.main_thread():
        previous = signal.signal(signal.SIGALRM, _exec_timeout_handler)
        signal.setitimer(signal.ITIMER_REAL, max(0.05, timeout_ms / 1000.0))
    try:
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
            exec(compile(script, "<dscida-exec>", "exec"), environment)
        result = environment.get("dscida_result")
    except TimeoutError:
        timed_out = True
        error = "exec timeout"
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        traceback_text = traceback.format_exc()
    finally:
        if previous is not None:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
    payload = {
        "session_id": SESSION_ID,
        "session_instance_id": SESSION_INSTANCE_ID,
        "pid": os.getpid(),
        "stdout": buffer.getvalue(),
        "execution_ms": round((time.monotonic() - started) * 1000, 3),
        "timed_out": timed_out,
        "error": error,
        "traceback": traceback_text,
    }
    if not timed_out and not error:
        if result is not None:
            try:
                json.dumps(result)
                payload["result"] = result
            except (TypeError, ValueError):
                payload["error"] = "dscida_result is not JSON-serializable"
    return payload


class UnifiedHandler(IdaMcpHttpRequestHandler):
    def _authorized(self):
        return self.headers.get("Authorization") == f"Bearer {TOKEN}"

    def _send_json(self, status, payload):
        try:
            body = json.dumps(payload, sort_keys=True).encode("utf-8")
        except TypeError:
            body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

    def _body(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > MAX_BODY:
            raise ValueError("invalid request body length")
        body = json.loads(self.rfile.read(length))
        if not isinstance(body, dict):
            raise ValueError("request body must be an object")
        return body

    def do_GET(self):
        path = urlparse(self.path).path
        if not path.startswith("/control/"):
            return super().do_GET()
        if not self._authorized():
            self._send_json(401, {"success": False, "error": "unauthorized"})
            return
        if path == "/control/ping":
            self._send_json(200, {"success": True, "pid": os.getpid()})
        elif path in ("/control/status", "/control/loaded-modules"):
            if path == "/control/loaded-modules" and TARGET_KIND != "dsc":
                self._send_json(
                    409,
                    {
                        "success": False,
                        "error": "operation_not_supported_for_target",
                        "target_kind": TARGET_KIND,
                    },
                )
                return
            identity = target_identity()
            self._send_json(
                200,
                {
                    "success": True,
                    "schema_version": 2,
                    "pid": os.getpid(),
                    **identity,
                    "ida": snapshot(),
                },
            )
        elif path == "/control/analysis-status":
            self._send_json(
                200,
                {"success": True, "auto_analysis_ready": ida_auto.auto_is_ok()},
            )
        else:
            self._send_json(404, {"success": False, "error": "not_found"})

    def _accept_job(self, body, operation):
        job_id = body.get("job_id")
        request_id = body.get("request_id")
        _, record = read_job(job_id)
        if record.get("request_id") != request_id:
            raise ValueError("request_id mismatch")
        if record.get("payload_hash") != body.get("payload_hash"):
            raise ValueError("payload_hash mismatch")
        if record.get("base_generation") != body.get("base_generation"):
            raise ValueError("base_generation mismatch")
        if record.get("operation") != operation:
            raise ValueError("operation mismatch")
        return job_id, record, record.get("state") == "queued"

    def do_POST(self):
        path = urlparse(self.path).path
        if not path.startswith("/control/"):
            return super().do_POST()
        if not self._authorized():
            self._send_json(401, {"success": False, "error": "unauthorized"})
            return
        try:
            if path == "/control/shutdown":
                self._send_json(200, {"success": True, "state": "stopping"})
                threading.Thread(target=MCP_SERVER.stop, daemon=True).start()
                return
            body = self._body()
            if path == "/control/load-module":
                if TARGET_KIND != "dsc":
                    self._send_json(
                        409,
                        {
                            "success": False,
                            "error": "operation_not_supported_for_target",
                            "target_kind": TARGET_KIND,
                        },
                    )
                    return
                job_id, record, is_new = self._accept_job(body, "add")
                if record.get("module_path") != body.get("module_path"):
                    raise ValueError("module_path mismatch")
                if record.get("image_index") != body.get("image_index"):
                    raise ValueError("image_index mismatch")
                if is_new:
                    update_job(job_id, "running_dscu")
                self._send_json(
                    202, {"success": True, "accepted": True, "job_id": job_id}
                )
                if not is_new:
                    return
                try:
                    result = load_module(
                        body["module_path"], int(body["image_index"])
                    )
                    if not result["changed"]:
                        update_job(job_id, "succeeded", result=result)
                        return
                    update_job(job_id, "running_analysis", load_result=result)
                    update_job(job_id, "snapshotting")
                    output = save_snapshot(job_id)
                    update_job(
                        job_id,
                        "validating",
                        snapshot_path=output,
                        loaded_image_indices=result["snapshot"][
                            "loaded_image_indices"
                        ],
                        loaded_image_backend=result["snapshot"][
                            "loaded_image_backend"
                        ],
                    )
                except Exception as exc:
                    update_job(
                        job_id,
                        "failed",
                        error=f"{type(exc).__name__}: {exc}",
                        traceback=traceback.format_exc(),
                    )
                return
            if path == "/control/save":
                job_id, _, is_new = self._accept_job(body, "save")
                if is_new:
                    update_job(job_id, "snapshotting")
                self._send_json(
                    202, {"success": True, "accepted": True, "job_id": job_id}
                )
                if not is_new:
                    return
                try:
                    output = save_snapshot(job_id)
                    state = snapshot()
                    update_job(
                        job_id,
                        "validating",
                        snapshot_path=output,
                        loaded_image_indices=state["loaded_image_indices"],
                        loaded_image_backend=state["loaded_image_backend"],
                    )
                except Exception as exc:
                    update_job(
                        job_id,
                        "failed",
                        error=f"{type(exc).__name__}: {exc}",
                        traceback=traceback.format_exc(),
                    )
                return
            if path == "/control/exec-python":
                script = body.get("script")
                if not isinstance(script, str) or not script.strip():
                    raise ValueError("script must be a non-empty string")
                timeout_ms = body.get("timeout_ms", 0)
                if not isinstance(timeout_ms, int) or timeout_ms < 0 or timeout_ms > 3600000:
                    raise ValueError("timeout_ms must be an integer in [0, 3600000]")
                args = body.get("args") or {}
                if not isinstance(args, dict):
                    raise ValueError("args must be an object")
                outcome = execute_python(script, args, timeout_ms)
                if outcome["timed_out"]:
                    self._send_json(
                        408,
                        {
                            "success": False,
                            "error": "exec timeout",
                            "session_id": outcome["session_id"],
                            "session_instance_id": outcome["session_instance_id"],
                            "pid": outcome["pid"],
                            "stdout": outcome["stdout"],
                            "execution_ms": outcome["execution_ms"],
                            "timed_out": True,
                            "traceback": "",
                        },
                    )
                else:
                    self._send_json(
                        200,
                        {
                            "success": not outcome["error"] and not outcome["timed_out"],
                            **outcome,
                        },
                    )
                return
            self._send_json(404, {"success": False, "error": "not_found"})
        except Exception as exc:
            self._send_json(
                400,
                {"success": False, "error": f"{type(exc).__name__}: {exc}"},
            )


analysis_started = time.monotonic()
log("initial_analysis_started")
ida_auto.auto_wait()
ensure_database_identity()
analysis_ms = round((time.monotonic() - analysis_started) * 1000, 3)
initial_state = snapshot()
log("initial_analysis_completed", duration_ms=analysis_ms)


def publish_endpoint():
    while MCP_SERVER._http_server is None or not MCP_SERVER._running:
        time.sleep(0.01)
    actual_host, actual_port = MCP_SERVER._http_server.server_address
    ready = {
        "success": True,
        "state": "ready",
        "session_id": SESSION_ID,
        "session_instance_id": SESSION_INSTANCE_ID,
        "target_kind": TARGET_KIND,
        "pid": os.getpid(),
        "host": actual_host,
        "port": actual_port,
        "mcp_url": f"http://{actual_host}:{actual_port}/mcp",
        "control_url": f"http://{actual_host}:{actual_port}/control",
        "initial_auto_analysis_ms": analysis_ms,
        "ida": initial_state,
        "published_at": time.time(),
    }
    write_json_atomic(READY_PATH, ready)
    log("server_ready", host=actual_host, port=actual_port)


threading.Thread(
    target=publish_endpoint, daemon=True, name="dscida-publish-ready"
).start()

try:
    MCP_SERVER.serve(
        HOST, PORT, background=False, request_handler=UnifiedHandler
    )
finally:
    log("server_stopped")
    ida_pro.qexit(0)
