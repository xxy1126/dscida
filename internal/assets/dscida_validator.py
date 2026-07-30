"""Short-lived validator for an immutable dscida generation candidate."""

import json
import os
import time
import traceback

import ida_auto
import ida_netnode
import ida_pro
import idaapi
import idc


OUTPUT = os.environ["DSCIDA_VALIDATION_RESULT"]
EXPECTED = sorted(json.loads(os.environ["DSCIDA_EXPECTED_INDEXES"]))
EXPECTED_DSC_PATH = os.path.realpath(os.environ["DSCIDA_DSC_PATH"])
EXPECTED_DSC_UUID = os.environ["DSCIDA_DSC_UUID"]
EXPECTED_MAIN_MODULE = os.environ["DSCIDA_MAIN_MODULE"]


def loaded_image_indices():
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


def write_result(payload):
    temporary = f"{OUTPUT}.tmp.{os.getpid()}"
    with open(temporary, "w", encoding="utf-8") as stream:
        json.dump(payload, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, OUTPUT)


def database_identity():
    node = ida_netnode.netnode("$ dscida")
    return {
        "dsc_path": node.supstr(0),
        "dsc_uuid": node.supstr(1),
        "main_module": node.supstr(2),
    }


exit_code = 1
try:
    started = time.monotonic()
    ida_auto.auto_wait()
    backend, indexes = loaded_image_indices()
    indexes = sorted(indexes)
    identity = database_identity()
    expected_identity = {
        "dsc_path": EXPECTED_DSC_PATH,
        "dsc_uuid": EXPECTED_DSC_UUID,
        "main_module": EXPECTED_MAIN_MODULE,
    }
    success = indexes == EXPECTED and identity == expected_identity
    write_result(
        {
            "success": success,
            "idb_path": idc.get_idb_path(),
            "ida_version": idaapi.get_kernel_version(),
            "loaded_image_backend": backend,
            "loaded_image_indices": indexes,
            "expected_loaded_image_indices": EXPECTED,
            "database_identity": identity,
            "expected_database_identity": expected_identity,
            "analysis_ms": round((time.monotonic() - started) * 1000, 3),
            "error": None if success else "loaded indexes or DSC identity mismatch",
        }
    )
    exit_code = 0 if success else 2
except Exception as exc:
    write_result(
        {
            "success": False,
            "error": f"{type(exc).__name__}: {exc}",
            "traceback": traceback.format_exc(),
        }
    )
finally:
    ida_pro.qexit(exit_code)
