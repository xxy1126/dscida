"""Short-lived validator for an immutable dscida generation candidate."""

import json
import os
import time
import traceback

import ida_auto
import ida_ida
import ida_idp
import ida_nalt
import ida_netnode
import ida_pro
import idaapi
import idc


OUTPUT = os.environ["DSCIDA_VALIDATION_RESULT"]
TARGET_KIND = os.environ.get("DSCIDA_TARGET_KIND", "dsc") or "dsc"
EXPECTED = sorted(json.loads(os.environ["DSCIDA_EXPECTED_INDEXES"]) or [])
EXPECTED_DSC_PATH = os.path.realpath(os.environ.get("DSCIDA_DSC_PATH", ""))
EXPECTED_DSC_UUID = os.environ.get("DSCIDA_DSC_UUID", "")
EXPECTED_MAIN_MODULE = os.environ.get("DSCIDA_MAIN_MODULE", "")
EXPECTED_SOURCE_PATH = os.path.realpath(os.environ.get("DSCIDA_SOURCE_PATH", ""))
EXPECTED_INPUT_PATH = os.path.realpath(os.environ.get("DSCIDA_INPUT_PATH", ""))
EXPECTED_INPUT_SHA256 = os.environ.get("DSCIDA_INPUT_SHA256", "")
EXPECTED_INPUT_SIZE = int(os.environ.get("DSCIDA_INPUT_SIZE", "0"))
EXPECTED_BINARY_FORMAT = os.environ.get("DSCIDA_BINARY_FORMAT", "")
EXPECTED_ARCHITECTURE = os.environ.get("DSCIDA_ARCHITECTURE", "")
EXPECTED_IDA_PROCESSOR = os.environ.get("DSCIDA_IDA_PROCESSOR", "")
EXPECTED_MACHO_UUID = os.environ.get("DSCIDA_MACHO_UUID", "")


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
    tagged = node.supstr(10)
    if tagged:
        return json.loads(tagged)
    return {
        "target_kind": "dsc",
        "dsc_path": node.supstr(0),
        "dsc_uuid": node.supstr(1),
        "main_module": node.supstr(2),
    }


def expected_identity():
    if TARGET_KIND == "binary":
        return {
            "target_kind": "binary",
            "source_path": EXPECTED_SOURCE_PATH,
            "input_path": EXPECTED_INPUT_PATH,
            "input_sha256": EXPECTED_INPUT_SHA256,
            "input_size": EXPECTED_INPUT_SIZE,
            "binary_format": EXPECTED_BINARY_FORMAT,
            "architecture": EXPECTED_ARCHITECTURE,
            "ida_processor": EXPECTED_IDA_PROCESSOR,
            "macho_uuid": EXPECTED_MACHO_UUID,
        }
    return {
        "target_kind": "dsc",
        "dsc_path": EXPECTED_DSC_PATH,
        "dsc_uuid": EXPECTED_DSC_UUID,
        "main_module": EXPECTED_MAIN_MODULE,
    }


def native_input_metadata():
    digest = ida_nalt.retrieve_input_file_sha256()
    return {
        "input_path": os.path.realpath(ida_nalt.get_input_file_path()),
        "input_sha256": bytes(digest).hex(),
        "filetype": int(ida_ida.inf_get_filetype()),
        "processor": ida_idp.get_idp_name(),
    }


exit_code = 1
try:
    started = time.monotonic()
    ida_auto.auto_wait()
    backend, indexes = loaded_image_indices()
    indexes = sorted(indexes)
    identity = database_identity()
    expected_target = expected_identity()
    identity = {key: identity.get(key) for key in expected_target}
    native = native_input_metadata()
    expected_filetype = (
        int(ida_ida.f_MACHO)
        if EXPECTED_BINARY_FORMAT == "macho"
        else int(ida_ida.f_ELF)
    )
    native_success = TARGET_KIND != "binary" or (
        native["input_path"] == EXPECTED_INPUT_PATH
        and native["input_sha256"] == EXPECTED_INPUT_SHA256
        and native["filetype"] == expected_filetype
        and native["processor"] == EXPECTED_IDA_PROCESSOR
    )
    success = indexes == EXPECTED and identity == expected_target and native_success
    write_result(
        {
            "success": success,
            "idb_path": idc.get_idb_path(),
            "ida_version": idaapi.get_kernel_version(),
            "loaded_image_backend": backend,
            "loaded_image_indices": indexes,
            "expected_loaded_image_indices": EXPECTED,
            "target_kind": TARGET_KIND,
            "database_identity": identity,
            "expected_database_identity": expected_target,
            "native_input": native,
            "analysis_ms": round((time.monotonic() - started) * 1000, 3),
            "error": None if success else "loaded indexes or target identity mismatch",
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
