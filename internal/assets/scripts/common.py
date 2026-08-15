"""Shared helpers for dscida built-in analysis scripts.

This file is prepended to every builtin template by the Go supervisor; the
combined source runs inside the sidecar's exec-python environment, where the
common IDA modules are already present as globals.
"""

import ida_funcs
import ida_ida
import ida_name
import idaapi


def resolve_addr(value):
    """Resolve a user ADDR: 0x hex, decimal, or a symbol name."""
    if value is None:
        raise ValueError("address is required")
    text = str(value).strip()
    if not text:
        raise ValueError("address is required")
    if text.startswith("0x") or text.startswith("0X"):
        try:
            ea = int(text, 16)
            if ea >= 0:
                return ea
        except ValueError:
            pass
    elif text.isdigit():
        return int(text)
    ea = idaapi.get_name_ea(idaapi.BADADDR, text)
    if ea != idaapi.BADADDR:
        return ea
    matches = []
    lowered = text.lower()
    fn = ida_funcs.get_next_func(ida_ida.inf_get_min_ea())
    while fn is not None and len(matches) < 8:
        name = ida_funcs.get_func_name(fn.start_ea) or ""
        if lowered in name.lower():
            matches.append(name)
        fn = ida_funcs.get_next_func(fn.start_ea)
    if matches:
        raise ValueError(
            "address not found: %s\nPossible matches:\n  %s"
            % (text, "\n  ".join(matches))
        )
    raise ValueError("address not found: %s" % text)


def fmt_addr(ea):
    return "0x%x" % ea


def ea_name(ea):
    return ida_name.get_name(ea) or ""
