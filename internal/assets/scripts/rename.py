"""Rename the symbol at ADDR."""

import ida_name


def main():
    addr = resolve_addr(dscida_args.get("addr"))
    name = dscida_args.get("name") or ""
    if not name:
        raise ValueError("name is required")
    previous = ida_name.get_name(addr) or ""
    if not ida_name.set_name(addr, name, ida_name.SN_FORCE):
        raise RuntimeError("rename failed at %s" % fmt_addr(addr))
    print("renamed %s: %s -> %s" % (fmt_addr(addr), previous or "(none)", name))
    global dscida_result
    dscida_result = {"address": fmt_addr(addr), "previous": previous, "name": name}


main()
