"""References (code and data) to ADDR."""

import ida_ida
import ida_xref


def main():
    addr = resolve_addr(dscida_args.get("addr"))
    result = []
    ref = ida_xref.get_first_cref_to(addr)
    while ref != idaapi.BADADDR:
        result.append(
            {
                "direction": "to",
                "type": "code",
                "address": fmt_addr(ref),
                "name": ea_name(ref),
            }
        )
        ref = ida_xref.get_next_cref_to(addr, ref)
    ref = ida_xref.get_first_dref_to(addr)
    while ref != idaapi.BADADDR:
        result.append(
            {
                "direction": "to",
                "type": "data",
                "address": fmt_addr(ref),
                "name": ea_name(ref),
            }
        )
        ref = ida_xref.get_next_dref_to(addr, ref)
    if not result:
        print("no references to %s" % fmt_addr(addr))
    for item in result:
        print(
            "%s  %-4s  %s"
            % (item["address"], item["type"], item["name"] or "(unnamed)")
        )
    global dscida_result
    dscida_result = {
        "target": fmt_addr(addr),
        "name": ea_name(addr),
        "references": result,
        "total": len(result),
    }


main()
