"""Decompile the function at ADDR."""

import ida_funcs
import ida_hexrays
import idaapi


def main():
    addr = resolve_addr(dscida_args.get("addr"))
    fn = idaapi.get_func(addr)
    if fn is None:
        raise ValueError("no function at %s" % fmt_addr(addr))
    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays decompiler is not available")
    cfunc = ida_hexrays.decompile(fn.start_ea)
    if cfunc is None:
        raise RuntimeError("decompilation failed")
    pseudo = str(cfunc)
    print(pseudo)
    result = {
        "address": fmt_addr(fn.start_ea),
        "name": ida_funcs.get_func_name(fn.start_ea) or "",
        "pseudocode": pseudo,
    }
    if dscida_args.get("cfg") == "1":
        blocks = []
        flow = idaapi.FlowChart(fn)
        for block in flow:
            blocks.append(
                {
                    "start": fmt_addr(block.start_ea),
                    "end": fmt_addr(block.end_ea),
                    "type": str(block.type),
                }
            )
        result["basic_blocks"] = blocks
    global dscida_result
    dscida_result = result


main()
