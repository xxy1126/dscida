"""Disassemble N instructions starting at ADDR."""

import ida_ua
import idaapi
import idc


def main():
    addr = resolve_addr(dscida_args.get("addr"))
    count = int(dscida_args.get("count", "20"))
    if count < 1 or count > 5000:
        raise ValueError("count must be in [1, 5000]")
    lines = []
    ea = addr
    for _ in range(count):
        insn = ida_ua.insn_t()
        length = ida_ua.decode_insn(insn, ea)
        if length == 0:
            break
        text = idc.generate_disasm_line(ea, 0) or ""
        lines.append({"address": fmt_addr(ea), "text": text, "length": length})
        ea += length
    if not lines:
        raise ValueError("no instructions at %s" % fmt_addr(addr))
    print("\n".join("%s: %s" % (line["address"], line["text"]) for line in lines))
    result = {
        "start": fmt_addr(addr),
        "instruction_count": len(lines),
        "instructions": lines,
    }
    if dscida_args.get("graph") == "1":
        fn = idaapi.get_func(addr)
        if fn is not None:
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
