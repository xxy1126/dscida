"""Set (or append to) a regular comment at ADDR."""

import idc


def main():
    addr = resolve_addr(dscida_args.get("addr"))
    text = dscida_args.get("text") or ""
    if not text:
        raise ValueError("text is required")
    append = dscida_args.get("append") == "1"
    existing = idc.get_cmt(addr, 0) or ""
    if append and existing:
        text = existing + "\n" + text
    if idc.set_cmt(addr, text, 0) == 0:
        raise RuntimeError("failed to set comment at %s" % fmt_addr(addr))
    print("%s: %s" % (fmt_addr(addr), text.replace("\n", "\\n")))
    global dscida_result
    dscida_result = {"address": fmt_addr(addr), "comment": text, "appended": append}


main()
