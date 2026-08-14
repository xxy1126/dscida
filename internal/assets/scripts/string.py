"""Read a C string at ADDR."""

import ida_bytes


def main():
    addr = resolve_addr(dscida_args.get("addr"))
    length = int(dscida_args.get("length", "256"))
    if length < 1 or length > 1 << 20:
        raise ValueError("length must be in [1, 1048576]")
    raw = ida_bytes.get_bytes(addr, length)
    if raw is None:
        raise ValueError("cannot read %d bytes at %s" % (length, fmt_addr(addr)))
    end = raw.find(b"\x00")
    if end >= 0:
        raw = raw[:end]
    text = raw.decode("utf-8", "replace")
    print(text)
    global dscida_result
    dscida_result = {
        "address": fmt_addr(addr),
        "length": len(raw),
        "string": text,
    }


main()
