"""Read raw bytes at ADDR as hex or text."""

import ida_bytes


def main():
    addr = resolve_addr(dscida_args.get("addr"))
    length = int(dscida_args.get("length", "16"))
    if length < 1 or length > 1 << 20:
        raise ValueError("length must be in [1, 1048576]")
    fmt = dscida_args.get("format", "hex")
    raw = ida_bytes.get_bytes(addr, length)
    if raw is None:
        raise ValueError("cannot read %d bytes at %s" % (length, fmt_addr(addr)))
    if fmt == "text":
        text = raw.decode("utf-8", "replace")
        print(text)
    else:
        for offset in range(0, len(raw), 16):
            chunk = raw[offset : offset + 16]
            hexpart = " ".join("%02x" % byte for byte in chunk)
            printable = "".join(
                chr(byte) if 32 <= byte < 127 else "." for byte in chunk
            )
            print("%s  %-47s  %s" % (fmt_addr(addr + offset), hexpart, printable))
    global dscida_result
    dscida_result = {
        "address": fmt_addr(addr),
        "length": len(raw),
        "hex": raw.hex(),
        "text": raw.decode("utf-8", "replace"),
    }


main()
