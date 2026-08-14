"""Patch raw bytes at ADDR in the live IDB."""

import ida_bytes


def main():
    addr = resolve_addr(dscida_args.get("addr"))
    hex_text = dscida_args.get("hex") or ""
    cleaned = hex_text.replace(" ", "").replace("0x", "")
    try:
        data = bytes.fromhex(cleaned)
    except ValueError:
        raise ValueError("invalid hex: %s" % hex_text)
    if not data:
        raise ValueError("empty hex")
    if len(data) > 1 << 20:
        raise ValueError("patch is too large")
    for offset, byte in enumerate(data):
        ida_bytes.patch_byte(addr + offset, byte)
    print(
        "patched %d bytes at %s: %s"
        % (len(data), fmt_addr(addr), data.hex())
    )
    global dscida_result
    dscida_result = {
        "address": fmt_addr(addr),
        "length": len(data),
        "hex": data.hex(),
    }


main()
