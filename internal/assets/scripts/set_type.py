"""Declare/apply a type at ADDR from a C declaration.

Function prototypes apply reliably (`int f(int a);`). Data items at an
undefined address may not be applicable in the current headless IDA build;
the error message covers that case.
"""

import ida_typeinf


def main():
    addr = resolve_addr(dscida_args.get("addr"))
    declaration = dscida_args.get("type") or ""
    if not declaration:
        raise ValueError("type is required")
    til = ida_typeinf.get_idati()
    if not ida_typeinf.apply_cdecl(til, addr, declaration, 0):
        raise RuntimeError(
            "failed to apply type at %s (function prototypes such as "
            "'int f(int a);' work best; data items may need an existing "
            "definition)" % fmt_addr(addr)
        )
    print("%s: %s" % (fmt_addr(addr), declaration))
    global dscida_result
    dscida_result = {"address": fmt_addr(addr), "type": declaration}


main()
