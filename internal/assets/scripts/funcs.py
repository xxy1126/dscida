"""List functions, optionally filtered by name."""

import ida_funcs
import ida_ida


def main():
    query = (dscida_args.get("query") or "").lower()
    limit = int(dscida_args.get("limit", "0"))
    if limit < 0 or limit > 100000:
        raise ValueError("limit must be in [0, 100000]")
    result = []
    fn = ida_funcs.get_next_func(ida_ida.inf_get_min_ea())
    while fn is not None:
        name = ida_funcs.get_func_name(fn.start_ea) or ""
        if not query or query in name.lower():
            result.append(
                {
                    "address": fmt_addr(fn.start_ea),
                    "name": name,
                    "size": fn.size(),
                }
            )
            if limit and len(result) >= limit:
                break
        fn = ida_funcs.get_next_func(fn.start_ea)
    print(
        "\n".join(
            "%s  %8d  %s" % (item["address"], item["size"], item["name"])
            for item in result
        )
    )
    global dscida_result
    dscida_result = {
        "total": len(result),
        "query": dscida_args.get("query", ""),
        "functions": result,
    }


main()
