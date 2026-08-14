"""List the import table, optionally filtered by module name."""

import ida_nalt


def main():
    query = (dscida_args.get("query") or "").lower()
    modules = []
    qty = ida_nalt.get_import_module_qty()
    for index in range(qty):
        module_name = ida_nalt.get_import_module_name(index) or ""
        if query and query not in module_name.lower():
            continue
        entries = []

        def collect(ea, name, ordinal):
            entries.append(
                {"address": fmt_addr(ea), "name": name or "", "ordinal": ordinal}
            )
            return True

        ida_nalt.enum_import_names(index, collect)
        modules.append({"module": module_name, "count": len(entries), "entries": entries})
    if not modules:
        print("no imports")
    for module in modules:
        print("module: %s (%d)" % (module["module"], module["count"]))
        for entry in module["entries"]:
            print(
                "  %s  %s (ordinal %d)"
                % (entry["address"], entry["name"], entry["ordinal"])
            )
    global dscida_result
    dscida_result = {"query": dscida_args.get("query", ""), "modules": modules}


main()
