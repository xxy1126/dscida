"""Binary/session overview: base, segments, functions, imports, entry points."""

import ida_entry
import ida_funcs
import ida_ida
import ida_idp
import ida_nalt
import ida_segment


def main():
    entry_points = []
    for index in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(index)
        ea = ida_entry.get_entry(ordinal)
        entry_points.append(
            {
                "address": fmt_addr(ea),
                "ordinal": ordinal,
                "name": ida_entry.get_entry_name(ordinal) or "",
            }
        )
    segments = []
    for index in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(index)
        if seg is None:
            continue
        segments.append(
            {
                "start": fmt_addr(seg.start_ea),
                "end": fmt_addr(seg.end_ea),
                "name": ida_segment.get_segm_name(seg) or "",
                "class": seg.type,
            }
        )
    result = {
        "target_kind": dscida_args.get("target_kind", ""),
        "imagebase": fmt_addr(ida_ida.inf_get_min_ea()),
        "min_ea": fmt_addr(ida_ida.inf_get_min_ea()),
        "max_ea": fmt_addr(ida_ida.inf_get_max_ea()),
        "processor": ida_idp.get_idp_name(),
        "segment_count": len(segments),
        "segments": segments,
        "function_count": ida_funcs.get_func_qty(),
        "import_module_count": ida_nalt.get_import_module_qty(),
        "entry_points": entry_points,
    }
    print("imagebase: %s" % result["imagebase"])
    print("processor: %s" % result["processor"])
    print("segments: %d" % len(segments))
    print("functions: %d" % result["function_count"])
    print("imports: %d" % result["import_module_count"])
    for entry in entry_points:
        print("entry: %s  %s" % (entry["address"], entry["name"] or "(unnamed)"))
    global dscida_result
    dscida_result = result


main()
