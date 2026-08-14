"""Search for a hex byte pattern or text within an address range.

Uses chunked in-process scans (4 MiB windows with pattern overlap) instead of
the version-dependent ida_bytes.bin_search API, so the same code works across
IDA 9.x and avoids C-extension argument-type surprises.
"""

import ida_bytes
import ida_ida


def scan(needle, start, end, limit, lower):
    """Chunked byte scan; returns list of match addresses."""
    if lower:
        needle = needle.lower()
    matches = []
    chunk_size = 4 * 1024 * 1024
    overlap = len(needle) - 1
    pos = start
    tail = b""
    while pos < end:
        size = min(chunk_size, end - pos)
        data = ida_bytes.get_bytes(pos, size)
        if data is None:
            break
        buffer = tail + data
        if lower:
            buffer = buffer.lower()
        base = pos - len(tail)
        index = buffer.find(needle)
        while index != -1:
            match_ea = base + index
            if start <= match_ea < end:
                matches.append(match_ea)
                if limit and len(matches) >= limit:
                    return matches
            index = buffer.find(needle, index + 1)
        tail = buffer[-overlap:] if overlap > 0 else b""
        pos += size
    return matches


def main():
    hex_pattern = dscida_args.get("hex") or ""
    text_pattern = dscida_args.get("text") or ""
    case_insensitive = dscida_args.get("case_insensitive") == "1"
    if bool(hex_pattern) == bool(text_pattern):
        raise ValueError("exactly one of hex or text is required")
    if case_insensitive and not text_pattern:
        raise ValueError("--case-insensitive requires --text")
    if hex_pattern:
        cleaned = hex_pattern.replace(" ", "").replace("0x", "")
        try:
            pattern = bytes.fromhex(cleaned)
        except ValueError:
            raise ValueError("invalid hex pattern: %s" % hex_pattern)
        if not pattern:
            raise ValueError("empty hex pattern")
    else:
        pattern = text_pattern.encode("utf-8")
    start = ida_ida.inf_get_min_ea()
    end = ida_ida.inf_get_max_ea()
    if dscida_args.get("from"):
        start = resolve_addr(dscida_args.get("from"))
    if dscida_args.get("to"):
        end = resolve_addr(dscida_args.get("to"))
    if end <= start:
        raise ValueError("search range is empty")
    count = int(dscida_args.get("count", "0"))
    if count < 0 or count > 10000:
        raise ValueError("count must be in [0, 10000]")
    matches = scan(pattern, start, end, count, case_insensitive)
    for match in matches:
        print("%s  %s" % (fmt_addr(match), ea_name(match)))
    global dscida_result
    dscida_result = {
        "pattern": pattern.hex(),
        "from": fmt_addr(start),
        "to": fmt_addr(end),
        "case_insensitive": case_insensitive,
        "matches": [fmt_addr(match) for match in matches],
        "total": len(matches),
    }


main()
