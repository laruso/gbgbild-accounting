#!/usr/bin/env python3
"""
Diagnostic: show the job-log table and the ji: buffer SIDE BY SIDE.

The pull joins these two SNMP sources to attach username + ink blob to each
job. It currently matches purely by job-name prefix, which silently drops
blobs whose ji: job_name is blank or formatted differently than the job log.

This script fetches the newest ~40 job-log rows and the full ji: buffer, prints
both, and reports how many job-log rows the current name-match would actually
attach a blob to. Use it to see whether a position/recency-based match would
do better.

Usage:
  python3 match_check.py [printer-ip]      # default 192.168.1.55
"""
import logging
import sys

from joblog import (snmp_walk_column, _col_root, _row_index, _as_int, _as_str,
                    _decode_datetime, fetch_ji_metadata)

NEWEST = 40   # how many newest job-log rows to inspect


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.55"
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    # --- newest job-log rows (rows are walked in index order; 1 = newest) ---
    names, starts, counters = {}, {}, {}
    for col, dest, conv in [(3, names, "str"), (5, starts, "dt"), (2, counters, "int")]:
        steps = 0
        for oid, tag, raw in snmp_walk_column(host, _col_root(col), "public", max_steps=NEWEST + 5):
            idx = _row_index(oid, col)
            if idx is None:
                continue
            if conv == "str":
                v = _as_str(tag, raw)
            elif conv == "int":
                v = _as_int(tag, raw)
            else:
                v = _decode_datetime(raw) if (tag == 0x04 and len(raw) >= 8) else None
            if v is not None:
                dest[idx] = v
            steps += 1
            if steps >= NEWEST:
                break

    print()
    print("=== JOB LOG (newest %d rows; row 1 = newest) ===" % NEWEST)
    print("  %-4s  %-12s  %-16s  %s" % ("row", "counter", "start", "job_name (col 3)"))
    for row in sorted(names):
        st = starts.get(row)
        print("  %-4d  %-12s  %-16s  %s" % (
            row, counters.get(row, "?"),
            st.strftime("%Y-%m-%d %H:%M") if st else "?",
            (names.get(row) or "")[:40]))

    # --- ji: buffer ---
    meta = fetch_ji_metadata(host, community="epson")
    print()
    print("=== ji: BUFFER (%d entries) ===" % len(meta))
    print("  %-4s  %-5s  %-18s  %s" % ("idx", "blob", "user", "job_name"))
    for idx in sorted(meta):
        m = meta[idx]
        print("  %-4d  %-5s  %-18s  %s" % (
            idx, "blob" if m.get("ji_blob") else " -- ",
            (m.get("username") or "")[:18], (m.get("job_name") or "")[:40]))

    # --- how well does the current name-prefix match do? ---
    matched = 0
    for row, name in names.items():
        if not name:
            continue
        for m in meta.values():
            jn = m.get("job_name", "")
            if jn and name[:20] == jn[:20]:
                matched += 1
                break
    print()
    print("Current name-prefix match would attach a blob to %d of %d job-log rows."
          % (matched, len(names)))
    blank = sum(1 for m in meta.values() if not (m.get("job_name") or "").strip())
    print("ji: entries with a blob but NO job_name (unmatchable by name): %d" % blank)


if __name__ == "__main__":
    main()
