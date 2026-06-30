#!/usr/bin/env python3
"""
Verify whether "-" (zero) ink rows are genuinely zero in the printer's data.

For recent jobs whose ink totals to 0 but which have a stored blob, this
re-decrypts the blob and prints all 12 channel values. If the blob decodes
cleanly to all-zero, the printer itself recorded no ink for that log entry
 — typically a duplicate entry for a file printed several times, where the ink
is attributed to the sibling entry — so nothing is actually lost and per-user
totals are unaffected. Each zero row is shown alongside its same-named siblings
and their ink totals for context.

Usage (on the Pi):
    python3 verify_zero_ink.py [scan_limit]      # default: 60 newest jobs
"""
import sqlite3
import sys
from pathlib import Path

from joblog import decode_ji_ink, INK_CHANNELS
from store import get_meta

DB = Path.home() / ".lfp_accounting" / "jobs.db"
SERIAL = get_meta("printer_serial") or "X6FB001980"


def main():
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    if not DB.exists():
        print("DB not found:", DB)
        sys.exit(1)

    c = sqlite3.connect(str(DB))
    c.row_factory = sqlite3.Row
    ink_sum = " + ".join("COALESCE(InkUse_%s,0)" % ch for ch in INK_CHANNELS)

    rows = c.execute(
        "SELECT job_id, substr(start_time,1,16) t, job_name, username, ji_blob, "
        "(%s) s FROM jobs ORDER BY start_time DESC LIMIT ?" % ink_sum, (limit,)
    ).fetchall()
    zero = [r for r in rows if (r["s"] or 0) == 0 and r["ji_blob"]]

    print("Serial: %s" % SERIAL)
    print("Zero-ink rows with a blob among newest %d jobs: %d\n" % (limit, len(zero)))

    for r in zero:
        print("=== %s  %s  %s" % (r["t"], (r["username"] or "")[:16], r["job_name"][:40]))
        ink = decode_ji_ink(r["ji_blob"], SERIAL)
        if ink is None:
            print("   blob did NOT decode to an ink TLV (tag 0x0F missing) <-- real problem")
        else:
            nonzero = {k: v for k, v in ink.items() if v}
            print("   decoded 12 channels, all zero: %s" % all(v == 0 for v in ink.values()))
            if nonzero:
                print("   non-zero channels: %s" % nonzero)
        sibs = c.execute(
            "SELECT substr(start_time,1,16) t, (%s) s FROM jobs "
            "WHERE substr(job_name,1,20) = substr(?,1,20) "
            "ORDER BY start_time DESC LIMIT 8" % ink_sum, (r["job_name"],)
        ).fetchall()
        print("   same-file entries (time, ink_sum): %s" % [(s["t"], s["s"]) for s in sibs])
        print()

    c.close()


if __name__ == "__main__":
    main()
