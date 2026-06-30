#!/usr/bin/env python3
"""
Diagnostic: show ink state for the newest jobs, to explain "-" ink in `list`.

For each recent job it prints whether a ji_blob is stored and the raw InkUse_PK
value. A "-" in `list` means one of:
  - InkUse_PK is NULL  -> never decrypted (a re-pull should fix it, if a blob
                          is present), or
  - InkUse_PK is 0.0   -> stored as zero by an earlier pull; the fill-if-missing
                          upsert won't overwrite it, so it needs a targeted fix.

Usage (on the Pi):
    python3 check_missing_ink.py [limit]        # default: 30
"""
import sqlite3
import sys
from pathlib import Path

DB = Path.home() / ".lfp_accounting" / "jobs.db"
INK = ["PK", "MK", "C", "VM", "Y", "OR", "GR", "LC", "VLM", "LK", "LLK", "V"]


def main():
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    if not DB.exists():
        print("DB not found:", DB)
        sys.exit(1)

    c = sqlite3.connect(str(DB))
    c.row_factory = sqlite3.Row
    ink_sum = " + ".join("COALESCE(InkUse_%s,0)" % ch for ch in INK)

    print("%-16s %-5s %-9s %-9s %-13s %s" % (
        "start", "blob", "InkUse_PK", "ink_sum", "user", "job"))
    print("-" * 90)
    rows = c.execute("""
        SELECT substr(start_time, 1, 16) t,
               substr(job_name, 1, 30)   n,
               username                  u,
               InkUse_PK                 pk,
               (%s)                      s,
               CASE WHEN ji_blob IS NOT NULL THEN 'blob' ELSE ' -- ' END b
        FROM jobs
        ORDER BY start_time DESC
        LIMIT ?""" % ink_sum, (limit,)).fetchall()
    for r in rows:
        pk = "NULL" if r["pk"] is None else repr(r["pk"])
        print("%-16s %-5s %-9s %-9s %-13s %s" % (
            r["t"], r["b"], pk, r["s"], (r["u"] or "")[:13], r["n"]))

    # Summary of the problem cases among these rows.
    null_pk = sum(1 for r in rows if r["pk"] is None)
    zero_pk = sum(1 for r in rows if r["pk"] is not None and (r["s"] or 0) == 0)
    null_with_blob = sum(1 for r in rows if r["pk"] is None and r["b"] == "blob")
    print()
    print("In these %d rows: %d have InkUse_PK NULL (%d of them still have a blob), "
          "%d have ink summing to 0." % (len(rows), null_pk, null_with_blob, zero_pk))


if __name__ == "__main__":
    main()
