#!/usr/bin/env python3
"""
Remove rows a previous merge INSERTED from the .accdb (undo bad duplicates).

An earlier merge run inserted .accdb rows as new jobs, which duplicated our own
SNMP-captured jobs (and added the .accdb's aggregate "Lost Job (N)" entries).
Those inserted rows are identifiable: their start_time has NO timezone offset,
whereas every SNMP-captured job's timestamp does (e.g. "...+00:00"). Scoped to
a date range, that uniquely marks the merge inserts (real jobs there are SNMP).

Dry-run by default (lists what it would delete). Pass --delete to remove.

Usage (on the Pi):
    python3 remove_merge_inserts.py --from 2026-05-01 --to 2026-06-30
    python3 remove_merge_inserts.py --from 2026-05-01 --to 2026-06-30 --delete
"""
import argparse
import sqlite3
import sys
from pathlib import Path

DB = Path.home() / ".lfp_accounting" / "jobs.db"

# A merge-inserted row's start_time has no timezone (no '+'); SNMP rows always
# carry an offset. Restricting to a date range keeps this unambiguous.
WHERE = ("substr(start_time,1,10) >= ? AND substr(start_time,1,10) <= ? "
         "AND start_time NOT LIKE '%+%' AND start_time IS NOT NULL "
         "AND start_time != ''")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from", dest="date_from", required=True, metavar="YYYY-MM-DD")
    ap.add_argument("--to", dest="date_to", required=True, metavar="YYYY-MM-DD")
    ap.add_argument("--delete", action="store_true",
                    help="Actually delete (default is a dry run that only lists).")
    args = ap.parse_args()

    if not DB.exists():
        print("DB not found:", DB)
        sys.exit(1)

    c = sqlite3.connect(str(DB))
    c.row_factory = sqlite3.Row
    p = (args.date_from, args.date_to)

    rows = c.execute(
        f"SELECT substr(start_time,1,19) t, job_name, username, "
        f"area_cm2, InkUse_PK FROM jobs WHERE {WHERE} ORDER BY start_time", p).fetchall()
    print(f"Merge-inserted rows in {args.date_from}..{args.date_to}: {len(rows)}")
    for r in rows[:40]:
        print("  %-19s  %-13s  area=%-6s ink_pk=%-6s  %s" % (
            r["t"], (r["username"] or "")[:13],
            "-" if r["area_cm2"] is None else r["area_cm2"],
            "-" if r["InkUse_PK"] is None else r["InkUse_PK"],
            (r["job_name"] or "")[:34]))
    if len(rows) > 40:
        print(f"  ... and {len(rows) - 40} more")

    if not args.delete:
        print("\nDry run. Re-run with --delete to remove these rows.")
        c.close()
        return

    with c:
        deleted = c.execute(f"DELETE FROM jobs WHERE {WHERE}", p).rowcount
    print(f"\nDeleted {deleted} row(s).")
    c.close()


if __name__ == "__main__":
    main()
