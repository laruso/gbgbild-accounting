#!/usr/bin/env python3
"""
Diagnose why missing-ink jobs don't match the .accdb export.

For each ink-less job in the live DB, find .accdb rows with the same job-name
prefix and report the smallest time difference. This reveals whether the
mismatch is a consistent clock offset (e.g. all matches land 2-5 min or ~60/120
min away => widen/shift the tolerance) or a genuine absence (no name match at
all => the job isn't in the .accdb).

Usage (on the Pi):
    python3 match_diag.py [accdb_export.db] [--from YYYY-MM-DD] [--to YYYY-MM-DD]
"""
import argparse
import sqlite3
from pathlib import Path
from datetime import datetime

LIVE = Path.home() / ".lfp_accounting" / "jobs.db"
INK = ["PK", "MK", "C", "VM", "Y", "OR", "GR", "LC", "VLM", "LK", "LLK", "V"]


def parse(t):
    try:
        return datetime.fromisoformat((t or "").replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("export", nargs="?", default="accdb_export.db")
    ap.add_argument("--from", dest="date_from")
    ap.add_argument("--to", dest="date_to")
    args = ap.parse_args()

    # .accdb rows grouped by name prefix.
    src = sqlite3.connect(args.export)
    src.row_factory = sqlite3.Row
    by_name = {}
    for r in src.execute("SELECT start_time, job_name FROM accdb_jobs"):
        dt = parse(r["start_time"])
        if dt:
            by_name.setdefault((r["job_name"] or "")[:20], []).append(dt)
    src.close()

    # Live missing-ink jobs, optionally date-scoped.
    db = sqlite3.connect(str(LIVE))
    db.row_factory = sqlite3.Row
    ink_total = "(" + " + ".join("COALESCE(InkUse_%s,0)" % c for c in INK) + ")"
    clauses = ["(InkUse_PK IS NULL OR %s = 0)" % ink_total]
    params = []
    if args.date_from:
        clauses.append("substr(start_time,1,10) >= ?"); params.append(args.date_from)
    if args.date_to:
        clauses.append("substr(start_time,1,10) <= ?"); params.append(args.date_to)
    missing = db.execute(
        "SELECT start_time, job_name FROM jobs WHERE " + " AND ".join(clauses), params
    ).fetchall()
    db.close()

    buckets = {"<=1 min": 0, "2-5 min": 0, "6-59 min": 0,
               "60-180 min (tz?)": 0, "same name, >180 min": 0, "no name in .accdb": 0}
    signed = []   # signed minute deltas for name-matched jobs
    examples = []
    for r in missing:
        dt = parse(r["start_time"])
        pre = (r["job_name"] or "")[:20]
        cands = by_name.get(pre)
        if not dt or not cands:
            buckets["no name in .accdb"] += 1
            continue
        nearest = min(cands, key=lambda c: abs((dt - c).total_seconds()))
        dsec = (dt - nearest).total_seconds()
        dmin = abs(dsec) / 60
        signed.append(dsec / 60)
        if dmin <= 1: buckets["<=1 min"] += 1
        elif dmin <= 5: buckets["2-5 min"] += 1
        elif dmin <= 59: buckets["6-59 min"] += 1
        elif dmin <= 180: buckets["60-180 min (tz?)"] += 1
        else: buckets["same name, >180 min"] += 1
        if 1 < dmin <= 180 and len(examples) < 12:
            examples.append((r["start_time"][:19], nearest.isoformat()[:19], round(dsec / 60, 1), pre))

    print("Missing-ink jobs analyzed:", len(missing))
    for k, v in buckets.items():
        print("  %-22s %d" % (k, v))
    if signed:
        signed.sort()
        print("\nSigned delta (live - .accdb) minutes for name-matched jobs:")
        print("  min %.1f   median %.1f   max %.1f" % (
            signed[0], signed[len(signed) // 2], signed[-1]))
    if examples:
        print("\nExamples (live_time, accdb_time, delta_min, name):")
        for e in examples:
            print("  %s  %s  %+6.1f  %s" % e)


if __name__ == "__main__":
    main()
