#!/usr/bin/env python3
"""
Merge an accdb_export.db (from export_accdb.py on the Windows PC) into the live
jobs.db on the Pi.

  - Fills username / machine / ink on jobs that currently lack ink, matched by
    start-minute + job-name prefix (with +/- 1 minute tolerance).
  - Inserts .accdb jobs that aren't in the DB at all.
  - Never overwrites data we already have, and is safe to run more than once.

Usage (on the Pi):
    python3 merge_accdb_export.py [accdb_export.db]
    python3 merge_accdb_export.py --from 2026-06-01 --to 2026-06-30
    python3 merge_accdb_export.py accdb_export.db --from 2026-06-01

--from / --to are inclusive YYYY-MM-DD filters on the job's start date; use them
to import only the gap period and leave already-billed months untouched.
"""
import argparse
import sys
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta

SQLITE_DB = Path.home() / ".lfp_accounting" / "jobs.db"
INK_CHANNELS = ["PK", "MK", "C", "VM", "Y", "OR", "GR", "LC", "VLM", "LK", "LLK", "V"]


def _key(start_time: str, job_name: str):
    return (start_time or "")[:16], (job_name or "")[:20]


def main():
    ap = argparse.ArgumentParser(description="Merge an accdb_export.db into the live jobs.db")
    ap.add_argument("export", nargs="?", default="accdb_export.db",
                    help="Path to the export DB (default: accdb_export.db)")
    ap.add_argument("--from", dest="date_from", metavar="YYYY-MM-DD",
                    help="Only import jobs on/after this date (inclusive)")
    ap.add_argument("--to", dest="date_to", metavar="YYYY-MM-DD",
                    help="Only import jobs on/before this date (inclusive)")
    args = ap.parse_args()

    export_path = Path(args.export)
    if not export_path.exists():
        print(f"Export file not found: {export_path}")
        sys.exit(1)
    if not SQLITE_DB.exists():
        print(f"Live DB not found: {SQLITE_DB}")
        sys.exit(1)

    src = sqlite3.connect(str(export_path))
    src.row_factory = sqlite3.Row
    accdb_rows = src.execute("SELECT * FROM accdb_jobs").fetchall()
    src.close()

    # Restrict to the requested date range (inclusive), compared on the date
    # portion of start_time (ISO text sorts lexically).
    if args.date_from or args.date_to:
        kept = []
        for r in accdb_rows:
            day = (r["start_time"] or "")[:10]
            if not day:
                continue
            if args.date_from and day < args.date_from:
                continue
            if args.date_to and day > args.date_to:
                continue
            kept.append(r)
        rng = f"{args.date_from or '(open)'} .. {args.date_to or '(open)'}"
        print(f"Export rows: {len(accdb_rows)} ({len(kept)} within {rng})")
        accdb_rows = kept
    else:
        print(f"Export rows: {len(accdb_rows)}")

    db = sqlite3.connect(str(SQLITE_DB))
    db.row_factory = sqlite3.Row

    # Build lookup: (start_minute, name_prefix) -> export row.
    lookup = {}
    for r in accdb_rows:
        k = _key(r["start_time"], r["job_name"])
        if k[0]:
            lookup[k] = r

    # --- 1. Fill missing ink/user on existing jobs (within the date range) ---
    # "Missing" means no ink at all (NULL) OR an all-zero total — the latter are
    # entries the printer hadn't populated when we pulled, which the .accdb has
    # the real value for. The update SETs ink directly, so zeros get overwritten.
    ink_total = "(" + " + ".join("COALESCE(InkUse_%s, 0)" % ch for ch in INK_CHANNELS) + ")"
    clauses = [f"(InkUse_PK IS NULL OR {ink_total} = 0)"]
    params: list = []
    if args.date_from:
        clauses.append("substr(start_time, 1, 10) >= ?")
        params.append(args.date_from)
    if args.date_to:
        clauses.append("substr(start_time, 1, 10) <= ?")
        params.append(args.date_to)
    missing = db.execute(
        "SELECT job_id, start_time, job_name FROM jobs WHERE " + " AND ".join(clauses),
        params).fetchall()
    print(f"Jobs missing ink: {len(missing)}")

    set_cols = ", ".join(f"InkUse_{ch} = ?" for ch in INK_CHANNELS)
    update_sql = f"""
        UPDATE jobs SET
            username     = COALESCE(NULLIF(username, ''), ?),
            machine_name = COALESCE(NULLIF(machine_name, ''), ?),
            {set_cols}
        WHERE job_id = ?
    """
    updated = not_matched = 0
    with db:
        for row in missing:
            k = _key(row["start_time"], row["job_name"])
            r = lookup.get(k)
            if not r:  # try +/- 1 minute
                try:
                    dt = datetime.fromisoformat((row["start_time"] or "").replace("Z", "+00:00"))
                    for delta in (-1, 1):
                        alt = (dt + timedelta(minutes=delta)).strftime("%Y-%m-%dT%H:%M")
                        r = lookup.get((alt, k[1]))
                        if r:
                            break
                except ValueError:
                    r = None
            if not r:
                not_matched += 1
                continue
            ink_vals = [r[f"InkUse_{ch}"] for ch in INK_CHANNELS]
            db.execute(update_sql, (
                (r["username"] or None), (r["machine_name"] or None),
                *ink_vals, row["job_id"]))
            updated += 1
    print(f"  {updated} filled, {not_matched} not matched in export")

    # --- 2. Insert export jobs not present at all ---
    existing = set()
    for row in db.execute("SELECT start_time, job_name FROM jobs"):
        existing.add(_key(row["start_time"], row["job_name"]))

    cols = (["job_id", "job_name", "username", "machine_name", "start_time"]
            + [f"InkUse_{ch}" for ch in INK_CHANNELS])
    insert_sql = (f"INSERT OR IGNORE INTO jobs ({', '.join(cols)}) "
                  f"VALUES ({','.join('?' * len(cols))})")
    inserted = 0
    with db:
        for r in accdb_rows:
            st = r["start_time"] or ""
            k = _key(st, r["job_name"])
            if not st or k in existing:
                continue
            job_id = f"{st}|{(r['job_name'] or '')}"
            ink_vals = [r[f"InkUse_{ch}"] for ch in INK_CHANNELS]
            db.execute(insert_sql, (
                job_id, r["job_name"], r["username"] or "", r["machine_name"] or "",
                st, *ink_vals))
            inserted += 1
            existing.add(k)
    print(f"  {inserted} new jobs inserted from export")

    total = db.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
    with_ink = db.execute("SELECT COUNT(*) FROM jobs WHERE InkUse_PK IS NOT NULL").fetchone()[0]
    print(f"\nDB now: {total} total jobs, {with_ink} with ink data")
    db.close()


if __name__ == "__main__":
    main()
