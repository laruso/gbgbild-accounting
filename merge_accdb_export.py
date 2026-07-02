#!/usr/bin/env python3
"""
Merge an accdb_export.db (from export_accdb.py on the Windows PC) into the live
jobs.db on the Pi.

  - Fills username / machine / ink on jobs that currently lack it, matched by
    job-name prefix + same calendar day (nearest time, one .accdb row per job).
  - Keeps every existing row untouched otherwise, including jobs the .accdb
    never had (the LFP "lost jobs"). Never overwrites real data; idempotent.
  - Fill-only by default: it does NOT add .accdb rows as new jobs. The SNMP
    capture is the source of truth for which jobs exist, so inserting .accdb
    rows would duplicate them (and its aggregate "Lost Job (N)" entries would
    double-count). Pass --insert only if you truly want the extras.
  - --replace (with --from/--to) instead wipes the range and imports the .accdb
    verbatim — only for gap months where the .accdb is the complete truth.

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
from collections import defaultdict
from pathlib import Path
from datetime import datetime

SQLITE_DB = Path.home() / ".lfp_accounting" / "jobs.db"
INK_CHANNELS = ["PK", "MK", "C", "VM", "Y", "OR", "GR", "LC", "VLM", "LK", "LLK", "V"]


def _parse(start_time: str):
    """Parse an ISO start_time to a naive datetime (drops tz), or None."""
    try:
        return datetime.fromisoformat(
            (start_time or "").replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def main():
    ap = argparse.ArgumentParser(description="Merge an accdb_export.db into the live jobs.db")
    ap.add_argument("export", nargs="?", default="accdb_export.db",
                    help="Path to the export DB (default: accdb_export.db)")
    ap.add_argument("--from", dest="date_from", metavar="YYYY-MM-DD",
                    help="Only import jobs on/after this date (inclusive)")
    ap.add_argument("--to", dest="date_to", metavar="YYYY-MM-DD",
                    help="Only import jobs on/before this date (inclusive)")
    ap.add_argument("--insert", action="store_true",
                    help="Also insert .accdb rows that don't match any existing "
                         "job. OFF by default: the SNMP capture is the source of "
                         "truth for which jobs exist, so inserting .accdb rows "
                         "(incl. its aggregate 'Lost Job (N)' entries) would "
                         "double-count. Default is fill-only.")
    ap.add_argument("--replace", action="store_true",
                    help="Authoritative mode: DELETE existing jobs in the date "
                         "range and import the .accdb's rows for it verbatim. "
                         "Requires --from and --to. Use for gap months where the "
                         ".accdb is the complete source of truth and per-job "
                         "timestamps don't line up for matching.")
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

    # --- Authoritative replace mode (for gap months) ---
    if args.replace:
        if not (args.date_from and args.date_to):
            print("--replace requires both --from and --to (refusing to replace "
                  "the whole database).")
            sys.exit(1)
        ins_cols = (["job_id", "job_name", "username", "machine_name", "start_time"]
                    + [f"InkUse_{ch}" for ch in INK_CHANNELS])
        ins_sql = (f"INSERT INTO jobs ({', '.join(ins_cols)}) "
                   f"VALUES ({','.join('?' * len(ins_cols))})")
        with db:
            deleted = db.execute(
                "DELETE FROM jobs WHERE substr(start_time,1,10) BETWEEN ? AND ?",
                (args.date_from, args.date_to)).rowcount
            inserted = 0
            for i, r in enumerate(accdb_rows):
                st = r["start_time"] or ""
                if not st:
                    continue
                # Unique id per .accdb row (these gap rows are never re-pulled).
                job_id = f"{st}|{(r['job_name'] or '')[:40]}|accdb{i}"
                ink = [r[f"InkUse_{ch}"] for ch in INK_CHANNELS]
                db.execute(ins_sql, (job_id, r["job_name"], r["username"] or "",
                                     r["machine_name"] or "", st, *ink))
                inserted += 1
        total = db.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
        with_ink = db.execute("SELECT COUNT(*) FROM jobs WHERE InkUse_PK IS NOT NULL").fetchone()[0]
        print(f"REPLACE {args.date_from}..{args.date_to}: deleted {deleted} existing "
              f"row(s), inserted {inserted} from .accdb.")
        print(f"DB now: {total} total jobs, {with_ink} with ink data")
        db.close()
        return

    # Match by (name prefix + same calendar day), greedily consuming each .accdb
    # row at most once. This is far more robust than +/-1 minute: the SNMP
    # job-log timestamps drift from the .accdb's by minutes (and a file printed
    # as a batch yields many same-named rows), so exact-minute matching missed
    # most jobs. Same-day + nearest-time + one-to-one consumption tolerates the
    # drift and pairs duplicates sensibly, while keeping every existing row —
    # including jobs the .accdb never had (the LFP "lost jobs").
    cands = defaultdict(list)   # name_prefix -> [[datetime, row, consumed], ...]
    for r in accdb_rows:
        dt = _parse(r["start_time"])
        if dt:
            cands[(r["job_name"] or "")[:20]].append([dt, r, False])
    for lst in cands.values():
        lst.sort(key=lambda x: x[0])

    def take_match(name_prefix, dt):
        """Nearest unconsumed same-day .accdb row for this name; consume it."""
        best, best_d = None, None
        for item in cands.get(name_prefix, ()):
            if item[2] or item[0].date() != dt.date():
                continue
            d = abs((item[0] - dt).total_seconds())
            if best_d is None or d < best_d:
                best, best_d = item, d
        if best is not None:
            best[2] = True
            return best[1]
        return None

    ink_total = "(" + " + ".join("COALESCE(InkUse_%s, 0)" % ch for ch in INK_CHANNELS) + ")"
    clauses = ["start_time IS NOT NULL"]
    params: list = []
    if args.date_from:
        clauses.append("substr(start_time, 1, 10) >= ?"); params.append(args.date_from)
    if args.date_to:
        clauses.append("substr(start_time, 1, 10) <= ?"); params.append(args.date_to)
    ours = db.execute(
        f"SELECT job_id, start_time, job_name, username, InkUse_PK, {ink_total} tot "
        f"FROM jobs WHERE {' AND '.join(clauses)} ORDER BY start_time", params).fetchall()

    set_cols = ", ".join(f"InkUse_{ch} = ?" for ch in INK_CHANNELS)
    fill_ink_sql = f"UPDATE jobs SET {set_cols} WHERE job_id = ?"
    fill_user_sql = ("UPDATE jobs SET username = COALESCE(NULLIF(username,''), ?), "
                     "machine_name = COALESCE(NULLIF(machine_name,''), ?) WHERE job_id = ?")

    def is_missing(row):
        return row["InkUse_PK"] is None or (row["tot"] or 0) == 0

    # Missing-ink jobs get first pick of the .accdb rows; already-inked jobs then
    # consume any remaining match so it can't be re-inserted as a duplicate.
    missing_jobs = [r for r in ours if is_missing(r)]
    inked_jobs = [r for r in ours if not is_missing(r)]

    # --- 1. Fill / match existing jobs ---
    filled_ink = filled_user = matched = unmatched = 0
    with db:
        for row in missing_jobs + inked_jobs:
            dt = _parse(row["start_time"])
            if not dt:
                continue
            r = take_match((row["job_name"] or "")[:20], dt)
            if r is None:
                unmatched += 1
                continue
            matched += 1
            if is_missing(row):
                db.execute(fill_ink_sql,
                           (*[r[f"InkUse_{ch}"] for ch in INK_CHANNELS], row["job_id"]))
                filled_ink += 1
            if not (row["username"] or "").strip() and (r["username"] or "").strip():
                db.execute(fill_user_sql,
                           (r["username"] or None, r["machine_name"] or None, row["job_id"]))
                filled_user += 1
    print(f"In-range jobs: {len(ours)}  matched to .accdb: {matched}  "
          f"(unmatched / lost jobs kept: {unmatched})")
    print(f"  filled ink on {filled_ink}, filled username on {filled_user}")

    # --- 2. (opt-in) Insert .accdb rows that no job consumed ---
    if args.insert:
        cols = (["job_id", "job_name", "username", "machine_name", "start_time"]
                + [f"InkUse_{ch}" for ch in INK_CHANNELS])
        insert_sql = (f"INSERT OR IGNORE INTO jobs ({', '.join(cols)}) "
                      f"VALUES ({','.join('?' * len(cols))})")
        inserted = 0
        with db:
            for lst in cands.values():
                for dt, r, consumed in lst:
                    if consumed:
                        continue
                    st = r["start_time"] or ""
                    job_id = f"{st}|{r['job_name'] or ''}"
                    db.execute(insert_sql, (
                        job_id, r["job_name"], r["username"] or "", r["machine_name"] or "",
                        st, *[r[f"InkUse_{ch}"] for ch in INK_CHANNELS]))
                    inserted += 1
        print(f"  inserted {inserted} .accdb job(s) we didn't have")
    else:
        unconsumed = sum(1 for lst in cands.values() for it in lst if not it[2])
        print(f"  fill-only (default): left {unconsumed} unmatched .accdb row(s) "
              f"un-inserted. Pass --insert to add them.")

    total = db.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
    with_ink = db.execute("SELECT COUNT(*) FROM jobs WHERE InkUse_PK IS NOT NULL").fetchone()[0]
    print(f"\nDB now: {total} total jobs, {with_ink} with ink data")
    db.close()


if __name__ == "__main__":
    main()
