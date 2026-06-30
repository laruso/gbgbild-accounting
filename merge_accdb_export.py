#!/usr/bin/env python3
"""
Merge an accdb_export.db (from export_accdb.py on the Windows PC) into the live
jobs.db on the Pi.

  - Fills username / machine / ink on jobs that currently lack ink, matched by
    start-minute + job-name prefix (with +/- 1 minute tolerance).
  - Inserts .accdb jobs that aren't in the DB at all.
  - Never overwrites data we already have, and is safe to run more than once.

Usage (on the Pi):
    python3 merge_accdb_export.py [accdb_export.db]    # default: accdb_export.db
"""
import sys
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta

SQLITE_DB = Path.home() / ".lfp_accounting" / "jobs.db"
INK_CHANNELS = ["PK", "MK", "C", "VM", "Y", "OR", "GR", "LC", "VLM", "LK", "LLK", "V"]


def _key(start_time: str, job_name: str):
    return (start_time or "")[:16], (job_name or "")[:20]


def main():
    export_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("accdb_export.db")
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
    print(f"Export rows: {len(accdb_rows)}")

    db = sqlite3.connect(str(SQLITE_DB))
    db.row_factory = sqlite3.Row

    # Build lookup: (start_minute, name_prefix) -> export row.
    lookup = {}
    for r in accdb_rows:
        k = _key(r["start_time"], r["job_name"])
        if k[0]:
            lookup[k] = r

    # --- 1. Fill missing ink/user on existing jobs ---
    missing = db.execute(
        "SELECT job_id, start_time, job_name FROM jobs WHERE InkUse_PK IS NULL"
    ).fetchall()
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
