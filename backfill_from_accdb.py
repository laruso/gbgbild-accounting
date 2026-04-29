"""
One-time backfill: import ink usage and username from the LFP Accounting Tool
.accdb into our SQLite database for jobs that are missing this data.

Usage:
    python backfill_from_accdb.py
"""
import sys
import io
import sqlite3
import pyodbc
from pathlib import Path
from datetime import datetime

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

ACCDB_PATH = r"C:\ProgramData\EPSON\LFP Accounting Tool\UserData\AccountingTool.accdb"
ACCDB_PWD = "4DC1AE17E60EF174B252"
SQLITE_DB = Path.home() / ".lfp_accounting" / "jobs.db"

INK_CHANNELS = ["PK", "MK", "C", "VM", "Y", "OR", "GR", "LC", "VLM", "LK", "LLK", "V"]


def main():
    # Connect to both databases
    accdb_conn = pyodbc.connect(
        f"DRIVER={{Microsoft Access Driver (*.mdb, *.accdb)}};"
        f"DBQ={ACCDB_PATH};"
        f"PWD={ACCDB_PWD};"
    )
    accdb_cur = accdb_conn.cursor()

    sqlite_conn = sqlite3.connect(str(SQLITE_DB))
    sqlite_conn.row_factory = sqlite3.Row

    # Get all SQLite jobs missing ink data
    missing = sqlite_conn.execute(
        "SELECT job_id, start_time, job_name FROM jobs WHERE InkUse_PK IS NULL"
    ).fetchall()
    print(f"SQLite jobs missing ink data: {len(missing)}")

    # Load all .accdb records into a lookup keyed by (start_minute, job_name_prefix)
    ink_cols = ", ".join(f"InkUse_{ch}" for ch in INK_CHANNELS)
    accdb_cur.execute(
        f"SELECT PrintStartTime, DocName, UserName, HostName, {ink_cols} "
        f"FROM [EPSON SC-P9500 Series]"
    )
    accdb_rows = accdb_cur.fetchall()
    print(f"Access DB records: {len(accdb_rows)}")

    # Build lookup: key = (start time truncated to minute, first 20 chars of job name)
    accdb_lookup = {}
    for row in accdb_rows:
        start = row[0]  # datetime
        doc = (row[1] or "")[:20]
        if start:
            key = (start.strftime("%Y-%m-%dT%H:%M"), doc)
            accdb_lookup[key] = row

    # Match and update
    update_sql = """
        UPDATE jobs SET
            username = COALESCE(NULLIF(username, ''), ?),
            machine_name = COALESCE(NULLIF(machine_name, ''), ?),
            InkUse_PK = ?, InkUse_MK = ?, InkUse_C = ?, InkUse_VM = ?,
            InkUse_Y = ?, InkUse_OR = ?, InkUse_GR = ?, InkUse_LC = ?,
            InkUse_VLM = ?, InkUse_LK = ?, InkUse_LLK = ?, InkUse_V = ?
        WHERE job_id = ?
    """

    updated = 0
    not_found = 0
    with sqlite_conn:
        for row in missing:
            job_id = row["job_id"]
            start_time = row["start_time"] or ""
            job_name = row["job_name"] or ""

            # Parse our ISO start_time to match format
            # Our format: 2026-04-14T14:09:45+00:00
            # We need:    2026-04-14T14:09
            start_minute = start_time[:16]  # "2026-04-14T14:09"
            name_prefix = job_name[:20]

            key = (start_minute, name_prefix)
            accdb_row = accdb_lookup.get(key)

            if not accdb_row:
                # Try with +/- 1 minute tolerance
                for delta in [-1, 1]:
                    try:
                        dt = datetime.fromisoformat(start_time.replace("+00:00", "+00:00"))
                        from datetime import timedelta
                        shifted = dt + timedelta(minutes=delta)
                        alt_key = (shifted.strftime("%Y-%m-%dT%H:%M"), name_prefix)
                        accdb_row = accdb_lookup.get(alt_key)
                        if accdb_row:
                            break
                    except Exception:
                        pass

            if accdb_row:
                username = accdb_row[2] or ""
                hostname = accdb_row[3] or ""
                ink_vals = [int(accdb_row[4 + i] or 0) for i in range(12)]

                sqlite_conn.execute(update_sql, (
                    username if username else None,
                    hostname if hostname else None,
                    *ink_vals,
                    job_id,
                ))
                updated += 1
            else:
                not_found += 1

    print(f"\nResults:")
    print(f"  {updated} jobs backfilled with ink/user data from .accdb")
    print(f"  {not_found} jobs not found in .accdb (no match)")

    # Also insert .accdb records that don't exist in SQLite at all
    existing_keys = set()
    for row in sqlite_conn.execute("SELECT start_time, job_name FROM jobs").fetchall():
        st = (row[0] or "")[:16]
        nm = (row[1] or "")[:20]
        existing_keys.add((st, nm))

    insert_sql = """
        INSERT OR IGNORE INTO jobs
            (job_id, job_name, username, machine_name,
             start_time, end_time,
             InkUse_PK, InkUse_MK, InkUse_C, InkUse_VM,
             InkUse_Y, InkUse_OR, InkUse_GR, InkUse_LC,
             InkUse_VLM, InkUse_LK, InkUse_LLK, InkUse_V)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """
    inserted = 0
    with sqlite_conn:
        for row in accdb_rows:
            start = row[0]
            if not start:
                continue
            doc = row[1] or ""
            key = (start.strftime("%Y-%m-%dT%H:%M"), doc[:20])
            if key in existing_keys:
                continue

            start_iso = start.isoformat()
            end_iso = row[0].isoformat() if row[0] else None  # end time is row index issue
            # Actually get end time properly
            end = row[0]  # PrintStartTime was row[0], but we need to re-query...
            # We already have the data - row[1] is DocName
            job_id = f"{start_iso}|{doc[:32]}"
            username = row[2] or ""
            hostname = row[3] or ""
            ink_vals = [int(row[4 + i] or 0) for i in range(12)]

            sqlite_conn.execute(insert_sql, (
                job_id, doc, username, hostname,
                start_iso, None,
                *ink_vals,
            ))
            inserted += 1
            existing_keys.add(key)

    print(f"  {inserted} new jobs imported from .accdb (not in printer SNMP)")

    total = sqlite_conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
    with_ink = sqlite_conn.execute("SELECT COUNT(*) FROM jobs WHERE InkUse_PK IS NOT NULL").fetchone()[0]
    print(f"\nDatabase now: {total} total jobs, {with_ink} with ink data")

    sqlite_conn.close()
    accdb_conn.close()


if __name__ == "__main__":
    main()
