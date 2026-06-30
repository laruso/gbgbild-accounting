#!/usr/bin/env python3
"""
Export the LFP Accounting Tool .accdb to a portable SQLite file.

Runs on the WINDOWS PC that has the .accdb and the Microsoft Access ODBC driver
(the same machine the old LFP Accounting Tool runs on). It only READS the
.accdb and writes a standalone `accdb_export.db`; it never touches any live
jobs.db. Copy the output to the Pi and import it with merge_accdb_export.py.

Usage (on the PC):
    pip install pyodbc
    python export_accdb.py [output.db]        # default: accdb_export.db
"""
import sys
import sqlite3
import pyodbc
from pathlib import Path

ACCDB_PATH = r"C:\ProgramData\EPSON\LFP Accounting Tool\UserData\AccountingTool.accdb"
ACCDB_PWD = "4DC1AE17E60EF174B252"
ACCDB_TABLE = "[EPSON SC-P9500 Series]"

INK_CHANNELS = ["PK", "MK", "C", "VM", "Y", "OR", "GR", "LC", "VLM", "LK", "LLK", "V"]


def main():
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("accdb_export.db")

    conn = pyodbc.connect(
        f"DRIVER={{Microsoft Access Driver (*.mdb, *.accdb)}};"
        f"DBQ={ACCDB_PATH};"
        f"PWD={ACCDB_PWD};"
    )
    cur = conn.cursor()
    ink_cols = ", ".join(f"InkUse_{ch}" for ch in INK_CHANNELS)
    cur.execute(
        f"SELECT PrintStartTime, DocName, UserName, HostName, {ink_cols} "
        f"FROM {ACCDB_TABLE}"
    )
    rows = cur.fetchall()
    conn.close()
    print(f"Read {len(rows)} rows from .accdb")

    if out.exists():
        out.unlink()
    db = sqlite3.connect(str(out))
    ink_def = ", ".join(f"InkUse_{ch} INTEGER" for ch in INK_CHANNELS)
    db.execute(
        f"CREATE TABLE accdb_jobs "
        f"(start_time TEXT, job_name TEXT, username TEXT, machine_name TEXT, {ink_def})"
    )
    placeholders = ",".join("?" * (4 + len(INK_CHANNELS)))
    written = skipped = 0
    with db:
        for r in rows:
            start = r[0]
            if not start:
                skipped += 1
                continue
            ink_vals = [int(r[4 + i] or 0) for i in range(len(INK_CHANNELS))]
            db.execute(
                f"INSERT INTO accdb_jobs VALUES ({placeholders})",
                (start.isoformat(), r[1] or "", r[2] or "", r[3] or "", *ink_vals))
            written += 1
    db.close()

    print(f"Wrote {written} rows to {out}  ({skipped} skipped: no start time)")
    print()
    print("Next steps:")
    print(f"  1. Copy to the Pi:   scp {out.name} gbgbild@<pi-ip>:~/gbgbild-accounting/")
    print(f"  2. On the Pi:        python3 merge_accdb_export.py {out.name}")


if __name__ == "__main__":
    main()
