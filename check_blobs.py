#!/usr/bin/env python3
"""
Diagnostic: report ink / blob coverage in the local job database.

Helps distinguish the two ways a job can end up with no ink:
  1. blob stored but not decrypted  -> recoverable (run `lfp_accounting.py recover`)
  2. no blob stored at all          -> ji: metadata was never captured/matched
                                       (a separate problem the serial fix can't help)

Usage:
  python3 check_blobs.py [path-to-jobs.db]   # defaults to ~/.lfp_accounting/jobs.db
"""
import sqlite3
import sys
from pathlib import Path

DEFAULT_DB = Path.home() / ".lfp_accounting" / "jobs.db"


def main():
    db = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_DB
    if not db.exists():
        print("Database not found: %s" % db)
        sys.exit(1)

    conn = sqlite3.connect(str(db))
    conn.row_factory = sqlite3.Row
    q = lambda s: conn.execute(s).fetchone()[0]

    print("DB:", db)
    print("total jobs                    :", q("SELECT COUNT(*) FROM jobs"))
    print("with ink                      :", q("SELECT COUNT(*) FROM jobs WHERE InkUse_PK IS NOT NULL"))
    print("with stored blob              :", q("SELECT COUNT(*) FROM jobs WHERE ji_blob IS NOT NULL"))
    print("blob but NO ink (recoverable) :", q("SELECT COUNT(*) FROM jobs WHERE ji_blob IS NOT NULL AND InkUse_PK IS NULL"))
    print("NO ink and NO blob            :", q("SELECT COUNT(*) FROM jobs WHERE ji_blob IS NULL AND InkUse_PK IS NULL"))

    print()
    print("--- last 20 jobs by start_time ---")
    print("  %-16s  %-4s %-4s  %-12s  %s" % ("start", "ink", "blob", "user", "job name"))
    for r in conn.execute("""
            SELECT substr(start_time, 1, 16) AS t,
                   substr(job_name, 1, 28)   AS n,
                   CASE WHEN InkUse_PK IS NOT NULL THEN 'ink' ELSE ' - ' END AS ink,
                   CASE WHEN ji_blob   IS NOT NULL THEN 'blob' ELSE ' -- ' END AS blob,
                   COALESCE(username, '')    AS u
            FROM jobs
            ORDER BY start_time DESC
            LIMIT 20"""):
        print("  %-16s  %-4s %-4s  %-12s  %s" % (r["t"], r["ink"], r["blob"], r["u"], r["n"]))

    conn.close()


if __name__ == "__main__":
    main()
