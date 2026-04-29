"""
SQLite storage for Epson SC-P9500 job log records.
"""
import sqlite3
from pathlib import Path
from typing import Optional
from joblog import JobRecord

_DEFAULT_DB = Path.home() / ".lfp_accounting" / "jobs.db"


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    _ensure_schema(conn)
    return conn


def _ensure_schema(conn: sqlite3.Connection):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS jobs (
            job_id        TEXT PRIMARY KEY,
            job_name      TEXT,
            username      TEXT,
            machine_name  TEXT,
            start_time    TEXT,
            end_time      TEXT,
            print_secs    INTEGER,
            paper_source  TEXT,
            width_mm      INTEGER,
            length_mm     INTEGER,
            area_cm2      REAL,
            media_type_id INTEGER,
            status_code   INTEGER,
            counter       INTEGER,
            InkUse_PK     REAL,
            InkUse_MK     REAL,
            InkUse_C      REAL,
            InkUse_VM     REAL,
            InkUse_Y      REAL,
            InkUse_OR     REAL,
            InkUse_GR     REAL,
            InkUse_LC     REAL,
            InkUse_VLM    REAL,
            InkUse_LK     REAL,
            InkUse_LLK    REAL,
            InkUse_V      REAL,
            ji_blob       BLOB,
            fetched_at    TEXT DEFAULT (datetime('now'))
        )
    """)
    # Add columns to existing tables that may lack them
    for col, coltype in [
        ("username", "TEXT"), ("machine_name", "TEXT"),
        ("InkUse_PK", "REAL"), ("InkUse_MK", "REAL"), ("InkUse_C", "REAL"),
        ("InkUse_VM", "REAL"), ("InkUse_Y", "REAL"), ("InkUse_OR", "REAL"),
        ("InkUse_GR", "REAL"), ("InkUse_LC", "REAL"), ("InkUse_VLM", "REAL"),
        ("InkUse_LK", "REAL"), ("InkUse_LLK", "REAL"), ("InkUse_V", "REAL"),
        ("ji_blob", "BLOB"),
    ]:
        try:
            conn.execute(f"ALTER TABLE jobs ADD COLUMN {col} {coltype}")
        except sqlite3.OperationalError:
            pass  # column already exists
    conn.execute("""
        CREATE TABLE IF NOT EXISTS monthly_ink_usage (
            username      TEXT    NOT NULL,
            month         TEXT    NOT NULL,
            job_count     INTEGER,
            InkUse_PK     REAL,
            InkUse_MK     REAL,
            InkUse_C      REAL,
            InkUse_VM     REAL,
            InkUse_Y      REAL,
            InkUse_OR     REAL,
            InkUse_GR     REAL,
            InkUse_LC     REAL,
            InkUse_VLM    REAL,
            InkUse_LK     REAL,
            InkUse_LLK    REAL,
            InkUse_V      REAL,
            InkUse_total_ml REAL,
            PRIMARY KEY (username, month)
        )
    """)
    conn.commit()


def _job_id(rec: JobRecord) -> str:
    """Stable ID: start time + job name."""
    ts = rec.start_time.isoformat() if rec.start_time else "unknown"
    return "%s|%s" % (ts, rec.job_name)


def upsert_jobs(records: list[JobRecord],
                db_path: Optional[Path] = None) -> tuple[int, int]:
    """Insert new jobs or update existing ones with new data. Returns (inserted, updated)."""
    db_path = db_path or _DEFAULT_DB
    conn = _connect(db_path)
    insert_sql = """
        INSERT OR IGNORE INTO jobs
            (job_id, job_name, username, machine_name,
             start_time, end_time, print_secs,
             paper_source, width_mm, length_mm, area_cm2,
             media_type_id, status_code, counter,
             InkUse_PK, InkUse_MK, InkUse_C, InkUse_VM,
             InkUse_Y, InkUse_OR, InkUse_GR, InkUse_LC,
             InkUse_VLM, InkUse_LK, InkUse_LLK, InkUse_V,
             ji_blob)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """
    update_sql = """
        UPDATE jobs SET
            username = ?, machine_name = ?,
            InkUse_PK = ?, InkUse_MK = ?, InkUse_C = ?, InkUse_VM = ?,
            InkUse_Y = ?, InkUse_OR = ?, InkUse_GR = ?, InkUse_LC = ?,
            InkUse_VLM = ?, InkUse_LK = ?, InkUse_LLK = ?, InkUse_V = ?,
            ji_blob = ?
        WHERE job_id = ? AND InkUse_PK IS NULL
    """
    ink_ch = ["PK", "MK", "C", "VM", "Y", "OR", "GR", "LC", "VLM", "LK", "LLK", "V"]
    inserted = updated = 0
    with conn:
        for rec in records:
            jid = _job_id(rec)
            ink_vals = [rec.ink_use.get(ch) if rec.ink_use else None for ch in ink_ch]
            cur = conn.execute(insert_sql, (
                jid,
                rec.job_name,
                rec.username,
                rec.machine_name,
                rec.start_time.isoformat() if rec.start_time else None,
                rec.end_time.isoformat()   if rec.end_time   else None,
                rec.print_secs,
                rec.paper_source,
                rec.width_mm,
                rec.length_mm,
                rec.area_cm2,
                rec.media_type_id,
                rec.status_code,
                rec.counter,
                *ink_vals,
                rec.ji_blob,
            ))
            if cur.rowcount > 0:
                inserted += 1
            elif rec.ink_use or rec.username:
                cur = conn.execute(update_sql, (
                    rec.username or None,
                    rec.machine_name or None,
                    *ink_vals,
                    rec.ji_blob,
                    jid,
                ))
                if cur.rowcount > 0:
                    updated += 1
    conn.close()
    return inserted, updated


def rebuild_monthly_summary(db_path: Optional[Path] = None) -> int:
    """Rebuild the monthly_ink_usage table from jobs. Returns row count."""
    db_path = db_path or _DEFAULT_DB
    conn = _connect(db_path)
    ink_ch = ["PK", "MK", "C", "VM", "Y", "OR", "GR", "LC", "VLM", "LK", "LLK", "V"]
    sum_cols = ", ".join("SUM(InkUse_%s)" % ch for ch in ink_ch)
    total_expr = " + ".join("COALESCE(SUM(InkUse_%s), 0)" % ch for ch in ink_ch)
    with conn:
        conn.execute("DELETE FROM monthly_ink_usage")
        conn.execute("""
            INSERT INTO monthly_ink_usage
                (username, month, job_count,
                 InkUse_PK, InkUse_MK, InkUse_C, InkUse_VM,
                 InkUse_Y, InkUse_OR, InkUse_GR, InkUse_LC,
                 InkUse_VLM, InkUse_LK, InkUse_LLK, InkUse_V,
                 InkUse_total_ml)
            SELECT
                username,
                substr(start_time, 1, 7) AS month,
                COUNT(*),
                %s,
                (%s) / 100.0
            FROM jobs
            WHERE username IS NOT NULL AND username != ''
              AND start_time IS NOT NULL
              AND InkUse_PK IS NOT NULL
            GROUP BY username, substr(start_time, 1, 7)
        """ % (sum_cols, total_expr))
    count = conn.execute("SELECT COUNT(*) FROM monthly_ink_usage").fetchone()[0]
    conn.close()
    return count


def get_monthly_summary(db_path: Optional[Path] = None) -> list[dict]:
    """Return monthly ink summary rows, ordered by month then username."""
    db_path = db_path or _DEFAULT_DB
    if not db_path.exists():
        return []
    conn = _connect(db_path)
    rows = conn.execute(
        "SELECT * FROM monthly_ink_usage ORDER BY month, username"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def all_jobs(db_path: Optional[Path] = None) -> list[dict]:
    """Return all stored jobs as dicts, newest first."""
    db_path = db_path or _DEFAULT_DB
    if not db_path.exists():
        return []
    conn = _connect(db_path)
    rows = conn.execute(
        "SELECT * FROM jobs ORDER BY start_time DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
