"""
SQLite storage for Epson SC-P9500 job log records.
"""
import sqlite3
from pathlib import Path
from typing import Optional
from joblog import JobRecord, decode_ji_ink, INK_CHANNELS

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
        ("ji_blob", "BLOB"), ("sent_at", "TEXT"),
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
    # Small key/value store for persistent settings. Used to cache the printer
    # serial number (a fixed hardware constant) so ink decryption no longer
    # depends on the flaky live BDC fetch succeeding on every single pull.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    conn.commit()


def get_meta(key: str, db_path: Optional[Path] = None) -> Optional[str]:
    """Return a persisted meta value, or None if unset."""
    db_path = db_path or _DEFAULT_DB
    if not db_path.exists():
        return None
    conn = _connect(db_path)
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    conn.close()
    return row["value"] if row else None


def set_meta(key: str, value: str, db_path: Optional[Path] = None) -> None:
    """Persist a meta value, overwriting any previous one."""
    db_path = db_path or _DEFAULT_DB
    conn = _connect(db_path)
    with conn:
        conn.execute(
            "INSERT INTO meta (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value))
    conn.close()


def redecrypt_stored_blobs(serial: str, db_path: Optional[Path] = None) -> int:
    """Decrypt ink for jobs that have a stored ji_blob but no ink yet.

    Recovers ink that was lost when the serial number was unavailable at pull
    time: the raw 208-byte blob is always stored, so once a valid serial is
    known we can decrypt it after the fact. Returns the number of jobs updated.
    """
    if not serial:
        return 0
    db_path = db_path or _DEFAULT_DB
    if not db_path.exists():
        return 0
    set_cols = ", ".join("InkUse_%s = ?" % ch for ch in INK_CHANNELS)
    conn = _connect(db_path)
    rows = conn.execute(
        "SELECT job_id, ji_blob FROM jobs "
        "WHERE ji_blob IS NOT NULL AND InkUse_PK IS NULL"
    ).fetchall()
    updated = 0
    with conn:
        for row in rows:
            ink = decode_ji_ink(row["ji_blob"], serial)
            if not ink:
                continue
            vals = [ink.get(ch) for ch in INK_CHANNELS]
            conn.execute(
                "UPDATE jobs SET %s WHERE job_id = ?" % set_cols,
                (*vals, row["job_id"]))
            updated += 1
    conn.close()
    return updated


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
    ink_ch = ["PK", "MK", "C", "VM", "Y", "OR", "GR", "LC", "VLM", "LK", "LLK", "V"]
    # Fill (or repair) a job's data without ever clobbering a real value:
    #  - username/machine: fill only when currently blank.
    #  - ink: replace when the existing total is 0 (NULL, or an all-zero row we
    #    stored before the printer had populated the blob — a real print always
    #    uses ink, so a stored 0 is "not captured yet"); keep it once it's real.
    #    The printer keeps the real ink in its buffer for a while, so a later
    #    pull repairs these stuck zeros directly — no .accdb needed.
    # The WHERE fires only when there is genuinely something to add: new ink for
    # an ink-less/zero job, or a username for one still missing it.
    ink_total = "(" + " + ".join("COALESCE(InkUse_%s, 0)" % ch for ch in ink_ch) + ")"
    ink_set = ", ".join(
        "InkUse_{c} = CASE WHEN {t} = 0 THEN COALESCE(?, InkUse_{c}) "
        "ELSE InkUse_{c} END".format(c=ch, t=ink_total) for ch in ink_ch)
    update_sql = f"""
        UPDATE jobs SET
            username     = COALESCE(NULLIF(username, ''), ?),
            machine_name = COALESCE(NULLIF(machine_name, ''), ?),
            {ink_set},
            ji_blob      = COALESCE(ji_blob, ?)
        WHERE job_id = ?
          AND ( ({ink_total} = 0 AND ? IS NOT NULL)
                OR ((username IS NULL OR username = '') AND ? IS NOT NULL) )
    """
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
                    ink_vals[0],            # new InkUse_PK — guards the ink fill
                    rec.username or None,   # new username — guards the user fill
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


def query_jobs(date_from: Optional[str] = None,
               date_to: Optional[str] = None,
               limit: Optional[int] = None,
               unsent_only: bool = False,
               db_path: Optional[Path] = None) -> list[dict]:
    """Return jobs as dicts, newest first, filtered by date range / sent state.

    date_from / date_to are inclusive 'YYYY-MM-DD' strings compared against the
    date portion of start_time (ISO-8601 text sorts lexically). limit caps the
    number of rows; unsent_only excludes jobs already marked sent.
    """
    db_path = db_path or _DEFAULT_DB
    if not db_path.exists():
        return []
    clauses = []
    params: list = []
    if date_from:
        clauses.append("substr(start_time, 1, 10) >= ?")
        params.append(date_from)
    if date_to:
        clauses.append("substr(start_time, 1, 10) <= ?")
        params.append(date_to)
    if unsent_only:
        clauses.append("sent_at IS NULL")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = "SELECT * FROM jobs %s ORDER BY start_time DESC" % where
    if limit is not None:
        sql += " LIMIT ?"
        params.append(limit)
    conn = _connect(db_path)
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def monthly_summary(date_from: Optional[str] = None,
                    date_to: Optional[str] = None,
                    db_path: Optional[Path] = None) -> list[dict]:
    """Compute monthly ink usage per user over an optional date range.

    Same aggregation as rebuild_monthly_summary() but filtered by job date range
    and returned directly without touching the persisted monthly_ink_usage table.
    """
    db_path = db_path or _DEFAULT_DB
    if not db_path.exists():
        return []
    ink_ch = ["PK", "MK", "C", "VM", "Y", "OR", "GR", "LC", "VLM", "LK", "LLK", "V"]
    sum_cols = ", ".join("SUM(InkUse_%s) AS InkUse_%s" % (ch, ch) for ch in ink_ch)
    total_expr = " + ".join("COALESCE(SUM(InkUse_%s), 0)" % ch for ch in ink_ch)
    clauses = [
        "username IS NOT NULL", "username != ''",
        "start_time IS NOT NULL", "InkUse_PK IS NOT NULL",
    ]
    params: list = []
    if date_from:
        clauses.append("substr(start_time, 1, 10) >= ?")
        params.append(date_from)
    if date_to:
        clauses.append("substr(start_time, 1, 10) <= ?")
        params.append(date_to)
    sql = """
        SELECT
            username,
            substr(start_time, 1, 7) AS month,
            COUNT(*) AS job_count,
            %s,
            (%s) / 100.0 AS InkUse_total_ml
        FROM jobs
        WHERE %s
        GROUP BY username, substr(start_time, 1, 7)
        ORDER BY month, username
    """ % (sum_cols, total_expr, " AND ".join(clauses))
    conn = _connect(db_path)
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def mark_sent(job_ids: list[str], db_path: Optional[Path] = None) -> int:
    """Stamp sent_at = now for the given job_ids. Returns rows updated."""
    db_path = db_path or _DEFAULT_DB
    if not job_ids:
        return 0
    conn = _connect(db_path)
    updated = 0
    with conn:
        for jid in job_ids:
            cur = conn.execute(
                "UPDATE jobs SET sent_at = datetime('now') WHERE job_id = ?", (jid,))
            updated += cur.rowcount
    conn.close()
    return updated
