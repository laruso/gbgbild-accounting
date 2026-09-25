"""
SQLite storage for Epson SC-P9500 job log records.
"""
import hashlib
import sqlite3
from pathlib import Path
from typing import Optional
from joblog import JobRecord, decode_ji_info, INK_CHANNELS

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
    # Append-only archive of exactly what the printer returned: every distinct
    # job-log row snapshot ("row") and ji: entry ("ji"). Never updated except
    # for last_seen/seen_count, never deleted — so any matching or repair logic
    # can be re-run against the original data later. Deduped by content hash,
    # so the 15-minute polls only add rows when something actually changed.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS raw_capture (
            sha1        TEXT PRIMARY KEY,
            kind        TEXT NOT NULL,
            slot        INTEGER,
            counter     INTEGER,
            payload     BLOB NOT NULL,
            first_seen  TEXT DEFAULT (datetime('now')),
            last_seen   TEXT DEFAULT (datetime('now')),
            seen_count  INTEGER DEFAULT 1
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS raw_capture_counter "
                 "ON raw_capture (kind, counter)")
    conn.execute("CREATE INDEX IF NOT EXISTS jobs_counter ON jobs (counter)")
    conn.commit()


def archive_raw(items: list[dict], db_path: Optional[Path] = None) -> int:
    """Store raw printer captures (from fetch_job_log's raw_sink).

    Returns the number of new distinct captures added.
    """
    db_path = db_path or _DEFAULT_DB
    conn = _connect(db_path)
    added = 0
    with conn:
        for it in items:
            payload = it["payload"]
            digest = hashlib.sha1(it["kind"].encode() + b"\0" + payload).hexdigest()
            cur = conn.execute(
                "INSERT OR IGNORE INTO raw_capture (sha1, kind, slot, counter, payload) "
                "VALUES (?, ?, ?, ?, ?)",
                (digest, it["kind"], it.get("slot"), it.get("counter"), payload))
            if cur.rowcount:
                added += 1
            else:
                conn.execute(
                    "UPDATE raw_capture SET last_seen = datetime('now'), "
                    "seen_count = seen_count + 1 WHERE sha1 = ?", (digest,))
    conn.close()
    return added


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
    known we can decrypt it after the fact. Only applies a blob whose embedded
    counter matches the job's own counter — older pulls attached blobs by
    position and some sit on the neighbouring job. Returns jobs updated.
    """
    if not serial:
        return 0
    db_path = db_path or _DEFAULT_DB
    if not db_path.exists():
        return 0
    set_cols = ", ".join("InkUse_%s = ?" % ch for ch in INK_CHANNELS)
    conn = _connect(db_path)
    rows = conn.execute(
        "SELECT job_id, counter, ji_blob FROM jobs "
        "WHERE ji_blob IS NOT NULL AND InkUse_PK IS NULL"
    ).fetchall()
    updated = 0
    with conn:
        for row in rows:
            info = decode_ji_info(row["ji_blob"], serial)
            if not info or not info["ink"] or info["counter"] != row["counter"]:
                continue
            vals = [info["ink"].get(ch) for ch in INK_CHANNELS]
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
    """Insert new jobs or update existing ones with new data. Returns (inserted, updated).

    A job is identified by its printer counter (unique per job); job_id is
    only the fallback for records without one. Matching on start time + name
    alone let a single bad pull (e.g. a missing start time) store the same
    print a second time.

    Ink and username on a record come from a ji: blob whose embedded counter
    matched this job (see joblog._match_ji_by_counter), so they are
    authoritative: they replace whatever is stored, which also repairs values
    earlier versions attached to the wrong job. A record without them never
    blanks existing data.
    """
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
    ink_set = ", ".join("InkUse_%s = ?" % ch for ch in ink_ch)
    inserted = updated = 0
    with conn:
        for rec in records:
            ink_vals = [rec.ink_use.get(ch) if rec.ink_use else None for ch in ink_ch]
            start = rec.start_time.isoformat() if rec.start_time else None
            end   = rec.end_time.isoformat()   if rec.end_time   else None

            existing = None
            if rec.counter is not None:
                existing = conn.execute(
                    "SELECT * FROM jobs WHERE counter = ? ORDER BY start_time IS NULL, "
                    "end_time LIMIT 1", (rec.counter,)).fetchone()
            if existing is None:
                existing = conn.execute("SELECT * FROM jobs WHERE job_id = ?",
                                        (_job_id(rec),)).fetchone()

            if existing is None:
                conn.execute(insert_sql, (
                    _job_id(rec), rec.job_name, rec.username, rec.machine_name,
                    start, end, rec.print_secs,
                    rec.paper_source, rec.width_mm, rec.length_mm, rec.area_cm2,
                    rec.media_type_id, rec.status_code, rec.counter,
                    *ink_vals, rec.ji_blob,
                ))
                inserted += 1
                continue

            jid = existing["job_id"]
            changed = False
            # Fill identity fields a bad earlier pull left empty.
            if (existing["start_time"] is None and start) or \
               (existing["end_time"] is None and end):
                conn.execute(
                    "UPDATE jobs SET start_time = COALESCE(start_time, ?), "
                    "end_time = COALESCE(end_time, ?), "
                    "print_secs = COALESCE(print_secs, ?) WHERE job_id = ?",
                    (start, end, rec.print_secs, jid))
                changed = True
            if rec.ink_use:
                old = [existing["InkUse_" + ch] for ch in ink_ch]
                if old != ink_vals or existing["ji_blob"] != rec.ji_blob:
                    conn.execute("UPDATE jobs SET %s, ji_blob = ? WHERE job_id = ?"
                                 % ink_set, (*ink_vals, rec.ji_blob, jid))
                    changed = True
            if rec.username and (existing["username"] != rec.username or
                                 (rec.machine_name and
                                  existing["machine_name"] != rec.machine_name)):
                conn.execute(
                    "UPDATE jobs SET username = ?, "
                    "machine_name = COALESCE(NULLIF(?, ''), machine_name) "
                    "WHERE job_id = ?", (rec.username, rec.machine_name, jid))
                changed = True
            if changed:
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
