"""
Read per-job ink usage from the LFP Accounting Tool's Access database (.accdb).

DFAgency decrypts the per-job ji: SNMP blobs and stores the result in an
Access database on the Windows machine. This script reads that database and
exports the ink ml per job to both SQLite and CSV.

Run on the Windows machine ONLY (requires Microsoft Access ODBC driver):
    python3 read_accdb.py [path_to_accdb]

If no path given, it searches common DFAgency data directories automatically.

The script first tries pyodbc, then falls back to mdbtools-based parsing if
available (for Linux/macOS).

INK CHANNELS (12 per job):
    PK  MK  C   VM  Y   OR  GR  LC  VLM  LK  LLK  V
"""
import sys
import os
import csv
import sqlite3
import glob
import struct
from datetime import datetime
from pathlib import Path

INK_CHANNELS = ["PK", "MK", "C", "VM", "Y", "OR", "GR", "LC", "VLM", "LK", "LLK", "V"]
INK_FIELDS   = [f"InkUse_{ch}"    for ch in INK_CHANNELS]
CUM_FIELDS   = [f"InkCumUse_{ch}" for ch in INK_CHANNELS]
MNT_FIELDS   = [f"InkMntUse_{ch}" for ch in INK_CHANNELS]

# Candidate search paths on Windows
SEARCH_PATHS = [
    r"C:\ProgramData\EPSON\*.accdb",
    r"C:\ProgramData\EPSON\**\*.accdb",
    r"C:\ProgramData\Epson\*.accdb",
    r"C:\ProgramData\Epson\**\*.accdb",
    r"C:\Users\*\AppData\Roaming\EPSON\*.accdb",
    r"C:\Users\*\AppData\Roaming\Epson\*.accdb",
    r"C:\Users\*\AppData\Local\EPSON\*.accdb",
    r"C:\Users\*\AppData\Local\Epson\*.accdb",
    r"C:\Program Files*\EPSON Software\**\*.accdb",
    r"C:\Program Files*\Epson\**\*.accdb",
]


def find_accdb():
    """Search common locations for the LFP .accdb file."""
    candidates = []
    for pattern in SEARCH_PATHS:
        try:
            found = glob.glob(pattern, recursive=True)
            candidates.extend(found)
        except Exception:
            pass

    if not candidates:
        return None

    # Prefer recently-modified files and those with 'account' or 'job' in name
    def score(p):
        name = Path(p).name.lower()
        mtime = 0
        try:
            mtime = os.path.getmtime(p)
        except Exception:
            pass
        prio = 1 if any(k in name for k in ('account', 'job', 'lfp', 'dfagency')) else 0
        return (prio, mtime)

    candidates.sort(key=score, reverse=True)
    return candidates[0] if candidates else None


def read_via_pyodbc(accdb_path):
    """Read ink data from .accdb using pyodbc (requires ACE ODBC driver)."""
    try:
        import pyodbc
    except ImportError:
        raise RuntimeError("pyodbc not installed: pip install pyodbc")

    conn_str = (
        r"Driver={Microsoft Access Driver (*.mdb, *.accdb)};"
        f"Dbq={accdb_path};"
    )
    conn = pyodbc.connect(conn_str, autocommit=True)
    cursor = conn.cursor()

    # List all tables
    tables = [row.table_name for row in cursor.tables(tableType="TABLE")]
    print(f"Tables found: {tables}")

    # Find the job log table — look for one with InkUse_ columns
    job_table = None
    for tbl in tables:
        cols = [row.column_name for row in cursor.columns(table=tbl)]
        if any(c.startswith("InkUse_") for c in cols):
            job_table = tbl
            all_cols = cols
            break

    if not job_table:
        # Try to find a table with ink-like columns
        for tbl in tables:
            cols = [row.column_name for row in cursor.columns(table=tbl)]
            print(f"  {tbl}: {cols[:10]}")
        raise RuntimeError("No table with InkUse_ columns found. See table list above.")

    print(f"\nJob log table: {job_table}")
    print(f"Columns: {all_cols}")

    # Query all rows
    cursor.execute(f"SELECT * FROM [{job_table}] ORDER BY StartTime DESC")
    rows = cursor.fetchall()
    col_names = [desc[0] for desc in cursor.description]
    conn.close()
    return col_names, rows


def read_via_mdbtools(accdb_path):
    """Fallback: use mdbtools CLI (Linux/macOS)."""
    import subprocess
    import io

    # List tables
    result = subprocess.run(
        ["mdb-tables", "-1", accdb_path],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        raise RuntimeError(f"mdb-tables failed: {result.stderr}")
    tables = [t.strip() for t in result.stdout.strip().split('\n') if t.strip()]
    print(f"Tables: {tables}")

    job_table = None
    for tbl in tables:
        result = subprocess.run(
            ["mdb-export", accdb_path, tbl],
            capture_output=True, text=True
        )
        if "InkUse_" in result.stdout:
            job_table = tbl
            data = result.stdout
            break

    if not job_table:
        for tbl in tables:
            result = subprocess.run(
                ["mdb-export", accdb_path, tbl],
                capture_output=True, text=True
            )
            first_line = result.stdout.split('\n')[0] if result.stdout else ''
            print(f"  {tbl}: {first_line[:80]}")
        raise RuntimeError("No table with InkUse_ columns found.")

    print(f"\nJob log table: {job_table}")
    reader = csv.reader(io.StringIO(data))
    rows_raw = list(reader)
    if not rows_raw:
        return [], []
    col_names = rows_raw[0]
    rows = rows_raw[1:]
    return col_names, rows


def export_to_csv(col_names, rows, out_path="ink_usage.csv"):
    """Write all columns to CSV."""
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(col_names)
        writer.writerows(rows)
    print(f"Exported {len(rows)} rows to {out_path}")


def export_to_sqlite(col_names, rows, out_path="ink_usage.db"):
    """Write to SQLite for cross-platform access."""
    conn = sqlite3.connect(out_path)

    # Build a safe CREATE TABLE
    safe_cols = []
    for c in col_names:
        # Quote any column name
        safe_cols.append(f'"{c}" TEXT')
    conn.execute(f"DROP TABLE IF EXISTS job_ink")
    conn.execute(f"CREATE TABLE job_ink ({', '.join(safe_cols)})")

    placeholders = ", ".join(["?"] * len(col_names))
    conn.executemany(f"INSERT INTO job_ink VALUES ({placeholders})", rows)
    conn.commit()
    conn.close()
    print(f"Exported {len(rows)} rows to {out_path}")


def print_ink_summary(col_names, rows, max_rows=20):
    """Print a readable summary of per-job ink usage."""
    col_lower = [c.lower() for c in col_names]

    # Find relevant column indices
    def find_col(*candidates):
        for c in candidates:
            try:
                return col_lower.index(c.lower())
            except ValueError:
                pass
        return None

    name_idx    = find_col("jobname", "job_name", "name", "filename")
    start_idx   = find_col("starttime", "start_time", "startdatetime", "datetime", "date")
    status_idx  = find_col("status", "result", "jobstatus")
    media_idx   = find_col("mediatype", "media_type", "media", "paper")
    width_idx   = find_col("mediawidth", "width", "width_mm")
    length_idx  = find_col("medialength", "length", "length_mm", "height")
    area_idx    = find_col("area", "printarea", "area_cm2")

    ink_idxs = {}
    for ch in INK_CHANNELS:
        idx = find_col(f"InkUse_{ch}", f"inkuse_{ch}")
        if idx is not None:
            ink_idxs[ch] = idx

    if not ink_idxs:
        print("WARNING: No InkUse_* columns found.")
        print(f"Available columns: {col_names}")
        return

    print(f"\nFound ink columns: {list(ink_idxs.keys())}")
    print(f"\n{'='*100}")
    header_parts = []
    if name_idx is not None:    header_parts.append(f"{'Job Name':<40}")
    if start_idx is not None:   header_parts.append(f"{'Start Time':<20}")
    if media_idx is not None:   header_parts.append(f"{'Media':<25}")
    header_parts.append(f"{'Ink ml: ' + ' '.join(f'{ch:>6}' for ch in INK_CHANNELS)}")
    print('  '.join(header_parts))
    print('-'*100)

    for row in rows[:max_rows]:
        if isinstance(row, (list, tuple)):
            r = row
        else:
            r = [getattr(row, c, None) for c in col_names]

        parts = []
        if name_idx is not None:
            parts.append(f"{str(r[name_idx]):<40}")
        if start_idx is not None:
            parts.append(f"{str(r[start_idx]):<20}")
        if media_idx is not None:
            parts.append(f"{str(r[media_idx]):<25}")

        ink_vals = []
        for ch in INK_CHANNELS:
            if ch in ink_idxs:
                v = r[ink_idxs[ch]]
                ink_vals.append(f"{float(v or 0):>6.3f}" if v else f"{'':>6}")
            else:
                ink_vals.append(f"{'N/A':>6}")
        parts.append(' '.join(ink_vals))
        print('  '.join(parts))

    if len(rows) > max_rows:
        print(f"  ... ({len(rows) - max_rows} more rows, see ink_usage.csv)")


def main():
    accdb_path = None

    if len(sys.argv) > 1:
        accdb_path = sys.argv[1]
        if not os.path.exists(accdb_path):
            print(f"ERROR: File not found: {accdb_path}")
            sys.exit(1)
    else:
        print("Searching for LFP .accdb database...")
        accdb_path = find_accdb()
        if not accdb_path:
            print("ERROR: No .accdb file found. Run the PowerShell command first:")
            print(r'  Get-ChildItem -Recurse -Filter "*.accdb" -Path "C:\ProgramData","C:\Users" '
                  r'-ErrorAction SilentlyContinue | Select FullName, LastWriteTime, Length | Sort LastWriteTime -Desc')
            print("\nThen pass the path as an argument:")
            print(r"  python3 read_accdb.py 'C:\path\to\database.accdb'")
            sys.exit(1)

    print(f"\nReading: {accdb_path}")
    print(f"File size: {os.path.getsize(accdb_path):,} bytes")
    print(f"Last modified: {datetime.fromtimestamp(os.path.getmtime(accdb_path))}")

    # Try pyodbc first (Windows native), then mdbtools (Linux/macOS)
    col_names = rows = None
    for reader_fn, name in [(read_via_pyodbc, "pyodbc"), (read_via_mdbtools, "mdbtools")]:
        try:
            print(f"\nTrying {name}...")
            col_names, rows = reader_fn(accdb_path)
            print(f"  OK — {len(rows)} rows, {len(col_names)} columns")
            break
        except Exception as e:
            print(f"  FAILED: {e}")

    if col_names is None:
        print("\nERROR: Could not read the database.")
        print("On Windows: pip install pyodbc  (requires 64-bit Microsoft Access Runtime)")
        print("On Linux/macOS: brew install mdbtools  or  apt install mdbtools")
        sys.exit(1)

    print_ink_summary(col_names, rows)
    export_to_csv(col_names, rows, "ink_usage.csv")
    export_to_sqlite(col_names, rows, "ink_usage.db")
    print("\nDone. Copy ink_usage.db or ink_usage.csv off the Windows machine.")


if __name__ == "__main__":
    main()
