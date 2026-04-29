"""
decode_ji_blob.py — Decode the 208-byte ji: binary blob from SNMP.

WHAT WE KNOW FROM DLL REVERSE ENGINEERING:
- SCP7595.dll AnalysisJobLog uses swscanf("%02x") to parse each BYTE
  of the blob into an integer value (0-255)
- Then uses "%d" to store combined values as integers
- Two %02x reads per InkUse field → 2 bytes = uint16 per ink channel
- Field names in DLL processing order:
  InkUse: LK, VM, OR, PK, VLM, LLK, LC, Y, GR, MK, V, C
  InkCumUse: same order (12 channels)
  InkMntUse: same order (12 channels)
  Plus: PaperWidth, PaperHeight, PageNumber, JOBID fields etc.

HYPOTHESIS:
The 208-byte blob = hex-encoded binary data. Each raw byte from SNMP
is ONE hex value (0x00-0xFF). Pairs of bytes form uint16 fields.
208 bytes → 104 uint16 values, or 52 uint32 values.

For 12 InkUse + 12 InkCumUse + 12 InkMntUse = 36 fields × 2 bytes = 72 bytes
Remaining: 208 - 72 = 136 bytes for other fields (width, height, times, etc.)

Or: if InkUse are 4-byte uint32 (two pairs of %02x reads):
36 fields × 4 bytes = 144 bytes. Remaining: 64 bytes. Also plausible.

THIS SCRIPT:
1. Extracts the 10 unique blobs from full-dump.pcap
2. Tries both uint16 BE and uint32 BE interpretations
3. Generates a Windows script (correlate_ink.py) that reads the .accdb
   ink values for the SAME jobs and finds the mapping

Run this on macOS. Then copy correlate_ink.py to Windows and run it there.
"""

import struct, os, sys

# ─── Extract blobs from pcap ─────────────────────────────────────────────────

PCAP = "lfp_accounting/full-dump.pcap"

def parse_pcap_ji():
    blobs = {}
    suffixes = {}
    with open(PCAP, 'rb') as f:
        magic = f.read(4)
        endian = '<' if magic == b'\xd4\xc3\xb2\xa1' else '>'
        f.read(20)
        while True:
            hdr = f.read(16)
            if len(hdr) < 16: break
            ts_s, ts_us, cap_len, _ = struct.unpack(endian + 'IIII', hdr)
            frame = f.read(cap_len)
            try:
                if frame[12:14] != b'\x08\x00': continue
                ihl = (frame[14] & 0xf) * 4
                if frame[14+9] != 17: continue
                src_port = struct.unpack_from('>H', frame, 14+ihl)[0]
                if src_port != 161: continue
                udp_payload = frame[14+ihl+8:]
                pos = udp_payload.find(b'ji:')
                if pos < 0: continue
                ji_data = udp_payload[pos:]
                if len(ji_data) < 8: continue
                if ji_data[3] != 0x00: continue
                job_idx = struct.unpack_from('>H', ji_data, 4)[0]
                if ji_data[6:8] != b'\xd0\x00': continue
                blob = ji_data[8:8+208]
                suffix = ji_data[8+208:]
                if len(blob) == 208 and job_idx not in blobs:
                    blobs[job_idx] = blob
                    suffixes[job_idx] = suffix
            except: continue
    return blobs, suffixes

blobs, suffixes = parse_pcap_ji()
print(f"Extracted {len(blobs)} unique blobs from pcap")

# ─── Parse suffix to get usernames and job names ──────────────────────────────

def parse_suffix(suffix):
    """Parse the TLV suffix to get username, job_name, machine."""
    result = {'username': '', 'job_name': '', 'machine': ''}
    i = 0
    if not suffix:
        return result
    # Skip header byte (F/G) + 0x00
    if i < len(suffix) and suffix[i] in (0x46, 0x47):
        i += 1
    if i < len(suffix) and suffix[i] == 0x00:
        i += 1

    while i < len(suffix) - 1:
        tag = suffix[i]; i += 1
        if tag == 0x00 and i < len(suffix):
            # tag 0x00 has subtype byte before length
            i += 1  # skip subtype
        if i >= len(suffix):
            break
        ln = suffix[i]; i += 1
        if i + ln > len(suffix):
            break
        val = suffix[i:i+ln]; i += ln
        try:
            text = val.decode('utf-8', errors='replace').strip('\x00').strip()
        except:
            text = val.hex()

        if tag == 0x09:
            result['machine'] = text
        elif tag == 0x08:
            result['job_name'] = text.strip()
        elif tag == 0x00:
            result['username'] = text
    return result

print("\nJob summary:")
print(f"{'idx':>3}  {'username':<20}  {'job_name'}")
print("-" * 60)
for idx in sorted(blobs.keys()):
    info = parse_suffix(suffixes[idx])
    print(f"{idx:3d}  {info['username']:<20}  {info['job_name'][:40]}")

# ─── Try decoding the blob as uint16 BE pairs ────────────────────────────────
print("\n" + "="*70)
print("Blob interpretation: 104 × uint16 BE (2 bytes each)")
print("="*70)

for idx in sorted(blobs.keys())[:3]:
    info = parse_suffix(suffixes[idx])
    blob = blobs[idx]
    vals = [struct.unpack_from('>H', blob, i*2)[0] for i in range(104)]
    print(f"\nJob {idx} ({info['username']}, {info['job_name'][:30]}):")
    for row_start in range(0, 104, 13):
        row = vals[row_start:row_start+13]
        print(f"  [{row_start:3d}-{row_start+12:3d}]: {' '.join(f'{v:6d}' for v in row)}")

# ─── Try uint32 BE ───────────────────────────────────────────────────────────
print("\n" + "="*70)
print("Blob interpretation: 52 × uint32 BE (4 bytes each)")
print("="*70)

for idx in sorted(blobs.keys())[:3]:
    info = parse_suffix(suffixes[idx])
    blob = blobs[idx]
    vals = [struct.unpack_from('>I', blob, i*4)[0] for i in range(52)]
    print(f"\nJob {idx} ({info['username']}, {info['job_name'][:30]}):")
    for row_start in range(0, 52, 13):
        row = vals[row_start:row_start+min(13, 52-row_start)]
        print(f"  [{row_start:3d}-{row_start+len(row)-1:3d}]: {' '.join(f'{v:10d}' for v in row)}")

# ─── Generate the Windows correlation script ─────────────────────────────────
print("\n" + "="*70)
print("Generating correlate_ink.py for Windows...")
print("="*70)

# Embed the blob data directly in the script so it's self-contained
blob_hex_data = {}
job_info = {}
for idx in sorted(blobs.keys()):
    blob_hex_data[idx] = blobs[idx].hex()
    job_info[idx] = parse_suffix(suffixes[idx])

correlate_script = '''#!/usr/bin/env python3
"""
correlate_ink.py — Run on Windows to correlate ji: blob bytes with .accdb ink values.

This script:
1. Reads the LFP Accounting Tool .accdb database
2. Finds the 10 jobs matching our pcap data (by job name)
3. Extracts InkUse_*, InkCumUse_*, InkMntUse_* values
4. Compares with the raw blob bytes to find the encoding

Run: python correlate_ink.py
Output: correlate_results.txt (copy back to Mac)
"""

import struct, os, sys, csv

# ─── Embedded blob data from pcap (10 jobs) ──────────────────────────────────
BLOBS = {
'''
for idx in sorted(blob_hex_data.keys()):
    info = job_info[idx]
    correlate_script += f'    {idx}: bytes.fromhex("{blob_hex_data[idx]}"),  # {info["username"]}: {info["job_name"][:30]}\n'

correlate_script += '''
}

JOB_INFO = {
'''
for idx in sorted(job_info.keys()):
    info = job_info[idx]
    correlate_script += f'    {idx}: {{"username": {info["username"]!r}, "job_name": {info["job_name"]!r}}},\n'

correlate_script += '''}

INK_CHANNELS = ["PK", "MK", "C", "VM", "Y", "OR", "GR", "LC", "VLM", "LK", "LLK", "V"]

# DLL processing order for InkUse fields:
DLL_INK_ORDER = ["LK", "VM", "OR", "PK", "VLM", "LLK", "LC", "Y", "GR", "MK", "V", "C"]

INK_FIELDS   = [f"InkUse_{ch}" for ch in INK_CHANNELS]
CUM_FIELDS   = [f"InkCumUse_{ch}" for ch in INK_CHANNELS]
MNT_FIELDS   = [f"InkMntUse_{ch}" for ch in INK_CHANNELS]

# ─── Read .accdb ─────────────────────────────────────────────────────────────

def find_accdb():
    """Search common paths for LFP Accounting Tool .accdb."""
    candidates = [
        r"C:\\ProgramData\\EPSON\\LFP Accounting Tool\\Database\\LFPAT.accdb",
        r"C:\\ProgramData\\Epson\\LFP Accounting Tool\\Database\\LFPAT.accdb",
        os.path.expanduser(r"~\\AppData\\Local\\EPSON\\LFP Accounting Tool\\Database\\LFPAT.accdb"),
    ]
    # Also search common locations
    for root in [r"C:\\ProgramData", r"C:\\Program Files", r"C:\\Program Files (x86)"]:
        for dirpath, dirnames, filenames in os.walk(root):
            for f in filenames:
                if f.lower().endswith('.accdb') and 'lfp' in dirpath.lower():
                    candidates.append(os.path.join(dirpath, f))
            # Don't recurse too deep
            if dirpath.count(os.sep) > 5:
                dirnames.clear()

    for p in candidates:
        if os.path.exists(p):
            return p
    return None

def read_accdb_pyodbc(path):
    """Read job data using pyodbc (Windows with Access driver)."""
    import pyodbc
    conn_str = (
        r"DRIVER={Microsoft Access Driver (*.mdb, *.accdb)};"
        f"DBQ={path};"
    )
    conn = pyodbc.connect(conn_str)
    cursor = conn.cursor()

    # Get table names
    tables = [row.table_name for row in cursor.tables(tableType='TABLE')]
    print(f"Tables: {tables}")

    # Find the job log table (usually "JobLog" or similar)
    job_table = None
    for t in tables:
        if 'job' in t.lower() or 'log' in t.lower():
            job_table = t
            break
    if not job_table:
        job_table = tables[0] if tables else None

    if not job_table:
        print("ERROR: No tables found in database")
        return []

    print(f"Using table: {job_table}")

    # Get column names
    columns = [col.column_name for col in cursor.columns(table=job_table)]
    print(f"Columns ({len(columns)}): {columns[:20]}...")

    # Read all rows
    cursor.execute(f"SELECT * FROM [{job_table}] ORDER BY ID")
    rows = cursor.fetchall()
    conn.close()

    # Convert to list of dicts
    result = []
    for row in rows:
        d = {}
        for i, col in enumerate(columns):
            d[col] = row[i]
        result.append(d)

    return result

def match_jobs(db_rows):
    """Match pcap jobs to database rows by job name."""
    matches = {}
    for idx, info in JOB_INFO.items():
        job_name = info["job_name"]
        username = info["username"]
        for row in db_rows:
            db_jobname = str(row.get("JobName", row.get("DocName", ""))).strip()
            db_username = str(row.get("UserName", "")).strip()
            # Match by job name prefix (pcap truncates at 32 chars)
            if db_jobname[:30] == job_name[:30] and db_username.lower() == username.lower():
                matches[idx] = row
                break
            # Also try matching by job name prefix only
            if db_jobname[:20] == job_name[:20] and idx not in matches:
                matches[idx] = row
    return matches

# ─── Main ─────────────────────────────────────────────────────────────────────

print("=" * 70)
print("correlate_ink.py — Correlate ji: blob bytes with .accdb ink values")
print("=" * 70)

accdb_path = find_accdb()
if not accdb_path:
    print("ERROR: Cannot find .accdb file. Please provide the path:")
    accdb_path = input("Path to LFPAT.accdb: ").strip().strip('"')

print(f"Database: {accdb_path}")
db_rows = read_accdb_pyodbc(accdb_path)
print(f"Total rows: {len(db_rows)}")

# Show first few rows
if db_rows:
    print(f"\\nFirst row keys: {list(db_rows[0].keys())[:15]}")

# Match jobs
matches = match_jobs(db_rows)
print(f"\\nMatched {len(matches)}/{len(JOB_INFO)} pcap jobs to database rows")

# ─── Extract and compare ink values ───────────────────────────────────────────

out_lines = []
out_lines.append("CORRELATION RESULTS")
out_lines.append("=" * 70)

for idx in sorted(matches.keys()):
    row = matches[idx]
    blob = BLOBS[idx]
    info = JOB_INFO[idx]

    out_lines.append(f"\\nJob {idx}: {info['username']} — {info['job_name'][:40]}")
    out_lines.append("-" * 60)

    # Extract ink values from database
    ink_values = {}
    for field in INK_FIELDS + CUM_FIELDS + MNT_FIELDS:
        val = row.get(field, None)
        if val is not None:
            try:
                ink_values[field] = float(val)
            except:
                ink_values[field] = val

    out_lines.append(f"  DB InkUse:    {' '.join(f'{ink_values.get(f\"InkUse_{ch}\", 0):8.1f}' for ch in INK_CHANNELS)}")
    out_lines.append(f"  DB InkCumUse: {' '.join(f'{ink_values.get(f\"InkCumUse_{ch}\", 0):8.1f}' for ch in INK_CHANNELS)}")

    # Try to find ink values in blob as uint16 BE
    u16_be = [struct.unpack_from('>H', blob, i*2)[0] for i in range(104)]
    out_lines.append(f"  Blob uint16 BE (first 26): {u16_be[:26]}")

    # Try uint32 BE
    u32_be = [struct.unpack_from('>I', blob, i*4)[0] for i in range(52)]
    out_lines.append(f"  Blob uint32 BE (first 13): {u32_be[:13]}")

    # Try to match: for each InkUse_* value, find which blob offset gives a matching value
    out_lines.append("\\n  SEARCHING for InkUse values in blob:")
    for ch in INK_CHANNELS:
        db_val = ink_values.get(f"InkUse_{ch}", None)
        if db_val is None or db_val == 0:
            continue

        # Search all uint16 BE offsets
        for off in range(104):
            ratio = u16_be[off] / db_val if db_val != 0 else 0
            if 0.999 < ratio < 1.001:
                out_lines.append(f"    InkUse_{ch}={db_val:.1f} EXACT MATCH at uint16_be[{off}] (byte {off*2})")
            elif 0.5 < ratio < 2.0:
                out_lines.append(f"    InkUse_{ch}={db_val:.1f} ~{ratio:.3f}x at uint16_be[{off}]={u16_be[off]} (byte {off*2})")

        # Search uint32 BE
        for off in range(52):
            ratio = u32_be[off] / db_val if db_val != 0 else 0
            if 0.999 < ratio < 1.001:
                out_lines.append(f"    InkUse_{ch}={db_val:.1f} EXACT MATCH at uint32_be[{off}] (byte {off*4})")

        # Try single raw bytes
        for off in range(208):
            if blob[off] == int(db_val) and db_val == int(db_val):
                out_lines.append(f"    InkUse_{ch}={db_val:.0f} byte match at blob[{off}]")

    # Also try scaled values (db_val * 1000, db_val * 100, etc.)
    out_lines.append("\\n  SEARCHING for scaled InkUse values:")
    for scale_name, scale in [("×1", 1), ("×10", 10), ("×100", 100), ("×1000", 1000)]:
        for ch in INK_CHANNELS:
            db_val = ink_values.get(f"InkUse_{ch}", None)
            if db_val is None or db_val == 0:
                continue
            target = db_val * scale
            for off in range(104):
                if abs(u16_be[off] - target) < 1:
                    out_lines.append(f"    InkUse_{ch}={db_val} × {scale} = {target:.0f} → uint16_be[{off}] (byte {off*2})")
            for off in range(52):
                if abs(u32_be[off] - target) < 1:
                    out_lines.append(f"    InkUse_{ch}={db_val} × {scale} = {target:.0f} → uint32_be[{off}] (byte {off*4})")

# Write results
result_path = "correlate_results.txt"
with open(result_path, "w", encoding="utf-8") as f:
    f.write("\\n".join(out_lines))
print(f"\\nResults written to {result_path}")
print("\\n".join(out_lines[:30]))
print(f"... ({len(out_lines)} total lines)")
print(f"\\nCopy {result_path} back to Mac for analysis.")
'''

correlate_path = "lfp_accounting/correlate_ink.py"
with open(correlate_path, "w", encoding="utf-8") as f:
    f.write(correlate_script)

print(f"Written: {correlate_path} ({os.path.getsize(correlate_path)} bytes)")
print("\nTo use:")
print("  1. Copy correlate_ink.py to the Windows machine")
print("  2. Run: python correlate_ink.py")
print("  3. Copy correlate_results.txt back here")

# ─── Also show raw blob hex for manual inspection ────────────────────────────
print("\n" + "="*70)
print("Raw blob hex for first 3 jobs (for manual comparison with .accdb)")
print("="*70)
for idx in sorted(blobs.keys())[:3]:
    info = parse_suffix(suffixes[idx])
    print(f"\nJob {idx} ({info['username']}, {info['job_name'][:30]}):")
    blob = blobs[idx]
    for row in range(0, 208, 16):
        chunk = blob[row:row+16]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        print(f"  {row:3d}: {hex_str}")
