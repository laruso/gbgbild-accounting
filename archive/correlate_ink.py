#!/usr/bin/env python3
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
    0: bytes.fromhex("678e6e4123378a96fdeb157e52c7fa6e0575ad008a44210c30ce6a7288b359bb463f821595715cf58544c88e0d19cd3203f1cdb8263569c73130643fbcde7889acb20d2e9667c787883d45afb2a9a122211cf28341d217591b833d7056b1da9cdc7016877be8e6d365342dfd3c6d9e998cff79cf54d94307bcebce92aca1cebdeeeeabc2763ef747c56e7a59854e26927973e9a98a2404bed36e7afeaf5a32d8b004fce91f53adaa8bac1e471a2f8329d1b131f4b7851d4c4310ea396abf8b5c37356c863aed988aa617e0da8ff81d0b"),  # : Bron_50x70.pdf - Page 1 of 1, 
    1: bytes.fromhex("62626b5a25298c9cd23a915f7e1cfa92f6c946a99024beb05d151071c85a135353c1175a73dbadbd866f94ebdedca263d84486a930cb84d1c5717353e2e3400d4312e07dea904e7710bedc3b5ab4e16c027ebf06bbd4d34987b1f5f21c5402c24d0ca7a047fc921349a0f79ba4f0b631af3f3eac16b70bcf0e35dccc2ec4a849d14eb89db23e5be33fe2e491ffab20ce44c77c12f2868a7247a01c5231c708b8f9103daa6f77d546b5ac186b4aa2cb5152d9b69769939dc0bf9660952e6ab75c64c5edeb6041c20e40afe8acfb496ff1"),  # : crane_reflections_50x70.pdf - 
    2: bytes.fromhex("ddda385b3f338aae2f59415cb6fd1e22c361ab569a8c330856085a48666b4b3754d7c499a56502a1468deb78c2e44a0a0877cc2e9eb40bbfb4c551fd1fd7b318904d4382b158d4b0daa507de2b87d23978e821612cf0b3006e59f151824d6c8aa610c4e3d85ebeecdc8a6d2cae7de4c938436b9923215dc811ef3c4f2c0d6003ca249b54f922616c401ee05863e866f23da723232deea02105df99a961ec6026aed4d23570ade176e5b7efac7225250589b92b4ed891af40a903c30e6c8f2b52c5bd382ccd199e46b0e075e54342df63"),  # : 30x40isfötter.jpg, 36x228dörr
    3: bytes.fromhex("608e4d5c213194941458f931d5ec9b8b867a48a94e8260387325de8bdde080d23fea7de8619bc13de206cc08a7d5fd814df86f3ff5b961a0927c306c078639f0c6515f6606d8a0f2d8a6befd4db9eca9249c890785f4df82a8ac3abcc8634c2a2894bcb5716896c8966d10cd7281e87994cb498706e9274cd366279a5e357e5f546e57c07c524f38ab5a2a43bb769adc773355f730c8bc10865dcd4a8934ee9800cc34e13daf3d6b52d34127925dcba7f3fd09666df15d957aff052dc0f15fd4d16b60b60c438a1b079e557607969d21"),  # : 26x24,5 jippi jag har betalat 
    4: bytes.fromhex("cbe602ddcbf7a28693b785404311431d23422d2a04b601381e0cf01053bf1a6404b8d2fd931daa8d69fbbc47a5fca3bd711f0746476192602bce5e2007d8c70a0007c7800c41a1eff5666cab17a1a6c3e46a71c378e5cd40cf9758d603899b0590c54aed2425d0822b6e0a053f33e96e008015576fb041aaba21391a87456df09c453df6ef79954ad23dca99ce983de19570a72f3d6fd4c2cddecf8c7e4ea153201d684f44469fa9e59863bd01752cea8b1631a258b4ef7727de3f230f196ecf5faaf8aec94cac2f30bd3fc4a8760472"),  # : 30x19regeringbråk4.jpg, 40x27.
    5: bytes.fromhex("c6ea0fcecdf1a48cc6aad99b53237202ed7000afc4485e90dbaf9cdd0b4f53fde4ecb51255ed853528ca1a5a88ced5673166a6ffa07b1aeb7726cd9c32719ffb34b31e581b7cc3ce518ce97f0e02e4bc685002c786e20c44d93aa7bad63afd8e1a9ffd435eb62b409769936b527cfb094a18f6f3719192a672acdc4a2a0cfb99eab74c7ab30c60fa56ac87815369811ee15660a76d8a1d3e510302c0cd17eb50c0971b0f707554e9ff7f9665a06e22850dce463e3abd5413a74910bfaaf43254cb8e9d92bdcdd7154eaaa0b2d18b9a33"),  # : 23x32ny.jpg, 25,5x25,5.jpg, 35
    6: bytes.fromhex("1102545f978bb2ae5531515633bbaf71418bea0d2a0a272a17c9ede4b5f0d7bcbfb2d1e665837af6ea4367da33387570e6e2b6448e64e751eb27a400ff6a39e9b92ee478ff9fd442e87ca33709d5921c4ebe0589cf0dd45b330a269aff9e5436d1595c579bd7dbe1476b8e7735ace29309d85b0d44b8cc8156c28f90999ade1dc727df40aa3f9aefe608faaffc9b780ee836175580a999e189678118aaf1aa9c9111a2ed3ad7d3b0d1fbe5662766f7770c32a76676332becf9f3f7e24d941d30d8269e5ed589323a6808e1e96251fbab"),  # : 20181015_Melissa_S3_032_v1_A4_
    7: bytes.fromhex("c4e609c8c9f9ac847c941d894b7f5494fdcc8221a4bc48f8a62629b1f8b0be2533879f7e0f0b0ff0f3c4b3afee6288673fda59aad48668972ed458c95540d9c69e692120a1ad6daa6161a962554186ebd1bfb427daf9c2c6a296aa7dbda8ceb792362917c6cf6980622f10a6bdf49ebc4c03224335ce7efed720416b4f42aabc62a2d8a24179103e3b024afed49d7e91e58d8a67cdf5ed768e93a79f72011ee3c8fecf0b6109395580e119b7efaa47b451d55ab80f2f977b8ee597d9753a9f932781ebbaf0df8acb49caa5f40ef719c8"),  # : 20181015_Melissa_S3_032_v1_A4_
    8: bytes.fromhex("afde264933379aa69f8b554033a7c50bcd6a81369c8e3d4c73dda1666e6c3390bb311aafb95342d44c4455c12cb7b537cabeb1fac132d8443cbe0f915f8bfc11fb7808966082f7bf2789388aa63f93abe26bede969d377ca61424feb11af0f0e21e87903b371363015d131eebf4d6f419309c425e43a77ca7448028fed2bad4f99322efa62b74b084ce017226e1e4702c6317675128fc48691114cb5a4a2ed7281b24b23ae31901bb3a91a3bdb0128bff611da0aa841929b937f92e33d63383e8421b7602977314152a4068ebab84e07"),  # : 20181015_Melissa_S5_039_v1_A4_
    9: bytes.fromhex("dad2132235399cac421acd036dd26f0f8c16e6e34e16fa8c9aded55f1eadc7a40e2b5f263f5dcfd8f14271c7667e8f7d3fb580fea85a2eb98b0f97bb6923d60ab82208e4d78beb358a76200cb7bc5583077e2bb7c081463a32b690f1a482cfa1d3e804d11c1171dadea9ee1c22eced208b1dcd1dc99ac802ed646157ee26df8019700b347d63a23c530e8c1a9b219dd9583f5bb5c705b15644a513bdbb6553839b98b8913b8f21174a291107e892c8ac8c1b47e6dd0fa33310c367e7aea2bcf7f63dfe763e85a66daf3805d2d1c9caca"),  # : 20181015_Melissa_S5_039_v1_A4_

}

JOB_INFO = {
    0: {"username": '', "job_name": 'Bron_50x70.pdf - Page 1 of 1, rs'},
    1: {"username": '', "job_name": 'crane_reflections_50x70.pdf - Pa'},
    2: {"username": '', "job_name": '30x40isfötter.jpg, 36x228dörr'},
    3: {"username": '', "job_name": '26x24,5 jippi jag har betalat 18'},
    4: {"username": '', "job_name": '30x19regeringbråk4.jpg, 40x27.j'},
    5: {"username": '', "job_name": '23x32ny.jpg, 25,5x25,5.jpg, 35x2'},
    6: {"username": '', "job_name": '20181015_Melissa_S3_032_v1_A4_Pr'},
    7: {"username": '', "job_name": '20181015_Melissa_S3_032_v1_A4_Pr'},
    8: {"username": '', "job_name": '20181015_Melissa_S5_039_v1_A4_Pr'},
    9: {"username": '', "job_name": '20181015_Melissa_S5_039_v1_A4_Pr'},
}

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
        r"C:\ProgramData\EPSON\LFP Accounting Tool\Database\LFPAT.accdb",
        r"C:\ProgramData\Epson\LFP Accounting Tool\Database\LFPAT.accdb",
        os.path.expanduser(r"~\AppData\Local\EPSON\LFP Accounting Tool\Database\LFPAT.accdb"),
    ]
    # Also search common locations
    for root in [r"C:\ProgramData", r"C:\Program Files", r"C:\Program Files (x86)"]:
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
    print(f"\nFirst row keys: {list(db_rows[0].keys())[:15]}")

# Match jobs
matches = match_jobs(db_rows)
print(f"\nMatched {len(matches)}/{len(JOB_INFO)} pcap jobs to database rows")

# ─── Extract and compare ink values ───────────────────────────────────────────

out_lines = []
out_lines.append("CORRELATION RESULTS")
out_lines.append("=" * 70)

for idx in sorted(matches.keys()):
    row = matches[idx]
    blob = BLOBS[idx]
    info = JOB_INFO[idx]

    out_lines.append(f"\nJob {idx}: {info['username']} — {info['job_name'][:40]}")
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

    out_lines.append(f"  DB InkUse:    {' '.join(f'{ink_values.get(f"InkUse_{ch}", 0):8.1f}' for ch in INK_CHANNELS)}")
    out_lines.append(f"  DB InkCumUse: {' '.join(f'{ink_values.get(f"InkCumUse_{ch}", 0):8.1f}' for ch in INK_CHANNELS)}")

    # Try to find ink values in blob as uint16 BE
    u16_be = [struct.unpack_from('>H', blob, i*2)[0] for i in range(104)]
    out_lines.append(f"  Blob uint16 BE (first 26): {u16_be[:26]}")

    # Try uint32 BE
    u32_be = [struct.unpack_from('>I', blob, i*4)[0] for i in range(52)]
    out_lines.append(f"  Blob uint32 BE (first 13): {u32_be[:13]}")

    # Try to match: for each InkUse_* value, find which blob offset gives a matching value
    out_lines.append("\n  SEARCHING for InkUse values in blob:")
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
    out_lines.append("\n  SEARCHING for scaled InkUse values:")
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
    f.write("\n".join(out_lines))
print(f"\nResults written to {result_path}")
print("\n".join(out_lines[:30]))
print(f"... ({len(out_lines)} total lines)")
print(f"\nCopy {result_path} back to Mac for analysis.")
