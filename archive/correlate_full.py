"""
Full systematic correlation of ji: blobs against .accdb ink values.
Tries every encoding at every offset across all 30 jobs.
"""
import pyodbc, sys, io, socket, struct, time, json
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# ===== STEP 1: Get ink values from .accdb =====
ACCDB_PATH = r"C:\ProgramData\EPSON\LFP Accounting Tool\UserData\AccountingTool.accdb"
PWD = "4DC1AE17E60EF174B252"
conn = pyodbc.connect(
    r"DRIVER={Microsoft Access Driver (*.mdb, *.accdb)};"
    f"DBQ={ACCDB_PATH};PWD={PWD};"
)
cursor = conn.cursor()

INK_CH = ['PK','MK','C','VM','Y','OR','GR','LC','VLM','LK','LLK','V']
ink_use = [f'InkUse_{c}' for c in INK_CH]
ink_cum = [f'InkCumUse_{c}' for c in INK_CH]
ink_mnt = [f'InkMntUse_{c}' for c in INK_CH]

fields = (['JOBID','DocName','UserName','PaperWidth','PaperHeight','PageNumber',
           'PrintStatus','MediaID','InkSet','CumulativeInkUseTotal',
           'CumulativeMntInkUseTotal','CumulativeMediaUse','CumulativePageUse']
          + ink_use + ink_cum + ink_mnt)

query = 'SELECT TOP 30 ' + ','.join(fields) + ' FROM [EPSON SC-P9500 Series] ORDER BY JOBID DESC'
cursor.execute(query)
cols = [d[0] for d in cursor.description]
db_jobs = [dict(zip(cols, row)) for row in cursor.fetchall()]
conn.close()
print(f"DB jobs: {len(db_jobs)}")

# ===== STEP 2: Get ji: blobs from printer =====
PRINTER = "10.0.0.48"
COMMUNITY = "epson"

def encode_oid(s):
    parts = list(map(int, s.split(".")))
    enc = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        if p == 0:
            enc += b"\x00"
        elif p < 128:
            enc += bytes([p])
        else:
            out = []
            while p:
                out.append(p & 0x7f)
                p >>= 7
            out.reverse()
            enc += bytes([b | 0x80 for b in out[:-1]] + [out[-1]])
    return enc

def tlv(t, v):
    l = len(v)
    if l < 128:
        return bytes([t, l]) + v
    elif l < 256:
        return bytes([t, 0x81, l]) + v
    else:
        return bytes([t, 0x82, l >> 8, l & 0xff]) + v

def dbl(d, p):
    l = d[p]
    if l < 128:
        return l, p + 1
    n = l & 0x7f
    v = 0
    for i in range(n):
        v = (v << 8) | d[p + 1 + i]
    return v, p + 1 + n

def snmp_get(oid):
    vb = tlv(0x30, tlv(0x06, encode_oid(oid)) + tlv(0x05, b""))
    pdu = tlv(0xa0, tlv(0x02, b"\x01") + tlv(0x02, b"\x00") + tlv(0x02, b"\x00") + tlv(0x30, vb))
    pkt = tlv(0x30, tlv(0x02, b"\x00") + tlv(0x04, COMMUNITY.encode()) + pdu)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(4)
    try:
        s.sendto(pkt, (PRINTER, 161))
        r, _ = s.recvfrom(65535)
    except:
        s.close()
        return None
    s.close()
    try:
        i = 0
        assert r[i] == 0x30; _, i = dbl(r, i + 1)
        assert r[i] == 0x02; l, i = dbl(r, i + 1); i += l
        assert r[i] == 0x04; l, i = dbl(r, i + 1); i += l
        _, i = dbl(r, i + 1)
        for _ in range(3):
            assert r[i] == 0x02; l, i = dbl(r, i + 1); i += l
        assert r[i] == 0x30; _, i = dbl(r, i + 1)
        assert r[i] == 0x30; _, i = dbl(r, i + 1)
        assert r[i] == 0x06; ol, i = dbl(r, i + 1); i += ol
        vt = r[i]; vl, i = dbl(r, i + 1)
        raw = r[i:i + vl]
        if vt in (0x80, 0x81, 0x82):
            return None
        return raw
    except:
        return None

HDR = b"\x00@BDC PS\r\nji:"
blobs = []
for idx in range(30):
    raw = snmp_get(f"1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1.106.105.3.0.0.0.{idx}")
    if raw and raw.startswith(HDR):
        pos = len(HDR) + 5  # header + separator(1) + index(2) + length(2)
        blob = raw[pos:pos + 208]
        suffix = raw[pos + 208:]
        username = ""
        if len(suffix) > 4 and suffix[0] in (0x46, 0x47):
            ulen = suffix[3]
            username = suffix[4:4 + ulen].decode("utf-8", errors="replace")
        blobs.append({"idx": idx, "blob": blob, "username": username})
    time.sleep(0.05)

print(f"Blobs: {len(blobs)}")

# Verify alignment
for i in range(min(5, len(blobs))):
    b = blobs[i]
    d = db_jobs[i]
    print(f"  ji:{b['idx']} user={b['username']!r} <-> JOBID={d['JOBID']} user={d.get('UserName','')!r}")

# ===== STEP 3: Build paired data =====
paired = []
for i in range(min(len(blobs), len(db_jobs))):
    b = blobs[i]["blob"]
    d = db_jobs[i]
    values = {}
    for ch in INK_CH:
        values[f"InkUse_{ch}"] = int(d.get(f"InkUse_{ch}") or 0)
        values[f"InkCumUse_{ch}"] = int(d.get(f"InkCumUse_{ch}") or 0)
        values[f"InkMntUse_{ch}"] = int(d.get(f"InkMntUse_{ch}") or 0)
    values["PaperWidth"] = int(d.get("PaperWidth") or 0)
    values["PaperHeight"] = int(d.get("PaperHeight") or 0)
    values["PageNumber"] = int(d.get("PageNumber") or 0)
    values["JOBID"] = int(d.get("JOBID") or 0)
    ps = d.get("PrintStatus") or 0
    values["PrintStatus"] = int(ps) if isinstance(ps, (int, float)) else 0
    mid = d.get("MediaID") or 0
    values["MediaID"] = int(mid) if isinstance(mid, (int, float)) else 0
    iks = d.get("InkSet") or 0
    values["InkSet"] = int(iks) if isinstance(iks, (int, float)) else 0
    values["CumulativeInkUseTotal"] = int(d.get("CumulativeInkUseTotal") or 0)
    values["CumulativeMntInkUseTotal"] = int(d.get("CumulativeMntInkUseTotal") or 0)
    paired.append({"blob": b, "values": values})

print(f"\nPaired records: {len(paired)}")

# ===== STEP 4: Systematic offset search =====
print("\n" + "=" * 70)
print("SYSTEMATIC OFFSET SEARCH")
print("For each field, test every offset with every encoding.")
print("A 'hit' = value at that offset matches across multiple jobs.")
print("=" * 70)

search_fields = (
    ink_use + ink_cum + ink_mnt +
    ["PaperWidth", "PaperHeight", "PageNumber", "JOBID", "MediaID",
     "InkSet", "PrintStatus", "CumulativeInkUseTotal", "CumulativeMntInkUseTotal"]
)

results = {}

for field_name in search_fields:
    best_matches = 0
    best_info = None

    for encoding in ["1byte", "2be", "2le", "4be", "4le"]:
        if encoding == "1byte":
            width = 1
        elif encoding in ("2be", "2le"):
            width = 2
        else:
            width = 4

        for off in range(208 - width + 1):
            matches = 0
            total_valid = 0
            for p in paired:
                val = p["values"][field_name]
                if val == 0:
                    continue
                total_valid += 1
                b = p["blob"]
                if encoding == "1byte":
                    bval = b[off]
                elif encoding == "2be":
                    bval = struct.unpack_from(">H", b, off)[0]
                elif encoding == "2le":
                    bval = struct.unpack_from("<H", b, off)[0]
                elif encoding == "4be":
                    bval = struct.unpack_from(">I", b, off)[0]
                elif encoding == "4le":
                    bval = struct.unpack_from("<I", b, off)[0]
                if bval == val:
                    matches += 1

            if matches > best_matches and total_valid >= 3:
                best_matches = matches
                best_info = (off, encoding, matches, total_valid)

    if best_info:
        off, enc, m, t = best_info
        pct = m / t * 100
        tag = "***" if pct > 80 else "**" if pct > 50 else "*" if pct > 30 else ""
        print(f"  {field_name:30s} off={off:3d} enc={enc:5s}: {m:2d}/{t:2d} ({pct:5.1f}%) {tag}")
        results[field_name] = best_info
    else:
        print(f"  {field_name:30s} — no matches found")

# ===== STEP 5: XOR-based search =====
# Maybe each byte is XOR'd with a per-job key derived from some known value
print("\n" + "=" * 70)
print("XOR-BASED SEARCH")
print("Try XOR with each byte of the blob against a per-job key")
print("=" * 70)

# For each potential key source, try XOR
# Key candidates: first byte, JOBID low byte, username hash, etc.
for key_desc, key_func in [
    ("blob[0]", lambda p, i: p["blob"][0]),
    ("blob[1]", lambda p, i: p["blob"][1]),
    ("blob[0]^blob[1]", lambda p, i: p["blob"][0] ^ p["blob"][1]),
    ("job_index", lambda p, i: i & 0xFF),
]:
    # For each field and offset, try XOR decoding
    for field_name in ink_use[:3] + ["PaperWidth"]:  # Sample fields
        best = (0, None)
        for off in range(208):
            matches = 0
            total = 0
            for ji, p in enumerate(paired):
                val = p["values"][field_name]
                if val == 0 or val > 255:
                    continue
                total += 1
                key = key_func(p, ji)
                decoded = p["blob"][off] ^ key
                if decoded == val:
                    matches += 1
            if matches > best[0] and total >= 3:
                best = (matches, (off, matches, total))
        if best[1] and best[0] >= 3:
            off, m, t = best[1]
            print(f"  XOR({key_desc:20s}) {field_name:20s} off={off:3d}: {m}/{t}")

# ===== STEP 6: Multi-byte XOR with position =====
print("\n" + "=" * 70)
print("POSITION-DEPENDENT XOR SEARCH")
print("blob[off] ^ off, blob[off] ^ (off*constant), etc.")
print("=" * 70)

for xor_desc, xor_func in [
    ("blob[i]^i", lambda b, i: b[i] ^ (i & 0xFF)),
    ("blob[i]^(i*3)", lambda b, i: b[i] ^ ((i * 3) & 0xFF)),
    ("blob[i]^(208-i)", lambda b, i: b[i] ^ ((208 - i) & 0xFF)),
    ("blob[i]^blob[207-i]", lambda b, i: b[i] ^ b[207 - i] if i < 208 else 0),
]:
    for field_name in ink_use:
        best = (0, None)
        for off in range(208):
            matches = 0
            total = 0
            for p in paired:
                val = p["values"][field_name]
                if val == 0 or val > 255:
                    continue
                total += 1
                decoded = xor_func(p["blob"], off)
                if decoded == val:
                    matches += 1
            if matches > best[0] and total >= 3:
                best = (matches, (off, matches, total))
        if best[1] and best[0] >= 4:
            off, m, t = best[1]
            print(f"  {xor_desc:25s} {field_name:20s} off={off:3d}: {m}/{t}")

print("\n=== Done ===")
