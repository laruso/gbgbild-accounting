"""
Decrypt the 208-byte ji: blob from the Epson SC-P9500 printer.

The encryption is a custom 3-round Feistel cipher with CBC-mode chaining.
Key = printer serial number (ASCII, zero-padded to 16 bytes).

Decrypted output is a TLV structure with 2-byte LE ink values.

Ink field order in the TLV (at offset 0x2F, tag 0x0F):
  LK, VM, OR, PK, VLM, LLK, LC, Y, GR, MK, V, C
  (12 channels x 2 bytes = 24 bytes)
"""
import sys, io, socket, struct, time
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')


def decrypt_blob(data: bytes, serial: str) -> bytes:
    """
    Decrypt the 208-byte ji: blob using the printer serial number as key.

    Args:
        data: The 208-byte encrypted blob from the ji: SNMP response
        serial: Printer serial number (e.g. 'X6FB001980')

    Returns:
        Decrypted 208-byte TLV data
    """
    # Key = serial number as ASCII, padded with zeros to 16 bytes
    key_full = serial.encode('ascii').ljust(16, b'\x00')

    # The decrypt function reads key bytes at offsets 2-9
    K = list(key_full[2:10])  # 8 key bytes

    # Derive round keys
    k4, k5, k6, k7 = K[4], K[5], K[6], K[7]

    va = (k4 + 1) & 0xFF
    vb = ((k4 + 2) * 2) & 0xFF
    vf = (k5 + 1) & 0xFF
    ve = (k6 + 1) & 0xFF
    vd = (k7 + 1) & 0xFF
    vk1 = (vf + va + 2) & 0xFF
    vk2 = (ve + va + 2) & 0xFF
    vk3 = (vd + va + 2) & 0xFF
    vk4 = (vb + vf + 3) & 0xFF
    vk5 = (vk1 + vf + 3) & 0xFF
    vk7 = (vk2 + vf + 3) & 0xFF
    vk6 = (vk3 + vf + 3) & 0xFF

    r1k = [vk4, vk5, vk7, vk6]
    r2k = [vb, vk1, vk2, vk3]
    r3k = [va, vf, ve, vd]

    buf = bytearray(data)
    original = bytes(data)
    n_blocks = len(buf) // 8

    # First block uses key bytes 0-7 as XOR key, subsequent blocks use
    # original (encrypted) data of previous block (CBC mode)
    xor_key = list(key_full[0:8])

    for blk in range(n_blocks):
        b = blk * 8

        # Round 1: read [4..7], modify [0..3]
        s1 = (buf[b+7] + buf[b+6] + buf[b+5] + buf[b+4]) & 0xFF
        for i in range(4):
            d = (buf[b+4+i] ^ r1k[i]) & 0xFF
            d = (d + s1) & 0xFF
            buf[b+i] ^= d

        # Round 2: read modified [0..3], modify [4..7]
        s2 = (buf[b+3] + buf[b+2] + buf[b+1] + buf[b+0]) & 0xFF
        for i in range(4):
            d = (buf[b+i] ^ r2k[i]) & 0xFF
            d = (d + s2) & 0xFF
            buf[b+4+i] ^= d

        # Round 3: read modified [4..7], modify [0..3]
        s3 = (buf[b+7] + buf[b+6] + buf[b+5] + buf[b+4]) & 0xFF
        for i in range(4):
            d = (buf[b+4+i] ^ r3k[i]) & 0xFF
            d = (d + s3) & 0xFF
            buf[b+i] ^= d

        # Final XOR with key (CBC: next key = original encrypted block)
        for i in range(8):
            buf[b+i] ^= xor_key[i]

        xor_key = list(original[b:b+8])

    return bytes(buf)


def parse_ink_values(decrypted: bytes) -> dict:
    """
    Parse the decrypted TLV data to extract per-job ink usage.

    The TLV structure has tag 0x0F with 24 bytes of ink data:
    12 channels x 2-byte little-endian values.

    DLL field order: LK, VM, OR, PK, VLM, LLK, LC, Y, GR, MK, V, C
    """
    DLL_INK_ORDER = ['LK', 'VM', 'OR', 'PK', 'VLM', 'LLK', 'LC', 'Y', 'GR', 'MK', 'V', 'C']

    # Parse TLV to find tag 0x0F
    i = 0
    while i < len(decrypted) - 1:
        tag = decrypted[i]
        if tag == 0:
            break
        length = decrypted[i + 1]
        if i + 2 + length > len(decrypted):
            break

        if tag == 0x0F and length == 24:
            # Ink data: 12 x 2-byte LE values
            ink_data = decrypted[i + 2:i + 2 + 24]
            values = {}
            for ch_idx, ch_name in enumerate(DLL_INK_ORDER):
                val = struct.unpack_from('<H', ink_data, ch_idx * 2)[0]
                values[ch_name] = val
            return values

        i += 2 + length

    return {}


# ===== SNMP helpers =====
PRINTER = "10.0.0.48"

def encode_oid(s):
    parts = list(map(int, s.split(".")))
    enc = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        if p == 0: enc += b"\x00"
        elif p < 128: enc += bytes([p])
        else:
            out = []
            while p: out.append(p & 0x7f); p >>= 7
            out.reverse(); enc += bytes([b | 0x80 for b in out[:-1]] + [out[-1]])
    return enc

def tlv(t, v):
    l = len(v)
    if l < 128: return bytes([t, l]) + v
    elif l < 256: return bytes([t, 0x81, l]) + v
    else: return bytes([t, 0x82, l >> 8, l & 0xff]) + v

def dbl(d, p):
    l = d[p]
    if l < 128: return l, p + 1
    n = l & 0x7f; v = 0
    for i in range(n): v = (v << 8) | d[p + 1 + i]
    return v, p + 1 + n

def snmp_get(oid, community="epson"):
    vb = tlv(0x30, tlv(0x06, encode_oid(oid)) + tlv(0x05, b""))
    pdu = tlv(0xa0, tlv(0x02, b"\x01") + tlv(0x02, b"\x00") + tlv(0x02, b"\x00") + tlv(0x30, vb))
    pkt = tlv(0x30, tlv(0x02, b"\x00") + tlv(0x04, community.encode()) + pdu)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(4)
    try: s.sendto(pkt, (PRINTER, 161)); r, _ = s.recvfrom(65535)
    except: s.close(); return None
    s.close()
    try:
        i = 0; assert r[i] == 0x30; _, i = dbl(r, i+1)
        assert r[i] == 0x02; l, i = dbl(r, i+1); i += l
        assert r[i] == 0x04; l, i = dbl(r, i+1); i += l
        _, i = dbl(r, i+1)
        for _ in range(3): assert r[i] == 0x02; l, i = dbl(r, i+1); i += l
        assert r[i] == 0x30; _, i = dbl(r, i+1)
        assert r[i] == 0x30; _, i = dbl(r, i+1)
        assert r[i] == 0x06; ol, i = dbl(r, i+1); i += ol
        vt = r[i]; vl, i = dbl(r, i+1); raw = r[i:i+vl]
        if vt in (0x80, 0x81, 0x82): return None
        return raw
    except: return None


# ===== Main: decrypt all 30 jobs and verify against .accdb =====
SERIAL = "X6FB001980"
HDR = b"\x00@BDC PS\r\nji:"

print(f"Serial number: {SERIAL}")
print(f"Key (hex): {SERIAL.encode('ascii').ljust(16, b'0').hex()}")
print()

# Fetch and decrypt all jobs
INK_CH_STD = ['PK', 'MK', 'C', 'VM', 'Y', 'OR', 'GR', 'LC', 'VLM', 'LK', 'LLK', 'V']

jobs_decoded = []
for idx in range(30):
    raw = snmp_get(f"1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1.106.105.3.0.0.0.{idx}")
    if not raw or not raw.startswith(HDR):
        break

    ji_data = raw[len(HDR):]
    blob = ji_data[5:5 + 208]

    # Extract username from TLV suffix
    suffix = ji_data[5 + 208:]
    username = ""
    if len(suffix) > 4 and suffix[0] in (0x46, 0x47):
        ulen = suffix[3]
        username = suffix[4:4 + ulen].decode("utf-8", errors="replace")

    # Decrypt
    decrypted = decrypt_blob(blob, SERIAL)
    ink = parse_ink_values(decrypted)

    if ink:
        jobs_decoded.append({"idx": idx, "username": username, "ink": ink})
        if idx < 5:
            ink_std = {ch: ink.get(ch, 0) for ch in INK_CH_STD}
            print(f"Job {idx} ({username}): {ink_std}")

    time.sleep(0.05)

print(f"\nDecoded {len(jobs_decoded)} jobs with ink values.")

# Verify against .accdb
try:
    import pyodbc
    conn = pyodbc.connect(
        r"DRIVER={Microsoft Access Driver (*.mdb, *.accdb)};"
        r"DBQ=C:\ProgramData\EPSON\LFP Accounting Tool\UserData\AccountingTool.accdb;"
        "PWD=4DC1AE17E60EF174B252;"
    )
    cursor = conn.cursor()
    cols = ["JOBID", "DocName"] + [f"InkUse_{ch}" for ch in INK_CH_STD]
    cursor.execute("SELECT TOP 30 " + ",".join(cols) + " FROM [EPSON SC-P9500 Series] ORDER BY JOBID DESC")
    db_rows = cursor.fetchall()
    conn.close()

    print("\n=== Verification against .accdb ===")
    all_match = True
    for i, job in enumerate(jobs_decoded):
        if i >= len(db_rows):
            break
        db = db_rows[i]
        db_ink = {ch: int(db[2 + j] or 0) for j, ch in enumerate(INK_CH_STD)}
        snmp_ink = {ch: job["ink"].get(ch, 0) for ch in INK_CH_STD}

        match = db_ink == snmp_ink
        if not match:
            all_match = False
            print(f"  Job {i} MISMATCH!")
            print(f"    DB:   {db_ink}")
            print(f"    SNMP: {snmp_ink}")
        elif i < 5:
            print(f"  Job {i}: MATCH (user={job['username']}, doc={db[1][:30]})")

    if all_match:
        print(f"\n  ALL {min(len(jobs_decoded), len(db_rows))} JOBS MATCH PERFECTLY!")
    else:
        print(f"\n  Some mismatches found.")

except ImportError:
    print("\n(pyodbc not available for verification)")
except Exception as e:
    print(f"\nVerification error: {e}")
