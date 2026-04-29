"""
probe_ji.py — Query all jobs via SNMP ji: OID (confirmed from Wireshark).

Confirmed OID structure:
  1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1.106.105.3.0.0.0.N
  where 106='j', 105='i', N = job index (0-based, up to ~499)
  Community: epson
  PDU: GET-REQUEST (0xa0)

Response payload format (after stripping SNMP envelope):
  00 @BDC PS\r\n ji: [3-byte BE job index] d0 00 [binary data] [ASCII TLV fields]

ASCII TLV fields at end of payload (tag, len, data):
  tag 0x00, 0x07: username
  tag 0x08: job name (prefixed with space char 0x20?)
  tag 0x09: machine name

Goal: Dump all 499 job payloads, isolate binary section, find ink channel byte offsets.

SC-P9500 ink channels (13 total):
  PK, MK, C, VM, Y, OR, GR, LC, VLM, LK, LLK, V, GY

Run: python3 probe_ji.py > probe_ji_log.txt 2>&1
Also writes: probe_ji_payloads.bin (raw), probe_ji_analysis.txt (structured)
"""
import socket, struct, sys, io, time, os

if hasattr(sys.stdout, 'buffer'):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

PRINTER   = "10.0.0.48"
COMMUNITY = "epson"
PORT      = 161
TIMEOUT   = 4.0

# Confirmed ji: OID prefix (up to job index)
# 1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1.106.105.3.0.0.0.N
JI_OID_PREFIX = "1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1.106.105.3.0.0.0"

INK_CHANNELS = ["PK", "MK", "C", "VM", "Y", "OR", "GR", "LC", "VLM", "LK", "LLK", "V", "GY"]

# ─── BER / SNMP helpers ──────────────────────────────────────────────────────

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

def tlv(tag, value):
    l = len(value)
    if l < 128:   return bytes([tag, l]) + value
    elif l < 256: return bytes([tag, 0x81, l]) + value
    else:         return bytes([tag, 0x82, l >> 8, l & 0xff]) + value

def decode_ber_len(data, pos):
    l = data[pos]
    if l < 128: return l, pos + 1
    n = l & 0x7f
    val = 0
    for i in range(n): val = (val << 8) | data[pos + 1 + i]
    return val, pos + 1 + n

def decode_oid_bytes(data):
    if not data: return ""
    parts = [data[0] // 40, data[0] % 40]
    i = 1
    while i < len(data):
        val = 0
        while i < len(data):
            b = data[i]; i += 1
            val = (val << 7) | (b & 0x7f)
            if not (b & 0x80): break
        parts.append(val)
    return ".".join(map(str, parts))

def snmp_get_request(community, oid_str):
    vb  = tlv(0x30, tlv(0x06, encode_oid(oid_str)) + tlv(0x05, b""))
    pdu = tlv(0xa0,  # GET-REQUEST
              tlv(0x02, b"\x01") +
              tlv(0x02, b"\x00") +
              tlv(0x02, b"\x00") +
              tlv(0x30, vb))
    return tlv(0x30, tlv(0x02, b"\x00") + tlv(0x04, community.encode()) + pdu)

def snmp_get(oid_str, community=COMMUNITY, retries=2):
    pkt = snmp_get_request(community, oid_str)
    for attempt in range(retries + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(TIMEOUT)
        try:
            sock.sendto(pkt, (PRINTER, PORT))
            resp, _ = sock.recvfrom(65535)
        except socket.timeout:
            sock.close()
            if attempt < retries:
                time.sleep(0.2)
                continue
            return None
        except Exception as e:
            sock.close()
            return None
        finally:
            sock.close()

        try:
            i = 0
            assert resp[i] == 0x30; _, i = decode_ber_len(resp, i + 1)
            assert resp[i] == 0x02; l, i = decode_ber_len(resp, i + 1); i += l
            assert resp[i] == 0x04; l, i = decode_ber_len(resp, i + 1); i += l
            _;                      _, i = decode_ber_len(resp, i + 1)  # PDU tag+len
            for _ in range(3):
                assert resp[i] == 0x02; l, i = decode_ber_len(resp, i + 1); i += l
            assert resp[i] == 0x30; _, i = decode_ber_len(resp, i + 1)
            assert resp[i] == 0x30; _, i = decode_ber_len(resp, i + 1)
            assert resp[i] == 0x06; oid_l, i = decode_ber_len(resp, i + 1)
            resp_oid = decode_oid_bytes(resp[i:i + oid_l]); i += oid_l
            val_tag = resp[i]; val_l, i = decode_ber_len(resp, i + 1)
            raw = resp[i:i + val_l]
            # noSuchObject / noSuchInstance
            if val_tag in (0x80, 0x81, 0x82):
                return None
            return raw
        except Exception:
            return None
    return None


# ─── ji: payload parser ────────────────────────────────────────────────────────

HEADER_MAGIC = b"\x00@BDC PS\r\nji:"

def parse_ji_payload(raw: bytes, job_index: int):
    """
    Strip the BDC header and parse the ji: payload.
    Returns dict with keys: ok, binary_data, job_name, username, machine, raw_hex
    """
    result = {
        "ok": False,
        "binary_data": b"",
        "job_name": "",
        "username": "",
        "machine": "",
        "raw_hex": raw.hex() if raw else "",
        "raw_len": len(raw) if raw else 0,
    }

    if not raw:
        return result

    if not raw.startswith(HEADER_MAGIC):
        # Try without leading \x00
        if raw.startswith(b"@BDC PS\r\nji:"):
            raw = b"\x00" + raw
        else:
            result["raw_hex"] = raw[:64].hex()
            return result

    # Skip past "@BDC PS\r\nji:" (13 bytes including leading \x00)
    pos = len(HEADER_MAGIC)

    # 3-byte big-endian job index
    if len(raw) < pos + 5:
        return result
    idx_from_payload = struct.unpack_from(">I", b"\x00" + raw[pos:pos+3])[0]
    pos += 3

    # d0 00
    if raw[pos:pos+2] != b"\xd0\x00":
        # Accept anyway — field may vary
        pass
    pos += 2

    result["ok"] = True
    result["idx_from_payload"] = idx_from_payload

    # The rest is binary data followed by ASCII TLV fields.
    # Strategy: scan from end to find the ASCII metadata fields.
    # Fields end with null or run to end of buffer.
    # Work backwards from end to find the start of ASCII section.
    binary_section = raw[pos:]

    # Find ASCII TLV fields at the end.
    # Known structure (from Wireshark decode):
    #   [... binary ...] [TLV1: username] [TLV2: job name] [TLV3: machine]
    # Each TLV appears to be: tag(1), len(1), data(len) — confirmed for machine tag 0x09.
    # For username: tag 0x00, then 0x07, then len, then data (multi-byte tag?)
    # Parse from END using known field order: machine, job name, username

    ascii_start = _find_ascii_section(binary_section)

    if ascii_start is not None:
        result["binary_data"] = binary_section[:ascii_start]
        ascii_section = binary_section[ascii_start:]
        _parse_ascii_tlv(ascii_section, result)
    else:
        result["binary_data"] = binary_section

    return result


def _find_ascii_section(data: bytes) -> int | None:
    """
    Scan backwards to find where the ASCII TLV metadata starts.
    Returns byte offset within data, or None if not found.

    The machine name (tag 0x09) is the last field. If we can find it,
    we know where the ASCII section starts.
    """
    # Tag 0x09 + length + "GBadmins..." — look for tag 0x09 followed by plausible len
    for i in range(len(data) - 3, max(len(data) - 80, 0), -1):
        tag = data[i]
        if tag == 0x09 and i + 1 < len(data):
            ln = data[i + 1]
            end = i + 2 + ln
            if end <= len(data):
                chunk = data[i + 2:end]
                # Check it looks like a hostname (printable ASCII)
                if all(32 <= b < 127 for b in chunk) and ln >= 4:
                    return i
    return None


def _parse_ascii_tlv(data: bytes, result: dict):
    """Parse the trailing ASCII TLV fields into result dict."""
    i = 0
    while i < len(data) - 1:
        tag = data[i]
        # Special case: tag 0x00 has extra byte before len
        if tag == 0x00 and i + 2 < len(data):
            # Structure observed: 00 07 0e [username]
            # or: 00 XX len [data]
            i += 1
            subtype = data[i]; i += 1

        if i >= len(data): break
        ln = data[i]; i += 1
        if i + ln > len(data): break
        chunk = data[i:i + ln]; i += ln

        try:
            text = chunk.decode('utf-8', errors='replace').strip('\x00').strip()
        except Exception:
            text = chunk.hex()

        if tag == 0x09:
            result["machine"] = text
        elif tag == 0x08:
            result["job_name"] = text.strip()
        elif tag == 0x00:
            result["username"] = text


# ─── Structural analysis of binary section ───────────────────────────────────

def analyze_binary_section(payloads: list[dict]):
    """
    Analyze binary sections across all jobs to find ink channel byte positions.

    Approach 1: Look for consistent offsets where values change between jobs
                but are plausible ink values (non-zero, < 2^24, consistent scale).
    Approach 2: Look for groups of N=13 consecutive 4-byte values that sum correctly.
    Approach 3: Entropy / variance analysis — ink bytes will vary per job.
    """
    bins = [p["binary_data"] for p in payloads if p.get("ok") and len(p.get("binary_data", b"")) > 16]
    if not bins:
        return

    min_len = min(len(b) for b in bins)
    print("\n=== Binary Section Analysis ===")
    print(f"Jobs with binary data: {len(bins)}")
    print(f"Min binary section length: {min_len} bytes")
    print(f"Max binary section length: {max(len(b) for b in bins)} bytes")

    # Show first few jobs' binary sections as hex grid
    print("\n--- First 10 jobs binary sections (hex, 16 bytes/row) ---")
    for idx, b in enumerate(bins[:10]):
        print(f"\nJob {idx} ({len(b)} bytes):")
        for row in range(0, min(len(b), 288), 16):
            chunk = b[row:row+16]
            hex_str = " ".join("%02x" % x for x in chunk)
            # Show printable chars
            asc = "".join(chr(x) if 32 <= x < 127 else "." for x in chunk)
            print(f"  {row:3d}: {hex_str:<48s}  {asc}")

    # Byte-by-byte variance: find positions that change across jobs (candidate ink bytes)
    print("\n--- Byte positions with variation (candidates for ink data) ---")
    varied_positions = []
    for pos in range(min_len):
        vals = [b[pos] for b in bins]
        mn, mx = min(vals), max(vals)
        if mx - mn > 2:  # varies across jobs
            varied_positions.append((pos, mn, mx, mx - mn))

    print(f"Total varied positions: {len(varied_positions)}")
    print("First 80 varied positions:")
    for pos, mn, mx, rng in varied_positions[:80]:
        vals = [b[pos] for b in bins[:10]]
        vals_str = " ".join("%3d" % v for v in vals)
        print(f"  byte[{pos:3d}]: range {mn:3d}–{mx:3d}  jobs0-9: {vals_str}")

    # Try to find 13 consecutive 4-byte big-endian values that look like ink amounts
    # Ink values in BDC are typically in units of 0.01 ml → values up to ~5000000 (50ml tank)
    print("\n--- Looking for 13-channel ink blocks (4-byte BE uint32) ---")
    for start in range(0, min_len - 52, 4):
        vals_per_job = []
        for b in bins[:20]:
            if start + 52 <= len(b):
                row = [struct.unpack_from(">I", b, start + ch*4)[0] for ch in range(13)]
                vals_per_job.append(row)

        if not vals_per_job:
            continue

        # Check: all values reasonable (< 100,000,000), at least some non-zero, some vary
        first = vals_per_job[0]
        all_ok = all(v < 100_000_000 for v in first)
        any_nonzero = any(v > 0 for v in first)

        if not all_ok or not any_nonzero:
            continue

        # Check some values differ across jobs (ink usage varies per job)
        vary_count = 0
        for ch in range(13):
            ch_vals = [row[ch] for row in vals_per_job]
            if max(ch_vals) - min(ch_vals) > 0:
                vary_count += 1

        if vary_count >= 3:
            print(f"\n  CANDIDATE at byte offset {start} (vary_count={vary_count}):")
            print(f"  Channels: {' '.join('%-6s' % c for c in INK_CHANNELS)}")
            for ji, row in enumerate(vals_per_job[:5]):
                vals_str = " ".join("%6d" % v for v in row)
                print(f"  Job {ji:3d}: {vals_str}")

    # Also try 2-byte BE uint16
    print("\n--- Looking for 13-channel ink blocks (2-byte BE uint16) ---")
    for start in range(0, min_len - 26, 2):
        vals_per_job = []
        for b in bins[:20]:
            if start + 26 <= len(b):
                row = [struct.unpack_from(">H", b, start + ch*2)[0] for ch in range(13)]
                vals_per_job.append(row)

        if not vals_per_job:
            continue

        first = vals_per_job[0]
        all_ok = all(v < 65535 for v in first)
        any_nonzero = any(v > 0 for v in first)

        if not all_ok or not any_nonzero:
            continue

        vary_count = 0
        for ch in range(13):
            ch_vals = [row[ch] for row in vals_per_job]
            if max(ch_vals) - min(ch_vals) > 0:
                vary_count += 1

        if vary_count >= 3:
            print(f"\n  CANDIDATE at byte offset {start} (vary_count={vary_count}):")
            print(f"  Channels: {' '.join('%-5s' % c for c in INK_CHANNELS)}")
            for ji, row in enumerate(vals_per_job[:5]):
                vals_str = " ".join("%5d" % v for v in row)
                print(f"  Job {ji:3d}: {vals_str}")

    # Also try 4-byte LE
    print("\n--- Looking for 13-channel ink blocks (4-byte LE uint32) ---")
    for start in range(0, min_len - 52, 4):
        vals_per_job = []
        for b in bins[:20]:
            if start + 52 <= len(b):
                row = [struct.unpack_from("<I", b, start + ch*4)[0] for ch in range(13)]
                vals_per_job.append(row)

        if not vals_per_job:
            continue

        first = vals_per_job[0]
        all_ok = all(v < 100_000_000 for v in first)
        any_nonzero = any(v > 0 for v in first)

        if not all_ok or not any_nonzero:
            continue

        vary_count = 0
        for ch in range(13):
            ch_vals = [row[ch] for row in vals_per_job]
            if max(ch_vals) - min(ch_vals) > 0:
                vary_count += 1

        if vary_count >= 3:
            print(f"\n  CANDIDATE at byte offset {start} (vary_count={vary_count}):")
            print(f"  Channels: {' '.join('%-6s' % c for c in INK_CHANNELS)}")
            for ji, row in enumerate(vals_per_job[:5]):
                vals_str = " ".join("%6d" % v for v in row)
                print(f"  Job {ji:3d}: {vals_str}")


# ─── Main ────────────────────────────────────────────────────────────────────

print("=" * 70)
print("probe_ji.py — SNMP ji: job ink query")
print(f"Printer: {PRINTER}  Community: {COMMUNITY}")
print("=" * 70)

# ── Step 1: Find range of valid job indices ──────────────────────────────────
print("\n=== Step 1: Find valid job index range ===")
print("Testing job indices 0, 1, 10, 50, 100, 200, 300, 400, 498, 499, 500...")

def test_index(n):
    oid = f"{JI_OID_PREFIX}.{n}"
    raw = snmp_get(oid)
    if raw is None:
        return None
    p = parse_ji_payload(raw, n)
    if p["ok"]:
        return p
    # Not a valid ji response but got data
    return {"ok": False, "raw_len": len(raw), "raw_hex": raw[:16].hex()}

valid_max = 0
for n in [0, 1, 10, 50, 100, 200, 300, 400, 450, 498, 499, 500, 501]:
    result = test_index(n)
    if result is None:
        print(f"  [{n}] timeout/no response")
    elif result.get("ok"):
        valid_max = n
        print(f"  [{n}] OK — job_name={result.get('job_name','?')!r}  username={result.get('username','?')!r}  bin_len={len(result.get('binary_data',b''))}")
    else:
        print(f"  [{n}] data but not ji: — len={result.get('raw_len',0)}  hex={result.get('raw_hex','')}")

print(f"\nHighest valid index seen: {valid_max}")

# ── Step 2: Query all valid jobs ─────────────────────────────────────────────
print("\n=== Step 2: Query all jobs (0 to valid_max) ===")

payloads = []
failed   = []
max_index = valid_max + 1  # query through the highest confirmed valid index

# First pass: find actual max by probing upward
print("Finding true upper bound...")
for n in range(valid_max + 1, valid_max + 50):
    raw = snmp_get(f"{JI_OID_PREFIX}.{n}")
    if raw is None:
        break
    p = parse_ji_payload(raw, n)
    if p["ok"]:
        max_index = n + 1
        print(f"  Extended max to {n}")
    else:
        break

print(f"Will query indices 0 to {max_index - 1} ({max_index} jobs)")
print("Progress: ", end="", flush=True)

t0 = time.time()
for n in range(max_index):
    oid = f"{JI_OID_PREFIX}.{n}"
    raw = snmp_get(oid)
    if raw is None:
        failed.append(n)
        print("!", end="", flush=True)
    else:
        p = parse_ji_payload(raw, n)
        p["job_index"] = n
        payloads.append(p)
        if n % 10 == 0:
            print(".", end="", flush=True)
    time.sleep(0.05)  # 50ms between queries — avoid overwhelming printer

elapsed = time.time() - t0
print(f"\n\nDone in {elapsed:.1f}s")
print(f"  Successful: {len(payloads)}")
print(f"  Failed/timeout: {len(failed)} — indices: {failed[:20]}")

# ── Step 3: Show summary of parsed jobs ─────────────────────────────────────
print("\n=== Step 3: Parsed job summary ===")
ok_jobs = [p for p in payloads if p.get("ok")]
print(f"OK jobs (ji: header confirmed): {len(ok_jobs)}")
print(f"Jobs with job name: {sum(1 for p in ok_jobs if p.get('job_name'))}")
print(f"Jobs with username: {sum(1 for p in ok_jobs if p.get('username'))}")
print()

print("First 20 jobs:")
print(f"{'idx':>4}  {'bin_len':>7}  {'username':<20}  {'job_name'}")
print("-" * 70)
for p in ok_jobs[:20]:
    print(f"{p['job_index']:4d}  {len(p.get('binary_data',b'')):7d}  "
          f"{p.get('username',''):<20}  {p.get('job_name','')}")

# ── Step 4: Write full payload dump to file ──────────────────────────────────
out_path = "probe_ji_analysis.txt"
print(f"\n=== Step 4: Writing full analysis to {out_path} ===")

with open(out_path, "w", encoding="utf-8") as f:
    f.write(f"probe_ji.py full dump — {len(ok_jobs)} jobs\n")
    f.write("=" * 80 + "\n\n")

    for p in ok_jobs:
        idx = p["job_index"]
        bd  = p.get("binary_data", b"")
        f.write(f"Job {idx:3d}  bin_len={len(bd):3d}  "
                f"user={p.get('username','?')!r}  "
                f"job={p.get('job_name','?')!r}  "
                f"machine={p.get('machine','?')!r}\n")
        # Write binary section as hex grid
        for row in range(0, len(bd), 16):
            chunk = bd[row:row+16]
            hex_str = " ".join("%02x" % x for x in chunk)
            asc = "".join(chr(x) if 32 <= x < 127 else "." for x in chunk)
            f.write(f"  {row:3d}: {hex_str:<48s}  {asc}\n")
        f.write("\n")

print(f"Written: {out_path}")

# Also write raw binary payload file (for external analysis)
bin_path = "probe_ji_payloads.bin"
with open(bin_path, "wb") as bf:
    for p in ok_jobs:
        bd = p.get("binary_data", b"")
        # Each record: 4-byte job index (BE) + 4-byte bin_len (BE) + binary data
        bf.write(struct.pack(">II", p["job_index"], len(bd)))
        bf.write(bd)
print(f"Written: {bin_path} ({os.path.getsize(bin_path)} bytes)")

# ── Step 5: Structural binary analysis ──────────────────────────────────────
analyze_binary_section(ok_jobs)

# ── Step 6: Print a few complete raw payloads for manual inspection ──────────
print("\n\n=== Step 6: First 5 complete raw payloads ===")
for p in ok_jobs[:5]:
    print(f"\nJob {p['job_index']}  total_raw_len={p.get('raw_len',0)}")
    print(f"  username={p.get('username','')!r}  job={p.get('job_name','')!r}  machine={p.get('machine','')!r}")
    print(f"  Binary section ({len(p.get('binary_data',b''))} bytes):")
    bd = p.get("binary_data", b"")
    for row in range(0, len(bd), 16):
        chunk = bd[row:row+16]
        print(f"    {row:3d}: {' '.join('%02x' % x for x in chunk)}")
    print(f"  Full raw hex (first 64 bytes): {p.get('raw_hex','')[:128]}")

print("\n\n=== Done ===")
print(f"Check {out_path} for full per-job binary hex dumps.")
print("Look for 'CANDIDATE' lines above — those are the ink channel byte offsets.")
