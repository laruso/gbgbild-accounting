"""
probe_vi.py — Try vi: BDC command via SNMP OID.

The SCP7595.dll contains the string 'vi:00:' — this is a BDC ink volume
info command. May return per-job ink usage in a readable format.

OID structure (same pattern as ji:):
  1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1.[v=118].[i=105].[params].[job_index]

We'll try various parameter combinations since we don't have a Wireshark
capture of a vi: query.

Also tries:
  - walking the subtree 1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1 to find all
    supported BDC command OIDs
  - ex: with different parameters for job ink data

Run: python3 probe_vi.py > probe_vi_log.txt 2>&1
"""
import socket, struct, sys, io, time

if hasattr(sys.stdout, 'buffer'):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

PRINTER   = "10.0.0.48"
COMMUNITY = "epson"
PORT      = 161
TIMEOUT   = 3.0

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

def make_get(community, oid_str):
    vb  = tlv(0x30, tlv(0x06, encode_oid(oid_str)) + tlv(0x05, b""))
    pdu = tlv(0xa0, tlv(0x02, b"\x01") + tlv(0x02, b"\x00") +
              tlv(0x02, b"\x00") + tlv(0x30, vb))
    return tlv(0x30, tlv(0x02, b"\x00") + tlv(0x04, community.encode()) + pdu)

def make_getnext(community, oid_str):
    vb  = tlv(0x30, tlv(0x06, encode_oid(oid_str)) + tlv(0x05, b""))
    pdu = tlv(0xa1, tlv(0x02, b"\x01") + tlv(0x02, b"\x00") +
              tlv(0x02, b"\x00") + tlv(0x30, vb))
    return tlv(0x30, tlv(0x02, b"\x00") + tlv(0x04, community.encode()) + pdu)

def snmp_query(pkt, retries=1):
    for attempt in range(retries + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(TIMEOUT)
        try:
            sock.sendto(pkt, (PRINTER, PORT))
            resp, _ = sock.recvfrom(65535)
        except socket.timeout:
            sock.close()
            if attempt < retries:
                time.sleep(0.1)
                continue
            return None, None, None
        except Exception:
            sock.close()
            return None, None, None
        finally:
            sock.close()

        try:
            i = 0
            assert resp[i] == 0x30; _, i = decode_ber_len(resp, i + 1)
            assert resp[i] == 0x02; l, i = decode_ber_len(resp, i + 1); i += l
            assert resp[i] == 0x04; l, i = decode_ber_len(resp, i + 1); i += l
            _;                      _, i = decode_ber_len(resp, i + 1)
            for _ in range(3):
                assert resp[i] == 0x02; l, i = decode_ber_len(resp, i + 1); i += l
            assert resp[i] == 0x30; _, i = decode_ber_len(resp, i + 1)
            assert resp[i] == 0x30; _, i = decode_ber_len(resp, i + 1)
            assert resp[i] == 0x06; oid_l, i = decode_ber_len(resp, i + 1)
            resp_oid = decode_oid_bytes(resp[i:i + oid_l]); i += oid_l
            val_tag = resp[i]; val_l, i = decode_ber_len(resp, i + 1)
            raw = resp[i:i + val_l]
            if val_tag in (0x80, 0x81, 0x82):
                return resp_oid, None, None
            return resp_oid, val_tag, raw
        except Exception:
            return None, None, None
    return None, None, None

def show_raw(raw, label=""):
    if raw is None:
        return
    # Check if it looks like a BDC response
    if raw.startswith(b"\x00@BDC"):
        text = raw.decode('utf-8', errors='replace')
        print(f"  BDC response ({len(raw)}B): {text[:120].replace(chr(10), ' ')!r}")
    else:
        preview = raw[:64].hex()
        print(f"  Raw ({len(raw)}B): {preview}")
        # Try to show as ASCII if printable
        try:
            text = raw.decode('utf-8', errors='replace')
            if sum(32 <= ord(c) < 127 for c in text) > len(text) * 0.7:
                print(f"  Text: {text[:120]!r}")
        except:
            pass


print("=" * 70)
print("probe_vi.py — vi: and other BDC command probes")
print(f"Printer: {PRINTER}  Community: {COMMUNITY}")
print("=" * 70)

# ── Section 1: Walk the BDC command OID space ─────────────────────────────────
# The full subtree for BDC commands is:
# 1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1.[cmd1].[cmd2].[params...]
# Known commands: ji (106.105), ex (101.120)
# Unknown: vi (118.105), jx (106.120), st (115.116), others

BDC_BASE = "1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1"

print(f"\n=== Section 1: Walk BDC subtree {BDC_BASE} ===")
print("(Finding what BDC commands the printer supports)")

current = BDC_BASE
seen_cmds = set()
for step in range(200):
    pkt = make_getnext(COMMUNITY, current)
    resp_oid, tag, raw = snmp_query(pkt)

    if resp_oid is None:
        print(f"  timeout at step {step}")
        break
    if not resp_oid.startswith(BDC_BASE):
        print(f"  Left subtree at: {resp_oid}")
        break

    # Extract the command bytes from OID
    suffix = resp_oid[len(BDC_BASE)+1:]
    parts = suffix.split(".")[:2]
    if len(parts) >= 2:
        try:
            c1, c2 = int(parts[0]), int(parts[1])
            cmd = chr(c1) + chr(c2) if 32 <= c1 < 127 and 32 <= c2 < 127 else f"{c1}.{c2}"
            if cmd not in seen_cmds:
                seen_cmds.add(cmd)
                print(f"  Found cmd: {cmd!r}  (OID suffix: {suffix[:30]})")
        except:
            pass

    if tag is not None and raw and len(raw) > 4:
        print(f"    → {resp_oid}")
        show_raw(raw)

    current = resp_oid
    time.sleep(0.05)

print(f"\nUnique BDC commands found: {sorted(seen_cmds)}")

# ── Section 2: vi: command probes ─────────────────────────────────────────────
# OID: 1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1.118.105.[params].[job_index]
# 'v' = 118, 'i' = 105

print("\n=== Section 2: vi: command probes (118.105.*) ===")
VI_BASE = f"{BDC_BASE}.118.105"

# Try walking from vi: base
print("Walking from vi: base:")
pkt = make_getnext(COMMUNITY, VI_BASE)
resp_oid, tag, raw = snmp_query(pkt)
if resp_oid and resp_oid.startswith(BDC_BASE):
    print(f"  First entry after vi:: {resp_oid}")
    show_raw(raw)
elif resp_oid:
    print(f"  No vi: entries found (jumped to: {resp_oid})")

# Try specific vi: OIDs with various parameter patterns
# BDC vi: command signature: vi:00: or vi:XX: where XX is a 2-char hex param
vi_oids = [
    # Pattern: vi:XX: where XX is 0x00 = 0.0 in OID
    f"{VI_BASE}.2.0.0.0",        # 2 params = 00 hex
    f"{VI_BASE}.3.0.0.0.0",      # 3 params
    f"{VI_BASE}.2.48.48.0",      # "00" as ASCII
    f"{VI_BASE}.1.0.0",          # 1 param = 0
    f"{VI_BASE}.0.0",            # no params, job 0
    f"{VI_BASE}.3.0.0.0",        # 3 params
    f"{VI_BASE}.2.0.0",          # 2 params, no job
    f"{VI_BASE}.8.0.1.0.0.0.27.0.7.0",  # same params as ex:
    f"{VI_BASE}.8.0.1.0.0.0.27.0.7.0.0",  # same + job 0
    # vi:00: encoded as bytes: '0'=48, '0'=48, ':'=58
    f"{VI_BASE}.3.48.48.58.0",
    # Try job-indexed vi:
    f"{VI_BASE}.3.0.0.0.0",  # job 0
    f"{VI_BASE}.3.0.0.0.1",  # job 1
]

for oid in vi_oids:
    pkt = make_get(COMMUNITY, oid)
    resp_oid, tag, raw = snmp_query(pkt)
    if raw and len(raw) > 0:
        print(f"  HIT: {oid}")
        show_raw(raw)
    time.sleep(0.1)

# ── Section 3: ex: with job index ────────────────────────────────────────────
# The Wireshark capture showed one ex: query. Let's try ex: for each job.
# ex: OID from Wireshark: 1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1.101.120.8.0.1.0.0.0.27.0.7.0

print("\n=== Section 3: ex: command for jobs 0-9 ===")
# Try appending job index to the ex: OID
EX_OID_BASE = f"{BDC_BASE}.101.120.8.0.1.0.0.0.27.0.7.0"

for job_n in range(10):
    oid = f"{EX_OID_BASE}.{job_n}"
    pkt = make_get(COMMUNITY, oid)
    resp_oid, tag, raw = snmp_query(pkt)
    if raw and len(raw) > 0:
        print(f"\n  Job {job_n}: {oid}")
        show_raw(raw)
        # Try to parse TLV
        if raw and len(raw) > 4:
            # BDC ex: response TLV parser
            # Skip BDC header
            bdc_header = b"\x00@BDC PS\r\nex:"
            if raw.startswith(bdc_header):
                data = raw[len(bdc_header):]
                print(f"  ex: TLV data ({len(data)} bytes):")
                i = 0
                while i < len(data) - 1:
                    tag_b = data[i]
                    if i + 1 >= len(data):
                        break
                    ln = data[i+1]
                    if i + 2 + ln > len(data):
                        break
                    chunk = data[i+2:i+2+ln]
                    # Try to decode as various types
                    hex_str = chunk.hex()
                    text = ""
                    try:
                        if all(32 <= b < 127 for b in chunk):
                            text = chunk.decode('ascii')
                    except:
                        pass
                    uint32 = struct.unpack('>I', chunk[:4])[0] if len(chunk) >= 4 else None
                    print(f"    tag=0x{tag_b:02x} len={ln}: hex={hex_str[:32]}{' text='+repr(text) if text else ''}{' uint32='+str(uint32) if uint32 is not None else ''}")
                    i += 2 + ln
    else:
        print(f"  Job {job_n}: no response")
    time.sleep(0.1)

# ── Section 4: Try ex: without job index for the ink usage ───────────────────
print("\n=== Section 4: ex: variants (different parameter combos) ===")
# Try different parameter bytes for ex: — some might return ink usage
ex_variants = [
    # Original Wireshark version
    f"{BDC_BASE}.101.120.8.0.1.0.0.0.27.0.7.0",
    # Try with ink-specific params
    f"{BDC_BASE}.101.120.8.0.1.0.0.0.27.0.6.0",  # param 6 instead of 7
    f"{BDC_BASE}.101.120.8.0.1.0.0.0.27.0.8.0",  # param 8
    f"{BDC_BASE}.101.120.8.0.1.0.0.0.27.0.9.0",  # param 9
    f"{BDC_BASE}.101.120.8.0.2.0.0.0.27.0.7.0",  # param 2 (was 1)
    # Different OID lengths
    f"{BDC_BASE}.101.120.4.0.1.0.27.0",
    f"{BDC_BASE}.101.120.6.0.1.0.0.0.27.0",
]

for oid in ex_variants:
    pkt = make_get(COMMUNITY, oid)
    resp_oid, tag, raw = snmp_query(pkt)
    if raw and len(raw) > 10:
        print(f"\n  HIT: {oid}")
        show_raw(raw)
    time.sleep(0.1)

# ── Section 5: Try other BDC commands with job index ─────────────────────────
print("\n=== Section 5: Other BDC commands with job 0 index ===")
# Try all plausible 2-char command codes (lowercase letters, common combinations)
commands = [
    (106, 120, "jx"),   # jx (extended job)
    (115, 116, "st"),   # st (status)
    (106, 108, "jl"),   # jl (job log?)
    (105, 106, "ij"),   # ij?
    (106, 100, "jd"),   # jd?
    (106, 115, "js"),   # js?
    (106, 118, "jv"),   # jv?
    (100, 105, "di"),   # di?
    (105, 110, "in"),   # in?
    (105, 107, "ik"),   # ik?
    (118, 106, "vj"),   # vj?
    (118, 117, "vu"),   # vu?
    (117, 115, "us"),   # us (usage?)
    (117, 105, "ui"),   # ui (usage ink?)
    (107, 106, "kj"),   # kj?
    (97,  105, "ai"),   # ai?
]

for c1, c2, name in commands:
    # Try with the same parameter structure as ji:
    for params, label in [
        (f".3.0.0.0.0", "ji-style params, job 0"),
        (f".3.0.0.0.1", "ji-style params, job 1"),
    ]:
        oid = f"{BDC_BASE}.{c1}.{c2}{params}"
        pkt = make_get(COMMUNITY, oid)
        resp_oid, tag, raw = snmp_query(pkt)
        if raw and len(raw) > 10:
            print(f"\n  HIT: {name} ({c1}.{c2}) {label}")
            print(f"  OID: {oid}")
            show_raw(raw)
    time.sleep(0.1)

print("\n\n=== Done ===")
print("Check log for any HITs — those are alternative BDC command responses.")
