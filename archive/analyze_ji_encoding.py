"""
Two-pronged analysis:
A) Disassemble func@0x18000c9a0 and func@0x18000c820 from SCP7595.dll
   — these are the main processors of the ji: binary section
B) Re-examine ji: SNMP responses from the pcap with multiple encoding interpretations:
   - UTF-16LE text (each "byte" might be a 2-byte char)
   - The "208" might be character count not byte count
   - Try to find printable ASCII or float32 LE/BE patterns in the data
   - Try to find int16 or int32 little-endian values that match ink quantities
"""

import struct
import sys
import os

# ─── Part A: DLL disassembly ──────────────────────────────────────────────────
try:
    import pefile, capstone
    HAS_DLL = True
except ImportError:
    HAS_DLL = False
    print("pefile/capstone not available — skipping DLL section")

DLL_PATH = "extracted/SCP7595.dll"
IMAGE_BASE = 0x180000000

if HAS_DLL and os.path.exists(DLL_PATH):
    pe = pefile.PE(DLL_PATH)
    text_section = next(s for s in pe.sections if s.Name.startswith(b'.text'))
    TEXT_VA   = IMAGE_BASE + text_section.VirtualAddress
    TEXT_DATA = text_section.get_data()

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    def disasm_func(va, max_bytes=4096, max_insns=400):
        rva = va - IMAGE_BASE
        offset = pe.get_offset_from_rva(rva)
        raw_off = offset - text_section.PointerToRawData
        data = TEXT_DATA[raw_off:raw_off + max_bytes]
        insns = []
        for i, insn in enumerate(md.disasm(data, va)):
            insns.append(insn)
            if i >= max_insns:
                break
            if insn.mnemonic in ('ret', 'retn') and i > 3:
                break
        return insns

    def find_calls(va, max_bytes=4096):
        rva = va - IMAGE_BASE
        offset = pe.get_offset_from_rva(rva)
        raw_off = offset - text_section.PointerToRawData
        data = TEXT_DATA[raw_off:raw_off + max_bytes]
        calls = []
        for insn in md.disasm(data, va):
            if insn.mnemonic == 'call':
                try:
                    tgt = int(insn.op_str, 16)
                    if IMAGE_BASE <= tgt < IMAGE_BASE + 0x200000:
                        calls.append((insn.address, tgt))
                except ValueError:
                    pass
            if insn.mnemonic in ('ret', 'retn'):
                break
        return calls

    print("=" * 70)
    print("A. SCP7595.dll — func@0x18000c9a0 (processes large data blocks)")
    print("=" * 70)
    for insn in disasm_func(0x18000c9a0, max_bytes=4096):
        print(f"  {insn.address:#x}  {insn.mnemonic:<8}  {insn.op_str}")

    print()
    print("=" * 70)
    print("A2. SCP7595.dll — func@0x18000c820")
    print("=" * 70)
    for insn in disasm_func(0x18000c820, max_bytes=4096):
        print(f"  {insn.address:#x}  {insn.mnemonic:<8}  {insn.op_str}")

    print()
    print("=" * 70)
    print("A3. Calls within func@0x18000c9a0")
    print("=" * 70)
    for src, tgt in find_calls(0x18000c9a0):
        print(f"  {src:#x}  ->  {tgt:#x}")


# ─── Part B: pcap ji: data re-analysis ───────────────────────────────────────
print()
print("=" * 70)
print("B. Re-examining ji: SNMP responses from pcap")
print("=" * 70)

PCAP = "lfp_accounting/full-dump.pcap"

def parse_pcap(path):
    """Yield (ts, data) tuples from a pcap file."""
    with open(path, 'rb') as f:
        magic = f.read(4)
        if magic == b'\xd4\xc3\xb2\xa1':
            endian = '<'
        elif magic == b'\xa1\xb2\xc3\xd4':
            endian = '>'
        else:
            raise ValueError(f"Not a pcap: {magic.hex()}")
        ver_maj, ver_min, tz, ts_acc, snap, link = struct.unpack(endian + 'HHiIII', f.read(20))
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            ts_sec, ts_usec, cap_len, orig_len = struct.unpack(endian + 'IIII', hdr)
            data = f.read(cap_len)
            yield ts_sec + ts_usec * 1e-6, data, link

def extract_udp_payload(frame, link_type):
    """Extract UDP payload from Ethernet frame."""
    try:
        if link_type == 1:  # Ethernet
            eth_hdr = frame[:14]
            if frame[12:14] != b'\x08\x00':  # not IPv4
                return None, None, None
            ip = frame[14:]
        else:
            return None, None, None

        ihl = (ip[0] & 0x0F) * 4
        proto = ip[9]
        if proto != 17:  # not UDP
            return None, None, None

        src_ip = '.'.join(str(b) for b in ip[12:16])
        dst_ip = '.'.join(str(b) for b in ip[16:20])
        udp = ip[ihl:]
        src_port = struct.unpack('>H', udp[0:2])[0]
        dst_port = struct.unpack('>H', udp[2:4])[0]
        payload = udp[8:]
        return (src_ip, src_port), (dst_ip, dst_port), payload
    except:
        return None, None, None

def parse_snmp_ji(payload):
    """
    Find ji: BDC data in an SNMP response.
    OID tail for ji: ends in .106.105.3.0.0.0.N
    The value is an OctetString (type 0x04).
    Returns (job_idx, raw_bytes) or None.
    """
    # Look for BER OctetString (0x04) after the ji: OID pattern
    # OID bytes for 106 105 (j i) in BER: 0x6a 0x69
    ji_marker = bytes([0x6a, 0x69])  # 'j','i' as single OID sub-identifiers

    # Find 'ji:' literal in text response (for ASCII-encoded SNMP values)
    pos = payload.find(b'ji:')
    if pos >= 0:
        return ('ascii', pos, payload[pos:pos+300])

    # Find OctetString value blobs — look for 0x04 <len> where len >= 200
    for i in range(len(payload) - 4):
        if payload[i] == 0x04:  # BER OctetString
            # Multi-byte length
            if payload[i+1] & 0x80:
                num_len_bytes = payload[i+1] & 0x7F
                if num_len_bytes == 1:
                    val_len = payload[i+2]
                    val_start = i + 3
                elif num_len_bytes == 2:
                    val_len = struct.unpack('>H', payload[i+2:i+4])[0]
                    val_start = i + 4
                else:
                    continue
            else:
                val_len = payload[i+1]
                val_start = i + 2

            if val_len >= 50 and val_start + val_len <= len(payload):
                val = payload[val_start:val_start + val_len]
                # Check if this contains 'ji:' signature
                if b'ji:' in val or val[:3] in (b'ji:', b'\x6a\x69\x3a'):
                    return ('ber', val_start, val)
    return None

# Parse pcap and collect ji: responses
ji_responses = []
link_type = None

for ts, frame, ltype in parse_pcap(PCAP):
    if link_type is None:
        link_type = ltype
    src, dst, payload = extract_udp_payload(frame, ltype)
    if payload is None:
        continue
    # SNMP response = source port 161
    if src and src[1] == 161 and len(payload) > 50:
        result = parse_snmp_ji(payload)
        if result:
            ji_responses.append((ts, src, dst, result, payload))

print(f"Found {len(ji_responses)} packets with ji: data")

# Group by job index (last 1-2 bytes of OID)
# Extract just the SNMP value bytes for each unique ji: response
seen_hashes = set()
unique_ji = []

for ts, src, dst, result, full_payload in ji_responses:
    kind, pos, data = result
    h = hash(data[:50])
    if h not in seen_hashes:
        seen_hashes.add(h)
        unique_ji.append((ts, kind, data, full_payload))

print(f"Unique ji: responses: {len(unique_ji)}")
print()

# Detailed analysis of first 3 unique responses
for i, (ts, kind, data, full_payload) in enumerate(unique_ji[:5]):
    print(f"{'─'*70}")
    print(f"ji: response #{i+1} (kind={kind}, {len(data)} bytes)")
    print(f"  First 80 bytes hex: {data[:80].hex()}")
    print(f"  As ASCII: {data[:80]}")
    print()

    # Look for the structure: header + job_idx + length + binary + suffix
    # Try to find the binary block
    # The ji: prefix looks like: ji:\x00\x01... or ji: + field data

    if b'ji:' in data:
        ji_pos = data.index(b'ji:')
        after_ji = data[ji_pos + 3:]
        print(f"  After 'ji:' marker ({len(after_ji)} bytes):")
        print(f"    hex: {after_ji[:60].hex()}")

        # Try to find the binary blob boundary
        # Looking for 0xD0 00 (LE) or 00 D0 (BE) = 208
        for off in range(len(after_ji) - 2):
            v16_le = struct.unpack_from('<H', after_ji, off)[0]
            v16_be = struct.unpack_from('>H', after_ji, off)[0]
            if v16_le == 208:
                print(f"    LE 208 at +{off}: blob starts at +{off+2}, len=208")
                blob = after_ji[off+2:off+2+208]
                print(f"    blob hex: {blob[:32].hex()}...")
                print(f"    suffix:   {after_ji[off+2+208:off+2+208+40]}")

                # Analyze the 208-byte blob
                print(f"\n    Blob analysis ({len(blob)} bytes):")
                print(f"      Unique byte values: {len(set(blob))}")
                print(f"      Zero bytes: {blob.count(0)}")
                print(f"      Non-zero: {len(blob) - blob.count(0)}")

                # Try treating as int16 LE array
                print(f"      As int16 LE: {[struct.unpack_from('<h', blob, j)[0] for j in range(0,32,2)]}")
                print(f"      As int16 BE: {[struct.unpack_from('>h', blob, j)[0] for j in range(0,32,2)]}")

                # Try treating as int32 LE array
                print(f"      As int32 LE: {[struct.unpack_from('<i', blob, j)[0] for j in range(0,48,4)]}")

                # Try as float32 LE
                f32 = [struct.unpack_from('<f', blob, j)[0] for j in range(0,48,4)]
                print(f"      As f32 LE:  {[f'{v:.3f}' for v in f32]}")

                # Try as float64 LE
                f64 = [struct.unpack_from('<d', blob, j)[0] for j in range(0,48,8)]
                print(f"      As f64 LE:  {[f'{v:.3f}' for v in f64]}")

                # Try XOR with common keys
                for key in [0xFF, 0x55, 0xAA, 0x5A, 0xA5]:
                    xored = bytes(b ^ key for b in blob[:48])
                    f32_xor = [struct.unpack_from('<f', xored, j)[0] for j in range(0,48,4)]
                    in_range = [v for v in f32_xor if 0 <= v <= 500]
                    if len(in_range) > 4:
                        print(f"      XOR {key:#x} → f32 in-range: {in_range[:12]}")

                break
            elif v16_be == 208:
                print(f"    BE 208 at +{off}: blob might start at +{off+2}")
                break

    # Also check full payload for structure
    print(f"\n  Full response structure scan:")
    # Try to find tags 0x07, 0x08, 0x09 (username, jobname, machinename)
    for tag in [0x07, 0x08, 0x09, 0x00]:
        idx = data.find(bytes([tag]))
        if idx >= 0:
            print(f"    tag {tag:#04x} at offset {idx}: context = {data[max(0,idx-4):idx+8].hex()}")

print()
print("=" * 70)
print("B2. Full hex dump of first unique ji: response")
print("=" * 70)
if unique_ji:
    ts, kind, data, full_payload = unique_ji[0]
    print(f"Length: {len(data)} bytes")
    for row in range(0, min(len(data), 512), 16):
        chunk = data[row:row+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        asc_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f"  {row:04x}  {hex_part:<47}  {asc_part}")

print()
print("=" * 70)
print("B3. Compare binary blobs across different jobs")
print("=" * 70)

# Collect all binary blobs
blobs = []
for ts, kind, data, full_payload in unique_ji:
    if b'ji:' in data:
        ji_pos = data.index(b'ji:')
        after_ji = data[ji_pos + 3:]
        for off in range(len(after_ji) - 2):
            v16_le = struct.unpack_from('<H', after_ji, off)[0]
            if v16_le == 208:
                blob = after_ji[off+2:off+2+208]
                suffix = after_ji[off+2+208:off+2+300]
                blobs.append((blob, suffix))
                break

print(f"Extracted {len(blobs)} binary blobs")

if len(blobs) >= 2:
    print(f"\nByte-by-byte comparison (first 32 bytes) across {len(blobs)} blobs:")
    print(f"  Offset  ", end='')
    for j in range(min(len(blobs), 6)):
        print(f"  job{j:02d}  ", end='')
    print()

    for off in range(0, 32):
        vals = [blobs[j][0][off] for j in range(min(len(blobs), 6)) if off < len(blobs[j][0])]
        print(f"  {off:3d}    ", end='')
        for v in vals:
            print(f"  0x{v:02x}   ", end='')
        # check if constant
        if len(set(vals)) == 1:
            print("  CONSTANT", end='')
        print()

    print(f"\nByte positions that are constant across ALL blobs:")
    const_positions = []
    for off in range(208):
        vals = [blobs[j][0][off] for j in range(len(blobs)) if off < len(blobs[j][0])]
        if len(set(vals)) == 1:
            const_positions.append((off, vals[0]))
    print(f"  {const_positions[:30]}")

    # Try subtraction between adjacent blobs — if cumulative ink, difference = per-job
    print(f"\nDifference blob[1] - blob[0] as int32 LE (first 12 values = 48 bytes):")
    diff_32 = [struct.unpack_from('<i', blobs[1][0], j)[0] - struct.unpack_from('<i', blobs[0][0], j)[0]
               for j in range(0, 48, 4)]
    print(f"  {diff_32}")

    # Try as uint32
    print(f"\nblob[0] as uint32 LE (first 52 values):")
    u32_0 = [struct.unpack_from('<I', blobs[0][0], j)[0] for j in range(0, min(208, 52*4), 4)]
    print(f"  {u32_0}")
    print(f"\nblob[1] as uint32 LE (first 52 values):")
    u32_1 = [struct.unpack_from('<I', blobs[1][0], j)[0] for j in range(0, min(208, 52*4), 4)]
    print(f"  {u32_1}")

    # Print suffix for each blob
    print(f"\nSuffixes (plaintext after binary blob):")
    for j, (blob, suffix) in enumerate(blobs[:6]):
        printable = ''.join(chr(b) if 32 <= b < 127 else f'\\x{b:02x}' for b in suffix[:80])
        print(f"  blob[{j}]: {printable}")
