"""
Fixed float analysis + jump table decode for AnalysisJobLog.

Key finding so far: ZERO float/SSE ops in AnalysisJobLog (0x50c0 - 0x9000).
This means the DLL processes ink data as pure integers, not floats.
Or: the 208-byte blob is not ink data at all — only the plaintext suffix matters.

This script:
1. Fixes the jump table read (section-relative offsets)
2. Shows what each of the 35 cases actually does
3. Checks all callees for float ops (to find the integer→float conversion)
4. Analyzes the 208-byte blob as various integer formats
5. Re-examines whether 'F\x00' / 'G\x00' header byte = case selector
"""

import struct, sys
try:
    import pefile, capstone
except ImportError:
    sys.exit("pip install pefile capstone")

DLL_PATH   = "extracted/SCP7595.dll"
IMAGE_BASE = 0x180000000

pe = pefile.PE(DLL_PATH)
text_sec  = next(s for s in pe.sections if s.Name.startswith(b'.text'))
rdata_sec = next(s for s in pe.sections if s.Name.startswith(b'.rdata'))

TEXT_VA    = IMAGE_BASE + text_sec.VirtualAddress   # full VA
TEXT_RVA   = text_sec.VirtualAddress                # just RVA (0x1000)
TEXT_RAW   = text_sec.get_data()
RDATA_VA   = IMAGE_BASE + rdata_sec.VirtualAddress
RDATA_RAW  = rdata_sec.get_data()

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

FLOAT_MNE = {
    'cvtsi2ss','cvtsi2sd','cvtss2sd','cvtsd2ss',
    'mulss','mulsd','divss','divsd','addss','addsd','subss','subsd',
    'movss','movsd','sqrtss','sqrtsd',
    'fmul','fdiv','fadd','fsub','fild','fist','fistp','fld','fst','fstp',
    'ucomisd','ucomiss','comiss','comisd',
}

def sec_off(va):
    """Offset into TEXT_RAW for a given VA."""
    return va - TEXT_VA

def disasm_at(va, n=512, stop_ret=True):
    off = sec_off(va)
    data = TEXT_RAW[off:off+n]
    insns = []
    for i, ins in enumerate(md.disasm(data, va)):
        insns.append(ins)
        if ins.mnemonic in ('ret','retn') and i > 2 and stop_ret:
            break
        if i > 300:
            break
    return insns

def fp_ops(va, n=2048):
    off = sec_off(va)
    if off < 0 or off >= len(TEXT_RAW):
        return []
    data = TEXT_RAW[off:off+n]
    hits = []
    for ins in md.disasm(data, va):
        if ins.mnemonic.lower() in FLOAT_MNE:
            hits.append(ins)
        if ins.mnemonic in ('ret','retn') and hits:
            break
        if len(hits) > 50:
            break
    return hits

# ── 1. Confirm zero float ops in AnalysisJobLog ───────────────────────────────
print("="*70)
print("1. Float ops scan: AnalysisJobLog 0x50c0 through 0x9000")
print("="*70)
off_start = sec_off(0x1800050c0)
off_end   = sec_off(0x180009000)
data = TEXT_RAW[off_start:off_end]
fp_hits = []
for ins in md.disasm(data, 0x1800050c0):
    if ins.mnemonic.lower() in FLOAT_MNE:
        fp_hits.append(ins)
print(f"Float/SSE instructions: {len(fp_hits)}")
for ins in fp_hits:
    print(f"  {ins.address:#x}  {ins.mnemonic}  {ins.op_str}")

# ── 2. Fix: read jump table correctly ─────────────────────────────────────────
print("\n"+"="*70)
print("2. Jump table at RVA 0x856c (IMAGE_BASE-relative offsets)")
print("="*70)

JMPTBL_RVA = 0x856c
jmptbl_off = JMPTBL_RVA - TEXT_RVA   # offset in TEXT_RAW = 0x756c
print(f"Jump table offset in TEXT_RAW: {jmptbl_off:#x}")
print(f"Bytes at table: {TEXT_RAW[jmptbl_off:jmptbl_off+16].hex()}")

entries = []
for i in range(35):
    rel32 = struct.unpack_from('<i', TEXT_RAW, jmptbl_off + i*4)[0]
    # target = IMAGE_BASE + rel32  (rel32 is RVA of target)
    # But wait: add rcx, r10 where r10=IMAGE_BASE, and ecx = [table+rax*4]
    # So ecx = rel32, rcx = IMAGE_BASE + rel32 (zero-extended from 32-bit)
    target_va = (IMAGE_BASE + rel32) & 0xFFFFFFFFFFFFFFFF
    # But rel32 is signed: if negative, that's wrong for a code VA
    # Check if target is in .text range
    in_text = (TEXT_VA <= target_va < TEXT_VA + len(TEXT_RAW))
    entries.append((i+1, rel32, target_va, in_text))
    print(f"  case {i+1:2d}  rel32={rel32:+#011x}  target={target_va:#x}  {'✓' if in_text else 'INVALID'}")

# ── 3. Disassemble each valid case ────────────────────────────────────────────
print("\n"+"="*70)
print("3. Disassemble first instruction of each valid switch case")
print("="*70)
unique_valid = {}
for case_i, rel, tgt, ok in entries:
    if ok and tgt not in unique_valid:
        unique_valid[tgt] = []
    if ok:
        unique_valid[tgt].append(case_i)

for tgt, cases in sorted(unique_valid.items()):
    insns = disasm_at(tgt, n=128, stop_ret=False)[:5]
    fp = fp_ops(tgt, n=512)
    print(f"\n  cases {cases} → {tgt:#x}  {'[HAS FLOAT OPS]' if fp else ''}")
    for ins in insns:
        print(f"    {ins.address:#x}  {ins.mnemonic:<8}  {ins.op_str}")
    for fins in fp[:3]:
        print(f"    >>> FLOAT: {fins.address:#x}  {fins.mnemonic}  {fins.op_str}")

# ── 4. Float ops in ALL callees of AnalysisJobLog ─────────────────────────────
print("\n"+"="*70)
print("4. Float ops in all AnalysisJobLog callees")
print("="*70)
CALLEES = [
    0x180001000, 0x1800014a0, 0x1800015c0, 0x1800017b0, 0x1800018b0,
    0x180001910, 0x180001bb0, 0x180001e30, 0x1800028c0, 0x180002f00,
    0x1800032d0, 0x180003440, 0x1800037f0, 0x180003890, 0x180003b30,
    0x180003ba0, 0x180003e70, 0x1800047c0, 0x1800049b0, 0x180004f70,
    0x18000c820, 0x18000c9a0, 0x18000e5d4, 0x18000e6d8, 0x18000e904,
    0x18000ef04, 0x18000fe78, 0x180010780, 0x180010a50, 0x180010dc8,
    0x180010e40, 0x18014fc40, 0x18015027c, 0x1801513f8, 0x1801542f0,
]
for va in CALLEES:
    fp = fp_ops(va, n=2048)
    if fp:
        print(f"\n  callee@{va:#x} — {len(fp)} float ops:")
        for ins in fp:
            print(f"    {ins.address:#x}  {ins.mnemonic:<8}  {ins.op_str}")

# ── 5. Broad scan: entire .text for any float ops ─────────────────────────────
print("\n"+"="*70)
print("5. Entire .text section: count float-op-containing functions")
print("="*70)
func_starts = set()
fp_func_count = 0
current_func_start = TEXT_VA
current_func_has_fp = False
fp_funcs = []

for ins in md.disasm(TEXT_RAW, TEXT_VA):
    if ins.mnemonic.lower() in FLOAT_MNE:
        current_func_has_fp = True
    if ins.mnemonic in ('ret', 'retn'):
        if current_func_has_fp:
            fp_func_count += 1
            fp_funcs.append(current_func_start)
        current_func_has_fp = False
        current_func_start = ins.address + ins.size

print(f"Functions containing float ops: {fp_func_count}")
print("First 20 float-op function starts:")
for va in fp_funcs[:20]:
    print(f"  {va:#x}")

# ── 6. Re-examine the plaintext suffix structure ──────────────────────────────
print("\n"+"="*70)
print("6. Analysis of suffix structure — what do tags 0x0e and 0x00 contain?")
print("="*70)

# From the hex dump, suffix = F\x00\x07\x0e... or G\x00\x07\x0f...
# F = 0x46 = 70, G = 0x47 = 71
# Then \x00 separator
# Then TLV fields

# Key question: what does tag 0x0e contain?
# From blob 0: \x0e\x00\x3b\x0c at end of suffix
# 0x0e = tag, 0x00 = len=0, so it's a zero-length field
# Then \x3b = 59, \x0c = 12 — these might be additional separate fields

# Alternative parse: \x0e is tag, \x00\x3b = 16-bit length?
# or: \x0e\x00 = tag+subtype like \x00\x07, \x0e\x3b, \x0c = 3-byte field?

# Let's look at all 10 suffixes again and find pattern
pcap_suffixes = [
    bytes.fromhex("4600070e616e64726561736f7374626572670820"),  # blob 0
    bytes.fromhex("4600070e616e64726561736f7374626572670820"),  # same user, diff job
    bytes.fromhex("470007"),
]

# Manual decode from B3 output
suffixes_raw = [
    b'F\x00\x07\x0eandreasostberg\x08 Bron_50x70.pdf - Page 1 of 1, rs\x09\x10GBadmins-Pro.loc\x0e\x00;\x0c',
    b'F\x00\x07\x0eandreasostberg\x08 crane_reflections_50x70.pdf - Pa\x09\x10GBadmins-Pro.loc\x0e\x00;\x0c',
    b'G\x00\x07\x0fdorotalukianska\x08 30x40isf\xc3\xb6tter.jpg, 36x228d\xc3\xb6rr \x09\x10GBadmins-Pro.loc\x0e\x00;\x0c',
    b'G\x00\x07\x0fdorotalukianska\x08 26x24,5 jippi jag har betalat 18\x09\x10GBadmins-Pro.loc\x0e\x00;\x0c',
    b'G\x00\x07\x0fdorotalukianska\x08 30x19regeringbr\xc3\xa5k4.jpg, 40x27.j\x09\x10GBadmins-Pro.loc\x0e\x00;\x0c',
    b'G\x00\x07\x0fdorotalukianska\x08 23x32ny.jpg, 25,5x25,5.jpg, 35x2\x09\x10GBadmins-Pro.loc\x0e\x00;\x0c',
]

for i, s in enumerate(suffixes_raw):
    print(f"\nSuffix blob[{i}] ({len(s)} bytes):")
    j = 0
    while j < len(s):
        tag = s[j]; j += 1
        if j >= len(s): break
        if tag == 0x00:
            # special: 00 XX len data
            sub = s[j]; j += 1
            if j >= len(s): break
            ln = s[j]; j += 1
            val = s[j:j+ln]; j += ln
            txt = val.decode('utf-8', errors='replace')
            print(f"  tag=0x00 subtype=0x{sub:02x} len={ln} → {txt!r}")
        elif tag in (0x46, 0x47):
            print(f"  header=0x{tag:02x} ({'F' if tag==0x46 else 'G'})")
            j += 1  # skip 0x00
        elif tag == 0x0e:
            ln = s[j]; j += 1
            val = s[j:j+ln]; j += ln
            print(f"  tag=0x0e len={ln} → {val.hex()!r}")
        else:
            if j >= len(s): break
            ln = s[j]; j += 1
            val = s[j:j+ln]; j += ln
            txt = ''.join(chr(b) if 32<=b<127 else f'\\x{b:02x}' for b in val)
            print(f"  tag=0x{tag:02x} len={ln} → {txt!r}")

# ── 7. What does the 'F'/'G' header byte indicate? ─────────────────────────────
print("\n"+"="*70)
print("7. F/G header and \\x00 after it — likely version or record type")
print("   F=0x46=70, G=0x47=71 (consecutive ASCII letters)")
print("   Check if F/G correlates with username length or other fields")
print("="*70)

jobs_info = [
    # (blob_header, username, username_len)
    (0x46, 'andreasostberg', 14),  # 0x0e=14
    (0x46, 'andreasostberg', 14),
    (0x47, 'dorotalukianska', 15), # 0x0f=15
    (0x47, 'dorotalukianska', 15),
    (0x47, 'dorotalukianska', 15),
    (0x47, 'dorotalukianska', 15),
]
print("header  username_len  → F=0x46 when len=14, G=0x47 when len=15")
print("This means header = 0x38 + username_len (0x38+14=0x46, 0x38+15=0x47)")
print("OR: header = 0x46 is baseline, increments with username length ≥ 15")
print("LIKELY: header encodes the username length as ASCII 'F'=len14, 'G'=len15")

# ── 8. Now: what does the BINARY SECTION actually encode? ─────────────────────
print("\n"+"="*70)
print("8. Binary section re-analysis — try uint24 BE (3-byte per value)")
print("   208 bytes / 3 = 69.3 (not clean)")
print("   208 bytes = 26 × 8-byte values")
print("   208 bytes = 13 × 16-byte values = 13 ink channels × 16 bytes each")
print("   208 bytes = 52 × 4-byte values")
print("="*70)

# Extract blobs from pcap for analysis
import struct as _struct
PCAP = "lfp_accounting/full-dump.pcap"

def parse_pcap_ji():
    blobs = {}
    with open(PCAP, 'rb') as f:
        magic = f.read(4)
        endian = '<' if magic == b'\xd4\xc3\xb2\xa1' else '>'
        f.read(20)
        while True:
            hdr = f.read(16)
            if len(hdr) < 16: break
            ts_s, ts_us, cap_len, _ = _struct.unpack(endian + 'IIII', hdr)
            frame = f.read(cap_len)
            # Extract UDP payload (Ethernet → IP → UDP)
            try:
                if frame[12:14] != b'\x08\x00': continue
                ihl = (frame[14] & 0xf) * 4
                if frame[14+9] != 17: continue  # not UDP
                src_port = _struct.unpack_from('>H', frame, 14+ihl)[0]
                dst_port = _struct.unpack_from('>H', frame, 14+ihl+2)[0]
                if src_port != 161: continue  # not SNMP response
                udp_payload = frame[14+ihl+8:]
                # Find ji: in payload
                pos = udp_payload.find(b'ji:')
                if pos < 0: continue
                ji_data = udp_payload[pos:]
                # Parse: ji: + \x00 + 2-byte job idx BE + \xd0\x00 + 208-byte blob
                if len(ji_data) < 8: continue
                job_idx = _struct.unpack_from('>H', ji_data, 4)[0]
                if ji_data[3] != 0x00: continue
                if ji_data[6:8] != b'\xd0\x00': continue
                blob = ji_data[8:8+208]
                if len(blob) == 208 and job_idx not in blobs:
                    blobs[job_idx] = blob
            except: continue
    return blobs

blobs = parse_pcap_ji()
print(f"Extracted {len(blobs)} unique blobs (jobs: {sorted(blobs.keys())})")

# Print all 10 blobs as 26 uint64 LE values
print("\n10 blobs as 26 × uint64 LE:")
print(f"  {'Offset':>6}", end='')
for j in sorted(blobs.keys())[:6]:
    print(f"  {'job'+str(j):>22}", end='')
print()
for off in range(0, 208, 8):
    print(f"  {off:6d}", end='')
    for j in sorted(blobs.keys())[:6]:
        v = _struct.unpack_from('<Q', blobs[j], off)[0]
        print(f"  {v:22d}", end='')
    print()

# Check if any column (offset) has values that are monotonically increasing
# across jobs 0-9 (would indicate cumulative counters)
print("\nMonotonicity check (uint32 LE at each 4-byte offset):")
job_keys = sorted(blobs.keys())
print(f"Offset  ", end='')
for j in job_keys[:10]:
    print(f"  j{j:02d}  ", end='')
print("  type")

mono_offsets = []
for off in range(0, 205, 4):
    vals = [_struct.unpack_from('<I', blobs[j], off)[0] for j in job_keys if off+4 <= len(blobs[j])]
    mono = all(vals[i] <= vals[i+1] for i in range(len(vals)-1))
    anti = all(vals[i] >= vals[i+1] for i in range(len(vals)-1))
    flag = "MONO↑" if mono else ("MONO↓" if anti else "")
    if flag:
        mono_offsets.append((off, flag, vals))
        v_str = ' '.join(f'{v:8d}' for v in vals[:8])
        print(f"  [{off:3d}]  {v_str}  {flag}")

if not mono_offsets:
    print("  (no monotonic offsets found)")

print("\nDone.")
