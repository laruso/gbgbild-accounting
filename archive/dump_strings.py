"""
Dump all rdata string literals referenced from AnalysisJobLog's switch cases.
The format strings tell us HOW the fields are encoded.

Also dump the format string used in func@0x180002f00 (case 5).
And dump func@0x180001e30 which processes cases 7/8/9.

Critical question: what format string does case 5 (large binary field) use?
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

TEXT_VA  = IMAGE_BASE + text_sec.VirtualAddress
TEXT_RAW = text_sec.get_data()
RDATA_VA  = IMAGE_BASE + rdata_sec.VirtualAddress
RDATA_RAW = rdata_sec.get_data()

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

def read_wstr(va, max_chars=100):
    """Read UTF-16LE string from rdata at VA."""
    off = va - RDATA_VA
    if off < 0 or off >= len(RDATA_RAW):
        return f"<out of rdata: {va:#x}>"
    s = ""
    for i in range(0, min(max_chars*2, len(RDATA_RAW)-off-1), 2):
        c = struct.unpack_from('<H', RDATA_RAW, off+i)[0]
        if c == 0:
            break
        s += chr(c) if 32 <= c < 0x200 else f'\\u{c:04x}'
    return s

def read_astr(va, max_bytes=100):
    """Read ASCII/UTF-8 string from rdata at VA."""
    off = va - RDATA_VA
    if off < 0 or off >= len(RDATA_RAW):
        return f"<out of rdata: {va:#x}>"
    s = ""
    for i in range(min(max_bytes, len(RDATA_RAW)-off)):
        c = RDATA_RAW[off+i]
        if c == 0:
            break
        s += chr(c) if 32 <= c < 127 else f'\\x{c:02x}'
    return s

def read_bytes(va, n=16):
    off = va - RDATA_VA
    return RDATA_RAW[off:off+n] if 0 <= off < len(RDATA_RAW) else b''

def sec_off(va):
    return va - TEXT_VA

def disasm_at(va, n=4096, max_i=300):
    off = sec_off(va)
    data = TEXT_RAW[off:off+n]
    insns = []
    for i, ins in enumerate(md.disasm(data, va)):
        insns.append(ins)
        if ins.mnemonic in ('ret','retn') and i > 2:
            break
        if i >= max_i:
            break
    return insns

# ── 1. Known format string at 0x1801cd1b8 ────────────────────────────────────
print("="*70)
print("1. Known format strings in rdata")
print("="*70)
for va, label in [
    (0x1801cd1b8, "case 1/2/13 format string"),
]:
    raw = read_bytes(va, 32)
    wstr = read_wstr(va)
    astr = read_astr(va)
    print(f"  {va:#x}  {label}")
    print(f"    wstr: {wstr!r}")
    print(f"    astr: {astr!r}")
    print(f"    raw:  {raw.hex()}")

# ── 2. Scan ALL rip-relative rdx/r8 loads in key functions ───────────────────
print("\n"+"="*70)
print("2. All rdata string refs from AnalysisJobLog + func@0x180002f00")
print("="*70)

import re
def find_rdata_refs(va, n=8192, label=""):
    off = sec_off(va)
    data = TEXT_RAW[off:off+n]
    hits = []
    for ins in md.disasm(data, va):
        if 'rip' in ins.op_str:
            m = re.search(r'\[rip \+ (0x[0-9a-f]+)\]', ins.op_str)
            if m:
                rel = int(m.group(1), 16)
                next_va = ins.address + ins.size
                target = next_va + rel
                if RDATA_VA <= target < RDATA_VA + len(RDATA_RAW):
                    wstr = read_wstr(target, 60)
                    raw = read_bytes(target, 16)
                    hits.append((ins.address, target, ins.mnemonic, ins.op_str, wstr, raw))
        if ins.mnemonic in ('ret','retn'):
            break
    return hits

for func_va, label in [
    (0x1800050c0, "AnalysisJobLog"),
    (0x180002f00, "func@0x180002f00 (case 5)"),
    (0x1800028c0, "func@0x1800028c0 (case 6)"),
    (0x180001e30, "func@0x180001e30 (cases 7/8/9)"),
    (0x1800032d0, "func@0x1800032d0 (cases 18/19)"),
    (0x180003440, "func@0x180003440 (case 11)"),
]:
    refs = find_rdata_refs(func_va, label=label)
    if refs:
        print(f"\n  {label} ({func_va:#x}):")
        for addr, tgt, mne, ops, wstr, raw in refs:
            print(f"    {addr:#x}  {mne}  → {tgt:#x}")
            print(f"      wstr: {wstr!r}")
            print(f"      raw:  {raw.hex()}")

# ── 3. Full disassembly of func@0x180001e30 ───────────────────────────────────
print("\n"+"="*70)
print("3. Full disassembly of func@0x180001e30 (numeric field parser)")
print("="*70)
for ins in disasm_at(0x180001e30, n=2048, max_i=200):
    print(f"  {ins.address:#x}  {ins.mnemonic:<8}  {ins.op_str}")

# ── 4. Full disassembly of func@0x180002f00 continuing from where we left off ─
print("\n"+"="*70)
print("4. func@0x180002f00 from offset 0x180002fd1 onward")
print("="*70)
for ins in disasm_at(0x180002fd1, n=4096, max_i=300):
    print(f"  {ins.address:#x}  {ins.mnemonic:<8}  {ins.op_str}")

# ── 5. Specifically dump what rdata contains at the format ref in 0x180002f00 ─
print("\n"+"="*70)
print("5. Dump rdata near 0x180002fa8 + 0x1ca210 = 0x1801ccfb8")
print("="*70)
target_va = 0x180002fa8 + 0x1ca210
print(f"Target VA: {target_va:#x}")
raw = read_bytes(target_va, 64)
print(f"Raw bytes: {raw.hex()}")
print(f"wstr:      {read_wstr(target_va, 30)!r}")
print(f"astr:      {read_astr(target_va, 30)!r}")

# Also dump neighbor rdata areas (format strings often clustered)
print("\nNeighboring rdata (offsets relative to target):")
for delta in range(-64, 128, 8):
    va = target_va + delta
    off = va - RDATA_VA
    if 0 <= off < len(RDATA_RAW)-1:
        raw8 = RDATA_RAW[off:off+8]
        wstr = read_wstr(va, 10)
        print(f"  {delta:+4d}  {va:#x}  {raw8.hex()}  {wstr!r}")

# ── 6. Look for known Epson format strings in all of rdata ────────────────────
print("\n"+"="*70)
print("6. Search rdata for known format/field strings")
print("="*70)

# Known Epson BDC field names and format strings
search_strings = [
    b'\x25\x00\x66\x00',        # '%f' (float)
    b'\x25\x00\x64\x00',        # '%d' (decimal)
    b'\x25\x00\x6c\x00\x64\x00',# '%ld' (long decimal)
    b'\x25\x00\x75\x00',        # '%u' (unsigned)
    b'\x25\x00\x73\x00',        # '%s' (string)
    b'\x49\x00\x6e\x00\x6b\x00',# 'Ink' (UTF-16LE)
    b'\x6a\x00\x69\x00\x3a\x00',# 'ji:' (UTF-16LE)
    b'\x4a\x00\x6f\x00\x62\x00',# 'Job' (UTF-16LE)
    b'\x55\x00\x73\x00\x65\x00',# 'Use' (UTF-16LE)
    b'ji:',                      # 'ji:' ASCII
    b'ink',
    b'Ink',
    b'Use',
    b'CumUse',
    b'MntUse',
    b'StartTime',
    b'EndTime',
    b'InkUse',
    b'InkCum',
]

for s in search_strings:
    pos = 0
    while True:
        idx = RDATA_RAW.find(s, pos)
        if idx < 0:
            break
        va = RDATA_VA + idx
        ctx = RDATA_RAW[idx:idx+32]
        print(f"  Found {s[:8]!r} at rdata+{idx:#06x} ({va:#x}):")
        print(f"    hex: {ctx.hex()}")
        # Try to decode as wide string
        wstr = read_wstr(va, 20)
        if wstr:
            print(f"    wstr: {wstr!r}")
        pos = idx + 1

# ── 7. Look for the BDC ji: field tag map ─────────────────────────────────────
print("\n"+"="*70)
print("7. Search for Epson ji: field tag strings (known field names)")
print("="*70)

# These are the field names that Epson's ji: protocol uses
# (from Epson DeviceFramework documentation / other probes)
field_names = [
    'StartTime', 'EndTime', 'MediaType', 'MediaWidth', 'MediaLength',
    'PaperSource', 'JobName', 'UserName', 'MachineName',
    'TotalInkUse', 'InkUse', 'Status', 'Counter', 'PrintMode',
    'ColorMode', 'Resolution', 'Area', 'Copies', 'Error',
    # Also try common short names
    'si', 'ei', 'mt', 'mw', 'ml', 'ps', 'jn', 'un', 'mn',
    'iu', 'ci', 'st', 'ct', 'pm', 'cm', 'rs', 'ar', 'cp',
]

for name in field_names:
    # Try both ASCII and UTF-16LE
    for enc in ['ascii', 'utf-16-le']:
        try:
            b = name.encode(enc)
            idx = RDATA_RAW.find(b)
            if idx >= 0:
                va = RDATA_VA + idx
                ctx_raw = RDATA_RAW[idx-2:idx+len(b)+16]
                print(f"  Found {name!r} as {enc} at rdata+{idx:#06x} ({va:#x}): {ctx_raw.hex()}")
        except:
            pass
