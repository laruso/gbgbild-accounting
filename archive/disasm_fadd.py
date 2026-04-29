"""
Focus on func@0x1800047c0 — the ONLY function with a float op (fadd).
Also: disassemble cases 5, 6, 7, 8, 9 of the AnalysisJobLog switch —
those are the "complex" cases that likely process numeric binary data.
Also decode the string literals referenced by rip+offset in cases 1 and 13
to understand what field names the DLL parses.
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
TEXT_RVA = text_sec.VirtualAddress
TEXT_RAW = text_sec.get_data()
RDATA_VA  = IMAGE_BASE + rdata_sec.VirtualAddress
RDATA_RVA = rdata_sec.VirtualAddress
RDATA_RAW = rdata_sec.get_data()

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

def sec_off(va):
    return va - TEXT_VA

def disasm_at(va, n=1024, max_i=300):
    off = sec_off(va)
    data = TEXT_RAW[off:off+n]
    insns = []
    for i, ins in enumerate(md.disasm(data, va)):
        insns.append(ins)
        if ins.mnemonic in ('ret','retn') and i > 3:
            break
        if i >= max_i:
            break
    return insns

def read_rdata(va, n=64):
    off = va - RDATA_VA
    if 0 <= off < len(RDATA_RAW):
        return RDATA_RAW[off:off+n]
    return b''

def read_wstr(va, max_chars=50):
    """Read a UTF-16LE string from rdata."""
    data = read_rdata(va, max_chars*2+2)
    s = ""
    for i in range(0, len(data)-1, 2):
        c = struct.unpack_from('<H', data, i)[0]
        if c == 0:
            break
        s += chr(c) if 32 <= c < 127 else f'\\u{c:04x}'
    return s

def extract_rip_refs(insns):
    """Extract all [rip + offset] references, resolve VA."""
    refs = []
    for ins in insns:
        if 'rip' in ins.op_str and '+' in ins.op_str:
            # parse offset from op_str like "[rip + 0x1c7a20]"
            import re
            m = re.search(r'\[rip \+ (0x[0-9a-f]+)\]', ins.op_str)
            if m:
                offset = int(m.group(1), 16)
                # rip at next instruction
                next_va = ins.address + ins.size
                target = next_va + offset
                refs.append((ins.address, target, ins.mnemonic, ins.op_str))
    return refs

# ─── 1. Full disassembly of func@0x1800047c0 ─────────────────────────────────
print("="*70)
print("1. func@0x1800047c0 — the ONLY function with float ops (fadd)")
print("="*70)
insns = disasm_at(0x1800047c0, n=4096, max_i=500)
for ins in insns:
    marker = " ◄ FLOAT" if ins.mnemonic.startswith('f') else ""
    print(f"  {ins.address:#x}  {ins.mnemonic:<10}  {ins.op_str}{marker}")

print(f"\nTotal instructions: {len(insns)}")
print("\nRIP-relative data references:")
for addr, tgt, mne, ops in extract_rip_refs(insns):
    rdata_str = read_wstr(tgt) if tgt >= RDATA_VA else ""
    raw_bytes = read_rdata(tgt, 16)
    f32_val = struct.unpack_from('<f', raw_bytes)[0] if len(raw_bytes) >= 4 else None
    print(f"  {addr:#x}  {mne}  target={tgt:#x}  wstr={rdata_str!r}  f32={f32_val}  raw={raw_bytes[:8].hex()}")

# ─── 2. Case 5 → 0x18000585d (calls 0x180002f00) ─────────────────────────────
print("\n"+"="*70)
print("2. Case 5 → 0x18000585d (large binary field handler?)")
print("="*70)
insns = disasm_at(0x18000585d, n=2048, max_i=200)
for ins in insns:
    print(f"  {ins.address:#x}  {ins.mnemonic:<8}  {ins.op_str}")

# ─── 3. Case 6 → 0x18000592c (calls 0x1800028c0) ─────────────────────────────
print("\n"+"="*70)
print("3. Case 6 → 0x18000592c")
print("="*70)
insns = disasm_at(0x18000592c, n=2048, max_i=200)
for ins in insns:
    print(f"  {ins.address:#x}  {ins.mnemonic:<8}  {ins.op_str}")

# ─── 4. Case 7 → 0x1800059fb ─────────────────────────────────────────────────
print("\n"+"="*70)
print("4. Case 7 → 0x1800059fb")
print("="*70)
insns = disasm_at(0x1800059fb, n=2048, max_i=200)
for ins in insns:
    print(f"  {ins.address:#x}  {ins.mnemonic:<8}  {ins.op_str}")

# ─── 5. Decode RIP-relative string literals from AnalysisJobLog ───────────────
print("\n"+"="*70)
print("5. String literals (rip+offset) referenced in AnalysisJobLog switch cases")
print("   These are the FIELD NAMES the DLL looks for in the ji: response")
print("="*70)

# From switch case 1 (0x18000578d): rdx = [rip + 0x1c7a20]
# At case 1: instruction at 0x180005791  lea rdx, [rip + 0x1c7a20]
# next_va = 0x180005798
# target = 0x180005798 + 0x1c7a20 = 0x1801cdfb8

field_refs = [
    # (case, insn_va, rip_offset, description)
    (1,  0x180005791, 0x1c7a20, "case 1 field name"),
    (2,  0x1800057cf, 0x1c79e2, "case 2 field name"),
    (13, 0x18000605d, 0x1c7154, "case 13 field name"),
]

# Also scan all cases for rip-relative loads to rdx
for case_va in [
    0x18000578d, 0x1800057cb, 0x1800057e8, 0x180005808, 0x18000585d,
    0x18000592c, 0x1800059fb, 0x180005ad5, 0x180005c99, 0x180005d73,
    0x180005ee0, 0x180005faf, 0x180006059, 0x1800060ae, 0x180006188,
    0x180006c44, 0x180006dc0, 0x180006e17, 0x180006e95, 0x180006f13,
    0x18000773c, 0x180007f65, 0x180007fb7,
]:
    insns = disasm_at(case_va, n=256, max_i=30)
    for ins in insns:
        if 'rip' in ins.op_str and 'rdx' in ins.op_str:
            import re
            m = re.search(r'\[rip \+ (0x[0-9a-f]+)\]', ins.op_str)
            if m:
                offset = int(m.group(1), 16)
                next_va = ins.address + ins.size
                target = next_va + offset
                if target >= RDATA_VA and target < RDATA_VA + len(RDATA_RAW):
                    wstr = read_wstr(target)
                    raw = read_rdata(target, 16)
                    print(f"  case@{case_va:#x}  insn@{ins.address:#x}  rdx→{target:#x}  '{wstr}'  raw={raw[:8].hex()}")
        if ins.mnemonic in ('ret','retn','call','jmp'):
            break

# ─── 6. Decode what 0x180002f00 and 0x1800028c0 do ───────────────────────────
print("\n"+"="*70)
print("6. func@0x180002f00 (called by case 5)")
print("="*70)
for ins in disasm_at(0x180002f00, n=2048, max_i=200):
    print(f"  {ins.address:#x}  {ins.mnemonic:<8}  {ins.op_str}")

print("\n"+"="*70)
print("7. func@0x1800028c0 (called by case 6)")
print("="*70)
for ins in disasm_at(0x1800028c0, n=2048, max_i=200):
    print(f"  {ins.address:#x}  {ins.mnemonic:<8}  {ins.op_str}")

# ─── 7. What is rbp+0x250 (used in case 5)? Look at the struct layout ─────────
print("\n"+"="*70)
print("8. Stack layout of AnalysisJobLog — what lives at rbp+0x...")
print("   Cases reference: rbp+0xc, rbp+0x14, rbp+0xc0, rbp+0x190, rbp+0xd0")
print("   rbp+0x100, rbp+0x160, rbp+0x180, rbp+0x158, rbp+0x200, rbp+0x250")
print("   rbp+0x248, rbp+0x240, rbp+0x170, rbp+0x220, rbp+0x68, rbp+0x70")
print("="*70)

# Known field sizes (from r9d in c820 calls):
# case 15 (rbp+0x100): 4 bytes (uint32?)
# case 16 (rbp+0x160): 4 bytes
# case 32 (rbp+0x180): 8 bytes (uint64?)
# case 33 (rbp+0x158): 8 bytes

layout = [
    (0x0c,  4, "case 1 (parsed int?)"),
    (0x14,  4, "case 2 (parsed int?)"),
    (0x50,  4, "switch selector (tag value)"),
    (0x68,  8, "ptr — used in case 10 loop"),
    (0x70,  8, "ptr — r15 loaded from here"),
    (0xc0, '?', "case 7 output"),
    (0xd0, '?', "case 9 output"),
    (0xf0, '?', "case 12 output"),
    (0x100, 4, "case 15 → 4-byte numeric field"),
    (0x158, 8, "case 33 → 8-byte numeric field"),
    (0x160, 4, "case 16 → 4-byte numeric field"),
    (0x170, '?', "case 18 output"),
    (0x180, 8, "case 32 → 8-byte numeric field"),
    (0x190, '?', "case 8 output"),
    (0x1a0, '?', "case 11 output"),
    (0x200, '?', "case 14 output"),
    (0x220, '?', "case 19 output"),
    (0x240, '?', "case 10 output"),
    (0x248, '?', "case 6 output"),
    (0x250, '?', "case 5 output (large binary?)"),
]
print(f"  {'rbp+':>6}  {'size':>4}  note")
for off, sz, note in layout:
    print(f"  +{off:04x}   {str(sz):>4}  {note}")
