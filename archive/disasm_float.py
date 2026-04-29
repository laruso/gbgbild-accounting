"""
Search AnalysisJobLog and its callees for floating-point operations.
Ink values must be converted from raw binary to float at some point.
We look for: CVTSI2SS, CVTSI2SD, MULSS, MULSD, DIVSS, DIVSD, ADDSS, ADDSD,
MOVSS, MOVSD, FMUL, FDIV, FADD, FILD, FIST.

Also: look for hard-coded scale constants (like 0.001, 0.0001, 1000, 10000)
in the .rdata section — these would be the divisor to convert raw to ml.

Also trace the full AnalysisJobLog switch table to see all 35 cases
and find which one handles the 208-byte block.
"""

import struct, sys, os
try:
    import pefile, capstone
except ImportError:
    sys.exit("pip install pefile capstone")

DLL_PATH   = "extracted/SCP7595.dll"
IMAGE_BASE = 0x180000000

pe = pefile.PE(DLL_PATH)
text_sec  = next(s for s in pe.sections if s.Name.startswith(b'.text'))
rdata_sec = next(s for s in pe.sections if s.Name.startswith(b'.rdata'))

TEXT_VA    = IMAGE_BASE + text_sec.VirtualAddress
TEXT_RAW   = text_sec.get_data()
RDATA_VA   = IMAGE_BASE + rdata_sec.VirtualAddress
RDATA_RAW  = rdata_sec.get_data()

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

FLOAT_MNEMONICS = {
    'cvtsi2ss','cvtsi2sd','cvtss2sd','cvtsd2ss',
    'mulss','mulsd','divss','divsd','addss','addsd','subss','subsd',
    'movss','movsd','sqrtss','sqrtsd',
    'fmul','fdiv','fadd','fsub','fild','fist','fistp','fld','fst','fstp',
    'ucomisd','ucomiss',
}

def va_to_raw(va, sec):
    rva = va - IMAGE_BASE
    off = pe.get_offset_from_rva(rva)
    return off - sec.PointerToRawData

def disasm_va(va, n_bytes=8192, max_insns=2000):
    off = va_to_raw(va, text_sec)
    data = TEXT_RAW[off:off + n_bytes]
    insns = []
    for i, ins in enumerate(md.disasm(data, va)):
        insns.append(ins)
        if i >= max_insns:
            break
        if ins.mnemonic in ('ret','retn') and i > 5:
            break
    return insns

def find_floats(va, n_bytes=8192, label=""):
    off = va_to_raw(va, text_sec)
    data = TEXT_RAW[off:off + n_bytes]
    hits = []
    for ins in md.disasm(data, va):
        if ins.mnemonic.lower() in FLOAT_MNEMONICS:
            hits.append(ins)
        if ins.mnemonic in ('ret','retn') and len(hits) > 0:
            break
    if hits:
        print(f"\n  [FLOAT OPS] {label or hex(va)} — {len(hits)} fp instructions:")
        for ins in hits:
            print(f"    {ins.address:#x}  {ins.mnemonic:<10}  {ins.op_str}")
    return hits

# ── 1. Scan AnalysisJobLog itself ─────────────────────────────────────────────
print("="*70)
print("1. Float instructions in AnalysisJobLog (0x1800050c0, 8KB)")
print("="*70)
find_floats(0x1800050c0, n_bytes=32768, label="AnalysisJobLog")

# ── 2. Find jump table entries for the 35-case switch ─────────────────────────
print("\n"+"="*70)
print("2. Decode the 35-case switch table at 0x18000577e")
print("="*70)

# At 0x180005780: mov ecx, dword ptr [r10 + rax*4 + 0x856c]
# r10 = RIP - 0x5767 = 0x180005767 - 0x5767 = 0x180000000 = IMAGE_BASE
# jump table base = IMAGE_BASE + 0x856c
JMPTBL_VA  = IMAGE_BASE + 0x856c
JMPTBL_OFF = JMPTBL_VA - IMAGE_BASE  # = 0x856c from image base

# The .text section starts at RVA 0x1000, so offset 0x856c is in .text
# raw offset = 0x856c - 0x1000 (VirtualAddress) + text_sec.PointerToRawData
TEXT_RVA = text_sec.VirtualAddress
jmptbl_raw = 0x856c - TEXT_RVA + text_sec.PointerToRawData
print(f"Jump table raw offset in DLL: {jmptbl_raw:#x}")
print(f"Jump table VA: {JMPTBL_VA:#x}")

# The add + jmp pattern: rcx = [table + rax*4]; add rcx, r10; jmp rcx
# So each entry is a relative offset from IMAGE_BASE
entries = []
for i in range(35):
    off = jmptbl_raw + i * 4
    if off + 4 > len(TEXT_RAW):
        break
    rel32 = struct.unpack_from('<i', TEXT_RAW, off)[0]
    target_va = IMAGE_BASE + 0x856c + rel32 + i*4  # relative to table entry position
    # Actually: target = r10 + entry_value = IMAGE_BASE + entry_value
    # entry_value is the 32-bit signed offset from IMAGE_BASE
    target_va2 = IMAGE_BASE + (rel32 & 0xFFFFFFFF) if rel32 >= 0 else IMAGE_BASE + rel32 + 0x100000000
    entries.append((i, rel32, target_va2))

# Show entries
print("\nCase  RelOffset   TargetVA")
for case_i, rel, tgt in entries:
    print(f"  {case_i+1:2d}    {rel:+#011x}  {tgt:#x}")

# ── 3. Disassemble each unique switch target briefly, note float ops ─────────
print("\n"+"="*70)
print("3. Float ops in each switch case target")
print("="*70)

unique_targets = {}
for case_i, rel, tgt in entries:
    if tgt not in unique_targets:
        unique_targets[tgt] = []
    unique_targets[tgt].append(case_i + 1)

for tgt, cases in sorted(unique_targets.items()):
    fp = find_floats(tgt, n_bytes=512, label=f"cases {cases} → {tgt:#x}")

# ── 4. Search ALL callees of AnalysisJobLog for float ops ────────────────────
print("\n"+"="*70)
print("4. Float ops in ALL callees of AnalysisJobLog")
print("="*70)

CALLEE_VAS = [
    0x180001000, 0x1800014a0, 0x1800015c0, 0x1800017b0, 0x1800018b0,
    0x180001910, 0x180001bb0, 0x180001e30, 0x1800028c0, 0x180002f00,
    0x1800032d0, 0x180003440, 0x1800037f0, 0x180003890, 0x180003b30,
    0x180003ba0, 0x180003e70, 0x1800047c0, 0x1800049b0, 0x180004f70,
    0x18000c820, 0x18000c9a0, 0x18000e5d4, 0x18000e6d8, 0x18000e904,
    0x18000ef04, 0x18000fe78, 0x180010780, 0x180010a50, 0x180010dc8,
    0x180010e40, 0x18014fc40, 0x18015027c, 0x1801513f8, 0x1801542f0,
]

for va in CALLEE_VAS:
    find_floats(va, n_bytes=2048, label=f"callee@{va:#x}")

# ── 5. Search rdata for float constants (scale factors like 1e-3, 1e-4) ───────
print("\n"+"="*70)
print("5. float32 / float64 scale constants in .rdata")
print("="*70)

interesting_f32 = []
interesting_f64 = []
for off in range(0, len(RDATA_RAW) - 8, 4):
    try:
        v32 = struct.unpack_from('<f', RDATA_RAW, off)[0]
        v64 = struct.unpack_from('<d', RDATA_RAW, off)[0]
        # Look for scale factors: powers of 10, or small fractions
        if v32 != 0:
            for exp in range(-6, 7):
                ratio = v32 / (10 ** exp)
                if 0.5 <= abs(ratio) <= 2.0:
                    va = RDATA_VA + off
                    interesting_f32.append((va, off, v32, exp))
                    break
        if v64 != 0:
            for exp in range(-6, 7):
                ratio = v64 / (10 ** exp)
                if 0.5 <= abs(ratio) <= 2.0:
                    va = RDATA_VA + off
                    interesting_f64.append((va, off, v64, exp))
                    break
    except:
        pass

print(f"Interesting f32 scale constants: {len(interesting_f32)}")
for va, off, v, exp in interesting_f32[:30]:
    print(f"  rdata+{off:#06x}  VA={va:#x}  {v:.8g}  (~1e{exp})")

print(f"\nInteresting f64 scale constants: {len(interesting_f64)}")
for va, off, v, exp in interesting_f64[:30]:
    print(f"  rdata+{off:#06x}  VA={va:#x}  {v:.8g}  (~1e{exp})")

# ── 6. Broader scan — find float ops anywhere in .text region 0x1800050c0-0x180009000 ──
print("\n"+"="*70)
print("6. All float ops in AnalysisJobLog + downstream (0x50c0-0x9000)")
print("="*70)
SCAN_START = 0x1800050c0
SCAN_SIZE  = 0x9000 - 0x50c0  # covers the function body
off = va_to_raw(SCAN_START, text_sec)
data = TEXT_RAW[off:off + SCAN_SIZE]

float_hits = []
for ins in md.disasm(data, SCAN_START):
    if ins.mnemonic.lower() in FLOAT_MNEMONICS:
        float_hits.append(ins)

print(f"Total float instructions in range: {len(float_hits)}")
for ins in float_hits:
    print(f"  {ins.address:#x}  {ins.mnemonic:<10}  {ins.op_str}")

print("\nDone.")
