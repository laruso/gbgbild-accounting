"""
Deep disassembly of SCP7595.dll focusing on:
1. AnalysisJobLog (RVA 0x50c0) — full function, look for decryption/XOR logic
2. func@0x4f70 — the 2-byte-stride parser called during ji: processing
3. func@0x18000ce20 — callee from 0x4f70, processes each parsed field
4. Any XOR loops, lookup tables, or key derivation from ji: data

Strategy: find the actual cipher by looking for:
  - XOR instructions (opcode 0x33, 0x31, 0x35, etc.)
  - SBOX-like reads (array indexed by byte)
  - Loops that process the 208-byte block
  - Key setup using job metadata (counter, timestamp)
"""

import struct
import sys

try:
    import pefile
    import capstone
except ImportError:
    print("Install: pip install pefile capstone")
    sys.exit(1)

DLL_PATH = "extracted/SCP7595.dll"
IMAGE_BASE = 0x180000000

pe = pefile.PE(DLL_PATH)
text_section = next(s for s in pe.sections if s.Name.startswith(b'.text'))
TEXT_VA   = IMAGE_BASE + text_section.VirtualAddress
TEXT_DATA = text_section.get_data()

# Also load rdata for lookup tables
rdata_section = next((s for s in pe.sections if s.Name.startswith(b'.rdata')), None)
RDATA_VA   = IMAGE_BASE + rdata_section.VirtualAddress if rdata_section else 0
RDATA_DATA = rdata_section.get_data() if rdata_section else b''

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

def va_to_raw(va):
    """Convert virtual address to raw file offset."""
    rva = va - IMAGE_BASE
    return pe.get_offset_from_rva(rva)

def disasm_at(va, max_bytes=512, max_insns=200, stop_at_ret=True):
    """Disassemble starting at virtual address."""
    rva = va - IMAGE_BASE
    offset = pe.get_offset_from_rva(rva)
    data = TEXT_DATA[offset - text_section.PointerToRawData :
                     offset - text_section.PointerToRawData + max_bytes]

    insns = []
    for i, insn in enumerate(md.disasm(data, va)):
        insns.append(insn)
        if i >= max_insns:
            break
        if stop_at_ret and insn.mnemonic in ('ret', 'retn') and i > 5:
            break
    return insns

def find_xor_patterns(va, size=4096):
    """Find XOR operations in a region — cipher indicator."""
    rva = va - IMAGE_BASE
    offset = pe.get_offset_from_rva(rva)
    data = TEXT_DATA[offset - text_section.PointerToRawData :
                     offset - text_section.PointerToRawData + size]

    results = []
    for i, insn in enumerate(md.disasm(data, va)):
        if insn.mnemonic.startswith('xor'):
            # Filter out zero-register idioms (xor eax, eax)
            ops = insn.op_str.split(',')
            if len(ops) == 2 and ops[0].strip() != ops[1].strip():
                results.append(insn)
        if i > 2000:
            break
    return results

def read_rdata_at(va, n=64):
    """Read bytes from rdata section at VA."""
    offset = va - RDATA_VA
    if 0 <= offset < len(RDATA_DATA):
        return RDATA_DATA[offset:offset+n]
    return b''

def find_calls_in_func(va, max_bytes=4096):
    """Find all CALL targets within a function body."""
    rva = va - IMAGE_BASE
    offset = pe.get_offset_from_rva(rva)
    data = TEXT_DATA[offset - text_section.PointerToRawData :
                     offset - text_section.PointerToRawData + max_bytes]

    calls = []
    for insn in md.disasm(data, va):
        if insn.mnemonic == 'call':
            try:
                target = int(insn.op_str, 16)
                if IMAGE_BASE <= target < IMAGE_BASE + 0x200000:
                    calls.append((insn.address, target))
            except ValueError:
                pass
        if insn.mnemonic in ('ret', 'retn'):
            break
    return calls

print("=" * 80)
print("SCP7595.dll — Deep Cipher Analysis")
print("=" * 80)

# ─── 1. AnalysisJobLog full disassembly for XOR patterns ────────────────────
ANALYSIS_VA = 0x1800050c0
print(f"\n{'='*60}")
print(f"1. XOR patterns in AnalysisJobLog (VA={ANALYSIS_VA:#x}, scan 8KB)")
print(f"{'='*60}")
xors = find_xor_patterns(ANALYSIS_VA, size=8192)
print(f"Found {len(xors)} non-trivial XOR instructions:")
for insn in xors:
    print(f"  {insn.address:#x}  {insn.mnemonic}  {insn.op_str}")

# ─── 2. Find all unique call targets from AnalysisJobLog ────────────────────
print(f"\n{'='*60}")
print(f"2. All CALL targets from AnalysisJobLog")
print(f"{'='*60}")
calls = find_calls_in_func(ANALYSIS_VA, max_bytes=8192)
unique_targets = sorted(set(t for _, t in calls))
print(f"Found {len(calls)} calls to {len(unique_targets)} unique targets:")
for t in unique_targets:
    print(f"  {t:#x}")

# ─── 3. Disassemble func@0x4f70 fully ────────────────────────────────────────
FUNC_4F70_VA = 0x180004f70
print(f"\n{'='*60}")
print(f"3. Full disassembly of func@0x4f70 (2-byte-stride parser)")
print(f"{'='*60}")
insns = disasm_at(FUNC_4F70_VA, max_bytes=1024, max_insns=500, stop_at_ret=True)
for insn in insns:
    print(f"  {insn.address:#x}  {insn.mnemonic:<8}  {insn.op_str}")

# XOR patterns inside func@0x4f70
xors_4f70 = find_xor_patterns(FUNC_4F70_VA, size=1024)
print(f"\n  XOR instructions in func@0x4f70: {len(xors_4f70)}")
for x in xors_4f70:
    print(f"    {x.address:#x}  {x.mnemonic}  {x.op_str}")

# ─── 4. Disassemble func@0x18000ce20 ─────────────────────────────────────────
FUNC_CE20_VA = 0x18000ce20
print(f"\n{'='*60}")
print(f"4. Disassembly of func@0x18000ce20 (field processor)")
print(f"{'='*60}")
insns = disasm_at(FUNC_CE20_VA, max_bytes=2048, max_insns=500)
for insn in insns:
    print(f"  {insn.address:#x}  {insn.mnemonic:<8}  {insn.op_str}")

xors_ce20 = find_xor_patterns(FUNC_CE20_VA, size=2048)
print(f"\n  XOR instructions: {len(xors_ce20)}")
for x in xors_ce20:
    print(f"    {x.address:#x}  {x.mnemonic}  {x.op_str}")

# ─── 5. Scan all call targets of AnalysisJobLog for XOR loops ────────────────
print(f"\n{'='*60}")
print(f"5. Scan each callee of AnalysisJobLog for XOR/cipher patterns")
print(f"{'='*60}")
for target_va in unique_targets:
    xors = find_xor_patterns(target_va, size=2048)
    if xors:
        print(f"\n  func@{target_va:#x} — {len(xors)} XOR instructions:")
        for x in xors:
            print(f"    {x.address:#x}  {x.mnemonic}  {x.op_str}")
        # Also show context around each XOR
        for xop in xors[:3]:
            ctx_rva = xop.address - IMAGE_BASE
            ctx_off = pe.get_offset_from_rva(ctx_rva)
            ctx_data = TEXT_DATA[ctx_off - text_section.PointerToRawData - 32 :
                                  ctx_off - text_section.PointerToRawData + 64]
            print(f"    Context around {xop.address:#x}:")
            for ci in md.disasm(ctx_data, xop.address - 32):
                marker = " <-- XOR" if ci.address == xop.address else ""
                print(f"      {ci.address:#x}  {ci.mnemonic:<8}  {ci.op_str}{marker}")
                if ci.mnemonic in ('ret', 'retn'):
                    break

# ─── 6. Look at the AnalysisJobLog body from offset 0x54af onward ────────────
print(f"\n{'='*60}")
print(f"6. AnalysisJobLog from 0x1800054af onward (post-header processing)")
print(f"{'='*60}")
insns = disasm_at(0x1800054af, max_bytes=2048, max_insns=300, stop_at_ret=True)
for insn in insns:
    print(f"  {insn.address:#x}  {insn.mnemonic:<8}  {insn.op_str}")

# ─── 7. Look for large read-only tables in rdata that could be S-boxes ────────
print(f"\n{'='*60}")
print(f"7. Scan rdata for potential S-box / lookup tables (256+ bytes with varied values)")
print(f"{'='*60}")
STEP = 256
hits = []
for off in range(0, min(len(RDATA_DATA), 0x20000), STEP):
    chunk = RDATA_DATA[off:off+256]
    if len(chunk) < 256:
        break
    unique = len(set(chunk))
    # A typical AES S-box has 256 unique bytes; XOR/RC4 tables are varied too
    if unique > 200:
        va = RDATA_VA + off
        hits.append((va, unique, chunk[:16]))

print(f"Found {len(hits)} candidate 256-byte blocks with 200+ unique values:")
for va, u, preview in hits[:20]:
    print(f"  rdata+{va - RDATA_VA:#06x}  VA={va:#x}  unique_bytes={u}  first16={preview.hex()}")

# ─── 8. Scan the entire .text for the 208-specific constant 0xD0 ────────────
print(f"\n{'='*60}")
print(f"8. Scan .text for use of constant 0xD0=208 (ji: binary block size)")
print(f"{'='*60}")
count = 0
text_va_base = TEXT_VA
for i, insn in enumerate(md.disasm(TEXT_DATA, text_va_base)):
    if '0xd0' in insn.op_str or ' 208' in insn.op_str or 'd0h' in insn.op_str.lower():
        print(f"  {insn.address:#x}  {insn.mnemonic}  {insn.op_str}")
        count += 1
        if count > 50:
            print("  (truncated at 50)")
            break
    if i > 500000:
        break

print("\n\nDone.")
