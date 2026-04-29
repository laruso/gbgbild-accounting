# Archive — reverse engineering scripts

These scripts are not used by the production tool. They document how the
proprietary `ji:` blob encryption was cracked. Kept for reference in case
the cipher changes in a future printer firmware and the work needs to be
redone.

## DLL static analysis (run on macOS, requires `pefile` and `capstone`)

| File | Purpose |
|---|---|
| `dump_strings.py` | Extracted field names (`InkUse_PK`, etc.) from `SCP7595.dll` rdata |
| `disasm_deep.py` | XOR pattern + S-box scan, call graph |
| `disasm_float.py`, `disasm_float2.py` | Searched for floating-point ops (none found) |
| `disasm_fadd.py` | Traced the single suspected float op (false positive) |
| `analyze_ji_encoding.py` | Multi-encoding statistical analysis of the blob |
| `decode_ji_blob.py` | Generates `correlate_ink.py` |

## Live probing (run on the network with the printer)

| File | Purpose |
|---|---|
| `probe_https2.py` | Crawled the printer's HTTPS UI looking for a job-log URL |
| `probe_ji.py` | Bulk-queried all 499 ji: indices and dumped raw blobs |
| `probe_vi.py` | Probed `vi:` / `ex:` BDC commands (no useful data) |

## Cipher cracking

| File | Purpose |
|---|---|
| `frida_hook.py` | Hooks `decrypt` in the running LFP process — produced ground-truth plaintext that revealed the algorithm |
| `frida_results.json` | Captured input/output pairs from the hook |
| `decrypt_blob.py` | Pure-Python reimplementation of the cipher (later moved into `joblog.py`) |

## .accdb access

| File | Purpose |
|---|---|
| `find_accdb_password.py` | Searched the LFP process memory for the .accdb password |
| `read_accdb.py` | Diagnostic reader |
| `correlate_ink.py`, `correlate_full.py` | Failed attempts to correlate raw blob bytes against decrypted .accdb values (before Frida cracked the cipher) |

## Captured data

| File | Purpose |
|---|---|
| `full-dump.pcap`, `capture_*.pcap` | Wireshark captures of the LFP tool talking to the printer |
| `wireshark-dump-lfp.csv` | CSV export of the pcap |
| `probe_ji_analysis.txt`, `probe_ji_payloads.bin` | Output of `probe_ji.py` |

## Key findings

- The cipher is a custom 3-round Feistel with 8-byte blocks and CBC chaining.
- The key is the printer serial number (ASCII, padded to 16 bytes).
  Only bytes 2–9 are used to derive round keys.
- Round-key derivation is purely additive (no S-boxes, no LUTs).
- Decrypted output is TLV. Tag `0x0F` length 24 holds 12 ink channels as
  2-byte little-endian integers.
- DLL channel order: `LK, VM, OR, PK, VLM, LLK, LC, Y, GR, MK, V, C`.
- Standard channel order (used in `.accdb`): `PK, MK, C, VM, Y, OR, GR, LC, VLM, LK, LLK, V`.
- .accdb password: stored in the LFP process memory at startup, recoverable
  via `find_accdb_password.py`.
