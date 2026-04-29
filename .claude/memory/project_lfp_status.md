---
name: LFP project current status
description: Current status of the LFP Accounting Tool replacement project — COMPLETE
type: project
---

## Status: COMPLETE

The standalone Python tool successfully polls the Epson SC-P9500 (IP 10.0.0.48) for per-job ink usage via SNMP, fully independent of the LFP Accounting Tool and .accdb.

## What Works
- Job metadata via SNMP table OID 1.3.6.1.4.1.1248.1.2.2.27.20.1.* (name, times, sizes, up to 500 slots)
- Username/machine via BDC ji: OID (TLV suffix after 208-byte blob)
- Current ink tank levels via Printer-MIB
- **Per-job ink usage: SOLVED** — custom 3-round Feistel cipher with CBC chaining, key = printer serial number
- SQLite storage with all data including ink
- CSV export with ink columns
- Verified: all ink values match .accdb exactly

## How the encryption works
- 208-byte ji: blob is encrypted with a custom Feistel cipher
- Key = printer serial number (`X6FB001980`), bytes at offset 2-9 derive round keys
- 3-round Feistel: 8-byte blocks, CBC chaining (previous ciphertext XOR'd with next block)
- Decrypted output is TLV: tag 0x0F with 24 bytes = 12 ink channels as 2-byte LE values
- Channel order in blob: LK, VM, OR, PK, VLM, LLK, LC, Y, GR, MK, V, C

## Files
- `joblog.py` — SNMP fetch + blob decryption + serial number retrieval
- `store.py` — SQLite storage
- `lfp_accounting.py` — CLI entry point (pull/status/list/export)
- `decrypt_blob.py` — standalone verification script
- `frida_hook.py` — Frida hook used to crack the cipher (no longer needed)

## Key details
- .accdb password: `4DC1AE17E60EF174B252`
- Printer serial: `X6FB001980`
- Printer web UI password: `77411709` (user: empty)
- ji: index 0 may not have data for the most recent job (buffer flush delay)
