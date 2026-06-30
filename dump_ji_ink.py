#!/usr/bin/env python3
"""
Diagnostic: decode the ink for EVERY entry in the printer's ji: buffer right now.

This reveals the buffer's ink-vs-age behaviour, which decides how to capture ink
reliably without the old LFP tool:

  - If only the NEWEST entries (low idx) read zero and they gain ink on a later
    run, the blob populates *after* the print (pending) -> a later pull catches
    it; 15-min polling is fine.
  - If the OLDEST entries (high idx) read zero, the ink *decays* as the entry
    ages in the buffer -> we must pull often enough to catch each job while its
    ink is still present.

Run it twice a few minutes apart (and/or right after a print) and compare which
indices are zero.

Usage (on the Pi):
    python3 dump_ji_ink.py [printer-ip]      # default 192.168.1.55
"""
import logging
import sys

from joblog import (fetch_ji_metadata, _decrypt_ji_blob, _parse_ink_from_tlv,
                    INK_CHANNELS)
from store import get_meta

SERIAL = get_meta("printer_serial") or "X6FB001980"


def ink_total(blob):
    """Raw decoded ink sum for a blob: int total, 0, or None if no ink TLV."""
    if not blob or len(blob) != 208:
        return None
    vals = _parse_ink_from_tlv(_decrypt_ji_blob(blob, SERIAL))
    if not vals:
        return None
    return sum(vals.values())


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.55"
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    meta = fetch_ji_metadata(host, community="epson")
    entries = [(idx, meta[idx]) for idx in sorted(meta) if idx < 256]
    print(f"\nSerial: {SERIAL}")
    print(f"ji: buffer entries (newest first, idx 0 = newest): {len(entries)}\n")
    print("  %-4s  %-9s  %-18s  %s" % ("idx", "ink_total", "user", "job_name"))
    print("  " + "-" * 70)

    zero_idx, none_idx = [], []
    for idx, m in entries:
        t = ink_total(m.get("ji_blob"))
        if t is None:
            flag, none_idx = "noTLV", none_idx + [idx]
        elif t == 0:
            flag, zero_idx = "ZERO", zero_idx + [idx]
        else:
            flag = ""
        print("  %-4d  %-9s  %-18s  %s  %s" % (
            idx, "-" if t is None else t,
            (m.get("username") or "")[:18], (m.get("job_name") or "")[:30], flag))

    print()
    print(f"zero-ink entries: {len(zero_idx)}  at indices {zero_idx}")
    print(f"no-TLV entries:   {len(none_idx)}  at indices {none_idx}")
    if zero_idx:
        n = len(entries)
        half = "newest half" if max(zero_idx) < n / 2 else (
               "oldest half" if min(zero_idx) >= n / 2 else "spread across buffer")
        print(f"zero entries cluster in the: {half}")


if __name__ == "__main__":
    main()
