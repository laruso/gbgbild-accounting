#!/usr/bin/env python3
"""
Diagnostic: dump the printer's CURRENT ji: metadata buffer.

The ji: buffer is where per-job username/machine and the encrypted ink blob
live. It only holds the most-recent jobs, so this shows exactly what a `pull`
running right now would be able to capture. If a freshly-printed job is NOT in
this list, the blob/ink for it can never be stored — the problem is capture,
not decryption.

Usage:
  python3 dump_ji.py [printer-ip]      # default 192.168.1.55
"""
import logging
import sys

from joblog import fetch_ji_metadata


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.55"
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    meta = fetch_ji_metadata(host, community="epson")
    print()
    print("ji: buffer entries captured: %d" % len(meta))
    if not meta:
        print("Buffer is EMPTY — the printer returned no ji: entries. "
              "That means no blob/ink can be captured for any job right now.")
        return

    print("  %-4s  %-5s  %-18s  %-16s  %s" % ("idx", "blob", "user", "machine", "job_name"))
    print("  " + "-" * 78)
    for idx in sorted(meta):
        m = meta[idx]
        blob = "blob" if m.get("ji_blob") else " -- "
        print("  %-4d  %-5s  %-18s  %-16s  %s" % (
            idx, blob,
            (m.get("username") or "")[:18],
            (m.get("machine") or "")[:16],
            (m.get("job_name") or "")[:36]))


if __name__ == "__main__":
    main()
