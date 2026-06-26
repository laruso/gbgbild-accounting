#!/usr/bin/env python3
"""
Diagnostic: dump the RAW ji: suffix bytes for each buffer entry.

The suffix is the TLV data after the 208-byte ink blob; it carries username /
machine / job_name. Some entries parse to a username and some come back blank.
This dumps the raw suffix (hex + ASCII) for every entry so we can see whether
the blank ones actually contain a username in a format the parser misses, or
genuinely have none.

Usage:
  python3 dump_ji_raw.py [printer-ip] [max-index]   # default 192.168.1.55 30
"""
import sys

from joblog import (_snmp_send, _snmp_pkt, _parse_snmp_resp, _JI_OID_PREFIX,
                    _parse_ji_suffix)


def hexdump(data: bytes, width: int = 24) -> None:
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexs = " ".join("%02x" % b for b in chunk)
        ascii_ = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print("    %04x  %-*s  %s" % (off, width * 3, hexs, ascii_))


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.55"
    max_idx = int(sys.argv[2]) if len(sys.argv) > 2 else 30

    for job_idx in range(max_idx):
        oid = "%s.%d" % (_JI_OID_PREFIX, job_idx)
        resp = _snmp_send(host, _snmp_pkt(0xa0, "epson", oid), 4.0)
        if not resp:
            continue
        parsed = _parse_snmp_resp(resp)
        if not parsed:
            continue
        _, val_tag, raw = parsed[0]
        if val_tag in (0x80, 0x81, 0x82):
            continue
        ji_pos = raw.find(b"ji:")
        if ji_pos < 0:
            continue
        ji_data = raw[ji_pos:]
        if len(ji_data) < 8 or ji_data[6:8] != b"\xd0\x00":
            continue

        suffix = ji_data[8 + 208:]
        meta = _parse_ji_suffix(suffix)
        tag = "NAMED" if (meta["username"] or meta["job_name"]) else ">>> BLANK <<<"
        print("=== ji[%d]  %s ===" % (job_idx, tag))
        print("  parsed: user=%r machine=%r job=%r"
              % (meta["username"], meta["machine"], meta["job_name"]))
        print("  suffix (%d bytes):" % len(suffix))
        hexdump(suffix[:160])
        print()


if __name__ == "__main__":
    main()
