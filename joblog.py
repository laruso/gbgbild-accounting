"""
Epson SC-P9500 job log retrieval via SNMP.

Discovered OID structure (Epson enterprise 1.3.6.1.4.1.1248.1.2.2.27.20):
  .27.20.1.COL.1.1.ROW  where ROW 1=newest, 499=oldest (max 500 entries)

  COL 2  : cumulative counter (int, increases over time)
  COL 3  : job name (string)
  COL 5  : start time  (SNMP DateAndTime, 11 bytes)
  COL 6  : end time    (SNMP DateAndTime, 11 bytes)
  COL 8  : paper source code (int: 1=cut 2=sheet 3=roll 4=posterboard 5=roll1 6=roll2)
  COL 9  : width mm (int)
  COL 10 : length mm (int)
  COL 11 : status/mode code (int)
  COL 12 : media type id (int)

Ink levels: standard RFC-3805 Printer-MIB
  1.3.6.1.2.1.43.11.1.1.{6,8,9}.1.N  (name, max, level)
"""

import json
import socket
import struct
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional

log = logging.getLogger("joblog")

PAPER_SOURCE = {
    1: "Cut paper",
    2: "Sheet",
    3: "Roll paper",
    4: "Poster Board",
    5: "Roll 1",
    6: "Roll 2",
}

STATUS_CODE = {
    1: "Completed",
    2: "Printing",
    3: "Pending",
    4: "Canceled",
    5: "Aborted",
}


INK_CHANNELS = ["PK", "MK", "C", "VM", "Y", "OR", "GR", "LC", "VLM", "LK", "LLK", "V"]

# DLL field order for ink values in the decrypted TLV blob (tag 0x0F)
_DLL_INK_ORDER = ["LK", "VM", "OR", "PK", "VLM", "LLK", "LC", "Y", "GR", "MK", "V", "C"]


@dataclass
class JobRecord:
    job_name:     str = ""
    username:     str = ""
    machine_name: str = ""
    start_time:   Optional[datetime] = None
    end_time:     Optional[datetime] = None
    print_secs:   Optional[int] = None
    paper_source: str = ""
    width_mm:     Optional[int] = None
    length_mm:    Optional[int] = None
    area_cm2:     Optional[float] = None
    media_type_id: Optional[int] = None
    status_code:  Optional[int] = None
    counter:      Optional[int] = None
    ink_use:      Optional[dict] = None   # {channel: value} e.g. {"PK": 12345, ...}
    ink_cum_use:  Optional[dict] = None
    ink_mnt_use:  Optional[dict] = None
    ji_blob:      Optional[bytes] = None  # raw 208-byte binary for future decoding

    def to_dict(self) -> dict:
        d = {
            "job_name":      self.job_name,
            "username":      self.username,
            "machine_name":  self.machine_name,
            "start_time":    self.start_time.isoformat() if self.start_time else "",
            "end_time":      self.end_time.isoformat()   if self.end_time   else "",
            "print_secs":    self.print_secs,
            "paper_source":  self.paper_source,
            "width_mm":      self.width_mm,
            "length_mm":     self.length_mm,
            "area_cm2":      self.area_cm2,
            "media_type_id": self.media_type_id,
            "status":        STATUS_CODE.get(self.status_code, str(self.status_code))
                             if self.status_code is not None else "",
        }
        if self.ink_use:
            for ch, val in self.ink_use.items():
                d[f"InkUse_{ch}"] = val
        return d


@dataclass
class InkChannel:
    index: int
    name:  str
    level: Optional[int]   # current level (same units as max)
    max:   Optional[int]   # max capacity
    pct:   Optional[float] # percentage remaining

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "name":  self.name,
            "level": self.level,
            "max":   self.max,
            "pct":   round(self.pct, 1) if self.pct is not None else None,
        }


# ─────────────────────────────────────────────────────────────────────────────
# SNMP primitives (no external libraries)
# ─────────────────────────────────────────────────────────────────────────────

def _encode_oid(oid_str: str) -> bytes:
    parts = list(map(int, oid_str.split(".")))
    enc = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        if p == 0:
            enc += b"\x00"
        elif p < 128:
            enc += bytes([p])
        else:
            out = []
            while p:
                out.append(p & 0x7f)
                p >>= 7
            out.reverse()
            enc += bytes([b | 0x80 for b in out[:-1]] + [out[-1]])
    return enc

def _tlv(tag: int, value: bytes) -> bytes:
    l = len(value)
    if l < 128:
        return bytes([tag, l]) + value
    elif l < 256:
        return bytes([tag, 0x81, l]) + value
    else:
        return bytes([tag, 0x82, l >> 8, l & 0xff]) + value

def _snmp_pkt(pdu_tag: int, community: str, oid: str) -> bytes:
    varbinds = _tlv(0x30, _tlv(0x06, _encode_oid(oid)) + _tlv(0x05, b""))
    pdu = _tlv(pdu_tag,
               _tlv(0x02, b"\x01") +
               _tlv(0x02, b"\x00") +
               _tlv(0x02, b"\x00") +
               _tlv(0x30, varbinds))
    return _tlv(0x30,
                _tlv(0x02, b"\x00") +
                _tlv(0x04, community.encode()) +
                pdu)

def _decode_ber_len(data: bytes, pos: int):
    l = data[pos]
    if l < 128:
        return l, pos + 1
    n = l & 0x7f
    val = 0
    for i in range(n):
        val = (val << 8) | data[pos + 1 + i]
    return val, pos + 1 + n

def _decode_oid_bytes(data: bytes) -> str:
    if not data:
        return ""
    parts = [data[0] // 40, data[0] % 40]
    i = 1
    while i < len(data):
        val = 0
        while i < len(data):
            b = data[i]; i += 1
            val = (val << 7) | (b & 0x7f)
            if not (b & 0x80):
                break
        parts.append(val)
    return ".".join(map(str, parts))

def _parse_snmp_resp(resp: bytes):
    """Return list of (oid_str, tag, raw_bytes)."""
    results = []
    try:
        i = 0
        assert resp[i] == 0x30
        _, i = _decode_ber_len(resp, i + 1)
        assert resp[i] == 0x02
        l, i = _decode_ber_len(resp, i + 1); i += l
        assert resp[i] == 0x04
        l, i = _decode_ber_len(resp, i + 1); i += l
        _, i = _decode_ber_len(resp, i + 1)  # PDU tag + skip
        for _ in range(3):
            assert resp[i] == 0x02
            l, i = _decode_ber_len(resp, i + 1); i += l
        assert resp[i] == 0x30
        l, i = _decode_ber_len(resp, i + 1)
        end = i + l
        while i < end:
            if resp[i] != 0x30: break
            _, i = _decode_ber_len(resp, i + 1)
            assert resp[i] == 0x06
            oid_l, i = _decode_ber_len(resp, i + 1)
            oid = _decode_oid_bytes(resp[i:i + oid_l]); i += oid_l
            val_tag = resp[i]
            val_l, i = _decode_ber_len(resp, i + 1)
            raw = resp[i:i + val_l]; i += val_l
            results.append((oid, val_tag, raw))
    except Exception as e:
        log.debug("SNMP parse error: %s", e)
    return results

def _snmp_send(host: str, pkt: bytes, timeout: float = 4.0) -> Optional[bytes]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(pkt, (host, 161))
        resp, _ = sock.recvfrom(65535)
        return resp
    except socket.timeout:
        return None
    finally:
        sock.close()

def _as_int(tag: int, raw: bytes) -> Optional[int]:
    if tag in (0x02, 0x41, 0x42, 0x43):
        v = 0
        for b in raw: v = (v << 8) | b
        return v
    return None

def _as_str(tag: int, raw: bytes) -> Optional[str]:
    if tag == 0x04:
        try:
            return raw.decode("utf-8", errors="replace").strip("\x00").strip()
        except Exception:
            return None
    return None

def snmp_get(host: str, oid: str, community: str = "public", timeout: float = 4.0):
    resp = _snmp_send(host, _snmp_pkt(0xa0, community, oid), timeout)
    if not resp:
        return None
    r = _parse_snmp_resp(resp)
    if r and r[0][0] == oid:
        return r[0]
    return None

def snmp_walk_column(host: str, root_oid: str, community: str = "public",
                     timeout: float = 4.0, max_steps: int = 600):
    """Walk a single SNMP column. Yields (oid, tag, raw) tuples."""
    current = root_oid
    for _ in range(max_steps):
        resp = _snmp_send(host, _snmp_pkt(0xa1, community, current), timeout)
        if not resp:
            log.debug("SNMP walk timeout at %s", current)
            break
        r = _parse_snmp_resp(resp)
        if not r:
            break
        oid, tag, raw = r[0]
        if not oid.startswith(root_oid):
            break
        if tag in (0x80, 0x81, 0x82):
            break
        yield oid, tag, raw
        current = oid


# ─────────────────────────────────────────────────────────────────────────────
# Timestamp decoding
# ─────────────────────────────────────────────────────────────────────────────

def _decode_datetime(raw: bytes) -> Optional[datetime]:
    """Decode SNMP DateAndTime (RFC 2579), 8 or 11 bytes."""
    if len(raw) < 8:
        return None
    try:
        year   = struct.unpack(">H", raw[0:2])[0]
        month  = raw[2]; day    = raw[3]
        hour   = raw[4]; minute = raw[5]; second = raw[6]
        if len(raw) >= 11:
            direction = raw[8]   # ord('+') = 43 or ord('-') = 45
            tz_h = raw[9]; tz_m = raw[10]
            offset = timedelta(hours=tz_h, minutes=tz_m)
            if direction == 45:  # '-'
                offset = -offset
            tz = timezone(offset)
        else:
            tz = timezone.utc
        return datetime(year, month, day, hour, minute, second, tzinfo=tz)
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Job log OID base
# ─────────────────────────────────────────────────────────────────────────────

_JL_BASE = "1.3.6.1.4.1.1248.1.2.2.27.20.1"

def _col_root(col: int) -> str:
    return "%s.%d.1.1" % (_JL_BASE, col)

def _row_index(oid: str, col: int) -> Optional[int]:
    prefix = "%s.%d.1.1." % (_JL_BASE, col)
    if oid.startswith(prefix):
        try:
            return int(oid[len(prefix):])
        except ValueError:
            pass
    return None


# ─────────────────────────────────────────────────────────────────────────────
# ji: blob decryption (custom 3-round Feistel cipher, key = serial number)
# ─────────────────────────────────────────────────────────────────────────────

def _decrypt_ji_blob(data: bytes, serial: str) -> bytes:
    """
    Decrypt the 208-byte ji: blob.

    The cipher is a 3-round Feistel with 8-byte blocks and CBC chaining.
    Key = printer serial number (ASCII, zero-padded to 16 bytes).
    Round keys derived from key bytes at offsets 2-9.
    First block XOR'd with key[2:10], subsequent blocks XOR'd with
    the previous block's original (encrypted) data (CBC mode).
    """
    key_full = serial.encode("ascii").ljust(16, b"\x00")
    K = list(key_full[2:10])
    k4, k5, k6, k7 = K[4], K[5], K[6], K[7]

    va = (k4 + 1) & 0xFF
    vb = ((k4 + 2) * 2) & 0xFF
    vf = (k5 + 1) & 0xFF
    ve = (k6 + 1) & 0xFF
    vd = (k7 + 1) & 0xFF
    vk1 = (vf + va + 2) & 0xFF
    vk2 = (ve + va + 2) & 0xFF
    vk3 = (vd + va + 2) & 0xFF
    vk4 = (vb + vf + 3) & 0xFF
    vk5 = (vk1 + vf + 3) & 0xFF
    vk7 = (vk2 + vf + 3) & 0xFF
    vk6 = (vk3 + vf + 3) & 0xFF

    r1k = [vk4, vk5, vk7, vk6]
    r2k = [vb, vk1, vk2, vk3]
    r3k = [va, vf, ve, vd]

    buf = bytearray(data)
    original = bytes(data)
    xor_key = list(key_full[2:10])

    for blk in range(len(buf) // 8):
        b = blk * 8
        s1 = (buf[b+7] + buf[b+6] + buf[b+5] + buf[b+4]) & 0xFF
        for i in range(4):
            d = (buf[b+4+i] ^ r1k[i]) & 0xFF
            d = (d + s1) & 0xFF
            buf[b+i] ^= d
        s2 = (buf[b+3] + buf[b+2] + buf[b+1] + buf[b+0]) & 0xFF
        for i in range(4):
            d = (buf[b+i] ^ r2k[i]) & 0xFF
            d = (d + s2) & 0xFF
            buf[b+4+i] ^= d
        s3 = (buf[b+7] + buf[b+6] + buf[b+5] + buf[b+4]) & 0xFF
        for i in range(4):
            d = (buf[b+4+i] ^ r3k[i]) & 0xFF
            d = (d + s3) & 0xFF
            buf[b+i] ^= d
        for i in range(8):
            buf[b+i] ^= xor_key[i]
        xor_key = list(original[b:b+8])

    return bytes(buf)


def _parse_ink_from_tlv(decrypted: bytes) -> dict:
    """
    Parse tag 0x0F (24 bytes = 12 x 2-byte LE) from the decrypted TLV.
    Returns {channel_name: value} for all 12 ink channels.
    """
    i = 0
    while i < len(decrypted) - 1:
        tag = decrypted[i]
        if tag == 0:
            break
        length = decrypted[i + 1]
        if i + 2 + length > len(decrypted):
            break
        if tag == 0x0F and length == 24:
            ink_data = decrypted[i + 2:i + 2 + 24]
            values = {}
            for ch_idx, ch_name in enumerate(_DLL_INK_ORDER):
                values[ch_name] = struct.unpack_from("<H", ink_data, ch_idx * 2)[0]
            return values
        i += 2 + length
    return {}


def decode_ji_ink(blob: bytes, serial: str) -> Optional[dict]:
    """
    Decrypt a 208-byte ji: blob and extract per-job ink usage values.

    Args:
        blob: The 208-byte encrypted blob from the ji: SNMP response
        serial: Printer serial number (e.g. 'X6FB001980')

    Returns:
        Dict mapping channel name to usage value, or None on failure or when
        the blob carries no usage yet. E.g. {'PK': 1, 'MK': 36, 'C': 7, ...}

    An all-zero result is treated as "no data" (returns None): a real print
    always lays down some ink, so all twelve channels reading zero means the
    printer hasn't populated this entry yet (the ji: buffer fills in slightly
    after the print) or it's a placeholder entry. Returning None keeps the job
    NULL/backfillable instead of locking in a 0 that a later pull or the .accdb
    backfill can never replace.
    """
    if not blob or len(blob) != 208 or not serial:
        return None
    try:
        decrypted = _decrypt_ji_blob(blob, serial)
        ink = _parse_ink_from_tlv(decrypted)
        if not ink or not any(ink.values()):
            return None
        return ink
    except Exception as e:
        log.debug("Blob decryption failed: %s", e)
        return None


def _iter_tlv(decrypted: bytes) -> dict:
    """Split the decrypted ji: TLV into {tag: value_bytes}."""
    out = {}
    i = 0
    while i < len(decrypted) - 1 and decrypted[i] != 0:
        tag, length = decrypted[i], decrypted[i + 1]
        if i + 2 + length > len(decrypted):
            break
        out[tag] = decrypted[i + 2:i + 2 + length]
        i += 2 + length
    return out


def _decode_ji_time(raw: bytes) -> Optional[datetime]:
    """ji: timestamps are 6 bytes: yy mm dd hh mm ss (local printer time).
    All-zero means the printer hasn't filled the entry in yet."""
    if len(raw) != 6 or not any(raw):
        return None
    try:
        return datetime(2000 + raw[0], raw[1], raw[2], raw[3], raw[4], raw[5])
    except ValueError:
        return None


def decode_ji_info(blob: bytes, serial: str) -> Optional[dict]:
    """Decrypt a ji: blob into its identity and usage fields.

    Returns {"counter", "start", "end", "ink"} or None if undecryptable.
    The blob carries its OWN job counter (tag 0x03) — the same value as the
    job-log counter column — plus start (0x12) and end (0x13) times. That is
    what ties a blob to exactly one job; never match blobs by position.
    "ink" follows decode_ji_ink's rule (None when all-zero / not yet filled).
    """
    if not blob or len(blob) != 208 or not serial:
        return None
    try:
        tlv = _iter_tlv(_decrypt_ji_blob(blob, serial))
    except Exception as e:
        log.debug("Blob decryption failed: %s", e)
        return None
    raw_counter = tlv.get(0x03)
    if not raw_counter or len(raw_counter) != 4:
        return None
    ink = None
    raw_ink = tlv.get(0x0F)
    if raw_ink and len(raw_ink) == 24:
        vals = {ch: struct.unpack_from("<H", raw_ink, n * 2)[0]
                for n, ch in enumerate(_DLL_INK_ORDER)}
        ink = vals if any(vals.values()) else None
    return {
        "counter": struct.unpack("<I", raw_counter)[0],
        "start":   _decode_ji_time(tlv.get(0x12, b"")),
        "end":     _decode_ji_time(tlv.get(0x13, b"")),
        "ink":     ink,
    }


def fetch_serial_number(host: str, community: str = "epson",
                        timeout: float = 4.0) -> Optional[str]:
    """
    Fetch the printer serial number via the BDC ST2 SNMP response.
    The serial is in the tail of OID 1.3.6.1.4.1.1248.1.2.2.1.1.1.4.
    """
    oid = "1.3.6.1.4.1.1248.1.2.2.1.1.1.4"
    for oid_try, comm in [(oid, community), (oid, "public")]:
        resp = _snmp_send(host, _snmp_pkt(0xa1, comm, oid_try), timeout)
        if not resp:
            continue
        parsed = _parse_snmp_resp(resp)
        for r_oid, tag, raw in parsed:
            if tag == 0x04 and len(raw) > 20:
                # Serial is at the end after "@BDC ST2\r\n" data,
                # preceded by 0x40 0x0a and the length
                st2_idx = raw.find(b"@BDC ST2")
                if st2_idx >= 0:
                    # Search for serial pattern: 0x40 0x0a then 10 ASCII chars
                    tail = raw[st2_idx:]
                    marker = tail.find(b"\x40\x0a")
                    if marker >= 0 and marker + 12 <= len(tail):
                        serial = tail[marker + 2:marker + 12].decode("ascii", errors="replace")
                        if serial.isalnum():
                            log.info("Printer serial number: %s", serial)
                            return serial
    # Fallback: try the device ID string
    oid2 = "1.3.6.1.4.1.1248.1.2.2.1.1.1.1"
    resp = _snmp_send(host, _snmp_pkt(0xa1, community, oid2), timeout)
    if resp:
        parsed = _parse_snmp_resp(resp)
        for r_oid, tag, raw in parsed:
            if tag == 0x04:
                text = raw.decode("ascii", errors="replace")
                # Look for SN: or serial pattern
                import re
                m = re.search(r"SN:(\w+)", text)
                if m:
                    return m.group(1)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Matching ji: entries to job-log rows
# ─────────────────────────────────────────────────────────────────────────────

def _match_ji_by_counter(ji_meta: dict, row_counters: dict, serial: str) -> dict:
    """Map job-log row index -> ji: entry, keyed on the job counter.

    Every decrypted ji: blob carries the job counter it belongs to (tag 0x03),
    which equals the job-log counter column. Matching on it is exact. The old
    positional alignment (newest row = ji index 0) shifted by one whenever the
    two lists didn't hold exactly the same jobs — e.g. a job in the log with no
    ji: entry, or a print finishing mid-pull — and then every ink value and
    username landed on the neighbouring job. Entries we can't decrypt (no
    serial) or whose counter isn't in the log are left unattached: a missing
    value is recoverable later, a wrong one silently mis-bills.

    Each matched entry gets "ji_info" (decode_ji_info result) added.
    Returns {row_index: ji_meta_entry}.
    """
    if not serial:
        log.warning("ji: no printer serial — cannot verify blobs, skipping ink/user")
        return {}
    row_by_counter = {c: idx for idx, c in row_counters.items() if c is not None}
    row_meta: dict = {}
    unmatched = 0
    for ji_idx in sorted(ji_meta):
        if ji_idx >= 256:          # the printer mirrors the buffer at >= 256
            continue
        m = ji_meta[ji_idx]
        info = decode_ji_info(m.get("ji_blob"), serial)
        if not info:
            continue
        row = row_by_counter.get(info["counter"])
        if row is None:
            unmatched += 1
            continue
        m["ji_info"] = info
        row_meta[row] = m
    log.info("ji: %d entries matched to jobs by counter (%d not in job log)",
             len(row_meta), unmatched)
    return row_meta


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

# Job-log columns read for every row (see module docstring).
_JL_COLS = (2, 3, 5, 6, 8, 9, 10, 11, 12)


def _snmp_get_multi_pkt(community: str, oids: list[str]) -> bytes:
    """SNMP GET with several varbinds in ONE request."""
    varbinds = b"".join(_tlv(0x30, _tlv(0x06, _encode_oid(o)) + _tlv(0x05, b""))
                        for o in oids)
    pdu = _tlv(0xa0,
               _tlv(0x02, b"\x01") +
               _tlv(0x02, b"\x00") +
               _tlv(0x02, b"\x00") +
               _tlv(0x30, varbinds))
    return _tlv(0x30, _tlv(0x02, b"\x00") + _tlv(0x04, community.encode()) + pdu)


def _get_row(host: str, community: str, timeout: float, row: int) -> Optional[dict]:
    """Read every column of one job-log row in a single SNMP GET.

    One request = one consistent snapshot of the row, so the name, counter,
    times and size always belong to the same job. Returns {col: (tag, raw)},
    {} if the row doesn't exist, or None if the printer didn't answer the
    multi-varbind request properly.
    """
    oids = ["%s.%d" % (_col_root(c), row) for c in _JL_COLS]
    resp = _snmp_send(host, _snmp_get_multi_pkt(community, oids), timeout)
    if not resp:
        return None
    parsed = _parse_snmp_resp(resp)
    if len(parsed) != len(oids) or [p[0] for p in parsed] != oids:
        return None
    out = {}
    for col, (_, tag, raw) in zip(_JL_COLS, parsed):
        if tag not in (0x80, 0x81, 0x82):       # noSuch* / endOfMib
            out[col] = (tag, raw)
    return out


def _fetch_rows_atomic(host: str, community: str, timeout: float,
                       max_rows: int = 500) -> Optional[dict]:
    """Fetch all job-log rows, one GET per row. None if unsupported."""
    rows: dict = {}
    empty_run = 0
    for row in range(1, max_rows + 1):
        r = _get_row(host, community, timeout, row)
        if r is None:
            r = _get_row(host, community, timeout, row)   # one retry
        if r is None:
            if row == 1:
                return None          # printer won't do multi-varbind GETs
            log.warning("  row %d: no answer, skipping", row)
            continue
        if 2 not in r:
            empty_run += 1
            if empty_run >= 3:
                break
            continue
        empty_run = 0
        rows[row] = r
    return rows


def _fetch_rows_walk(host: str, community: str, timeout: float,
                     attempts: int = 3) -> dict:
    """Fallback: walk column by column, but only accept a stable snapshot.

    Row 1 is always the newest job, so if a print finishes during the 2-4
    minute walk every row index shifts by one between columns, and a row ends
    up with one job's name and the next job's times/size. We re-walk the
    counter column afterwards and only accept the result when it didn't move.
    """
    for attempt in range(1, attempts + 1):
        cols: dict = {c: {} for c in _JL_COLS}
        for c in _JL_COLS:
            for oid, tag, raw in snmp_walk_column(host, _col_root(c), community, timeout):
                idx = _row_index(oid, c)
                if idx is not None:
                    cols[c][idx] = (tag, raw)
        after = {}
        for oid, tag, raw in snmp_walk_column(host, _col_root(2), community, timeout):
            idx = _row_index(oid, 2)
            if idx is not None:
                after[idx] = (tag, raw)
        if after == cols[2] and after:
            rows: dict = {}
            for c, vals in cols.items():
                for idx, v in vals.items():
                    rows.setdefault(idx, {})[c] = v
            return {i: r for i, r in rows.items() if 2 in r}
        log.warning("  job log changed during walk (attempt %d/%d), retrying",
                    attempt, attempts)
    log.error("  job log never stable during walk — skipping this pull")
    return {}


def fetch_job_log(host: str, community: str = "public",
                  timeout: float = 4.0, serial: str = "",
                  raw_sink: Optional[list] = None) -> list[JobRecord]:
    """
    Fetch all job log entries from the printer via SNMP.
    If serial is provided, decrypts ji: blobs to extract per-job ink usage.
    If raw_sink is a list, every job-log row ("row", JSON of {col: [tag, hex]})
    and every raw ji: entry ("ji", the bytes from "ji:" on) is appended to it as
    {"kind", "slot", "counter", "payload"} so the caller can archive exactly
    what the printer returned.
    Returns a list of JobRecord objects, sorted oldest-first, one per job
    counter.
    """
    log.info("Fetching job log from %s via SNMP...", host)

    rows = _fetch_rows_atomic(host, community, timeout)
    if rows is None:
        # Distinguish "printer off / unreachable" from "won't do multi-varbind
        # GETs": only the latter is worth the slow column-walk fallback.
        if _snmp_send(host, _snmp_pkt(0xa1, community, _col_root(2)), timeout) is None:
            log.warning("  printer %s not answering SNMP — skipping this pull", host)
            return []
        log.warning("  multi-varbind GET not supported; falling back to column walk")
        rows = _fetch_rows_walk(host, community, timeout)
    log.info("  Found %d job entries", len(rows))

    def as_int(r, c):
        v = r.get(c)
        return _as_int(*v) if v else None

    def as_str(r, c):
        v = r.get(c)
        return _as_str(*v) if v else None

    def as_dt(r, c):
        v = r.get(c)
        if v and v[0] == 0x04 and len(v[1]) >= 8:
            return _decode_datetime(v[1])
        return None

    # A job can show up at two row indices if a print finished while we were
    # reading (everything shifts down by one) — keep one row per counter.
    by_counter: dict = {}
    for idx in sorted(rows):
        c = as_int(rows[idx], 2)
        if c is not None and c not in by_counter:
            by_counter[c] = idx
    row_counters = {idx: c for c, idx in by_counter.items()}

    # Fetch ji: metadata for username/machine (uses BDC protocol, community='epson')
    ji_meta = {}
    try:
        ji_meta = fetch_ji_metadata(host, community="epson", timeout=timeout)
    except Exception as e:
        log.warning("Could not fetch ji: metadata: %s", e)

    if raw_sink is not None:
        for c, idx in by_counter.items():
            snap = {str(col): [tag, raw.hex()] for col, (tag, raw) in rows[idx].items()}
            raw_sink.append({"kind": "row", "slot": idx, "counter": c,
                             "payload": json.dumps(snap, sort_keys=True).encode()})
        for ji_idx, m in sorted(ji_meta.items()):
            if ji_idx >= 256 or not m.get("raw"):
                continue
            info = decode_ji_info(m.get("ji_blob"), serial) if serial else None
            raw_sink.append({"kind": "ji", "slot": ji_idx,
                             "counter": info["counter"] if info else None,
                             "payload": m["raw"]})

    row_meta = _match_ji_by_counter(ji_meta, row_counters, serial)

    records: list[JobRecord] = []
    for idx, counter in row_counters.items():
        r = rows[idx]
        name = as_str(r, 3) or ""
        if not name:
            continue

        start = as_dt(r, 5)
        end   = as_dt(r, 6)
        secs  = None
        if start and end:
            secs = max(0, int((end - start).total_seconds()))

        w = as_int(r, 9)
        l = as_int(r, 10)
        area = round(w * l / 100.0, 2) if w and l else None  # cm²

        pcode = as_int(r, 8) or 0
        psrc  = PAPER_SOURCE.get(pcode, str(pcode))

        meta = row_meta.get(idx)
        username     = (meta.get("username") if meta else "") or ""
        machine_name = (meta.get("machine")  if meta else "") or ""
        ji_blob      = meta.get("ji_blob") if meta else None
        ink_use      = meta["ji_info"]["ink"] if meta else None

        records.append(JobRecord(
            job_name      = name,
            username      = username,
            machine_name  = machine_name,
            start_time    = start,
            end_time      = end,
            print_secs    = secs,
            paper_source  = psrc,
            width_mm      = w,
            length_mm     = l,
            area_cm2      = area,
            media_type_id = as_int(r, 12),
            status_code   = as_int(r, 11),
            counter       = counter,
            ink_use       = ink_use,
            ji_blob       = ji_blob,
        ))

    # Row 1 = newest, row N = oldest → sort oldest-first by counter ascending
    records.sort(key=lambda r: r.counter or 0)
    log.info("Done. %d valid job records.", len(records))
    return records


# ─────────────────────────────────────────────────────────────────────────────
# BDC ji: per-job data via SNMP (username, machine, binary blob)
# ─────────────────────────────────────────────────────────────────────────────

_JI_OID_PREFIX = "1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1.106.105.3.0.0.0"


def _parse_ji_suffix(data: bytes) -> dict:
    """
    Parse the TLV suffix from a ji: BDC response.

    Format after the 208-byte binary blob:
      [len_prefix] 0x00 [tag length data]...

    The first byte is a one-byte length prefix (= len(data) - 4) whose value
    varies with the suffix length — long suffixes land in the uppercase-ASCII
    range (B/D/E…), short ones don't (0x33, 0x3e, 0x40…). The real TLV stream
    starts at the first 0x00, so we skip a single non-zero lead byte rather
    than only skipping when it looks like a letter (which dropped the username
    and job name for every short suffix).

    Tags:
      0x00 + subtype 0x07 + len + username
      0x08 + len + job_name (32 bytes max)
      0x09 + len + machine_name
      0x0e + len + (end marker)
    """
    result = {"username": "", "job_name": "", "machine": ""}
    if len(data) < 4:
        return result

    i = 0
    # Skip the leading length-prefix byte (TLV proper begins at the first 0x00).
    if data[0] != 0x00:
        i += 1

    while i < len(data) - 1:
        tag = data[i]; i += 1
        if tag == 0x00 and i + 1 < len(data):
            # compound tag: 0x00 + subtype + len + data
            subtype = data[i]; i += 1
            if i >= len(data):
                break
            ln = data[i]; i += 1
            if i + ln > len(data):
                break
            val = data[i:i + ln]; i += ln
            if subtype == 0x07:
                result["username"] = val.decode("utf-8", errors="replace").strip("\x00")
        elif tag in (0x08, 0x09, 0x0e, 0x3b):
            if i >= len(data):
                break
            ln = data[i]; i += 1
            if i + ln > len(data):
                break
            val = data[i:i + ln]; i += ln
            text = val.decode("utf-8", errors="replace").strip("\x00").strip()
            if tag == 0x08:
                result["job_name"] = text
            elif tag == 0x09:
                result["machine"] = text
        else:
            break  # unknown tag, stop parsing

    return result


def fetch_ji_metadata(host: str, community: str = "epson",
                      timeout: float = 4.0, max_jobs: int = 500) -> dict:
    """
    Query BDC ji: for each job index to get username, machine, and binary blob.

    Returns {row_index: {"username": ..., "machine": ..., "ji_blob": bytes}}
    where row_index matches the SNMP table row index (0-based).
    """
    log.info("Fetching ji: metadata from %s via BDC/SNMP...", host)
    results = {}
    last_hit = -1   # highest index that yielded a real ji: entry

    for job_idx in range(max_jobs):
        # The live buffer is a contiguous block at low indices (the printer
        # mirrors it again at index >= 256, which we don't need). Once we are
        # well past the last real entry, stop rather than scan to max_jobs.
        if last_hit >= 0 and job_idx - last_hit > 48:
            break

        oid = f"{_JI_OID_PREFIX}.{job_idx}"
        resp = _snmp_send(host, _snmp_pkt(0xa0, community, oid), timeout)
        if not resp:
            if job_idx > 10:
                break
            continue

        parsed = _parse_snmp_resp(resp)
        if not parsed:
            continue

        r_oid, val_tag, raw = parsed[0]
        if val_tag in (0x80, 0x81, 0x82):
            if job_idx > 10:
                break
            continue

        # Find ji: marker in raw value
        ji_pos = raw.find(b"ji:")
        if ji_pos < 0:
            continue

        ji_data = raw[ji_pos:]
        if len(ji_data) < 8:
            continue
        if ji_data[6:8] != b"\xd0\x00":
            continue

        # Extract 208-byte binary blob and suffix
        blob = ji_data[8:8 + 208]
        suffix = ji_data[8 + 208:]

        meta = _parse_ji_suffix(suffix)
        meta["ji_blob"] = blob if len(blob) == 208 else None
        meta["raw"] = bytes(ji_data)   # verbatim, for the raw_capture archive

        if meta["username"] or meta["machine"] or meta.get("ji_blob"):
            results[job_idx] = meta
            last_hit = job_idx
            log.debug("  ji[%d]: user=%s machine=%s", job_idx, meta["username"], meta["machine"])

    log.info("  Got ji: metadata for %d jobs", len(results))
    return results


def fetch_ink_status(host: str, community: str = "public",
                     timeout: float = 4.0) -> list[InkChannel]:
    """
    Return current ink levels for all channels via standard Printer-MIB.
    """
    channels = []
    for idx in range(1, 30):
        r_name  = snmp_get(host, "1.3.6.1.2.1.43.11.1.1.6.1.%d" % idx, community, timeout)
        r_level = snmp_get(host, "1.3.6.1.2.1.43.11.1.1.9.1.%d" % idx, community, timeout)
        r_max   = snmp_get(host, "1.3.6.1.2.1.43.11.1.1.8.1.%d" % idx, community, timeout)

        if r_name is None:
            break
        oid_n, tag_n, raw_n = r_name
        if not oid_n.endswith(".%d" % idx):
            break

        name  = _as_str(tag_n, raw_n) or ("channel %d" % idx)
        level = _as_int(r_level[1], r_level[2]) if r_level else None
        mx    = _as_int(r_max[1],   r_max[2])   if r_max   else None
        pct   = round(level / mx * 100, 1) if (level is not None and mx and mx > 0) else None

        channels.append(InkChannel(index=idx, name=name, level=level, max=mx, pct=pct))

    return channels
