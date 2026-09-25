#!/usr/bin/env python3
"""
Repair jobs.db after the positional ji:-matching / column-shift bug.

Before the fix, a pull could (a) attach a ji: blob — ink + username — to the
neighbouring job, and (b) build a job row from two different jobs when a print
finished mid-pull (the job log is newest-first, so every row index shifts),
storing it as an extra "ghost" job. This script fixes the stored history:

  1. Archives every stored blob into raw_capture first (nothing is lost).
  2. Collapses duplicate rows per printer counter (one counter = one job).
     The kept row is the one whose end time matches the job's own blob, else
     the one with a start time, else the earliest (ghost rows carry the times
     of a NEWER job). sent_at is carried over so billing state is preserved.
     Rows without a counter that duplicate a printer-read job (inserted by the
     April .accdb backfill) are folded into that job.
  3. Re-attaches every blob to the job whose counter is embedded in it; a job
     whose stored blob belongs to another job has that ink/username cleared.
  4. Optionally (--csv) applies the old LFP Accounting Tool CSV export as the
     authority for ink + username of the jobs it covers (matched by end time).

Dry run by default. --apply writes, after copying the DB to
jobs.db.bak-<timestamp>; every change and every deleted row is recorded in the
repair_log table.

Usage (on the Pi):
    python3 repair_alignment.py                       # dry run, report only
    python3 repair_alignment.py --csv "lfpa-logs/EPSON ...csv"
    python3 repair_alignment.py --csv "lfpa-logs/EPSON ...csv" --apply
"""
import argparse
import csv
import json
import shutil
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from joblog import decode_ji_info, INK_CHANNELS
from store import _connect, archive_raw

DEFAULT_DB = Path.home() / ".lfp_accounting" / "jobs.db"
SERIAL = "X6FB001980"
INK_COLS = ["InkUse_" + ch for ch in INK_CHANNELS]

# Old-tool CSV column -> our channel (verified against a decrypted blob).
CSV_INK = {
    "Gray(ml)": "LK", "Vivid Magenta(ml)": "VM", "Orange(ml)": "OR",
    "Photo Black(ml)": "PK", "Vivid Light Magenta(ml)": "VLM",
    "Light Gray(ml)": "LLK", "Light Cyan(ml)": "LC", "Yellow(ml)": "Y",
    "Green(ml)": "GR", "Matte Black(ml)": "MK", "Violet(ml)": "V", "Cyan(ml)": "C",
}


def _dt(s):
    """Stored ISO text (naive local time tagged +00:00) -> naive datetime."""
    if not s:
        return None
    try:
        return datetime.fromisoformat(s[:19])
    except ValueError:
        return None


def _near(a, b, secs=2):
    return a is not None and b is not None and abs((a - b).total_seconds()) <= secs


def _ink_total(row):
    vals = [row[c] for c in INK_COLS]
    return None if all(v is None for v in vals) else round(sum(v or 0 for v in vals))


def _came_from(row, info):
    """True if the row's stored ink is exactly what this blob decodes to,
    i.e. the ink (and its ji: username) was taken from that blob."""
    blob_ink = [info["ink"].get(ch) if info["ink"] else None for ch in INK_CHANNELS]
    return [row[c] for c in INK_COLS] == blob_ink or _ink_total(row) is None


def _num(s):
    s = (s or "").replace(" ", "").replace(" ", "").replace(",", ".")
    try:
        return float(s)
    except ValueError:
        return 0.0


def load_csv(path):
    rows = list(csv.reader(open(path, encoding="utf-8-sig")))
    hdr = next(i for i, r in enumerate(rows) if r and r[0] == "Job Name")
    out = []
    for r in rows[hdr + 1:]:
        if not r or r[0].startswith("Lost Job"):
            continue
        d = dict(zip(rows[hdr], r))
        ink = {ch: round(_num(d[col]) * 100) for col, ch in CSV_INK.items()}
        out.append({
            "name": d["Job Name"], "end": _dt(d["Completion Time"].replace(" ", "T")),
            "user": d["User Name"] if d["User Name"] not in ("", "-") else None,
            "host": d["Host Name"] if d["Host Name"] not in ("", "-") else None,
            "ink": ink if any(ink.values()) else None,
        })
    return out


class Repair:
    def __init__(self, conn, apply):
        self.conn, self.apply = conn, apply
        self.stats = defaultdict(int)

    def log(self, job_id, action, detail):
        self.stats[action] += 1
        if self.apply:
            self.conn.execute(
                "INSERT INTO repair_log (job_id, action, detail) VALUES (?, ?, ?)",
                (job_id, action, json.dumps(detail, default=str, ensure_ascii=False)))

    def exec(self, sql, params):
        if self.apply:
            self.conn.execute(sql, params)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--db", type=Path, default=DEFAULT_DB)
    ap.add_argument("--csv", help="old LFP Accounting Tool CSV export to apply")
    ap.add_argument("--apply", action="store_true", help="write changes (default: dry run)")
    args = ap.parse_args()

    if args.apply:
        bak = args.db.with_name(args.db.name + ".bak-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
        shutil.copy2(args.db, bak)
        print("Backup:", bak)

    conn = _connect(args.db)
    conn.execute("""CREATE TABLE IF NOT EXISTS repair_log (
        ts TEXT DEFAULT (datetime('now')), job_id TEXT, action TEXT, detail TEXT)""")
    R = Repair(conn, args.apply)
    rows = [dict(r) for r in conn.execute("SELECT * FROM jobs")]
    before = {r["job_id"]: r for r in rows}

    # 1. Archive every stored blob, and decode it.
    if args.apply:
        archive_raw([{"kind": "ji_blob_legacy", "slot": None, "counter": r["counter"],
                      "payload": r["ji_blob"]} for r in rows if r["ji_blob"]], args.db)
    blob_for = {}                   # counter -> (blob, info), best one
    user_for = {}                   # counter -> (username, machine) verified
    for r in rows:
        info = decode_ji_info(r["ji_blob"], SERIAL) if r["ji_blob"] else None
        r["_blob_info"] = info
        if not info or not info["end"]:
            continue                                  # undecryptable / pending
        c = info["counter"]
        cur = blob_for.get(c)
        if cur is None or (info["ink"] and not cur[1]["ink"]):
            blob_for[c] = (r["ji_blob"], info)
        if c == r["counter"] and r["username"]:
            user_for[c] = (r["username"], r["machine_name"])

    # 2. One row per counter.
    groups = defaultdict(list)
    for r in rows:
        if r["counter"] is not None:
            groups[r["counter"]].append(r)
    alive = {r["job_id"]: r for r in rows}
    for c, g in groups.items():
        if len(g) < 2:
            continue
        bend = blob_for[c][1]["end"] if c in blob_for else None

        def rank(r):
            return (not _near(_dt(r["end_time"]), bend),
                    r["start_time"] is None,
                    r["end_time"] or "9999",
                    r["sent_at"] is None)
        g.sort(key=rank)
        keep = g[0]
        sent = min((r["sent_at"] for r in g if r["sent_at"]), default=None)
        for r in g[1:]:
            R.log(r["job_id"], "delete_duplicate",
                  {"kept": keep["job_id"], "row": {k: v for k, v in r.items()
                                                   if not k.startswith("_") and k != "ji_blob"}})
            R.exec("DELETE FROM jobs WHERE job_id = ?", (r["job_id"],))
            del alive[r["job_id"]]
        if sent and not keep["sent_at"]:
            R.log(keep["job_id"], "carry_sent_at", {"sent_at": sent})
            R.exec("UPDATE jobs SET sent_at = ? WHERE job_id = ?", (sent, keep["job_id"]))
            keep["sent_at"] = sent

    # 2b. Counter-less rows (the April .accdb backfill inserted jobs instead of
    # filling them) that duplicate a printer-read job: same name, the .accdb
    # start (= blob start) 0-10 min before the job-log start. Hand any ink /
    # username the printer row lacks over to it, then drop the copy.
    by_name = defaultdict(list)
    for r in alive.values():
        if r["counter"] is not None and _dt(r["start_time"]):
            by_name[r["job_name"]].append(r)
    pairs = []
    for r in alive.values():
        s = _dt(r["start_time"])
        if r["counter"] is not None or not s:
            continue
        for w in by_name.get(r["job_name"], []):
            d = (_dt(w["start_time"]) - s).total_seconds()
            if -60 <= d <= 600:
                pairs.append((abs(d), r["job_id"], w["job_id"]))
    used = set()
    for _, cid, wid in sorted(pairs):
        if cid in used or wid in used:
            continue
        used.update((cid, wid))
        r, w = alive[cid], alive[wid]
        upd = {}
        if _ink_total(w) is None and _ink_total(r) is not None:
            upd.update({k: r[k] for k in INK_COLS})
        if not w["username"] and r["username"]:
            upd["username"], upd["machine_name"] = r["username"], r["machine_name"]
        if r["sent_at"] and not w["sent_at"]:
            upd["sent_at"] = r["sent_at"]
        if upd:
            R.exec("UPDATE jobs SET %s WHERE job_id = ?" % ", ".join(k + " = ?" for k in upd),
                   (*upd.values(), wid))
            w.update(upd)
        R.log(cid, "delete_accdb_duplicate",
              {"kept": wid, "moved": sorted(upd),
               "row": {k: v for k, v in r.items() if not k.startswith("_") and k != "ji_blob"}})
        R.exec("DELETE FROM jobs WHERE job_id = ?", (cid,))
        del alive[cid]

    # 3. Re-attach blobs by their embedded counter.
    for r in alive.values():
        c = r["counter"]
        own = r["_blob_info"]
        if c in blob_for:
            blob, info = blob_for[c]
            new_ink = [info["ink"].get(ch) if info["ink"] else None for ch in INK_CHANNELS]
            user = user_for.get(c)
            upd = {}
            if [r[k] for k in INK_COLS] != new_ink:
                upd.update(dict(zip(INK_COLS, new_ink)))
            if r["ji_blob"] != blob:
                upd["ji_blob"] = blob
            if user and r["username"] != user[0]:
                upd["username"], upd["machine_name"] = user
            elif not user and own and own["counter"] != c and r["username"] \
                    and _came_from(r, own):
                upd["username"] = None           # came with the wrong blob
            # Ghost row that was the only copy: take the times from the blob.
            if info["start"] and info["end"] and not _near(_dt(r["end_time"]), info["end"], 5):
                upd["start_time"] = info["start"].isoformat() + "+00:00"
                upd["end_time"] = info["end"].isoformat() + "+00:00"
                upd["print_secs"] = int((info["end"] - info["start"]).total_seconds())
            if upd:
                R.log(r["job_id"], "reattach_blob",
                      {"old_ink": _ink_total(r), "new_ink": sum(v or 0 for v in new_ink),
                       "changed": sorted(k for k in upd if k != "ji_blob"),
                       "old_user": r["username"], "sent_at": r["sent_at"]})
                R.exec("UPDATE jobs SET %s WHERE job_id = ?" % ", ".join(k + " = ?" for k in upd),
                       (*upd.values(), r["job_id"]))
                r.update(upd)
        elif own and own["counter"] != c:
            if _came_from(r, own):
                # Its ink (and the username that came with the same ji: entry)
                # belongs to another job and we have no verified source for
                # this one — clear, don't guess.
                R.log(r["job_id"], "clear_foreign_blob",
                      {"old_ink": _ink_total(r), "old_user": r["username"],
                       "blob_counter": own["counter"], "sent_at": r["sent_at"]})
                R.exec("UPDATE jobs SET %s, ji_blob = NULL, username = NULL WHERE job_id = ?"
                       % ", ".join(k + " = NULL" for k in INK_COLS), (r["job_id"],))
                for k in INK_COLS + ["ji_blob", "username"]:
                    r[k] = None
            else:
                # Ink came from elsewhere (e.g. the .accdb merge) — keep it,
                # only detach the wrong blob.
                R.log(r["job_id"], "detach_foreign_blob",
                      {"blob_counter": own["counter"]})
                R.exec("UPDATE jobs SET ji_blob = NULL WHERE job_id = ?", (r["job_id"],))
                r["ji_blob"] = None

    # 3b. The old upsert could later overwrite a zero-ink job's ink from a
    # different (mis-positioned) blob while keeping the first stored blob, so
    # some rows hold another job's exact ink with no blob to show for it. Clear
    # ink identical to a different job's verified blob when that job has a
    # different name, or when this job never printed (status 0, 0 s). Same-name
    # reprints legitimately use identical ink and are left alone.
    ink_owner = defaultdict(set)
    payloads = [r["ji_blob"] for r in rows if r["ji_blob"]]
    for kind, p in conn.execute(
            "SELECT kind, payload FROM raw_capture WHERE kind IN ('ji', 'ji_blob_legacy')"):
        payloads.append(p[8:216] if kind == "ji" else p)
    for p in payloads:
        info = decode_ji_info(p, SERIAL)
        if info and info["ink"]:
            ink_owner[tuple(info["ink"][ch] for ch in INK_CHANNELS)].add(info["counter"])
    name_of = {r["counter"]: r["job_name"] for r in alive.values() if r["counter"] is not None}
    for r in alive.values():
        if r["counter"] is None or _ink_total(r) is None:
            continue
        vec = tuple(None if r[k] is None else round(r[k]) for k in INK_COLS)
        owners = ink_owner.get(vec, set()) - {r["counter"]}
        if not owners or r["counter"] in ink_owner.get(vec, set()):
            continue
        never_printed = r["status_code"] == 0 and not r["print_secs"]
        # Prefix compare: multi-file jobs are named "a.tif, b.tif, …".
        if never_printed or any((name_of.get(o) or "")[:15] != r["job_name"][:15]
                                for o in owners):
            R.log(r["job_id"], "clear_borrowed_ink",
                  {"old_ink": _ink_total(r), "owners": sorted(owners), "sent_at": r["sent_at"]})
            R.exec("UPDATE jobs SET %s WHERE job_id = ?"
                   % ", ".join(k + " = NULL" for k in INK_COLS), (r["job_id"],))
            for k in INK_COLS:
                r[k] = None

    # 4. Old-tool CSV as authority for the jobs it covers.
    unmatched = []
    if args.csv:
        by_day = defaultdict(list)
        for r in alive.values():
            e = _dt(r["end_time"])
            if e:
                by_day[e.date()].append(r)
        taken = set()
        for o in load_csv(args.csv):
            cands = [r for d in (o["end"].date(),) for r in by_day[d]
                     if _near(_dt(r["end_time"]), o["end"]) and r["job_id"] not in taken]
            cands.sort(key=lambda r: (r["job_name"][:20] != o["name"][:20],
                                      abs((_dt(r["end_time"]) - o["end"]).total_seconds())))
            if not cands:
                unmatched.append(o)
                continue
            r = cands[0]
            taken.add(r["job_id"])
            new_ink = [o["ink"][ch] if o["ink"] else None for ch in INK_CHANNELS]
            upd = {}
            if [None if v is None else round(v) for v in (r[k] for k in INK_COLS)] != new_ink:
                upd.update(dict(zip(INK_COLS, new_ink)))
            if o["user"] and r["username"] != o["user"]:
                upd["username"] = o["user"]
                if o["host"]:
                    upd["machine_name"] = o["host"]
            if upd:
                R.log(r["job_id"], "apply_csv",
                      {"old_ink": _ink_total(r), "new_ink": sum(v or 0 for v in new_ink),
                       "old_user": r["username"], "new_user": o["user"], "sent_at": r["sent_at"]})
                R.exec("UPDATE jobs SET %s WHERE job_id = ?" % ", ".join(k + " = ?" for k in upd),
                       (*upd.values(), r["job_id"]))
                r.update(upd)

    if args.apply:
        conn.commit()
    conn.close()

    # Report
    print("\n%s" % ("APPLIED" if args.apply else "DRY RUN — nothing written (use --apply)"))
    for k, v in sorted(R.stats.items()):
        print("  %-20s %d" % (k, v))
    if args.csv:
        print("  %-20s %d (old-tool jobs with no job at that end time — listed below)"
              % ("csv_unmatched", len(unmatched)))
        for o in unmatched:
            print("      %s  %s" % (o["end"], o["name"][:50]))

    # Per-month effect, split by what was already billed.
    def month_totals(rs):
        t = defaultdict(lambda: [0, 0.0, 0.0])
        for r in rs:
            m = (r["start_time"] or r["end_time"] or "")[:7]
            t[m][0] += 1
            t[m][1] += (_ink_total(r) or 0) / 100
            t[m][2] += (r["area_cm2"] or 0) / 1e4
        return t
    b, a = month_totals(before.values()), month_totals(alive.values())
    sent_months = {(r["start_time"] or "")[:7] for r in before.values() if r["sent_at"]}
    print("\n  month    billed  jobs before→after   ink ml before→after     media m² before→after")
    for m in sorted(set(b) | set(a)):
        if not m:
            continue
        print("  %-7s  %-6s  %5d → %-5d        %8.1f → %-8.1f     %7.1f → %-7.1f"
              % (m, "yes" if m in sent_months else "", b[m][0], a[m][0],
                 b[m][1], a[m][1], b[m][2], a[m][2]))


if __name__ == "__main__":
    sys.exit(main())
