#!/usr/bin/env python3
"""
Epson SC-P9500 accounting tool — SNMP-based replacement for LFP Accounting Tool.

Usage:
  python3 lfp_accounting.py --printer 10.0.0.48 pull
  python3 lfp_accounting.py --printer 10.0.0.48 status
  python3 lfp_accounting.py --printer 10.0.0.48 list [--limit 20]
  python3 lfp_accounting.py --printer 10.0.0.48 export jobs.csv
"""
import argparse
import csv
import sys
import logging
from pathlib import Path

from joblog import fetch_job_log, fetch_ink_status, fetch_serial_number, STATUS_CODE, INK_CHANNELS
from store  import upsert_jobs, all_jobs, rebuild_monthly_summary, get_monthly_summary


def cmd_pull(args):
    print("Connecting to %s via SNMP..." % args.printer)

    # Fetch serial number for ink decryption
    serial = fetch_serial_number(args.printer, community="epson")
    if serial:
        print("Printer serial: %s (ink decryption enabled)" % serial)
    else:
        print("WARNING: Could not get serial number — ink values will be unavailable")

    print("Fetching up to 499 job records (may take 2-4 minutes)...")
    records = fetch_job_log(args.printer, community=args.community, serial=serial or "")
    if not records:
        print("No job records found.")
        return

    ink_count = sum(1 for r in records if r.ink_use)
    inserted, updated = upsert_jobs(records)
    print("Done.")
    print("  %d new jobs stored" % inserted)
    print("  %d existing jobs updated with ink/user data" % updated)
    print("  %d total jobs retrieved from printer" % len(records))
    print("  %d jobs with ink usage data" % ink_count)

    if records:
        newest = max((r for r in records if r.start_time), key=lambda r: r.start_time, default=None)
        oldest = min((r for r in records if r.start_time), key=lambda r: r.start_time, default=None)
        if newest:
            print("  Newest: %s  '%s'" % (newest.start_time.strftime("%Y-%m-%d %H:%M"), newest.job_name[:50]))
        if oldest:
            print("  Oldest: %s  '%s'" % (oldest.start_time.strftime("%Y-%m-%d %H:%M"), oldest.job_name[:50]))


def cmd_status(args):
    print("Fetching ink status from %s..." % args.printer)
    channels = fetch_ink_status(args.printer, community=args.community)
    if not channels:
        print("No ink data returned.")
        return

    print()
    print("  %-40s  %6s  %6s  %5s" % ("Ink Channel", "Level", "Max", "Pct"))
    print("  " + "-" * 64)
    for ch in channels:
        bar = ""
        if ch.pct is not None:
            filled = int(ch.pct / 5)
            bar = "[" + "#" * filled + "-" * (20 - filled) + "]"
        pct_str = "%.0f%%" % ch.pct if ch.pct is not None else "?"
        print("  %-40s  %6s  %6s  %5s  %s" % (
            ch.name[:40], ch.level or "?", ch.max or "?", pct_str, bar))


def cmd_list(args):
    jobs = all_jobs()
    if not jobs:
        print("No jobs in database. Run 'pull' first.")
        return

    limit = args.limit
    display = jobs[:limit]
    has_ink = any(j.get("InkUse_PK") is not None for j in display)

    if has_ink:
        print("  %-20s  %-30s  %-14s  %8s  %6s  %s" % (
            "Start Time", "Job Name", "User", "Area cm²", "Secs", "Ink (ml total)"))
        print("  " + "-" * 120)
    else:
        print("  %-20s  %-45s  %8s  %6s" % ("Start Time", "Job Name", "Area cm²", "Secs"))
        print("  " + "-" * 86)

    for j in display:
        ts = (j["start_time"] or "")[:19].replace("T", " ")
        name = (j["job_name"] or "")[:29]
        user = (j.get("username") or "")[:13]
        area = "%.0f" % j["area_cm2"] if j["area_cm2"] else "?"
        secs = str(j["print_secs"]) if j["print_secs"] else "?"
        if has_ink:
            ink_total = sum(j.get("InkUse_%s" % ch, 0) or 0 for ch in INK_CHANNELS)
            ink_str = str(int(ink_total)) if ink_total else "-"
            print("  %-20s  %-30s  %-14s  %8s  %6s  %s" % (ts, name, user, area, secs, ink_str))
        else:
            print("  %-20s  %-45s  %8s  %6s" % (ts, (j["job_name"] or "")[:44], area, secs))
    print()
    print("  Showing %d of %d jobs in database." % (len(display), len(jobs)))


def cmd_export(args):
    jobs = all_jobs()
    if not jobs:
        print("No jobs in database. Run 'pull' first.")
        return

    out_path = Path(args.file)
    ink_cols = ["InkUse_%s" % ch for ch in INK_CHANNELS]
    fieldnames = [
        "start_time", "end_time", "print_secs",
        "job_name", "username", "machine_name", "paper_source",
        "width_mm", "length_mm", "area_cm2",
        "media_type_id", "status_code",
    ] + ink_cols + ["InkUse_total_ml"]
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for j in reversed(jobs):  # oldest first
            row = {k: j.get(k, "") for k in fieldnames}
            for ts_key in ("start_time", "end_time"):
                v = row.get(ts_key, "")
                if v:
                    row[ts_key] = str(v)[:19].replace("T", " ")
            ink_sum = sum(j.get("InkUse_%s" % ch, 0) or 0 for ch in INK_CHANNELS)
            row["InkUse_total_ml"] = round(ink_sum / 100, 2) if ink_sum else ""
            writer.writerow(row)

    print("Exported %d jobs to %s" % (len(jobs), out_path))


def cmd_summary(args):
    count = rebuild_monthly_summary()
    rows = get_monthly_summary()
    if not rows:
        print("No ink data available. Run 'pull' first.")
        return

    print("  %-20s  %-8s  %5s  %10s" % ("Username", "Month", "Jobs", "Total ml"))
    print("  " + "-" * 50)
    for r in rows:
        print("  %-20s  %-8s  %5d  %10.2f" % (
            r["username"][:20], r["month"], r["job_count"], r["InkUse_total_ml"] or 0))
    print()
    print("  %d summary rows (%d unique users)." % (
        len(rows), len(set(r["username"] for r in rows))))


def cmd_export_summary(args):
    count = rebuild_monthly_summary()
    rows = get_monthly_summary()
    if not rows:
        print("No ink data available. Run 'pull' first.")
        return

    out_path = Path(args.file)
    ink_cols = ["InkUse_%s" % ch for ch in INK_CHANNELS]
    fieldnames = ["username", "month", "job_count"] + ink_cols + ["InkUse_total_ml"]
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k, "") for k in fieldnames})

    print("Exported %d summary rows to %s" % (len(rows), out_path))


def main():
    parser = argparse.ArgumentParser(
        description="Epson SC-P9500 accounting tool"
    )
    parser.add_argument("--printer",   default="192.168.1.107",
                        help="Printer IP address (default: 192.168.1.107)")
    parser.add_argument("--community", default="public",
                        help="SNMP community string (default: public)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show debug logging")

    sub = parser.add_subparsers(dest="command")

    sub.add_parser("pull",    help="Fetch job log from printer and store in DB")
    sub.add_parser("status",  help="Show current ink levels")
    sub.add_parser("summary", help="Rebuild and show monthly ink usage per user")

    p_list = sub.add_parser("list", help="List jobs from local database")
    p_list.add_argument("--limit", type=int, default=50,
                        help="Max jobs to show (default: 50)")

    p_export = sub.add_parser("export", help="Export jobs to CSV")
    p_export.add_argument("file", nargs="?", default="jobs.csv",
                          help="Output CSV file (default: jobs.csv)")

    p_export_summary = sub.add_parser("export-summary", help="Export monthly ink summary to CSV")
    p_export_summary.add_argument("file", nargs="?", default="summary.csv",
                                  help="Output CSV file (default: summary.csv)")

    sub.add_parser("help", help="Show this help message")

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG,
                            format="%(levelname)s %(name)s: %(message)s")
    else:
        logging.basicConfig(level=logging.INFO,
                            format="%(message)s")

    if args.command == "pull":
        cmd_pull(args)
    elif args.command == "status":
        cmd_status(args)
    elif args.command == "list":
        cmd_list(args)
    elif args.command == "export":
        cmd_export(args)
    elif args.command == "summary":
        cmd_summary(args)
    elif args.command == "export-summary":
        cmd_export_summary(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
