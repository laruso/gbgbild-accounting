#!/usr/bin/env python3
"""
Epson SC-P9500 accounting tool — SNMP-based replacement for LFP Accounting Tool.

Usage:
  python3 lfp_accounting.py --printer <ip> pull
  python3 lfp_accounting.py --printer <ip> status
  python3 lfp_accounting.py list [--limit 20] [--from YYYY-MM-DD] [--to YYYY-MM-DD]
  python3 lfp_accounting.py summary [--from YYYY-MM-DD] [--to YYYY-MM-DD]
  python3 lfp_accounting.py export jobs.csv
  python3 lfp_accounting.py export-summary summary.csv
  python3 lfp_accounting.py send <index> [--resend]
  python3 lfp_accounting.py send-batch [--from YYYY-MM-DD] [--to YYYY-MM-DD] [--resend] [--article N]

Sending requires the Bearer token in the environment (never committed):
  export LFP_SEND_TOKEN=<token>
  # optional: LFP_SEND_BASE_URL (test endpoint), LFP_SEND_ARTICLE (default articleNumber)
"""
import argparse
import csv
import os
import sys
import logging
from datetime import date, timedelta
from pathlib import Path

from joblog import fetch_job_log, fetch_ink_status, fetch_serial_number, STATUS_CODE, INK_CHANNELS
from store  import (upsert_jobs, all_jobs, rebuild_monthly_summary, get_monthly_summary,
                    query_jobs, monthly_summary, mark_sent)
import senders


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
    display = query_jobs(date_from=args.from_date, date_to=args.to_date, limit=args.limit)
    if not display:
        print("No matching jobs in database. Run 'pull' first, or widen the date range.")
        return

    has_ink = any(j.get("InkUse_PK") is not None for j in display)

    if has_ink:
        print("  %4s  %-20s  %-30s  %-14s  %8s  %6s  %s" % (
            "#", "Start Time", "Job Name", "User", "Area cm²", "Secs", "Ink (ml total)"))
        print("  " + "-" * 126)
    else:
        print("  %4s  %-20s  %-45s  %8s  %6s" % ("#", "Start Time", "Job Name", "Area cm²", "Secs"))
        print("  " + "-" * 92)

    for idx, j in enumerate(display, start=1):
        ts = (j["start_time"] or "")[:19].replace("T", " ")
        name = (j["job_name"] or "")[:29]
        user = (j.get("username") or "")[:13]
        area = "%.0f" % j["area_cm2"] if j["area_cm2"] else "?"
        secs = str(j["print_secs"]) if j["print_secs"] else "?"
        if has_ink:
            ink_total = sum(j.get("InkUse_%s" % ch, 0) or 0 for ch in INK_CHANNELS)
            ink_str = str(int(ink_total)) if ink_total else "-"
            print("  %4d  %-20s  %-30s  %-14s  %8s  %6s  %s" % (idx, ts, name, user, area, secs, ink_str))
        else:
            print("  %4d  %-20s  %-45s  %8s  %6s" % (idx, ts, (j["job_name"] or "")[:44], area, secs))
    print()
    print("  Showing %d job(s). Use the # index with 'send <#>'." % len(display))


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
    if args.from_date or args.to_date:
        rows = monthly_summary(date_from=args.from_date, date_to=args.to_date)
    else:
        rebuild_monthly_summary()
        rows = get_monthly_summary()
    if not rows:
        print("No ink data available for that range. Run 'pull' first, or widen it.")
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


def _previous_month_range(today: date) -> tuple[str, str]:
    """Return (first_day, last_day) of the calendar month before `today`."""
    first_this = today.replace(day=1)
    last_prev = first_this - timedelta(days=1)
    first_prev = last_prev.replace(day=1)
    return first_prev.isoformat(), last_prev.isoformat()


def _why_unsendable(job: dict) -> str:
    if not (job.get("username") or "").strip():
        return "job has no username"
    if job.get("InkUse_PK") is None:
        return "job has no ink usage data"
    return ""


def cmd_send(args):
    # send resolves the index against the default (unfiltered) newest-first order,
    # i.e. the same ordering shown by a bare `list`.
    jobs = query_jobs()
    if not jobs:
        print("No jobs in database. Run 'pull' first.")
        return
    if args.index < 1 or args.index > len(jobs):
        print("Index %d out of range (1..%d). Run 'list' to see indexes." % (
            args.index, len(jobs)))
        return

    job = jobs[args.index - 1]
    reason = _why_unsendable(job)
    if reason:
        print("Cannot send job #%d ('%s'): %s." % (
            args.index, (job.get("job_name") or "")[:40], reason))
        return
    if job.get("sent_at") and not args.resend:
        print("Job #%d was already sent at %s. Use --resend to send it again." % (
            args.index, job["sent_at"]))
        return

    try:
        result = senders.post_single(job)
    except senders.SendError as e:
        print("Send failed: %s" % e)
        sys.exit(1)

    mark_sent([job["job_id"]])
    print("Sent job '%s' (%s ml) for %s — HTTP %s" % (
        (job.get("job_name") or "")[:40], senders.job_quantity_ml(job),
        job.get("username"), result["status"]))


def cmd_send_batch(args):
    if args.from_date or args.to_date:
        date_from, date_to = args.from_date, args.to_date
    else:
        date_from, date_to = _previous_month_range(date.today())
    print("Batch range: %s .. %s" % (date_from or "(open)", date_to or "(open)"))

    jobs = query_jobs(date_from=date_from, date_to=date_to,
                      unsent_only=not args.resend)
    sendable = [j for j in jobs if senders.is_sendable(j)]
    skipped = len(jobs) - len(sendable)
    if not sendable:
        print("No sendable jobs in range%s." % (
            "" if args.resend else " (all already sent, or none with user+ink)"))
        return

    if args.article:
        os.environ["LFP_SEND_ARTICLE"] = args.article

    try:
        result = senders.post_batch(sendable)
    except senders.SendError as e:
        print("Batch send failed: %s" % e)
        sys.exit(1)

    mark_sent([j["job_id"] for j in sendable])
    total_ml = round(sum(senders.job_quantity_ml(j) for j in sendable), 2)
    print("Sent %d job(s), %s ml total — HTTP %s" % (
        len(sendable), total_ml, result["status"]))
    if skipped:
        print("Skipped %d job(s) (no user/ink data)." % skipped)


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

    p_summary = sub.add_parser("summary", help="Show monthly ink usage per user")
    p_summary.add_argument("--from", dest="from_date", metavar="YYYY-MM-DD",
                           help="Only include jobs on/after this date")
    p_summary.add_argument("--to", dest="to_date", metavar="YYYY-MM-DD",
                           help="Only include jobs on/before this date")

    p_list = sub.add_parser("list", help="List jobs from local database")
    p_list.add_argument("--limit", type=int, default=50,
                        help="Max jobs to show (default: 50)")
    p_list.add_argument("--from", dest="from_date", metavar="YYYY-MM-DD",
                        help="Only list jobs on/after this date")
    p_list.add_argument("--to", dest="to_date", metavar="YYYY-MM-DD",
                        help="Only list jobs on/before this date")

    p_send = sub.add_parser("send", help="Send one job (by list index) to the shop endpoint")
    p_send.add_argument("index", type=int, help="Job index from 'list' output")
    p_send.add_argument("--resend", action="store_true",
                        help="Send even if already sent")

    p_send_batch = sub.add_parser("send-batch",
                                  help="Send a range of jobs (default: previous month)")
    p_send_batch.add_argument("--from", dest="from_date", metavar="YYYY-MM-DD",
                              help="Start date (default: first day of previous month)")
    p_send_batch.add_argument("--to", dest="to_date", metavar="YYYY-MM-DD",
                              help="End date (default: last day of previous month)")
    p_send_batch.add_argument("--resend", action="store_true",
                              help="Include jobs already marked sent")
    p_send_batch.add_argument("--article", metavar="N",
                              help="Override articleNumber (default: %s)" % senders.DEFAULT_ARTICLE)

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
    elif args.command == "send":
        cmd_send(args)
    elif args.command == "send-batch":
        cmd_send_batch(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
