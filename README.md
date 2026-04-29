# LFP Accounting

Standalone replacement for the Epson LFP Accounting Tool.

Polls an Epson SC-P9500 large-format printer over SNMP, decrypts the printer's
proprietary per-job ink usage data, and stores everything in a local SQLite
database. Independent of the original LFP Accounting Tool and its Access
database — it doesn't rely on a Windows service, manual "Refresh" clicks, or
the `.accdb` file.

## Requirements

- Python 3.9+
- Network access to the printer
- `pyodbc` (only if you want to backfill historical data from an existing
  `.accdb`)

```bash
pip install pyodbc   # optional
```

No other dependencies. SNMP is implemented in pure Python sockets.

## Quick start

```bash
# Pull the latest jobs from the printer (run this regularly — see "Important")
python lfp_accounting.py pull

# See what's in the local database
python lfp_accounting.py list

# Show current ink tank levels
python lfp_accounting.py status

# Build/refresh the per-user-per-month summary and print it
python lfp_accounting.py summary

# Export jobs to CSV
python lfp_accounting.py export jobs.csv

# Export the monthly summary to CSV
python lfp_accounting.py export-summary summary.csv

# Show all commands
python lfp_accounting.py help
```

The default printer IP is `192.168.1.107`. Override with `--printer`:

```bash
python lfp_accounting.py --printer 192.168.1.50 pull
```

## ⚠️ Important: run `pull` regularly

The printer's detailed job buffer (with ink usage and username) only holds
**~30 recent jobs**. Older jobs still appear in the basic job log but their
ink/user data has been overwritten. Run `pull` on a schedule (Windows Task
Scheduler, cron, or similar) often enough that no more than ~30 jobs print
between runs. Daily is fine for most setups, hourly for heavy use.

## Refreshing the seed database before deployment

If a few days have passed since the last backfill, the LFP Accounting Tool
on the Windows machine has likely captured new prints in its `.accdb` that
aren't yet in `seed/jobs.db`. Refresh the seed before deploying to the Pi:

```bash
# 1. Pull latest from the printer (catches anything still in the ji: buffer)
python lfp_accounting.py pull

# 2. Backfill anything else from the .accdb (catches what was flushed)
python backfill_from_accdb.py

# 3. Copy the refreshed DB into the project's seed folder
copy %USERPROFILE%\.lfp_accounting\jobs.db seed\jobs.db
```

## Claude Code context (CLAUDE.md and project memory)

This repo also tracks the Claude Code project context so anyone (or any
machine) opening it later has the full background:

- `CLAUDE.md` — project design rules (kept at the repo root so Claude Code
  picks it up automatically).
- `.claude/memory/` — saved memory notes about this project, including:
  - `MEMORY.md` — index of memory files
  - `project_lfp_status.md` — full project status, what works, what was tried
  - `project_lfp_accdb_password.md` — the cracked `.accdb` password

If you open this repo on a new machine and want Claude Code to load the
memory files automatically, copy them into Claude's per-project memory dir:

```bash
# Linux / macOS
mkdir -p ~/.claude/projects/$(pwd | sed 's|/|-|g; s|^-|C--|')/memory
cp .claude/memory/*.md ~/.claude/projects/$(pwd | sed 's|/|-|g; s|^-|C--|')/memory/
```

On Windows, copy `.claude/memory/*.md` into
`%USERPROFILE%\.claude\projects\<this-folder-id>\memory\`.

(Otherwise, just leave them in `.claude/memory/` — Claude can still read
them as regular files if you point it at them.)

## Files

| File | Purpose |
|---|---|
| `lfp_accounting.py` | Main CLI |
| `joblog.py` | SNMP fetch + ink-blob decryption |
| `store.py` | SQLite storage and monthly aggregation |
| `backfill_from_accdb.py` | One-time import from a legacy `.accdb` (Windows only — see below) |
| `seed/jobs.db` | Pre-populated database with all historical data backfilled from the original `.accdb`. Copy to `~/.lfp_accounting/jobs.db` on first deploy. |
| `archive/` | Reverse-engineering scripts kept for reference |
| `deploy/` | systemd unit/timer + crontab example for the Pi |
| `CLAUDE.md` | Claude Code project design rules |
| `.claude/memory/` | Project memory notes (status, .accdb password, etc.) |

## Database

Stored at `~/.lfp_accounting/jobs.db`
(Windows: `C:\Users\<you>\.lfp_accounting\jobs.db`,
 Linux/Pi: `/home/<you>/.lfp_accounting/jobs.db`).

Two tables:

- **`jobs`** — one row per print job: timestamps, dimensions, username,
  machine name, all 12 ink channels, raw encrypted blob.
- **`monthly_ink_usage`** — rebuilt by `summary` / `export-summary`. One row
  per (username, month) with totals for each channel and `InkUse_total_ml`.

The repo ships with `seed/jobs.db` containing all historical data
(2023-10 → 2026-04, ~5,000 jobs). On first deploy, copy it into place:

```bash
mkdir -p ~/.lfp_accounting
cp seed/jobs.db ~/.lfp_accounting/jobs.db
```

After that, `pull` keeps it up to date from the printer directly — no
`.accdb` access needed ever again.

## Deploying to a Raspberry Pi (or any Linux box)

1. Copy this folder to the Pi (git clone, scp, USB stick — whatever).
2. Make sure Python 3.9+ is installed: `python3 --version`.
3. Seed the database (one-time):
   ```bash
   mkdir -p ~/.lfp_accounting
   cp seed/jobs.db ~/.lfp_accounting/jobs.db
   ```
4. Verify it works:
   ```bash
   python3 lfp_accounting.py list --limit 5
   python3 lfp_accounting.py status
   ```
5. Schedule a pull every 10 minutes (see next section).

You do **not** need `pyodbc` or any Microsoft Access driver on the Pi —
those are only used by `backfill_from_accdb.py`, which has already been
run on Windows and the result baked into `seed/jobs.db`.

## Running every 10 minutes (and surviving reboots)

The repo includes ready-made files in `deploy/` for both options. Pick one.

### Option A — cron (simplest)

```bash
crontab -e
```

Paste the line from `deploy/crontab.example` (adjust the path if you
cloned elsewhere than `/home/pi/lfp_accounting`):

```cron
*/10 * * * * cd /home/pi/lfp_accounting && /usr/bin/python3 lfp_accounting.py pull >> /home/pi/lfp_accounting/pull.log 2>&1
```

That's it. The cron daemon starts automatically at every boot, so this
keeps running across reboots. Logs go to `pull.log` next to the script.

Verify it's installed:
```bash
crontab -l
tail -f /home/pi/lfp_accounting/pull.log     # watch the next run
```

### Option B — systemd timer (cleaner logging, more features)

Edit `deploy/lfp-accounting.service` if your username or path differs
from `pi` / `/home/pi/lfp_accounting`, then install:

```bash
sudo cp deploy/lfp-accounting.service /etc/systemd/system/
sudo cp deploy/lfp-accounting.timer   /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now lfp-accounting.timer
```

That last command both starts the timer now AND tells systemd to start
it again at every boot.

Useful commands:
```bash
systemctl list-timers lfp-accounting.timer    # next/last run times
journalctl -u lfp-accounting.service -f       # tail the log
sudo systemctl start lfp-accounting.service   # run once immediately
```

The timer config has `Persistent=true`, so if the Pi was off when a
scheduled run was due, it catches up on the missed run when it boots.

## Backfilling from the old `.accdb` (Windows only, already done)

The historical data has already been imported and is included in
`seed/jobs.db`. You only need this section if you ever want to re-do
the backfill (e.g. on a different printer's accounting database).

The backfill must be run on Windows because it uses the Microsoft Access
ODBC driver via `pyodbc`. It will not work on a Raspberry Pi or other
Linux machine.

```bash
pip install pyodbc
python backfill_from_accdb.py
```

This:
- Fills in missing ink/user data on jobs already in SQLite
- Inserts older jobs that are no longer in the printer's memory at all

Edit `ACCDB_PATH` and `ACCDB_PWD` in the script if your install differs from
the defaults.

## Commands reference

| Command | What it does |
|---|---|
| `pull` | SNMP-pull the job log + ji: detail buffer from the printer, decrypt ink blobs, upsert into SQLite |
| `status` | Show current ink tank levels |
| `list [--limit N]` | Show recent jobs from the local DB |
| `export [file]` | Write all jobs to CSV (default `jobs.csv`) |
| `summary` | Rebuild the `monthly_ink_usage` table and print it |
| `export-summary [file]` | Rebuild the summary and write it to CSV (default `summary.csv`) |
| `help` | Show all commands |

## How the ink decryption works

The printer encrypts per-job ink usage in a 208-byte blob returned by an
Epson-proprietary SNMP command (`ji:`). The cipher is a custom 3-round
Feistel with 8-byte blocks and CBC-style chaining, keyed by the printer's
serial number. The serial is fetched automatically over SNMP at the start of
each `pull`.

The decryption logic lives in `joblog.py` (`_decrypt_ji_blob`,
`_parse_ink_from_tlv`, `decode_ji_ink`). The reverse-engineering process —
DLL static analysis, Frida hooking, and verification against the .accdb —
is preserved in `archive/`.
