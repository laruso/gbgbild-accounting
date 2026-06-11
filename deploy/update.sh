#!/usr/bin/env bash
#
# Safe production updater for the Raspberry Pi (pull-only).
#
# This Pi is a *consumer* of the repo: all code changes are made elsewhere,
# pushed to GitHub, and pulled here. This script performs that pull safely:
#   - refuses to run if you've edited files locally (pull-only discipline)
#   - only fast-forwards (never creates merge commits or rewrites history)
#   - leaves the live database (~/.lfp_accounting/jobs.db) completely untouched
#
# Usage:  ./deploy/update.sh
#
set -euo pipefail

# cd to the repo root (this script lives in <repo>/deploy/)
cd "$(dirname "$(readlink -f "$0")")/.."

branch="$(git rev-parse --abbrev-ref HEAD)"
if [ "$branch" != "main" ]; then
    echo "ERROR: on branch '$branch', expected 'main'. Aborting." >&2
    exit 1
fi

# Pull-only discipline: bail out rather than clobber local edits.
if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "ERROR: working tree has local changes — this Pi is meant to be" >&2
    echo "       pull-only. Inspect with 'git status'/'git diff' and revert" >&2
    echo "       (git checkout -- .) before updating." >&2
    exit 1
fi

echo "Fetching from origin..."
git fetch --quiet origin

if [ -z "$(git log --oneline HEAD..origin/main)" ]; then
    echo "Already up to date ($(git rev-parse --short HEAD)). Nothing to do."
    exit 0
fi

echo "Incoming changes:"
git log --oneline HEAD..origin/main

echo
echo "Fast-forwarding..."
git pull --ff-only origin main

echo
echo "Updated to $(git rev-parse --short HEAD)."
echo "No restart needed — cron picks up the new code on its next run."
