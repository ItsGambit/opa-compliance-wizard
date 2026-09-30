#!/bin/bash
# Repeatable deploy: pulls the latest OPA Secrets Wizard from GitHub and
# reinstalls it in place on this server. Run this ON THE SERVER (as the
# `rparikh` user, or whichever user owns /home/rparikh/opa-secrets-folders
# and the systemd service), not from your own machine.
#
#   ./deploy.sh
#
# What it does, in order:
#   1. Sparse-clones just OPA/Secrets-Wizard/ from the GitHub repo (this
#      project lives nested inside a larger monorepo, not at repo root) into
#      a throwaway temp dir.
#   2. rsyncs it over the live app directory, EXCLUDING local-only state that
#      must never be overwritten or deleted: the Python venv, credential/
#      session stores, the audit log, and the locally-preserved System Log
#      cache. See the exclude list below -- if a new local-only file/store is
#      ever added to this project, add it here too, or a deploy will silently
#      wipe it.
#   3. Reinstalls Python deps into the existing venv (requirements.txt).
#   4. Rebuilds the frontend (npm ci + vite build) -- serve.py serves the
#      built frontend/dist, so a deploy without this step ships new backend
#      code against a stale UI.
#   5. Restarts the systemd service and prints its status.
#
# Safe to re-run any time; every step is idempotent.

set -euo pipefail

REPO_URL="https://github.com/ItsGambit/Okta.git"
REPO_SUBDIR="OPA/Secrets-Wizard"
APP_DIR="/home/rparikh/opa-secrets-folders"
SERVICE_NAME="opa-secrets-wizard"
TMP_DIR="$(mktemp -d)"

cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

echo "==> Fetching latest '$REPO_SUBDIR' from $REPO_URL"
git clone --depth 1 --filter=blob:none --sparse "$REPO_URL" "$TMP_DIR/repo"
git -C "$TMP_DIR/repo" sparse-checkout set "$REPO_SUBDIR"

SRC="$TMP_DIR/repo/$REPO_SUBDIR"
if [ ! -f "$SRC/create_secret_folders.py" ]; then
  echo "ERROR: expected files not found under $SRC -- check REPO_URL/REPO_SUBDIR above." >&2
  exit 1
fi

echo "==> Syncing into $APP_DIR (excluding local-only state)"
rsync -a --delete \
  --exclude '.venv/' \
  --exclude '.git/' \
  --exclude '__pycache__/' \
  --exclude 'frontend/node_modules/' \
  --exclude 'frontend/dist/' \
  --exclude 'environments.json' \
  --exclude 'banner_config.json' \
  --exclude 'audit_log.jsonl' \
  --exclude 'secrets_log_cache.json' \
  --exclude 'audit_store.db' \
  --exclude 'audit_store.db-wal' \
  --exclude 'audit_store.db-shm' \
  --exclude '.env' \
  "$SRC/" "$APP_DIR/"

# git-for-windows checkouts of this repo commonly have core.fileMode=false,
# which silently drops the executable bit on *.sh files whenever they're
# edited/committed from Windows (chmod succeeds on disk but git never
# records it, so the tree's tracked mode stays 100644) -- confirmed as the
# real cause of a service crash-loop the first time this script ran
# (start-headless.sh landed non-executable, systemd failed with
# "203/EXEC ... Permission denied"). Restoring the bit here is a
# belt-and-suspenders fix independent of ever getting every .sh file's
# git-tracked mode right at commit time.
find "$APP_DIR" -maxdepth 3 -name '*.sh' -exec chmod +x {} +

echo "==> Reinstalling Python dependencies"
"$APP_DIR/.venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"

echo "==> Rebuilding frontend"
(cd "$APP_DIR/frontend" && npm ci --silent && npx vite build)

echo "==> Restarting $SERVICE_NAME"
# -n (non-interactive): without a pseudo-TTY (e.g. run via `ssh host "cmd"`
# rather than an interactive shell), plain `sudo` can still try to prompt
# for a password even when a matching NOPASSWD rule exists, and then hang
# or fail with "a terminal is required to authenticate". -n makes it fail
# fast instead if the rule ever stops matching, rather than hanging.
sudo -n systemctl restart "$SERVICE_NAME"
sleep 1
systemctl status "$SERVICE_NAME" --no-pager -l

echo "==> Done. Deployed version:"
grep -m1 'SCRIPT_VERSION = ' "$APP_DIR/create_secret_folders.py"
