#!/bin/bash
# Repeatable deploy: pulls the latest OPA Compliance Wizard from GitHub and
# reinstalls it in place on this server. Run this ON THE SERVER (as the
# `rparikh` user, or whichever user owns /home/rparikh/opa-secrets-folders
# and the systemd service), not from your own machine.
#
#   ./deploy.sh
#
# What it does, in order:
#   1. Clones the GitHub repo (standalone as of the 2026-09-30 split from the
#      ItsGambit/Okta monorepo -- this project now lives at repo root, not
#      nested under OPA/Secrets-Wizard/) into a throwaway temp dir.
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
#   5. Restarts BOTH systemd units (opa-secrets-wizard AND opa-auth-gate --
#      see the H-4 fix note below) and prints their status.
#   6. Applies the repo's nginx config if it differs from what's actually
#      loaded at /etc/nginx/sites-available/opa-secrets-wizard, `nginx -t`
#      validates it, then reloads nginx -- only if the validation passes.
#
# SECURITY/CORRECTNESS FIX (external review, 2026-09-30, "H-4"): this used
# to restart ONLY opa-secrets-wizard and only WARN (never apply) on nginx
# config drift, because the deploying user's NOPASSWD sudoers rule was
# scoped to just that one unit. Confirmed as a real, repeatedly-hit gap
# this session: auth_gate.py changes (e.g. the P0 NGINX_PROXY_SECRET fix)
# or nginx conf changes landed in the repo and got rsynced to $APP_DIR by
# this very script, but kept running under the OLD code/config until
# someone remembered the separate manual step. Steps 5-6 below now
# actually restart/apply instead of just warning -- this REQUIRES widening
# the server's NOPASSWD sudoers rule beyond systemctl restart
# opa-secrets-wizard to also cover: systemctl restart opa-auth-gate,
# cp <repo nginx conf> /etc/nginx/sites-available/opa-secrets-wizard,
# nginx -t, and systemctl reload nginx. If that rule hasn't been widened
# yet on this server, each `sudo -n` call below fails fast (same -n
# non-interactive behavior as the pre-existing restart call) and this
# script prints the exact fix needed and continues rather than aborting
# the whole deploy over it -- the app code/frontend is still fully
# deployed and the main service still restarts either way.
#
# SELF-MODIFICATION FIX (confirmed live, 2026-10-01): step 2's rsync
# overwrites THIS file on disk while bash is still executing it -- the
# very first time this script's own tail grew past "warn and stop" (the
# H-4 fix above), the deployed-on-disk copy was correctly updated to
# 5.24.0, but every step AFTER the rsync (opa-auth-gate restart, nginx
# apply) silently never ran: bash kept executing the OLD in-memory/
# already-read copy for the rest of the run, not the one just written to
# disk. This was invisible before because the old tail only ever printed
# a warning, so a stale in-memory tail happened to produce the same
# observable behavior as the new one would have. Fixed below by
# re-executing from a frozen copy of THIS script in a private temp dir
# before doing anything else -- the running process then never reads
# from the path rsync is about to overwrite, at all.
#
# Safe to re-run any time; every step is idempotent.

set -euo pipefail

# Must happen before anything else (see "SELF-MODIFICATION FIX" above) --
# $BASH_SOURCE is this script's own path as actually invoked; re-exec a
# frozen copy of it from a private temp dir exactly once (the
# DEPLOY_SH_REEXEC guard prevents infinite re-exec once already running
# from that frozen copy).
if [ -z "${DEPLOY_SH_REEXEC:-}" ]; then
  _frozen_dir="$(mktemp -d)"
  _frozen_copy="$_frozen_dir/deploy.sh"
  cp "${BASH_SOURCE[0]}" "$_frozen_copy"
  chmod +x "$_frozen_copy"
  export DEPLOY_SH_REEXEC="$_frozen_dir"
  exec "$_frozen_copy" "$@"
fi
# `exec` above replaces this entire process -- nothing after it in THIS
# branch ever runs. The copy that actually continues past this point owns
# BOTH the frozen-copy dir (DEPLOY_SH_REEXEC) and its own TMP_DIR below --
# one single trap cleans up both at exit (a second `trap ... EXIT` would
# silently REPLACE this one, not stack with it, so TMP_DIR's own cleanup
# is folded in here rather than set separately below).

REPO_URL="https://github.com/ItsGambit/opa-compliance-wizard.git"
APP_DIR="/home/rparikh/opa-secrets-folders"
SERVICE_NAME="opa-secrets-wizard"
AUTH_GATE_SERVICE="opa-auth-gate"
NGINX_LIVE="/etc/nginx/sites-available/opa-secrets-wizard"
NGINX_REPO="$APP_DIR/server/nginx-opa-secrets-wizard.conf"
TMP_DIR="$(mktemp -d)"
SUDOERS_GAPS=()

cleanup() { rm -rf "$TMP_DIR" "$DEPLOY_SH_REEXEC"; }
trap cleanup EXIT

echo "==> Fetching latest from $REPO_URL"
git clone --depth 1 "$REPO_URL" "$TMP_DIR/repo"

SRC="$TMP_DIR/repo"
if [ ! -f "$SRC/create_secret_folders.py" ]; then
  echo "ERROR: expected files not found under $SRC -- check REPO_URL above." >&2
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

echo "==> Restarting $AUTH_GATE_SERVICE"
# H-4 fix: previously never restarted here at all -- any auth_gate.py
# change deployed above kept running under the OLD code until a separate,
# easy-to-forget manual restart. Same -n fail-fast behavior as above; if
# the server's sudoers rule hasn't been widened to cover this unit yet,
# don't abort the whole deploy over it -- warn and keep going, same
# graceful-degradation shape the old nginx-drift warning used.
if sudo -n systemctl restart "$AUTH_GATE_SERVICE" 2>/dev/null; then
  sleep 1
  systemctl status "$AUTH_GATE_SERVICE" --no-pager -l
else
  SUDOERS_GAPS+=("systemctl restart $AUTH_GATE_SERVICE")
  echo "    (skipped -- sudoers rule doesn't cover this yet, see warning below)"
fi

echo "==> Done. Deployed version:"
grep -m1 'SCRIPT_VERSION = ' "$APP_DIR/create_secret_folders.py"

if [ -f "$NGINX_LIVE" ] && ! diff -q "$NGINX_REPO" "$NGINX_LIVE" > /dev/null 2>&1; then
  echo ""
  echo "==> nginx config has drifted from what's actually live -- applying repo copy"
  echo "    Repo copy (just deployed): $NGINX_REPO"
  echo "    Live copy (currently serving): $NGINX_LIVE"
  # Back up the current live file BEFORE overwriting it, so a bad new
  # config (one that fails `nginx -t`) can be rolled back immediately
  # rather than left in place -- `nginx -t` only validates whatever is
  # CURRENTLY at $NGINX_LIVE (sites-available files aren't standalone
  # configs nginx -c can point at directly; they're pulled in via
  # sites-enabled's include), so validating has to happen in-place,
  # which means a failure must be reversible, not just reported.
  NGINX_BACKUP="$TMP_DIR/opa-secrets-wizard.conf.live-backup"
  if sudo -n cp "$NGINX_LIVE" "$NGINX_BACKUP" 2>/dev/null \
      && sudo -n cp "$NGINX_REPO" "$NGINX_LIVE" 2>/dev/null; then
    if sudo -n nginx -t 2>&1; then
      if sudo -n systemctl reload nginx 2>/dev/null; then
        echo "    Applied, validated, and reloaded."
      else
        SUDOERS_GAPS+=("systemctl reload nginx")
        echo "    Config copied and passed 'nginx -t', but reload didn't happen"
        echo "    (sudoers gap) -- the OLD config is still what's actually serving"
        echo "    traffic until a reload runs. See warning below."
      fi
    else
      echo "    !!! New config FAILED 'nginx -t' -- rolling back to the previous"
      echo "    !!! live config so nginx doesn't break on its next reload/restart."
      sudo -n cp "$NGINX_BACKUP" "$NGINX_LIVE" 2>/dev/null \
        || echo "    !!! ROLLBACK ALSO FAILED -- $NGINX_LIVE may now be broken. Fix manually."
    fi
  else
    SUDOERS_GAPS+=("cp '$NGINX_REPO' '$NGINX_LIVE' && nginx -t && systemctl reload nginx")
    echo "    (skipped -- sudoers rule doesn't cover this yet, see warning below)"
  fi
fi

if [ "${#SUDOERS_GAPS[@]}" -gt 0 ]; then
  echo ""
  echo "!!! WARNING: this server's NOPASSWD sudoers rule doesn't yet cover !!!"
  echo "!!! everything this script needs -- the following step(s) were    !!!"
  echo "!!! skipped and need either a widened sudoers rule or a manual run: !!!"
  for gap in "${SUDOERS_GAPS[@]}"; do
    echo "      sudo $gap"
  done
  echo "    To fix permanently, widen the deploying user's sudoers rule to also"
  echo "    allow (visudo): systemctl restart $AUTH_GATE_SERVICE, cp to $NGINX_LIVE,"
  echo "    nginx -t, systemctl reload nginx -- in addition to the existing"
  echo "    systemctl restart $SERVICE_NAME rule."
fi
