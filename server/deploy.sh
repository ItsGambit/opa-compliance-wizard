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
# THREE distinct cp invocations (backup the live config to a fixed
# .deploy-backup path, apply the repo's config over the live path, and
# roll the backup back over the live path if `nginx -t` fails -- sudoers
# matches each exact argument list separately, so all three need their
# own grant, not just one), nginx -t, and systemctl reload nginx. See
# docs/hosting.md's "Hosting on a server" setup for the exact rule. If that rule
# hasn't been widened yet on this server, each `sudo -n` call below fails
# fast (same -n non-interactive behavior as the pre-existing restart
# call) and this script prints the exact fix needed and continues rather
# than aborting the whole deploy over it -- the app code/frontend is
# still fully deployed and the main service still restarts either way.
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
# observable behavior as the new one would have.
#
# ONE-VERSION-LAG FIX (confirmed live, 2026-10-01, the SAME DAY as the fix
# above): freezing a copy of this script BEFORE the rsync step (the first
# attempt at the fix above) stops the corruption, but means every run
# executes the PREVIOUS version's post-rsync logic, never the one just
# pulled -- confirmed live: a run that correctly rsynced 5.24.2's nginx
# backup-path fix to disk still printed 5.24.1's old warning text
# verbatim for the rest of that same run, because the frozen copy it was
# re-exec'd from was taken from the 5.24.1 file, before rsync overwrote
# it. Fixed by re-executing a SECOND time, from a NEW frozen copy taken
# AFTER the rsync -- the first re-exec (before rsync) only exists to
# protect the clone+rsync steps themselves from self-corruption; the
# second one (right after rsync) is what makes the restart/nginx-apply
# steps that follow actually run THIS run's freshly-pulled logic, not
# last run's.
#
# Safe to re-run any time; every step is idempotent.

set -euo pipefail

APP_DIR="/home/rparikh/opa-secrets-folders"

# Phase 1 re-exec (see "SELF-MODIFICATION FIX" above): protects the
# clone+rsync steps below from reading a file that's changing out from
# under them. $DEPLOY_SH_PHASE tracks which phase is currently running
# (unset -> "1" -> "2") so each phase re-execs exactly once and never
# loops.
if [ -z "${DEPLOY_SH_PHASE:-}" ]; then
  _frozen_dir="$(mktemp -d)"
  _frozen_copy="$_frozen_dir/deploy.sh"
  cp "${BASH_SOURCE[0]}" "$_frozen_copy"
  chmod +x "$_frozen_copy"
  export DEPLOY_SH_PHASE=1
  export DEPLOY_SH_PHASE1_FROZEN_DIR="$_frozen_dir"
  exec "$_frozen_copy" "$@"
fi

NGINX_LIVE="/etc/nginx/sites-available/opa-secrets-wizard"
NGINX_REPO="$APP_DIR/server/nginx-opa-secrets-wizard.conf"
SERVICE_NAME="opa-secrets-wizard"
AUTH_GATE_SERVICE="opa-auth-gate"
SUDOERS_GAPS=()

if [ "$DEPLOY_SH_PHASE" = "1" ]; then
  REPO_URL="https://github.com/ItsGambit/opa-compliance-wizard.git"
  TMP_DIR="$(mktemp -d)"

  # Phase 1's own cleanup -- only matters if phase 1 exits WITHOUT
  # reaching the phase-2 re-exec at the end of this block (e.g. the clone
  # or rsync step fails). Once phase 2 is successfully exec'd, this trap
  # (and this entire process image) is gone -- phase 2 sets its OWN trap
  # further down to clean up everything listed here, via
  # DEPLOY_SH_PHASE1_FROZEN_DIR/DEPLOY_SH_PHASE1_TMP_DIR passed through as
  # env vars.
  trap 'rm -rf "$TMP_DIR" "$DEPLOY_SH_PHASE1_FROZEN_DIR"' EXIT

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
    --exclude 'audit_log.jsonl' \
    --exclude 'secrets_log_cache.json' \
    --exclude 'access_control.json' \
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
  # git-tracked mode right at commit time. MUST happen before the phase-2
  # re-exec below, which execs this exact file.
  find "$APP_DIR" -maxdepth 3 -name '*.sh' -exec chmod +x {} +

  # Phase 2 re-exec (see "ONE-VERSION-LAG FIX" above): $APP_DIR/server/
  # deploy.sh is now THIS run's freshly-rsynced copy -- exec it directly
  # (no new frozen copy needed; nothing modifies this file again for the
  # rest of the run, so there's no self-corruption risk left to protect
  # against). Passes through phase 1's temp dirs so phase 2's cleanup can
  # remove them too, since phase 1's own trap never fires once exec below
  # succeeds (exec replaces this process entirely, trap included).
  export DEPLOY_SH_PHASE=2
  export DEPLOY_SH_PHASE1_TMP_DIR="$TMP_DIR"
  exec "$APP_DIR/server/deploy.sh" "$@"
fi

# Everything below only ever runs in phase 2 (DEPLOY_SH_PHASE=2) --
# phase 1's block above always ends in `exec`, so execution only
# reaches here via that exec, never by falling through from phase 1.

# Cleans up phase 1's frozen-copy dir AND its TMP_DIR (the git clone,
# already rsynced and no longer needed) -- phase 1's own trap never fired
# for these since exec replaced that process entirely before it could.
trap 'rm -rf "$DEPLOY_SH_PHASE1_FROZEN_DIR" "$DEPLOY_SH_PHASE1_TMP_DIR"' EXIT

# NEW (2026-10-01): surfaces deploy events (deploy.started/.completed/
# .failed) in the dashboard's own Audit Log, same file every other write
# action already logs to (audit_log.jsonl) -- requested so a deploy shows
# up alongside everything else instead of being invisible outside this
# script's own terminal output. Reuses engine.log_audit_event directly
# (the exact same locked JSON-line-append every other call site uses, see
# create_secret_folders.py) rather than hand-rolling a second way to
# write that file. actor_email/actor_sub are both None -- this is a
# system/deploy-initiated event with no logged-in human behind it, same
# convention _run_scheduler_loop's sync.scheduler_error already uses.
# Deliberately best-effort (|| true): a logging failure must never fail
# or block the actual deploy.
_log_deploy_event() {
  local action="$1" details_json="$2"
  "$APP_DIR/.venv/bin/python" -c "
import sys
sys.path.insert(0, '$APP_DIR')
import create_secret_folders as engine
import json
engine.log_audit_event(None, None, '$action', json.loads('''$details_json'''))
" 2>/dev/null || true
}

_log_deploy_event "deploy.started" '{"trigger": "deploy.sh"}'

# Fires on any unhandled command failure for the rest of this script (set
# -e's exact trigger condition) -- logs deploy.failed before this process
# exits, so a failed deploy shows up in the Audit Log too, not just a
# successful one. Does NOT fire for the SUDOERS_GAPS warnings above/below
# (those are handled, non-fatal, printed-and-continue, not a script
# failure) -- only for something that actually aborts the script, e.g.
# pip install, npm ci, or the main systemctl restart failing outright.
trap '_log_deploy_event "deploy.failed" "{\"trigger\": \"deploy.sh\"}"' ERR

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

# FIX (confirmed real, 2026-10-01): NGINX_REPO (the checked-in template)
# can NEVER contain a real NGINX_PROXY_SECRET value -- it's a public repo
# file. Every deploy that applies NGINX_REPO over NGINX_LIVE below was
# therefore reverting a correctly-configured secret back to the literal
# placeholder string, requiring a manual reapply after every single
# deploy. Fixed here, BEFORE the drift diff/apply below even runs: read
# whatever real secret is CURRENTLY live (NGINX_LIVE is rparikh-owned,
# readable without sudo) and bake it into the freshly-rsynced LOCAL copy
# at NGINX_REPO (also rparikh-owned, in $APP_DIR -- writable without sudo)
# in place of the placeholder. The existing diff/apply logic below is
# UNCHANGED otherwise: if nothing else in the config differs, the diff
# now comes back clean (secret already matches) and nothing gets
# overwritten at all; if something else DID change, the copy that gets
# applied already carries the real secret forward. No new sudoers grant
# needed -- both files involved here are already readable/writable by
# this user.
if [ -f "$NGINX_LIVE" ]; then
  LIVE_SECRET=$(grep -oP 'set \$nginx_proxy_secret "\K[^"]*' "$NGINX_LIVE" 2>/dev/null || true)
  if [ -n "$LIVE_SECRET" ] && [ "$LIVE_SECRET" != "REPLACE_WITH_NGINX_PROXY_SECRET_VALUE" ]; then
    awk -v secret="$LIVE_SECRET" '
      /set \$nginx_proxy_secret "/ { sub(/"[^"]*"/, "\"" secret "\"") }
      { print }
    ' "$NGINX_REPO" > "$NGINX_REPO.tmp" && mv "$NGINX_REPO.tmp" "$NGINX_REPO"
    echo "==> Carried forward the live NGINX_PROXY_SECRET into the deployed nginx config"
  fi
fi

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
  #
  # FIX (confirmed live, 2026-10-01): this backup path previously lived
  # inside $TMP_DIR, which mktemp -d generates fresh (a new random path)
  # on every single run -- a sudoers rule authorizing `cp` with a fixed
  # argument list can never match a path that's different every time, so
  # this cp always failed even with an otherwise-correct, intentionally
  # widened sudoers rule. Fixed by using a FIXED path next to the live
  # config instead, so the one-time sudoers grant (see docs/hosting.md's
  # "Hosting on a server" setup) can actually name it.
  NGINX_BACKUP="${NGINX_LIVE}.deploy-backup"
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
    SUDOERS_GAPS+=("cp '$NGINX_LIVE' '$NGINX_BACKUP' && cp '$NGINX_REPO' '$NGINX_LIVE' && nginx -t && systemctl reload nginx")
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
  echo "    See docs/hosting.md's \"Hosting on a server\" setup (step 7) for the exact"
  echo "    sudoers rule to add -- it needs THREE distinct cp invocations (backup,"
  echo "    apply, and rollback-on-failure), not just one, since sudoers matches"
  echo "    each exact argument list separately."
fi

# Reaching here means every command above succeeded (set -e would have
# already fired the ERR trap and exited otherwise) -- clear the trap
# before logging deploy.completed itself, so a (very unlikely) failure
# inside _log_deploy_event's own python call can't recursively re-trigger
# it as a deploy.failed on top of a deploy that actually succeeded.
trap - ERR
_DEPLOYED_VERSION="$(grep -m1 'SCRIPT_VERSION = ' "$APP_DIR/create_secret_folders.py" | sed -E 's/.*"([^"]+)".*/\1/')"
_log_deploy_event "deploy.completed" "{\"version\": \"$_DEPLOYED_VERSION\", \"sudoers_gaps\": ${#SUDOERS_GAPS[@]}}"
