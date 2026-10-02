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
# TWO distinct cp invocations (apply the repo's config over the live
# path, and roll this script's own backup -- kept in $APP_DIR, not
# under /etc/nginx, so creating/deleting it never needs sudo at all --
# back over the live path if `nginx -t` or the reload then fails;
# sudoers matches each exact argument list separately, so both need
# their own grant, not just one), nginx -t, and systemctl reload nginx.
# See docs/hosting.md's "Hosting on a server" setup for the exact rule.
#
# FIX (Phase 8 follow-up, 2026-10-02, external review): EVERY one of the
# "sudo -n call below fails fast and this script prints the exact fix
# needed and continues" paths this comment used to promise -- nginx -t
# failure, reload failure, or the whole backup/apply/validate/reload
# sequence being denied outright by sudoers -- used to still fall
# through to `deploy.completed` at the very end, with no exit code and
# nothing in SUDOERS_GAPS counted as a real failure. Confirmed real:
# a deploy where the new nginx config was flat-out rejected, or where
# reload (or even the ROLLBACK itself) failed, was indistinguishable
# from a clean success in the audit log. All three nginx failure paths
# below are now unconditionally fatal, matching the same auth-gate-
# restart reasoning two sections down -- nginx IS this app's auth
# boundary (the NGINX_PROXY_SECRET header-spoofing fix earlier this
# project's history was itself an nginx config change), so it's at
# least as security-sensitive as the auth-gate restart, not less.
# SUDOERS_GAPS is retired as of this fix -- nothing populates it
# anymore now that every sudoers-gated nginx path exits instead of
# warning-and-continuing.
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
#
# SCOPE DECISION (Phase 8 of docs/fast-follow-redesign.md, documented
# via two independent AI code reviews of this exact script): there is
# still NO code-level rollback/backup of the previous app code/venv/
# frontend build -- only the nginx config has one (see NGINX_BACKUP
# below). A full release-directory/symlink-atomic-swap pattern would
# add real, permanent structural complexity on top of this script's
# already-nontrivial two-phase self-re-exec (three documented past
# incidents already live in the comments below) for a 2-real-install
# project where `git revert` + re-run already works today as the actual
# recovery path. Deliberately scoped out, not an unflagged gap -- `git
# revert <bad commit> && git push`, then re-run this script, is the
# documented way to undo a bad deploy until/unless this list grows
# enough to justify revisiting.

set -euo pipefail

# FIX (external review, 2026-10-02, "will run on servers neither of us
# administers"): confirmed none of this script's own reasoning about
# "this specific server" is actually a safe assumption once this is
# distributed as a public tool deployed by third-party operators on
# machines/distros we've never seen. Preflight-check every external
# tool this script calls BEFORE the destructive rsync --delete step --
# a missing command discovered mid-deploy (after the live tree is
# already half-overwritten) is strictly worse than failing here, before
# anything on disk has changed.
for _cmd in git rsync curl grep awk sed diff find mktemp sudo systemctl nginx; do
  command -v "$_cmd" >/dev/null 2>&1 || {
    echo "ERROR: required command not found on PATH: $_cmd" >&2
    exit 1
  }
done
# grep -P (PCRE) specifically -- GNU grep has it, but it's not
# universal (BusyBox/macOS/some non-GNU distros' grep do not). Checked
# separately from the bare existence check above since `grep` existing
# doesn't guarantee the -P flag this script relies on (version parsing,
# nginx secret extraction) actually works.
if ! echo "x" | grep -P "x" >/dev/null 2>&1; then
  echo "ERROR: this system's 'grep' doesn't support -P (PCRE) -- this script" >&2
  echo "       relies on it for version/secret extraction. Install GNU grep," >&2
  echo "       or adapt the two 'grep -oP' call sites below for your grep." >&2
  exit 1
fi

APP_DIR="/home/rparikh/opa-secrets-folders"

# FIX (external review, 2026-10-02, "will run on servers neither of us
# administers"): this script trusts DEPLOY_SH_PHASE/
# DEPLOY_SH_PHASE1_FROZEN_DIR/DEPLOY_SH_PHASE1_TMP_DIR as pure internal
# phase-handoff state (set by this script's own earlier exec, never
# meant to be supplied by a caller) -- but nothing enforced that before
# this fix. An unexpected externally-supplied DEPLOY_SH_PHASE value
# (anything other than unset/"1"/"2") used to fall through the two
# existing `if "$DEPLOY_SH_PHASE" = "1"` checks straight into phase 2's
# logic with none of phase 1's own setup having run -- most immediately,
# the cleanup trap a few lines below would reference
# DEPLOY_SH_PHASE1_FROZEN_DIR/_TMP_DIR before either was ever set. Not a
# scenario either of us has ever hit running this ourselves, but once
# this is a tool other people's scripts/CI/wrappers might invoke, "only
# ever called the one way we call it" isn't something to assume anymore.
case "${DEPLOY_SH_PHASE:-}" in
  "" | 1 | 2) ;;
  *)
    echo "ERROR: DEPLOY_SH_PHASE must be unset, 1, or 2 (got '${DEPLOY_SH_PHASE}') --" >&2
    echo "       this variable is this script's own internal phase-handoff state," >&2
    echo "       not meant to be set by a caller. Run ./deploy.sh with no" >&2
    echo "       DEPLOY_SH_PHASE in its environment." >&2
    exit 2
    ;;
esac
if [ "${DEPLOY_SH_PHASE:-}" = "2" ]; then
  : "${DEPLOY_SH_PHASE1_FROZEN_DIR:?DEPLOY_SH_PHASE=2 requires DEPLOY_SH_PHASE1_FROZEN_DIR to be set -- this is internal phase-handoff state, not meant to be set by a caller}"
  : "${DEPLOY_SH_PHASE1_TMP_DIR:?DEPLOY_SH_PHASE=2 requires DEPLOY_SH_PHASE1_TMP_DIR to be set -- this is internal phase-handoff state, not meant to be set by a caller}"
fi

# Used by both phases' cleanup traps below -- confirms a path is one
# this script actually created (the opa-deploy-{frozen,source}.* prefix
# both mktemp -d calls below use) before recursively deleting it, so a
# corrupted/tampered DEPLOY_SH_PHASE1_FROZEN_DIR/_TMP_DIR value (however
# unlikely in practice) can't turn an EXIT trap into an unexpected
# arbitrary-path `rm -rf`.
_safe_rm_rf_temp() {
  local path="$1"
  [ -n "$path" ] || return 0
  case "$path" in
    "${TMPDIR:-/tmp}"/opa-deploy-frozen.* | "${TMPDIR:-/tmp}"/opa-deploy-source.*)
      rm -rf -- "$path"
      ;;
    *)
      echo "WARNING: refusing to remove unexpected temp path: $path" >&2
      ;;
  esac
}

# Phase 1 re-exec (see "SELF-MODIFICATION FIX" above): protects the
# clone+rsync steps below from reading a file that's changing out from
# under them. $DEPLOY_SH_PHASE tracks which phase is currently running
# (unset -> "1" -> "2") so each phase re-execs exactly once and never
# loops.
if [ -z "${DEPLOY_SH_PHASE:-}" ]; then
  # Recognizable prefix (not a bare `mktemp -d`'s random name) so the
  # cleanup trap below can confirm it's about to rm -rf a path THIS
  # script actually created, not something else entirely.
  _frozen_dir="$(mktemp -d "${TMPDIR:-/tmp}/opa-deploy-frozen.XXXXXXXX")"
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

if [ "$DEPLOY_SH_PHASE" = "1" ]; then
  REPO_URL="https://github.com/ItsGambit/opa-compliance-wizard.git"
  TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/opa-deploy-source.XXXXXXXX")"

  # Phase 1's own cleanup -- only matters if phase 1 exits WITHOUT
  # reaching the phase-2 re-exec at the end of this block (e.g. the clone
  # or rsync step fails). Once phase 2 is successfully exec'd, this trap
  # (and this entire process image) is gone -- phase 2 sets its OWN trap
  # further down to clean up everything listed here, via
  # DEPLOY_SH_PHASE1_FROZEN_DIR/DEPLOY_SH_PHASE1_TMP_DIR passed through as
  # env vars.
  trap '_safe_rm_rf_temp "$TMP_DIR"; _safe_rm_rf_temp "$DEPLOY_SH_PHASE1_FROZEN_DIR"' EXIT

  echo "==> Fetching latest from $REPO_URL"
  git clone --depth 1 "$REPO_URL" "$TMP_DIR/repo"

  SRC="$TMP_DIR/repo"
  if [ ! -f "$SRC/create_secret_folders.py" ]; then
    echo "ERROR: expected files not found under $SRC -- check REPO_URL above." >&2
    exit 1
  fi

  # Phase 8 follow-up (2026-10-02, external review): record exactly
  # which commit got deployed, not just which VERSION -- SCRIPT_VERSION
  # is bumped by hand and can lag or (in a hotfix) not change at all,
  # while the commit SHA is the actual, unambiguous answer to "what code
  # is this." Captured here (phase 1, right after the clone, before
  # $TMP_DIR -- and the .git/ directory inside it -- gets cleaned up)
  # and passed through to phase 2 the same way DEPLOY_SH_PHASE1_TMP_DIR
  # already is.
  DEPLOY_COMMIT="$(git -C "$SRC" rev-parse HEAD)"

  echo "==> Syncing into $APP_DIR (excluding local-only state)"
  # BUG FIX (real incident, found live deploying Phase 2's SQLite
  # migration, 2026-10-01): environments.json/banner_config.json's
  # exclude lines were REMOVED when Phase 2 shipped, on the reasoning
  # "the migration deletes these files anyway, so excluding is a no-op."
  # That reasoning only holds AFTER a successful migration -- on an
  # install that hasn't migrated yet (or is deploying the very release
  # that introduces the migration), this rsync step runs BEFORE the
  # server process (and its migration) ever starts, so --delete removed
  # the real environments.json/banner_config.json itself, with the
  # server never getting a chance to read and import them first.
  # Confirmed live: the Ubuntu server's real 4-environment metadata
  # (including its genuine two-owner collision case) was deleted by this
  # rsync step, recovered only because a manual pre-deploy backup had
  # been taken outside $APP_DIR. Excluding them is the correct
  # permanent state regardless of migration status -- once a real
  # install HAS migrated, these files no longer exist on either side of
  # the sync, so the exclude is a harmless no-op; it is NOT a no-op
  # before/during migration, which is exactly the case that broke.
  # Phase 8 (2026-10-02): the 5 patterns below (TestCreds.txt through
  # docs/fast-follow-redesign.md) were confirmed MISSING from this list
  # despite all being listed in .gitignore as local-only -- a REAL,
  # CURRENT gap (not hypothetical), same incident class as the
  # environments.json/banner_config.json bug above: if any of these
  # exist under $APP_DIR on the real server (plausible for
  # TestCreds.txt/ubuntuserver.txt/folders_result_*.csv, which accumulate
  # from ad hoc CLI usage on the server itself), the next --delete
  # silently wipes them with no warning.
  rsync -a --delete \
    --exclude '.venv/' \
    --exclude '.git/' \
    --exclude '__pycache__/' \
    --exclude 'frontend/node_modules/' \
    --exclude 'frontend/dist/' \
    --exclude 'environments.json' \
    --exclude 'environments.json.*' \
    --exclude 'banner_config.json' \
    --exclude 'banner_config.json.*' \
    --exclude 'audit_log.jsonl' \
    --exclude 'access_control.json' \
    --exclude 'audit_store.db' \
    --exclude 'audit_store.db-wal' \
    --exclude 'audit_store.db-shm' \
    --exclude 'audit_store.db.*' \
    --exclude '.env' \
    --exclude 'TestCreds.txt' \
    --exclude 'ubuntuserver.txt' \
    --exclude 'folders_result_*.csv' \
    --exclude '.pytest_cache/' \
    --exclude 'docs/fast-follow-redesign.md' \
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
  export DEPLOY_COMMIT
  exec "$APP_DIR/server/deploy.sh" "$@"
fi

# Everything below only ever runs in phase 2 (DEPLOY_SH_PHASE=2) --
# phase 1's block above always ends in `exec`, so execution only
# reaches here via that exec, never by falling through from phase 1.

# Cleans up phase 1's frozen-copy dir AND its TMP_DIR (the git clone,
# already rsynced and no longer needed) -- phase 1's own trap never fired
# for these since exec replaced that process entirely before it could.
trap '_safe_rm_rf_temp "$DEPLOY_SH_PHASE1_FROZEN_DIR"; _safe_rm_rf_temp "$DEPLOY_SH_PHASE1_TMP_DIR"' EXIT

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
#
# FIX (Phase 8 follow-up, 2026-10-02, external review): this used to
# interpolate $action/$details_json directly into the Python source
# string (single-quoted literals, a JSON string inside triple-quotes) --
# fragile in a way that's cheap to just not have: a value containing an
# unescaped quote, backslash, or embedded newline could produce invalid
# Python or feed `json.loads` something that itself isn't valid JSON,
# and (since this whole call is `|| true`) the failure would be
# silently swallowed rather than surfaced. Every value this script
# actually passes today is a hardcoded literal (never attacker- or
# even operator-controlled), so this was never exploitable in
# practice -- fixed anyway since passing values through the
# environment instead of through string interpolation costs nothing
# and removes the whole class of failure, not just today's instances
# of it.
_log_deploy_event() {
  local action="$1" details_json="$2"
  # DEPLOY_COMMIT (Phase 8 follow-up, 2026-10-02) is merged into every
  # event's own details here, in Python, rather than making every call
  # site below repeat it in its own literal JSON string -- "what commit
  # was this" is a property of the WHOLE deploy run, not something each
  # individual call site should have to know to include. Unset (phase 2
  # never ran without it being exported from phase 1) falls back to
  # "unknown" rather than a Python KeyError, since this function is
  # deliberately best-effort end to end.
  DEPLOY_ACTION="$action" DEPLOY_DETAILS="$details_json" DEPLOY_COMMIT="${DEPLOY_COMMIT:-unknown}" APP_DIR="$APP_DIR" \
    "$APP_DIR/.venv/bin/python" <<'PY' 2>/dev/null || true
import json
import os
import sys
sys.path.insert(0, os.environ["APP_DIR"])
import create_secret_folders as engine
details = json.loads(os.environ["DEPLOY_DETAILS"])
details["commit"] = os.environ["DEPLOY_COMMIT"]
engine.log_audit_event(None, None, os.environ["DEPLOY_ACTION"], details)
PY
}

_log_deploy_event "deploy.started" '{"trigger": "deploy.sh"}'

# Fires on any unhandled command failure for the rest of this script (set
# -e's exact trigger condition) -- logs deploy.failed before this process
# exits, so a failed deploy shows up in the Audit Log too, not just a
# successful one. Does NOT fire for the nginx block's own explicit
# `exit 1` paths (a bare exit doesn't trigger bash's ERR trap -- those
# paths log their own deploy.failed first, with a `stage` detail this
# generic trap can't provide) -- this one catches everything else that
# aborts the script, e.g. pip install, npm ci, or either systemctl
# restart failing outright.
trap '_log_deploy_event "deploy.failed" "{\"trigger\": \"deploy.sh\"}"' ERR

echo "==> Reinstalling Python dependencies"
"$APP_DIR/.venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"

echo "==> Rebuilding frontend"
(cd "$APP_DIR/frontend" && npm ci --silent && npx vite build)

_DEPLOYED_VERSION="$(grep -m1 'SCRIPT_VERSION = ' "$APP_DIR/create_secret_folders.py" | sed -E 's/.*"([^"]+)".*/\1/')"

echo "==> Restarting $SERVICE_NAME"
# -n (non-interactive): without a pseudo-TTY (e.g. run via `ssh host "cmd"`
# rather than an interactive shell), plain `sudo` can still try to prompt
# for a password even when a matching NOPASSWD rule exists, and then hang
# or fail with "a terminal is required to authenticate". -n makes it fail
# fast instead if the rule ever stops matching, rather than hanging.
sudo -n systemctl restart "$SERVICE_NAME"
sleep 1
systemctl status "$SERVICE_NAME" --no-pager -l

# FIX (Phase 8, 2026-10-02): `systemctl status` above only proves the
# PROCESS is running -- it can't distinguish "running the OLD code"
# from "running the NEW code," which is exactly the failure class the
# self-modification/one-version-lag fixes earlier in this file's own
# history were about. /healthz (new this phase, see server/serve.py)
# didn't exist yet when the version endpoint below was first wired up,
# but /api/version already did -- reuse it rather than adding a second
# equivalent check. Bounded retry (5 attempts, 1s apart): a slow-
# starting process shouldn't fail the deploy just for not yet being
# ready on the very first curl.
_version_confirmed=""
for _attempt in 1 2 3 4 5; do
  _live_version="$(curl -sf --max-time 2 "http://127.0.0.1:8766/api/version" 2>/dev/null | grep -oP '"version"\s*:\s*"\K[^"]*' || true)"
  if [ "$_live_version" = "$_DEPLOYED_VERSION" ]; then
    _version_confirmed="1"
    break
  fi
  sleep 1
done
if [ -z "$_version_confirmed" ]; then
  echo "ERROR: $SERVICE_NAME is active, but /api/version never reported the just-deployed" >&2
  echo "       version ($_DEPLOYED_VERSION) after 5 attempts -- last response: '${_live_version:-<none>}'." >&2
  # FIX (third-party follow-up review, 2026-10-02): a bare `exit 1` here
  # does NOT fire bash's ERR trap (same confirmed-via-direct-test fact
  # the nginx failure paths above already account for) -- this path
  # was missed when that fix was applied there, so a deploy that got
  # this far (code/frontend/deps all installed, service restarted) but
  # never confirmed the new version was live would exit nonzero with no
  # matching deploy.failed in the audit log at all, just an orphaned
  # deploy.started.
  _log_deploy_event "deploy.failed" '{"trigger": "deploy.sh", "stage": "main_service_version_check_failed"}'
  exit 1
fi
echo "    Confirmed live and serving version $_DEPLOYED_VERSION."

echo "==> Restarting $AUTH_GATE_SERVICE"
# H-4 fix: previously never restarted here at all -- any auth_gate.py
# change deployed above kept running under the OLD code until a separate,
# easy-to-forget manual restart. Same -n fail-fast behavior as above.
#
# FIX (Phase 8, 2026-10-02): this used to be a soft warning
# (SUDOERS_GAPS, continue, still report deploy.completed) on the
# reasoning that the sudoers grant for this restart might not be in
# place yet. That reasoning stopped being correct the moment
# docs/hosting.md's setup documented this restart as one of the six
# REQUIRED grants (step 7c) -- auth_gate.py is this app's own OIDC auth
# gate, explicitly security-sensitive, and a deploy that ships new auth
# logic but silently fails to actually restart the process running it,
# while still reporting success, is the wrong default. Now unconditional
# and fatal, matching $SERVICE_NAME's own treatment above -- if the
# sudoers rule genuinely isn't in place on a given server, this is now a
# real deploy failure (logged via the ERR trap below), not a silent gap.
sudo -n systemctl restart "$AUTH_GATE_SERVICE"
sleep 1
systemctl status "$AUTH_GATE_SERVICE" --no-pager -l

echo "==> Done. Deployed version:"
grep -m1 'SCRIPT_VERSION = ' "$APP_DIR/create_secret_folders.py"
echo "    Commit: ${DEPLOY_COMMIT:-unknown}"

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
#
# FIX (external review, 2026-10-02, "will run on servers neither of us
# administers"): NGINX_LIVE legitimately not existing at all is fine --
# standalone/local-only mode with no nginx in front, or nginx simply not
# set up yet on this install -- and stays a non-fatal skip, same as
# before. But if it DOES exist, require it to be a real regular file,
# not a symlink, before this script reads from or writes to it -- same
# for NGINX_REPO (checked into git, so this should never trip, but an
# operator's own fork/local checkout is something we can't vouch for).
# A symlink here on an install we don't control could point anywhere.
if [ -L "$NGINX_REPO" ] || { [ -e "$NGINX_REPO" ] && [ ! -f "$NGINX_REPO" ]; }; then
  echo "ERROR: $NGINX_REPO must be a regular file, not a symlink or other" >&2
  echo "       special file type." >&2
  exit 1
fi
if [ -L "$NGINX_LIVE" ] || { [ -e "$NGINX_LIVE" ] && [ ! -f "$NGINX_LIVE" ]; }; then
  echo "ERROR: $NGINX_LIVE exists but is not a regular file (symlink, including" >&2
  echo "       a dangling one, or other special file type) -- refusing to read" >&2
  echo "       from or write to it." >&2
  exit 1
fi
if [ -f "$NGINX_LIVE" ]; then
  LIVE_SECRET=$(grep -oP 'set \$nginx_proxy_secret "\K[^"]*' "$NGINX_LIVE" 2>/dev/null || true)
  if [ -n "$LIVE_SECRET" ] && [ "$LIVE_SECRET" != "REPLACE_WITH_NGINX_PROXY_SECRET_VALUE" ]; then
    # FIX (Phase 8 follow-up, 2026-10-02, external review): `awk -v
    # secret="$LIVE_SECRET"` used to both (a) let awk's OWN -v assignment
    # interpret C-style backslash escapes in the secret (confirmed real
    # -- a secret containing a literal `\t`/`\n`/`\\` sequence got
    # silently corrupted before the script body even ran, independent of
    # anything sub() does) and (b) feed the secret straight into sub()'s
    # replacement-text argument, where a literal `&` means "whatever
    # matched" and `\` is itself an escape introducer (confirmed real --
    # a secret containing either character was NOT reproduced literally).
    # `openssl rand -hex 32` (the documented generation command) never
    # produces either, but there's no reason to leave this fragile for
    # a secret generated any other way. Fixed by passing the secret
    # through ENVIRON instead of -v (skips awk's -v-specific escape
    # processing entirely) and replacing sub()'s pattern/replacement
    # matching with plain string ops (index/substr/concatenation have
    # no special characters of their own) -- confirmed byte-for-byte
    # faithful for a secret containing &, ", \, and \t/\n-shaped
    # sequences, not just the common case.
    export LIVE_SECRET
    awk '
      BEGIN { secret = ENVIRON["LIVE_SECRET"]; prefix = "set $nginx_proxy_secret \"" }
      {
        line = $0
        prefix_pos = index(line, prefix)
        if (prefix_pos > 0) {
          prefix_end = prefix_pos + length(prefix) - 1
          rest = substr(line, prefix_end + 1)
          close_pos = index(rest, "\"")
          if (close_pos > 0) {
            print substr(line, 1, prefix_end) secret substr(rest, close_pos)
            next
          }
        }
        print line
      }
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
  # FIX (Phase 8 follow-up, 2026-10-02, external review): every branch
  # below now exits nonzero on failure instead of warning-and-continuing
  # -- see this block's own header comment for why nginx is treated as
  # at least as security-sensitive as the auth-gate restart above. A
  # bare `exit 1` does NOT fire bash's ERR trap (confirmed directly --
  # only EXIT does), so each failure path below logs deploy.failed
  # explicitly before exiting, rather than relying on the ERR trap to
  # catch it the way ordinary command failures elsewhere in this script
  # do.
  # FIX (external review, 2026-10-02, "will run on servers neither of
  # us administers"): this backup previously lived at a FIXED path
  # inside /etc/nginx/sites-available itself (${NGINX_LIVE}.deploy-
  # backup) and needed its own sudo grant just to CREATE it, even
  # though NGINX_LIVE is already documented above as readable without
  # sudo -- only WRITING into /etc/nginx ever actually needed root. That
  # meant the one artifact in this whole script containing the real
  # NGINX_PROXY_SECRET sat world-readable (cp preserves the live file's
  # permissions) under /etc/nginx indefinitely after every deploy, with
  # no sudoers-free way to even clean it up. Moved to $APP_DIR (which
  # the deploying user already owns) instead: creating it needs no sudo
  # at all (one fewer required sudoers grant), it can be chmod 600'd
  # without sudo since we own it, and it's deleted outright after a
  # successful reload so the secret doesn't persist on disk longer than
  # the length of this one deploy run. Deliberately NOT inside $TMP_DIR
  # (mktemp -d, a fresh random path every run) -- same reasoning as the
  # old fixed path: a failed deploy's backup needs to survive THIS
  # process exiting, both so a human can inspect it and so a retried
  # deploy's rollback path (if it gets there again) can still find it.
  NGINX_BACKUP="$APP_DIR/.nginx-deploy-backup"
  if ! cp "$NGINX_LIVE" "$NGINX_BACKUP"; then
    echo "ERROR: could not read $NGINX_LIVE to back it up (no sudo needed for" >&2
    echo "       this step -- if this failed, check that file's own permissions)." >&2
    _log_deploy_event "deploy.failed" '{"trigger": "deploy.sh", "stage": "nginx_backup_failed"}'
    exit 1
  fi
  chmod 600 "$NGINX_BACKUP"
  if ! sudo -n cp "$NGINX_REPO" "$NGINX_LIVE" 2>/dev/null; then
    echo "ERROR: could not apply the new nginx config -- sudoers rule doesn't" >&2
    echo "       cover 'cp $NGINX_REPO $NGINX_LIVE'. See docs/hosting.md's" >&2
    echo "       \"Hosting on a server\" setup (step 7) for the exact sudoers rule to add." >&2
    _log_deploy_event "deploy.failed" '{"trigger": "deploy.sh", "stage": "nginx_apply_denied"}'
    exit 1
  fi
  if ! sudo -n nginx -t 2>&1; then
    echo "ERROR: new nginx config FAILED 'nginx -t' -- rolling back to the" >&2
    echo "       previous live config." >&2
    if ! sudo -n cp "$NGINX_BACKUP" "$NGINX_LIVE" 2>/dev/null; then
      echo "CRITICAL: nginx rollback ALSO failed -- $NGINX_LIVE may now be" >&2
      echo "          broken. Fix manually." >&2
      _log_deploy_event "deploy.failed" '{"trigger": "deploy.sh", "stage": "nginx_validate_rollback_failed"}'
      exit 1
    fi
    # FIX (third-party follow-up review, 2026-10-02): confirm the
    # RESTORED file itself is still a valid config, not just that the
    # cp succeeded -- catches a corrupted backup or a filesystem
    # anomaly on the copy itself, distinct from "did the cp command
    # exit 0." The old config was already serving traffic before this
    # deploy touched it, so this isn't expected to ever actually fail,
    # but confirming it costs one cheap `nginx -t` call.
    if ! sudo -n nginx -t 2>&1; then
      echo "CRITICAL: restored nginx config is ALSO invalid -- $NGINX_LIVE may" >&2
      echo "          now be broken. Fix manually." >&2
      _log_deploy_event "deploy.failed" '{"trigger": "deploy.sh", "stage": "nginx_restored_config_invalid"}'
      exit 1
    fi
    _log_deploy_event "deploy.failed" '{"trigger": "deploy.sh", "stage": "nginx_validate_failed"}'
    exit 1
  fi
  if ! sudo -n systemctl reload nginx 2>/dev/null; then
    # Distinct failure mode from the nginx -t failure above: the new
    # config passed validation but nginx's RUNNING process never picked
    # it up -- rolling back the live FILE (not just reporting the
    # failure) keeps it from silently diverging from what's actually
    # loaded until some unrelated future reload/restart activates it
    # unexpectedly.
    echo "ERROR: nginx config passed 'nginx -t' but reload failed -- rolling" >&2
    echo "       back to the previous live config." >&2
    if ! sudo -n cp "$NGINX_BACKUP" "$NGINX_LIVE" 2>/dev/null; then
      echo "CRITICAL: nginx rollback ALSO failed -- $NGINX_LIVE may now be" >&2
      echo "          broken. Fix manually." >&2
      _log_deploy_event "deploy.failed" '{"trigger": "deploy.sh", "stage": "nginx_reload_rollback_failed"}'
      exit 1
    fi
    # Same revalidation reasoning as the nginx -t failure branch above.
    if ! sudo -n nginx -t 2>&1; then
      echo "CRITICAL: restored nginx config is ALSO invalid -- $NGINX_LIVE may" >&2
      echo "          now be broken. Fix manually." >&2
      _log_deploy_event "deploy.failed" '{"trigger": "deploy.sh", "stage": "nginx_restored_config_invalid"}'
      exit 1
    fi
    _log_deploy_event "deploy.failed" '{"trigger": "deploy.sh", "stage": "nginx_reload_failed"}'
    exit 1
  fi
  echo "    Applied, validated, and reloaded."
  # The backup (containing the real secret) is only needed for THIS
  # run's own rollback paths above -- once we're past them, delete it
  # rather than leave it on disk until the next deploy overwrites it.
  rm -f "$NGINX_BACKUP"
fi

# Reaching here means every command above succeeded (set -e would have
# already fired the ERR trap and exited otherwise, and every nginx
# failure path above exits explicitly with its own deploy.failed logged
# first) -- clear the trap before logging deploy.completed itself, so a
# (very unlikely) failure inside _log_deploy_event's own python call
# can't recursively re-trigger it as a deploy.failed on top of a deploy
# that actually succeeded.
trap - ERR
_log_deploy_event "deploy.completed" "{\"version\": \"$_DEPLOYED_VERSION\"}"
