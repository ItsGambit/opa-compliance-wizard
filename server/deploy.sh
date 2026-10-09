#!/bin/bash
# Repeatable deploy: pulls the OPA Compliance Wizard from GitHub and
# reinstalls it in place on this server. Run this ON THE SERVER (as the
# app's deploy user -- whichever user owns the install directory and the
# systemd services), not from your own machine:
#
#   <install dir>/server/deploy.sh [--ref <branch | tag | 40-char commit>]
#
# The install directory is the one this script lives in (its parent's
# parent), so nothing in this file needs editing for a different path or
# user (OPS-02, 5.41.0). Optional settings, each from the environment or
# from an optional `<install dir>/.deploy.conf` (KEY=VALUE lines; read,
# never sourced; the environment wins; the file is excluded from the
# rsync below, so it survives deploys):
#   OPA_REPO_URL           repository to deploy from (default: upstream on
#                          GitHub) -- a fork sets this once in .deploy.conf
#   OPA_DEPLOY_REF         branch, tag or full commit to deploy (default:
#                          the repository's default branch); --ref wins
#   OPA_BACKEND_PORT       port serve.py listens on (default 8766)
#   OPA_NGINX_SITE         the live nginx site file (default
#                          /etc/nginx/sites-available/opa-secrets-wizard;
#                          e.g. /etc/nginx/conf.d/opa.conf on distros
#                          without sites-available). The sudoers rule must
#                          name the same path.
#   OPA_DEPLOY_BACKUP_DIR  if set, take an online copy of the archive
#                          (audit_store.db) and audit_log.jsonl into this
#                          directory before the services restart; this
#                          script never deletes anything there
#   OPA_APP_DIR            (environment only) the install directory, when
#                          running a copy of this script kept elsewhere
#
# What it does, in order:
#   0. Takes a lock (one deploy at a time), checks that every sudo command
#      it will need is granted, and that the live nginx site is readable,
#      BEFORE anything on disk changes (OPS-11).
#   1. Clones the repo (standalone as of the 2026-09-30 split from the
#      ItsGambit/Okta monorepo) into a throwaway temp dir.
#   2. rsyncs it over the live app directory, EXCLUDING local-only state that
#      must never be overwritten or deleted: the Python venv, credential/
#      session stores, the audit log, and the archive. See the exclude list
#      below -- if a new local-only file/store is ever added to this project,
#      add it here too, or a deploy will silently wipe it.
#   3. Reinstalls Python deps into the existing venv (requirements.txt).
#   4. Rebuilds the frontend (npm ci + vite build) into frontend/dist.new and
#      swaps it in -- serve.py serves the built frontend/dist, so a deploy
#      without this step ships new backend code against a stale UI.
#   5. Restarts the backend, the auth gate(s) and the optional host status
#      service, and checks each one actually stays up.
#   6. Applies the repo's nginx config if it differs from what's actually
#      loaded at /etc/nginx/sites-available/opa-secrets-wizard, `nginx -t`
#      validates it, then reloads nginx -- only if the validation passes.
#   Every run that gets past the clone writes exactly one deploy.started and
#   exactly one deploy.completed or deploy.failed (with the stage) to the
#   dashboard's Audit Log.
#
# SECURITY/CORRECTNESS FIX (external review, 2026-09-30, "H-4"): this used
# to restart ONLY opa-secrets-wizard and only WARN (never apply) on nginx
# config drift, because the deploying user's NOPASSWD sudoers rule was
# scoped to just that one unit. auth_gate.py or nginx conf changes landed
# in the repo, got rsynced, and kept running under the OLD code/config until
# someone remembered the separate manual step. Steps 5-6 now restart/apply,
# which needs the sudoers rule in docs/hosting.md step 7 (two distinct cp
# grants: apply the repo's config over the live path, and roll this
# script's own backup -- kept in the install dir, not under /etc/nginx --
# back over it; sudoers matches each exact argument list separately).
# That rule is effectively root for the deploy account (nginx's root master
# parses whatever config it is handed) -- see docs/hosting.md (OPS-05).
#
# FIX (Phase 8 follow-up, 2026-10-02, external review): every nginx failure
# path (nginx -t failure, reload failure, a denied apply) is fatal; a deploy
# whose new nginx config was rejected used to be indistinguishable from a
# clean success in the audit log. nginx IS this app's auth boundary.
#
# SELF-MODIFICATION FIX (confirmed live, 2026-10-01): step 2's rsync
# overwrites THIS file on disk while bash is still executing it -- bash
# kept executing the OLD already-read copy for the rest of the run.
# ONE-VERSION-LAG FIX (confirmed live, the SAME DAY): freezing a copy before
# the rsync stops the corruption, but then every run executes the PREVIOUS
# version's post-rsync logic. So the script runs in three phases:
#   phase 0  the installed copy: resolves the install dir, takes the lock,
#            re-execs a frozen copy from a temp dir;
#   phase 1  the frozen copy: preflight, clone, rsync, then re-execs the
#            freshly-rsynced copy;
#   phase 2  THIS run's freshly-pulled logic: deps, build, restarts, nginx.
# Each re-exec runs `bash <file>` rather than the file itself, so a temp dir
# on a `noexec` mount (common CIS hardening) works (OPS-11).
# Compatibility: the first deploy of a new release always runs the OLD
# release's phases 0-1 and the NEW release's phase 2, so phase 2 accepts an
# old phase 1's handoff (only DEPLOY_SH_PHASE1_* / DEPLOY_COMMIT /
# DEPLOY_VERSION set) and does the lock / preflight / started event itself;
# and phase 1 still exports everything an older phase 2 expects.
#
# Safe to re-run any time; every step is idempotent.
#
# SCOPE DECISION (Phase 8 of the fast-follow redesign, documented via two
# independent AI code reviews of this exact script): there is still NO
# code-level rollback of the previous app code/venv -- only the nginx config
# has one (see NGINX_BACKUP below), and the frontend build is swapped in
# whole. `git revert <bad commit> && git push`, then re-run this script, or
# `--ref <last good commit>`, is the documented way to undo a bad deploy.

set -euo pipefail

# deploy.sh handoff protocol: 2
# (Release 5.41.0+. Phase 1 of a newer deploy.sh looks for this line in the
# deploy.sh it is about to run as phase 2; see the --ref check below. Keep it.)

_usage() {
  echo "usage: $0 [--ref <branch | tag | 40-character commit>]" >&2
  echo "       settings: see the comment at the top of this file" >&2
}
_ARG_REF=""
while [ $# -gt 0 ]; do
  case "$1" in
    --ref) [ $# -ge 2 ] || { _usage; exit 2; }; _ARG_REF="$2"; shift 2 ;;
    --ref=*) _ARG_REF="${1#--ref=}"; shift ;;
    -h | --help) _usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; _usage; exit 2 ;;
  esac
done

# FIX (external review, 2026-10-02, "will run on servers neither of us
# administers"): preflight-check every external tool this script calls
# BEFORE the destructive rsync --delete step -- a missing command
# discovered mid-deploy (after the live tree is already half-overwritten)
# is strictly worse than failing here. 5.41.0: GNU `grep -P` is no longer
# needed (the two PCRE extractions are plain sed now), so BusyBox/non-GNU
# grep hosts work too.
for _cmd in git rsync curl grep awk sed diff find mktemp cp mv chmod rm sleep seq \
    head tail tr date df du id realpath dirname basename npm npx sudo systemctl nginx; do
  command -v "$_cmd" >/dev/null 2>&1 || {
    echo "ERROR: required command not found on PATH: $_cmd" >&2
    exit 1
  }
done

# FIX (external review, 2026-10-02): DEPLOY_SH_PHASE / DEPLOY_SH_PHASE1_* /
# DEPLOY_* are this script's own internal phase-handoff state, set by its
# own earlier exec -- never meant to be supplied by a caller. An unexpected
# value used to fall straight into phase 2's logic.
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
if [ -z "${DEPLOY_SH_PHASE:-}" ]; then
  # Phase 0: nothing inherited from the caller is handoff state.
  unset DEPLOY_SH_PHASE1_FROZEN_DIR DEPLOY_SH_PHASE1_TMP_DIR DEPLOY_COMMIT DEPLOY_VERSION \
    DEPLOY_APP_DIR DEPLOY_LOCK_HELD DEPLOY_PREFLIGHT_DONE DEPLOY_STARTED_LOGGED
fi
# FIX (4th independent review, 2026-10-02): every variable each phase's own
# later logic depends on is required up front.
if [ "${DEPLOY_SH_PHASE:-}" = "1" ]; then
  : "${DEPLOY_SH_PHASE1_FROZEN_DIR:?DEPLOY_SH_PHASE=1 requires DEPLOY_SH_PHASE1_FROZEN_DIR to be set -- this is internal phase-handoff state, not meant to be set by a caller}"
  : "${DEPLOY_APP_DIR:?DEPLOY_SH_PHASE=1 requires DEPLOY_APP_DIR to be set -- this is internal phase-handoff state, not meant to be set by a caller}"
fi
if [ "${DEPLOY_SH_PHASE:-}" = "2" ]; then
  : "${DEPLOY_SH_PHASE1_FROZEN_DIR:?DEPLOY_SH_PHASE=2 requires DEPLOY_SH_PHASE1_FROZEN_DIR to be set -- this is internal phase-handoff state, not meant to be set by a caller}"
  : "${DEPLOY_SH_PHASE1_TMP_DIR:?DEPLOY_SH_PHASE=2 requires DEPLOY_SH_PHASE1_TMP_DIR to be set -- this is internal phase-handoff state, not meant to be set by a caller}"
  : "${DEPLOY_COMMIT:?DEPLOY_SH_PHASE=2 requires DEPLOY_COMMIT to be set -- this is internal phase-handoff state, not meant to be set by a caller}"
  : "${DEPLOY_VERSION:?DEPLOY_SH_PHASE=2 requires DEPLOY_VERSION to be set -- this is internal phase-handoff state, not meant to be set by a caller}"
fi
for _flag in DEPLOY_LOCK_HELD DEPLOY_PREFLIGHT_DONE DEPLOY_STARTED_LOGGED; do
  case "${!_flag:-}" in
    "" | 1) ;;
    *) echo "ERROR: $_flag must be unset or 1 -- internal phase-handoff state" >&2; exit 2 ;;
  esac
done

# OPS-02 (external review, 2026-10-05): the install directory used to be a
# hardcoded path on line 147, and an operator's edit of it was overwritten
# by this script's own rsync (phase 2 then ran with the maintainer's path).
# Now: phase 0 runs from <install dir>/server/deploy.sh, so the install dir
# is this file's parent's parent (OPA_APP_DIR overrides it for a copy of
# the script kept elsewhere); phase 1 runs from a temp copy and gets it
# from phase 0 (DEPLOY_APP_DIR); phase 2 runs from <install dir>/server/
# again -- including when an OLDER phase 1 exec'd it, which never passes
# DEPLOY_APP_DIR.
if [ "${DEPLOY_SH_PHASE:-}" = "1" ]; then
  APP_DIR="$DEPLOY_APP_DIR"
elif [ -z "${DEPLOY_SH_PHASE:-}" ] && [ -n "${OPA_APP_DIR:-}" ]; then
  APP_DIR="$(cd "$OPA_APP_DIR" && pwd -P)"
else
  APP_DIR="$(cd "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
fi
if [ ! -f "$APP_DIR/create_secret_folders.py" ] || [ ! -x "$APP_DIR/.venv/bin/python" ]; then
  echo "ERROR: $APP_DIR does not look like an installed OPA Compliance Wizard" >&2
  echo "       (expected create_secret_folders.py and .venv/bin/python there)." >&2
  echo "       Run the deploy.sh inside your install (<install dir>/server/deploy.sh)," >&2
  echo "       or set OPA_APP_DIR=<install dir>." >&2
  exit 1
fi

# Optional settings file (see the header). Parsed, never sourced: only the
# keys below are read, and each value is validated before use.
DEPLOY_CONF="$APP_DIR/.deploy.conf"
if [ -f "$DEPLOY_CONF" ]; then
  while IFS= read -r _line || [ -n "$_line" ]; do
    case "$_line" in "" | "#"*) continue ;; esac
    _key="${_line%%=*}"
    _val="${_line#*=}"
    [ "$_key" != "$_line" ] || { echo "ERROR: $DEPLOY_CONF: not KEY=VALUE: $_line" >&2; exit 1; }
    case "$_val" in \"*\") _val="${_val#\"}"; _val="${_val%\"}" ;; \'*\') _val="${_val#\'}"; _val="${_val%\'}" ;; esac
    case "$_key" in
      OPA_REPO_URL | OPA_DEPLOY_REF | OPA_BACKEND_PORT | OPA_DEPLOY_BACKUP_DIR | OPA_NGINX_SITE)
        # The environment wins over the file.
        if [ -z "${!_key:-}" ]; then
          printf -v "$_key" '%s' "$_val"
          export "${_key?}"
        fi
        ;;
      *) echo "ERROR: $DEPLOY_CONF: unknown setting '$_key'" >&2; exit 1 ;;
    esac
  done < "$DEPLOY_CONF"
fi
if [ -n "$_ARG_REF" ]; then
  OPA_DEPLOY_REF="$_ARG_REF"
  export OPA_DEPLOY_REF
fi
REPO_URL="${OPA_REPO_URL:-https://github.com/ItsGambit/opa-compliance-wizard.git}"
DEPLOY_REF="${OPA_DEPLOY_REF:-}"
BACKEND_PORT="${OPA_BACKEND_PORT:-8766}"
BACKUP_DIR="${OPA_DEPLOY_BACKUP_DIR:-}"
NGINX_LIVE="${OPA_NGINX_SITE:-/etc/nginx/sites-available/opa-secrets-wizard}"
case "$NGINX_LIVE" in
  /*) ;;
  *) echo "ERROR: OPA_NGINX_SITE must be an absolute path (got '$NGINX_LIVE')" >&2; exit 1 ;;
esac
case "$NGINX_LIVE" in
  *[[:space:]]*) echo "ERROR: OPA_NGINX_SITE must not contain whitespace" >&2; exit 1 ;;
esac
case "$REPO_URL" in
  https://* | ssh://* | git@* | file://*) ;;
  *) echo "ERROR: OPA_REPO_URL must start with https://, ssh://, git@ or file:// (got '$REPO_URL')" >&2; exit 1 ;;
esac
case "$REPO_URL" in
  *[[:space:]]* | -*) echo "ERROR: OPA_REPO_URL contains whitespace or starts with '-'" >&2; exit 1 ;;
esac
if [ -n "$DEPLOY_REF" ]; then
  case "$DEPLOY_REF" in
    -* | *..* | *[!A-Za-z0-9._/-]*) echo "ERROR: --ref / OPA_DEPLOY_REF must be a branch, tag or commit (letters, digits, . _ / -), got '$DEPLOY_REF'" >&2; exit 1 ;;
  esac
fi
case "$BACKEND_PORT" in
  "" | *[!0-9]*) echo "ERROR: OPA_BACKEND_PORT must be a number (got '$BACKEND_PORT')" >&2; exit 1 ;;
esac
if [ -n "$BACKUP_DIR" ]; then
  case "$BACKUP_DIR" in
    /*) ;;
    *) echo "ERROR: OPA_DEPLOY_BACKUP_DIR must be an absolute path (got '$BACKUP_DIR')" >&2; exit 1 ;;
  esac
  case "$BACKUP_DIR/" in
    "$APP_DIR"/*) echo "ERROR: OPA_DEPLOY_BACKUP_DIR must be outside $APP_DIR (the rsync below would delete it)" >&2; exit 1 ;;
  esac
fi

# Used by both phases' cleanup traps below -- confirms a path is one
# this script actually created (the opa-deploy-{frozen,source}.* prefix
# both mktemp -d calls below use) before recursively deleting it.
#
# FIX (4th independent review, 2026-10-02): canonicalize (via `realpath -m`,
# which doesn't require the path to exist) BEFORE matching, and require the
# canonical path's PARENT to be exactly the temp root -- a textual glob
# match let "$TMPDIR/opa-deploy-source.fake/../../x" through.
_safe_rm_rf_temp() {
  local path="$1" temp_root canonical parent base
  [ -n "$path" ] || return 0
  temp_root="$(realpath -m -- "${TMPDIR:-/tmp}")"
  canonical="$(realpath -m -- "$path")"
  parent="$(dirname -- "$canonical")"
  base="$(basename -- "$canonical")"
  if [ "$parent" != "$temp_root" ]; then
    echo "WARNING: refusing to remove temp path outside $temp_root: $path" >&2
    return 0
  fi
  case "$base" in
    opa-deploy-frozen.* | opa-deploy-source.*)
      rm -rf -- "$canonical"
      ;;
    *)
      echo "WARNING: refusing to remove unexpected temp path: $path" >&2
      ;;
  esac
}

# NEW (2026-10-01): surfaces deploy events (deploy.started/.completed/
# .failed) in the dashboard's own Audit Log, same file every other write
# action logs to (audit_log.jsonl), via engine.log_audit_event (the same
# locked JSON-line append every other call site uses). actor_email/
# actor_sub are None -- a system-initiated event. Deliberately best-effort
# (|| true): a logging failure must never fail or block the actual deploy.
# Values travel through the environment, never through string interpolation
# into Python source (Phase 8 follow-up, 2026-10-02). DEPLOY_COMMIT is
# merged into every event's details.
_log_deploy_event() {
  local action="$1" details_json="$2" py="$APP_DIR/.venv/bin/python"
  DEPLOY_ACTION="$action" DEPLOY_DETAILS="$details_json" DEPLOY_COMMIT="${DEPLOY_COMMIT:-unknown}" APP_DIR="$APP_DIR" \
    "$py" <<'PY' 2>/dev/null || true
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

# OPS-11: one deploy at a time. Two concurrent runs used to both rsync
# --delete into the install dir and race on the nginx temp/backup files.
# The lock is taken once (phase 0, or phase 2 behind an older phase 1) on
# fd 9, which both re-execs inherit; the kernel drops it when the last
# process holding fd 9 exits. The lock file is excluded from the rsync.
_take_deploy_lock() {
  if command -v flock >/dev/null 2>&1; then
    exec 9>>"$APP_DIR/.deploy.lock"
    if ! flock -n 9; then
      echo "ERROR: another deploy.sh run holds $APP_DIR/.deploy.lock -- wait for it to finish." >&2
      exit 1
    fi
  else
    echo "WARNING: flock (util-linux) not found -- concurrent deploys are not prevented." >&2
  fi
  export DEPLOY_LOCK_HELD=1
}

# Phase 1 re-exec (see "SELF-MODIFICATION FIX" above). $DEPLOY_SH_PHASE
# tracks which phase is running (unset -> "1" -> "2") so each phase re-execs
# exactly once and never loops.
if [ -z "${DEPLOY_SH_PHASE:-}" ]; then
  _take_deploy_lock
  # Recognizable prefix (not a bare `mktemp -d`'s random name) so the
  # cleanup trap below can confirm it's about to rm -rf a path THIS
  # script actually created.
  _frozen_dir="$(mktemp -d "${TMPDIR:-/tmp}/opa-deploy-frozen.XXXXXXXX")"
  _frozen_copy="$_frozen_dir/deploy.sh"
  cp "${BASH_SOURCE[0]}" "$_frozen_copy"
  export DEPLOY_SH_PHASE=1
  export DEPLOY_SH_PHASE1_FROZEN_DIR="$_frozen_dir"
  export DEPLOY_APP_DIR="$APP_DIR"
  exec "$BASH" "$_frozen_copy"
fi

NGINX_REPO="$APP_DIR/server/nginx-opa-secrets-wizard.conf"
# Rollback copy of the live site, made right before an apply. In the
# install dir (the deploy user owns it), not under /etc/nginx, so making
# and deleting it needs no sudo; created owner-only from the first byte
# (it holds NGINX_PROXY_SECRET) and excluded from the rsync.
NGINX_BACKUP="$APP_DIR/.nginx-deploy-backup"
# BUG FIX (external review, 2026-10-05, OPS-01): the backend unit was renamed
# opa-secrets-wizard -> opa-compliance-wizard at 5.20.0. Detect which one is
# ACTUALLY installed (`systemctl cat` on a nonexistent unit exits nonzero
# with nothing on stdout -- a side-effect-free existence check). Prefers the
# legacy name when both exist.
if systemctl cat opa-secrets-wizard >/dev/null 2>&1; then
  SERVICE_NAME="opa-secrets-wizard"
elif systemctl cat opa-compliance-wizard >/dev/null 2>&1; then
  SERVICE_NAME="opa-compliance-wizard"
else
  echo "ERROR: neither opa-secrets-wizard.service nor opa-compliance-wizard.service" >&2
  echo "       is installed -- see docs/hosting.md's systemd unit install step." >&2
  exit 1
fi
AUTH_GATE_SERVICE="opa-auth-gate"

# 5.38.1: additional auth gates for other Okta orgs (server/setup-second-gate.sh,
# units named opa-auth-gate-<name>) run the same auth_gate.py. Only ENABLED
# units: a gate that setup-second-gate.sh created but couldn't start yet
# (missing keyring secrets) is skipped.
_enabled_extra_gates() {
  local _u
  for _u in $(systemctl list-unit-files 'opa-auth-gate-*.service' --no-legend 2>/dev/null | awk '{print $1}'); do
    _u="${_u%.service}"
    systemctl is-enabled --quiet "$_u" 2>/dev/null && echo "$_u"
  done
  return 0
}
_host_status_enabled() {
  systemctl is-enabled --quiet opa-host-status 2>/dev/null
}

# OPS-11 (external review, 2026-10-05): the sudo grants and the readable live
# site used to be exercised for the first time AFTER rsync/pip/build and the
# service restarts -- a missing nginx grant aborted with both services
# already running new code and the old nginx config still live. Checked here,
# before anything changes. `sudo -n -l <command>` lists without running:
# sudo(8): "If a command is specified but not allowed by the policy, sudo
# will exit with a status value of 1." Listing needs no password while at
# least one of the user's rules is NOPASSWD (sudoers(5) listpw, default
# "any"); where listing itself needs a password, the check is skipped with
# a warning and a missing grant stops the deploy where it is used, as before.
_preflight() {
  local _missing="" _u _first
  if [ -e "$NGINX_LIVE" ] && [ ! -r "$NGINX_LIVE" ]; then
    echo "ERROR: $NGINX_LIVE is not readable by $(id -un). deploy.sh reads it to carry" >&2
    echo "       NGINX_PROXY_SECRET forward into the new config. Make it readable by this" >&2
    echo "       account's group only (nginx's master process reads it as root):" >&2
    echo "         sudo chown root:$(id -gn) $NGINX_LIVE && sudo chmod 0640 $NGINX_LIVE" >&2
    return 1
  fi
  # A rollback copy that is still here means an earlier run stopped inside
  # its nginx step (interrupted, or its rollback FAILED -- every other path
  # deletes it): the live site may be the broken one -- nginx keeps serving
  # the config it loaded, until its next restart -- and this copy the last
  # good config. Never overwrite it; never deploy over it.
  if [ -e "$NGINX_BACKUP" ]; then
    echo "ERROR: $NGINX_BACKUP is still here: an earlier deploy stopped during its" >&2
    echo "       nginx step or its rollback failed, so it may be the last good config. Compare it with" >&2
    echo "       $NGINX_LIVE (sudo nginx -t), restore whichever is right, then delete" >&2
    echo "       $NGINX_BACKUP and run deploy.sh again." >&2
    return 1
  fi
  local _list_err
  if ! _list_err="$(sudo -n -l 2>&1 >/dev/null)"; then
    case "$_list_err" in
      *"not allowed to run sudo"* | *"may not run sudo"*)
        echo "ERROR: $(id -un) may not run sudo at all; deploy.sh needs the deploy sudoers" >&2
        echo "       rule (docs/hosting.md, step 7). Nothing has been changed." >&2
        return 1
        ;;
    esac
    echo "WARNING: this account's sudo rules can't be listed without a password, so the" >&2
    echo "         grants deploy.sh needs were not pre-checked; a missing one will stop" >&2
    echo "         the deploy at the step that uses it." >&2
    return 0
  fi
  # `sudo -l <command>` says whether the policy allows the command at all,
  # not whether it is allowed WITHOUT a password (an account that is also in
  # %sudo would pass for everything). Classic sudo 1.9.15+ prints the
  # matching rule when the command is listed twice (-l -l; NEWS 1.9.15), and
  # a NOPASSWD rule shows "!authenticate" there (sudoers display.c). sudo-rs
  # (Ubuntu's default since 25.10) and older sudo print only the command, so
  # for them "allowed" is all that can be checked; a password-requiring rule
  # then still stops the deploy at the step that uses it (sudo -n).
  _NOPASSWD_UNCHECKED=""
  _need() {
    local _out
    if ! _out="$(sudo -n -l -l "$@" 2>/dev/null)" || [ -z "$_out" ]; then
      :
    elif ! grep -Eq '^[[:space:]]*(Sudoers entry|Matched)' <<<"$_out"; then
      _NOPASSWD_UNCHECKED=1
      return 0
    elif grep -q '!authenticate' <<<"$_out"; then
      return 0
    fi
    _first="$(command -v "$1" 2>/dev/null || echo "$1")"
    shift
    _missing="${_missing}    ${_first}${*:+ $*}
"
  }
  _need systemctl restart "$SERVICE_NAME"
  _need systemctl restart "$AUTH_GATE_SERVICE"
  for _u in $(_enabled_extra_gates); do
    _need systemctl restart "$_u"
  done
  if _host_status_enabled; then
    _need systemctl restart opa-host-status
  fi
  if [ -f "$NGINX_LIVE" ]; then
    _need cp "$NGINX_REPO" "$NGINX_LIVE"
    _need cp "$NGINX_BACKUP" "$NGINX_LIVE"
    _need nginx -t
    _need systemctl reload nginx
  fi
  if [ -n "$_missing" ]; then
    echo "ERROR: sudo does not grant $(id -un) these commands without a password, which this deploy runs:" >&2
    printf '%s' "$_missing" >&2
    echo "       Nothing has been changed. Add them to the deploy sudoers rule" >&2
    echo "       (docs/hosting.md, step 7: sudo visudo -f /etc/sudoers.d/opa-compliance-wizard-deploy)" >&2
    echo "       and run deploy.sh again." >&2
    return 1
  fi
  if [ -n "$_NOPASSWD_UNCHECKED" ]; then
    echo "NOTE: every sudo command this deploy runs is granted; this sudo can't show whether"
    echo "      a rule asks for a password (a deploy stops where one does)."
  fi
  return 0
}

# The live nginx site must carry over onto the template being deployed
# (server/nginx_bake.py) -- checked before anything changes, so a site with
# another layout stops the deploy here instead of after every service has
# restarted on new code. $1 = the template to check against.
_nginx_layout_check() {
  local _template="$1" _baker
  [ -f "$NGINX_LIVE" ] || return 0
  _baker="$(dirname -- "$_template")/nginx_bake.py"
  [ -f "$_baker" ] || return 0
  "$APP_DIR/.venv/bin/python" "$_baker" --check "$NGINX_LIVE" "$_template"
}

if [ "$DEPLOY_SH_PHASE" = "1" ]; then
  TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/opa-deploy-source.XXXXXXXX")"
  _P1_STAGE="fetch"
  _P1_STARTED=""

  # Phase 1's own exit handler -- only runs if phase 1 exits WITHOUT
  # reaching the phase-2 exec at the end of this block (an exec replaces the
  # process, trap included). Once deploy.started is logged, a failure here
  # logs deploy.failed with the stage (OPS-10).
  _phase1_exit() {
    local _rc=$?
    set +e
    if [ -n "$_P1_STARTED" ]; then
      _log_deploy_event "deploy.failed" "{\"trigger\": \"deploy.sh\", \"stage\": \"$_P1_STAGE\"}"
    fi
    _safe_rm_rf_temp "$TMP_DIR"
    _safe_rm_rf_temp "$DEPLOY_SH_PHASE1_FROZEN_DIR"
    exit "$_rc"
  }
  trap _phase1_exit EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  trap 'exit 129' HUP

  if ! _preflight; then
    exit 1
  fi
  export DEPLOY_PREFLIGHT_DONE=1

  echo "==> Fetching ${DEPLOY_REF:-the default branch} from $REPO_URL"
  # OPS-06: an explicit ref deploys exactly that branch, tag or commit
  # instead of whatever the default branch's tip is at that moment.
  if [ -z "$DEPLOY_REF" ]; then
    git clone --depth 1 -- "$REPO_URL" "$TMP_DIR/repo"
  elif printf '%s' "$DEPLOY_REF" | grep -Eq '^[0-9a-f]{40}$'; then
    git clone -- "$REPO_URL" "$TMP_DIR/repo"
    git -C "$TMP_DIR/repo" checkout --quiet --detach "$DEPLOY_REF"
  else
    git clone --depth 1 --branch "$DEPLOY_REF" -- "$REPO_URL" "$TMP_DIR/repo"
  fi

  SRC="$TMP_DIR/repo"
  if [ ! -f "$SRC/create_secret_folders.py" ]; then
    echo "ERROR: expected files not found under $SRC -- check OPA_REPO_URL." >&2
    exit 1
  fi

  # FIX (4th independent review, 2026-10-02): SCRIPT_VERSION is parsed and
  # validated here, against the fresh clone, before anything in the install
  # dir is touched, and exported to phase 2 so it's parsed exactly once.
  DEPLOY_VERSION="$(grep -m1 'SCRIPT_VERSION = ' "$SRC/create_secret_folders.py" | sed -E 's/.*"([^"]+)".*/\1/')"
  case "$DEPLOY_VERSION" in
    "" | *[!0-9A-Za-z.+-]*)
      echo "ERROR: could not parse SCRIPT_VERSION from $SRC/create_secret_folders.py (got '$DEPLOY_VERSION')" >&2
      exit 1
      ;;
  esac
  # A ref older than 5.41.0 brings a deploy.sh whose phase 2 (which runs
  # right after the sync below) hardcodes the maintainer's install path:
  # anywhere else it fails after the old code is already in place, and the
  # installed deploy.sh is then the old one. Allowed only where that path
  # is this install.
  if ! grep -Eq '^# deploy.sh handoff protocol: ([2-9]|[1-9][0-9]+)$' "$SRC/server/deploy.sh"; then
    if ! grep -qxF "APP_DIR=\"$APP_DIR\"" "$SRC/server/deploy.sh"; then
      echo "ERROR: ${DEPLOY_REF:-this ref} has a deploy.sh from before 5.41.0, which only works in" >&2
      echo "       its own hardcoded install directory, not $APP_DIR. Deploy 5.41.0 or" >&2
      echo "       later (to roll back the app further, check out the old commit by hand)." >&2
      exit 1
    fi
    echo "WARNING: deploying a release older than 5.41.0; its deploy.sh runs from here on." >&2
    echo "         It applies its own nginx template, carrying over only the proxy secret" >&2
    echo "         (not your server_name or certificate paths), and it is not pre-checked." >&2
  fi
  if ! _nginx_layout_check "$SRC/server/nginx-opa-secrets-wizard.conf"; then
    exit 1
  fi

  # Phase 8 follow-up (2026-10-02): record exactly which commit got deployed
  # -- SCRIPT_VERSION is bumped by hand and can lag.
  DEPLOY_COMMIT="$(git -C "$SRC" rev-parse HEAD)"
  echo "    Version $DEPLOY_VERSION, commit $DEPLOY_COMMIT"

  _log_deploy_event "deploy.started" '{"trigger": "deploy.sh"}'
  _P1_STARTED=1
  _P1_STAGE="rsync"

  echo "==> Syncing into $APP_DIR (excluding local-only state)"
  # BUG FIX (real incident, 2026-10-01): environments.json/banner_config.json
  # must stay excluded regardless of migration status -- this rsync runs
  # BEFORE the server (and its migration) starts, and --delete once removed
  # the real files before the server could import them.
  # Phase 8 (2026-10-02): every .gitignore'd local-only file is excluded.
  # BUG FIX (external review, 2026-10-05, OPS-03): every *.csv is excluded,
  # except the one tracked CSV (folders_template.csv), whose include rule
  # comes FIRST (rsync: first matching rule wins).
  # 5.41.0: this script's own local state (.deploy.conf, .deploy.lock,
  # .nginx-deploy-backup) and the frontend build swap dirs are excluded too
  # (OPS-11: a retried deploy's phase 1 used to delete the nginx backup).
  rsync -a --delete \
    --exclude '.venv/' \
    --exclude '.git/' \
    --exclude '__pycache__/' \
    --exclude 'frontend/node_modules/' \
    --exclude 'frontend/dist/' \
    --exclude 'frontend/dist.new/' \
    --exclude 'frontend/dist.old/' \
    --exclude 'environments.json' \
    --exclude 'environments.json.*' \
    --exclude 'banner_config.json' \
    --exclude 'banner_config.json.*' \
    --exclude 'audit_log.jsonl' \
    --exclude '.audit_log.jsonl.lock' \
    --exclude 'access_control.json' \
    --exclude 'audit_store.db' \
    --exclude 'audit_store.db-wal' \
    --exclude 'audit_store.db-shm' \
    --exclude 'audit_store.db.*' \
    --exclude '.env' \
    --exclude '.deploy.conf' \
    --exclude '.deploy.lock' \
    --exclude '.nginx-deploy-backup' \
    --exclude 'TestCreds.txt' \
    --exclude 'ubuntuserver.txt' \
    --include 'folders_template.csv' \
    --exclude '*.csv' \
    --exclude '.pytest_cache/' \
    --exclude 'docs/fast-follow-redesign.md' \
    "$SRC/" "$APP_DIR/"

  # git-for-windows checkouts commonly have core.fileMode=false, which can
  # leave *.sh files at 100644 -- confirmed as the real cause of a 203/EXEC
  # crash-loop (start-headless.sh). Belt-and-suspenders with the tracked
  # modes (fixed in 5.41.0). MUST happen before the phase-2 exec below.
  find "$APP_DIR" -maxdepth 3 -name '*.sh' -exec chmod +x {} +

  # Phase 2 exec (see "ONE-VERSION-LAG FIX" above): $APP_DIR/server/
  # deploy.sh is now THIS run's freshly-rsynced copy. Passes phase 1's temp
  # dirs through so phase 2's cleanup can remove them.
  _P1_STAGE="phase2_exec"
  export DEPLOY_SH_PHASE=2
  export DEPLOY_SH_PHASE1_TMP_DIR="$TMP_DIR"
  export DEPLOY_COMMIT
  export DEPLOY_VERSION
  export DEPLOY_STARTED_LOGGED=1
  exec "$BASH" "$APP_DIR/server/deploy.sh"
fi

# Everything below only ever runs in phase 2 (DEPLOY_SH_PHASE=2) --
# phase 1's block above always ends in `exec`.

# OPS-10 (external review, 2026-10-05): one EXIT handler writes exactly one
# terminal event -- deploy.completed if the run reached the end, otherwise
# deploy.failed with the stage it was in. The old ERR trap missed every
# bare `exit 1` (bash runs the ERR trap only for a failing command), so
# several failure paths left an orphaned deploy.started. Also cleans up
# phase 1's frozen copy and clone (phase 1's own trap never fired for them,
# since exec replaced that process).
_STAGE="setup"
_DEPLOY_OK=""
_phase2_exit() {
  local _rc=$?
  set +e
  if [ -n "$_DEPLOY_OK" ] && [ "$_rc" = 0 ]; then
    _log_deploy_event "deploy.completed" "{\"version\": \"$DEPLOY_VERSION\"}"
  else
    _log_deploy_event "deploy.failed" "{\"trigger\": \"deploy.sh\", \"stage\": \"$_STAGE\"}"
  fi
  _safe_rm_rf_temp "$DEPLOY_SH_PHASE1_FROZEN_DIR"
  _safe_rm_rf_temp "$DEPLOY_SH_PHASE1_TMP_DIR"
  exit "$_rc"
}
trap _phase2_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

case "$DEPLOY_VERSION" in
  *[!0-9A-Za-z.+-]*) echo "ERROR: unexpected DEPLOY_VERSION '$DEPLOY_VERSION'" >&2; exit 1 ;;
esac

# An older release's phase 1 (the first deploy of 5.41.0 always runs one)
# logs nothing, takes no lock and checks no grants -- do it here.
if [ "${DEPLOY_STARTED_LOGGED:-}" != "1" ]; then
  _log_deploy_event "deploy.started" '{"trigger": "deploy.sh"}'
fi
if [ "${DEPLOY_LOCK_HELD:-}" != "1" ]; then
  _take_deploy_lock
fi
if [ "${DEPLOY_PREFLIGHT_DONE:-}" != "1" ]; then
  _STAGE="preflight"
  _preflight
  _nginx_layout_check "$NGINX_REPO" || exit 1
fi

_STAGE="pip_install"
echo "==> Reinstalling Python dependencies"
"$APP_DIR/.venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"

_STAGE="frontend_build"
echo "==> Rebuilding frontend"
# OPS-06: --ignore-scripts -- no package this frontend needs runs an install
# script (the lockfile's only one is fsevents, a macOS-only optional
# dependency), so none get to run code on the server at install time.
# OPS-11: build into dist.new and swap it in, so the running server never
# serves a half-emptied dist/ while vite builds, and a failed build leaves
# the previous UI in place.
(
  cd "$APP_DIR/frontend"
  rm -rf dist.new
  npm ci --ignore-scripts --silent
  npx vite build --outDir dist.new
)
if [ ! -f "$APP_DIR/frontend/dist.new/index.html" ]; then
  echo "ERROR: the frontend build produced no dist.new/index.html" >&2
  exit 1
fi
rm -rf "$APP_DIR/frontend/dist.old"
if [ -d "$APP_DIR/frontend/dist" ]; then
  mv "$APP_DIR/frontend/dist" "$APP_DIR/frontend/dist.old"
fi
mv "$APP_DIR/frontend/dist.new" "$APP_DIR/frontend/dist"
rm -rf "$APP_DIR/frontend/dist.old"

# OPS-11 (opt-in, OPA_DEPLOY_BACKUP_DIR): a copy of the archive and the audit
# log taken before the new code starts (a release can migrate the schema at
# startup). SQLite's online backup API, through the app's own venv Python
# (no sqlite3 CLI needed), safe while the old server keeps writing. Copies
# are owner-only. deploy.sh never deletes anything in that directory.
_backup_archive() {
  local _db="$APP_DIR/audit_store.db" _envfile _line _stamp _dest _need_kb _free_kb
  # The service may keep the archive elsewhere (OPA_AUDIT_DB_PATH in its
  # EnvironmentFile, see docs/hosting.md).
  for _envfile in $(systemctl show -p EnvironmentFiles --value "$SERVICE_NAME" 2>/dev/null | awk '{print $1}'); do
    if [ ! -r "$_envfile" ]; then
      echo "WARNING: can't read $_envfile, so an OPA_AUDIT_DB_PATH set there is not seen;" >&2
      echo "         backing up $_db." >&2
      continue
    fi
    _line="$(sed -n 's/^[[:space:]]*OPA_AUDIT_DB_PATH=//p' "$_envfile" | tail -n 1)"
    _line="${_line%\"}"; _line="${_line#\"}"
    [ -n "$_line" ] && _db="$_line"
  done
  if [ ! -d "$BACKUP_DIR" ] || [ ! -w "$BACKUP_DIR" ]; then
    echo "ERROR: OPA_DEPLOY_BACKUP_DIR=$BACKUP_DIR is not a writable directory." >&2
    return 1
  fi
  if [ ! -f "$_db" ]; then
    echo "    No archive at $_db yet -- nothing to back up."
    return 0
  fi
  _need_kb="$(du -k "$_db" | awk '{print $1}')"
  [ -f "$_db-wal" ] && _need_kb=$((_need_kb + $(du -k "$_db-wal" | awk '{print $1}')))
  _free_kb="$(df -Pk "$BACKUP_DIR" | awk 'NR==2 {print $4}')"
  if [ "$_free_kb" -lt $((_need_kb + _need_kb / 5 + 1024)) ]; then
    echo "ERROR: not enough free space in $BACKUP_DIR for a copy of $_db" >&2
    echo "       (need about $((_need_kb / 1024)) MB plus 20%, have $((_free_kb / 1024)) MB)." >&2
    return 1
  fi
  _stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  _dest="$BACKUP_DIR/audit_store-pre-$DEPLOY_VERSION-$_stamp.db"
  echo "==> Backing up the archive to $_dest"
  "$APP_DIR/.venv/bin/python" - "$_db" "$_dest" <<'PY'
import os
import sqlite3
import sys

os.umask(0o077)
src = sqlite3.connect(sys.argv[1])
dst = sqlite3.connect(sys.argv[2])
try:
    src.backup(dst)
    ok = dst.execute("PRAGMA integrity_check").fetchone()[0]
finally:
    dst.close()
    src.close()
if ok != "ok":
    sys.exit(f"backup copy failed integrity_check: {ok}")
PY
  if [ -f "$APP_DIR/audit_log.jsonl" ]; then
    (umask 077; cp "$APP_DIR/audit_log.jsonl" "$BACKUP_DIR/audit_log-pre-$DEPLOY_VERSION-$_stamp.jsonl")
  fi
  echo "    Done. $BACKUP_DIR now holds $(du -sh "$BACKUP_DIR" | awk '{print $1}'); deploy.sh never deletes old copies."
}
if [ -n "$BACKUP_DIR" ]; then
  _STAGE="db_backup"
  _backup_archive
fi

# The units this run restarts, in order.
_UNITS="$SERVICE_NAME $AUTH_GATE_SERVICE $(_enabled_extra_gates | tr '\n' ' ')"
if _host_status_enabled; then
  _UNITS="$_UNITS opa-host-status"
fi

# A file root's processes load (a systemd unit, the nginx site) that a
# non-root account can write is a way for that account to get root at the
# next reload or boot. deploy.sh can't change ownership without new sudo
# grants, so it reports the exact one-time fix on every run until it's done.
_warn_if_not_root_controlled() {
  local _file="$1" _what="$2"
  [ -f "$_file" ] || return 0
  if [ -n "$(find "$_file" -prune \( ! -user 0 -o -perm -0002 -o \( -perm -0020 ! -group 0 \) \) -print)" ]; then
    echo "WARNING: $_file ($_what) can be changed by an account other than root, but" >&2
    echo "         root loads it. One-time fix (keeps it readable where it needs to be):" >&2
    echo "           sudo chown root:${3:-root} $_file && sudo chmod ${4:-0644} $_file" >&2
  fi
}

# systemctl prints "The unit file, source configuration file or drop-ins of
# X changed on disk. Run 'systemctl daemon-reload'" whenever a unit's
# NeedDaemonReload is yes. In systemd (src/core/unit.c,
# unit_need_daemon_reload) that is true either because THAT unit's file or
# drop-ins changed since the last load, or because of a manager-wide flag
# (unit_file_state_outdated) set by ANY enable/disable-style call made
# without a daemon-reload afterwards -- e.g. snapd enabling a snap's mount
# unit -- which then marks every unit until the next daemon-reload. deploy.sh
# never changes unit files (they live in /etc/systemd/system, outside the
# rsync), so compare against systemd-journald to tell the two apart.
_explain_daemon_reload() {
  local _u _mine _ref _specific=""
  _ref="$(systemctl show -p NeedDaemonReload --value systemd-journald.service 2>/dev/null || true)"
  for _u in $_UNITS; do
    _mine="$(systemctl show -p NeedDaemonReload --value "$_u" 2>/dev/null || true)"
    [ "$_mine" = "yes" ] || continue
    if [ "$_ref" != "yes" ]; then
      _specific="$_specific $_u"
    fi
  done
  if [ -n "$_specific" ]; then
    echo "WARNING: the unit file or drop-ins of:$_specific changed on disk since systemd" >&2
    echo "         loaded them, so the restarts below use the OLD definition. If you" >&2
    echo "         changed them on purpose, stop here (Ctrl+C), run" >&2
    echo "         'sudo systemctl daemon-reload', and deploy again." >&2
    sleep 5
  elif [ "$_ref" = "yes" ]; then
    echo "NOTE: systemd reports a pending daemon-reload for every unit (another tool --"
    echo "      often snapd or a package -- enabled or disabled a unit without reloading)."
    echo "      This deploy changes no unit files; the 'changed on disk' warnings from the"
    echo "      restarts below are harmless. 'sudo systemctl daemon-reload' clears them."
  fi
}

for _u in $_UNITS; do
  _warn_if_not_root_controlled "$(systemctl show -p FragmentPath --value "$_u" 2>/dev/null || true)" "systemd unit $_u"
done
_explain_daemon_reload

# OPS-11: `systemctl status`/`is-active` one second after a restart can't
# tell a healthy unit from one that crashes a second later and is restarted
# by Restart=on-failure. systemd counts those automatic restarts in
# NRestarts and resets it to 0 on a manual start (src/core/service.c), so
# after our own restart: NRestarts must stay 0, and the unit must be active
# -- for a gate, also answering 401 on /verify without a cookie (no Okta
# call, no side effect).
_unit_stays_up() {
  local _unit="$1" _port="$2" _tries="${3:-10}" _i _n _state _code
  for _i in $(seq 1 "$_tries"); do
    sleep 1
    _n="$(systemctl show -p NRestarts --value "$_unit" 2>/dev/null || true)"
    if [ -n "$_n" ] && [ "$_n" != "0" ]; then
      echo "ERROR: $_unit crashed and was restarted by systemd $_n time(s) after this deploy restarted it." >&2
      echo "       See: journalctl -u $_unit -n 50 --no-pager" >&2
      return 1
    fi
    _state="$(systemctl show -p ActiveState --value "$_unit" 2>/dev/null || true)"
    [ "$_state" = "active" ] || continue
    if [ -z "$_port" ]; then
      # No HTTP probe for this unit: active and not restarted for the
      # whole window (longer than the units' RestartSec=3).
      [ "$_i" -ge "$_tries" ] && return 0
      continue
    fi
    _code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "http://127.0.0.1:$_port/verify" 2>/dev/null || true)"
    [ "$_code" = "401" ] && return 0
  done
  if [ -n "$_port" ]; then
    echo "ERROR: $_unit did not come back up (state ${_state:-unknown}, /verify on port $_port answered ${_code:-nothing}, expected 401)." >&2
  else
    echo "ERROR: $_unit did not stay up (state ${_state:-unknown})." >&2
  fi
  echo "       See: journalctl -u $_unit -n 50 --no-pager" >&2
  return 1
}
# The gate's port is on its ExecStart (--port N); auth_gate.py defaults to 8767.
_gate_port() {
  local _p
  _p="$(systemctl show -p ExecStart --value "$1" 2>/dev/null | sed -n 's/.*--port[ =]\([0-9][0-9]*\).*/\1/p' | head -n 1)"
  echo "${_p:-8767}"
}

_STAGE="restart_main"
echo "==> Restarting $SERVICE_NAME"
# -n (non-interactive): without a TTY, plain `sudo` can try to prompt even
# when a NOPASSWD rule exists; -n fails fast instead of hanging.
_old_pid="$(systemctl show -p MainPID --value "$SERVICE_NAME" 2>/dev/null || echo 0)"
sudo -n systemctl restart "$SERVICE_NAME"
systemctl status "$SERVICE_NAME" --no-pager -l || true

# FIX (Phase 8, 2026-10-02): a running process can't distinguish "running the
# OLD code" from "running the NEW code" -- /api/version must report THIS
# run's version, from a NEW process (MainPID changed: the restart really
# happened, which matters for a same-version hotfix), with no automatic
# restarts since. Up to 30 s: a release can run a schema migration at
# startup.
_STAGE="main_service_version_check_failed"
_version_confirmed=""
_live_version=""
for _attempt in $(seq 1 30); do
  sleep 1
  _n="$(systemctl show -p NRestarts --value "$SERVICE_NAME" 2>/dev/null || true)"
  if [ -n "$_n" ] && [ "$_n" != "0" ]; then
    break
  fi
  _live_version="$(curl -sf --max-time 2 "http://127.0.0.1:$BACKEND_PORT/api/version" 2>/dev/null \
    | sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1 || true)"
  _new_pid="$(systemctl show -p MainPID --value "$SERVICE_NAME" 2>/dev/null || echo 0)"
  if [ "$_live_version" = "$DEPLOY_VERSION" ] && [ "$_new_pid" != "0" ] && [ "$_new_pid" != "$_old_pid" ]; then
    _version_confirmed="1"
    break
  fi
done
if [ -z "$_version_confirmed" ]; then
  echo "ERROR: $SERVICE_NAME did not come up serving the just-deployed version ($DEPLOY_VERSION):" >&2
  echo "       last /api/version answer '${_live_version:-<none>}', automatic restarts '${_n:-?}'." >&2
  echo "       See: journalctl -u $SERVICE_NAME -n 50 --no-pager" >&2
  exit 1
fi
echo "    Confirmed live and serving version $DEPLOY_VERSION."

# H-4 / Phase 8: the gate restart is unconditional and fatal -- a deploy
# that ships new auth logic but fails to restart the process running it is
# not "completed".
_STAGE="restart_gate"
echo "==> Restarting $AUTH_GATE_SERVICE"
sudo -n systemctl restart "$AUTH_GATE_SERVICE"
_unit_stays_up "$AUTH_GATE_SERVICE" "$(_gate_port "$AUTH_GATE_SERVICE")"
echo "    $AUTH_GATE_SERVICE is up."

_STAGE="restart_extra_gate"
for _unit in $(_enabled_extra_gates); do
  echo "==> Restarting $_unit (additional Okta org gate)"
  sudo -n systemctl restart "$_unit"
  _unit_stays_up "$_unit" "$(_gate_port "$_unit")"
  echo "    $_unit is up."
done

# 5.39.0: the optional host status service runs host_status.py from this
# checkout; restart it when installed so it serves the new code.
_STAGE="restart_host_status"
if _host_status_enabled; then
  echo "==> Restarting opa-host-status"
  sudo -n systemctl restart opa-host-status
  _unit_stays_up opa-host-status "" 5
  echo "    opa-host-status is up."
fi

# A unit that answered once and then crashed (e.g. on its first keyring call
# a couple of seconds in) would pass the checks above. After every restart,
# wait out the units' RestartSec=3 once more and require each one to still
# be active with no automatic restart since ours.
_STAGE="post_restart_check"
sleep 5
for _unit in $_UNITS; do
  _n="$(systemctl show -p NRestarts --value "$_unit" 2>/dev/null || true)"
  _state="$(systemctl show -p ActiveState --value "$_unit" 2>/dev/null || true)"
  if { [ -n "$_n" ] && [ "$_n" != "0" ]; } || [ "$_state" != "active" ]; then
    echo "ERROR: $_unit did not stay up after the restart (state ${_state:-unknown}, automatic restarts ${_n:-?})." >&2
    echo "       See: journalctl -u $_unit -n 50 --no-pager" >&2
    exit 1
  fi
done

# FIX (confirmed real, 2026-10-01): NGINX_REPO (the public template) can
# never contain the real NGINX_PROXY_SECRET, so every apply used to revert
# the live secret to the placeholder. The live values are carried into the
# freshly-rsynced local copy before the drift diff (see the bake below).
# deploy.sh only supports the hosted/nginx-fronted path, so NGINX_REPO must
# exist; NGINX_LIVE not existing YET is a first-time setup that hasn't
# installed the site.
_STAGE="nginx_repo_config_invalid"
if [ ! -f "$NGINX_REPO" ] || [ -L "$NGINX_REPO" ]; then
  echo "ERROR: repository nginx config is missing or invalid: $NGINX_REPO --" >&2
  echo "       deploy.sh only supports the hosted/nginx-fronted path (see" >&2
  echo "       docs/hosting.md); this file should always exist in a real" >&2
  echo "       checkout of this repo." >&2
  exit 1
fi
_STAGE="nginx_live_not_regular_file"
if [ -L "$NGINX_LIVE" ] || { [ -e "$NGINX_LIVE" ] && [ ! -f "$NGINX_LIVE" ]; }; then
  echo "ERROR: $NGINX_LIVE exists but is not a regular file (symlink, including" >&2
  echo "       a dangling one, or other special file type) -- refusing to read" >&2
  echo "       from or write to it." >&2
  exit 1
fi

# OPS-09 (external review, 2026-10-05; seen live 2026-10-09): the live site
# holds NGINX_PROXY_SECRET. `sudo cp` onto an EXISTING file keeps that
# file's owner and mode (POSIX cp opens it O_WRONLY|O_TRUNC), so deploy.sh
# can't fix a wrong mode without a new sudo grant -- but once it is
# root:<deploy group> 0640, every later deploy keeps it that way. nginx
# needs no group access: its master process (root) reads the config.
if [ -f "$NGINX_LIVE" ]; then
  if [ -n "$(find "$NGINX_LIVE" -prune -perm -0004 -print)" ]; then
    echo "WARNING: $NGINX_LIVE holds NGINX_PROXY_SECRET and every local account can read it." >&2
    echo "         Anyone who reads it can call the backend as any user, including an admin." >&2
    echo "         One-time fix:  sudo chown root:$(id -gn) $NGINX_LIVE && sudo chmod 0640 $NGINX_LIVE" >&2
  else
    _warn_if_not_root_controlled "$NGINX_LIVE" "nginx site" "$(id -gn)" 0640
  fi
fi
# Deploys before 5.36.0 kept their rollback copy here, at the live file's
# (often world-readable) mode; nothing removes it.
if [ -e "$NGINX_LIVE.deploy-backup" ]; then
  echo "WARNING: $NGINX_LIVE.deploy-backup is a leftover rollback copy from an older" >&2
  echo "         deploy.sh and holds an old copy of NGINX_PROXY_SECRET. Remove it:" >&2
  echo "           sudo rm $NGINX_LIVE.deploy-backup" >&2
fi

# The public template can't hold this server's values, so the proxy secret,
# server_name(s) and certificate paths are carried from the live site into
# the local copy (server/nginx_bake.py; it refuses -- and nothing is
# applied -- when the live site doesn't have the template's layout).
# FIX (Phase 8 follow-up, 2026-10-02) kept: values are copied verbatim, so a
# secret containing & or \ survives byte for byte. OPS-09: the baked copy
# holds the secret and is written owner-only (0600); it used to be left at
# the default 0664 in the install dir.
_STAGE="nginx_bake"
if [ -f "$NGINX_LIVE" ]; then
  rm -f "$NGINX_REPO.tmp"
  if ! "$APP_DIR/.venv/bin/python" "$APP_DIR/server/nginx_bake.py" "$NGINX_LIVE" "$NGINX_REPO"; then
    exit 1
  fi
  echo "==> Carried this server's proxy secret, server names and certificate paths into the deployed nginx config"
fi

if [ -f "$NGINX_LIVE" ] && ! diff -q "$NGINX_REPO" "$NGINX_LIVE" > /dev/null 2>&1; then
  echo ""
  echo "==> nginx config has drifted from what's actually live -- applying repo copy"
  echo "    Repo copy (just deployed): $NGINX_REPO"
  echo "    Live copy (currently serving): $NGINX_LIVE"
  # Back up the current live file BEFORE overwriting it, so a bad new config
  # (one that fails `nginx -t`) can be rolled back immediately -- `nginx -t`
  # only validates whatever is CURRENTLY at $NGINX_LIVE (sites-available
  # files are pulled in via sites-enabled's include), so validating has to
  # happen in place, which means a failure must be reversible.
  # (A backup left by an earlier run whose rollback failed stops the deploy
  # in _preflight, before anything changes.)
  _STAGE="nginx_backup_failed"
  # OPS-09: created owner-only from the first byte (cp creates a new file
  # with the source's mode minus the umask), not chmod'ed afterwards.
  if ! (umask 077; cp "$NGINX_LIVE" "$NGINX_BACKUP"); then
    echo "ERROR: could not read $NGINX_LIVE to back it up (no sudo needed for" >&2
    echo "       this step -- if this failed, check that file's own permissions)." >&2
    exit 1
  fi
  chmod 600 "$NGINX_BACKUP"
  _STAGE="nginx_apply_denied"
  if ! sudo -n cp "$NGINX_REPO" "$NGINX_LIVE" 2>/dev/null; then
    echo "ERROR: could not apply the new nginx config -- sudoers rule doesn't" >&2
    echo "       cover 'cp $NGINX_REPO $NGINX_LIVE'. See docs/hosting.md's" >&2
    echo "       \"Hosting on a server\" setup (step 7) for the exact sudoers rule to add." >&2
    rm -f "$NGINX_BACKUP"
    exit 1
  fi
  # Rolls the backup back over the live file and re-validates it. Returns 0
  # only if the old config is back and valid (the backup is then deleted);
  # otherwise the backup stays for a human (and blocks the next deploy's
  # nginx stage, see above).
  _nginx_rollback() {
    if ! sudo -n cp "$NGINX_BACKUP" "$NGINX_LIVE" 2>/dev/null; then
      echo "CRITICAL: nginx rollback ALSO failed -- $NGINX_LIVE may now be" >&2
      echo "          broken. The previous config is in $NGINX_BACKUP. Fix manually." >&2
      _STAGE="$1_rollback_failed"
      return 1
    fi
    # FIX (third-party follow-up review, 2026-10-02): confirm the RESTORED
    # file is still a valid config, not just that the cp succeeded.
    if ! sudo -n nginx -t 2>&1; then
      echo "CRITICAL: restored nginx config is ALSO invalid -- $NGINX_LIVE may" >&2
      echo "          now be broken. The previous config is in $NGINX_BACKUP. Fix manually." >&2
      _STAGE="nginx_restored_config_invalid"
      return 1
    fi
    rm -f "$NGINX_BACKUP"
    return 0
  }
  _STAGE="nginx_validate_failed"
  if ! sudo -n nginx -t 2>&1; then
    echo "ERROR: new nginx config FAILED 'nginx -t' -- rolling back to the" >&2
    echo "       previous live config." >&2
    _nginx_rollback nginx_validate || exit 1
    exit 1
  fi
  _STAGE="nginx_reload_failed"
  if ! sudo -n systemctl reload nginx 2>/dev/null; then
    # The new config passed validation but nginx's RUNNING process never
    # picked it up -- roll the FILE back so it doesn't silently diverge from
    # what's loaded until some unrelated future reload activates it.
    echo "ERROR: nginx config passed 'nginx -t' but reload failed -- rolling" >&2
    echo "       back to the previous live config." >&2
    _nginx_rollback nginx_reload || exit 1
    exit 1
  fi
  echo "    Applied, validated, and reloaded."
  # The backup (it holds the real secret) is only needed for this run's own
  # rollback paths above.
  rm -f "$NGINX_BACKUP"
fi

_STAGE="done"
echo "==> Done. Deployed version $DEPLOY_VERSION, commit ${DEPLOY_COMMIT:-unknown}"
_DEPLOY_OK=1
