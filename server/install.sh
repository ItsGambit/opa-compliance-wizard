#!/bin/bash
# One-time installer for the upgrade layout (5.47.0). Run it ON THE SERVER, AS ROOT.
#
#   sudo server/install.sh --dry-run          # print exactly what it would do, change nothing
#   sudo server/install.sh                    # do it
#
# What it sets up (design: README "Upgrading"):
#
#   /opt/opa-compliance-wizard/            owned by root: the web application's account cannot write its own code
#     releases/<version>/                  every installed release (code + its own virtualenv), root-owned once verified
#     current -> releases/<version>        the running release; switched atomically by the updater
#     previous -> releases/<version>       what a rollback switches back to
#     updater/                             the small root-run updater (Python standard library only) + its trust list
#   /var/lib/opa-compliance-wizard/        the application's data (archive, audit log, access control, ...): the only
#                                          place the application can write (OPA_DATA_DIR)
#   /var/lib/ocw-updater/                  the unprivileged `ocw-updater` account's downloads
#   units: ocw-stage@.service (stages a release as `ocw-updater`), ocw-upgrade.path/.service (root: activates, rolls
#          back, resumes after a crash), ocw-upgrade-due.* (only while an upgrade is scheduled)
#   /usr/local/bin/ocw-updater             the operator's command
#
# Three situations, detected automatically:
#   fresh install     no layout and no running install: installs the release in this checkout AND makes the server work
#                     (5.52.0): the application account (--create-app-user), lingering, the environment file with generated
#                     secrets, the two application units (the login gate is installed but neither enabled nor started: it needs your Okta
#                     settings), the nginx site and a TLS certificate, the session key; starts the backend and checks it.
#                     Resumable: a second run after a failure repairs what is missing and never overwrites a data or
#                     settings file. Needs --server-name HOST (or --no-nginx) and a certificate choice (see below).
#   migration         an existing in-home install (the usual one, from docs/hosting.md): moves its data files, rewrites the
#                     units' WorkingDirectory / ReadWritePaths (the keyring and /run/user carve-outs are kept exactly:
#                     see the ProtectHome incident in the unit's comments), restarts, checks health and puts everything
#                     back if the new layout does not come up. The old directory is KEPT (nothing is deleted).
#   already installed re-run: repairs ownership, directories and units; touches no data and does not replace the
#                     root-owned updater code (use --refresh-updater to copy this checkout's updater files over it).
#
# Options:
#   --dry-run                  print the plan and exit; nothing is changed
#   --app-user NAME            the web application's account (default: the User= of the existing unit, else the owner of
#                              the install directory)
#   --source DIR               the checkout / unpacked release to install (default: the directory this script is in)
#   --legacy-dir DIR           the existing in-home install to migrate (default: the WorkingDirectory of its unit)
#   --wheelhouse DIR           install Python packages from DIR only (--no-index), for a server without internet access
#   --remove-legacy-sudoers    also remove the old deploy sudoers file (opa-compliance-wizard-deploy) after checking it only
#                              grants what deploy.sh used to need; moved aside, never deleted. Never done without this flag.
#   --apply-nginx              also bake and apply this release's nginx template (adds the maintenance page)
#   --refresh-updater          (re-run) replace the root-owned updater code, the units and the ocw-updater command with this
#                              checkout's, and record this checkout's version in the updater's config.json (install_sh_version):
#                              the updater refuses a release whose newest change to those files is newer than that version.
#                              Touches no data. This is the command a refused upgrade asks for ("needs_install_sh").
#   --regenerate-second-sites  regenerate the nginx site of every additional login gate (opa-auth-gate-*) from the live main site
#                              with this release's deny rules (every denied route), with `nginx -t` first and a restore on failure
#   --yes                      do not ask for confirmation (a fresh install must then name its certificate choice)
#
# Fresh install (5.52.0):
#   --create-app-user          create the application account if it does not exist (default name ocw; a regular account with
#                              its home under the data directory, shell nologin, lingering on); refuses root
#   --server-name HOST         the public DNS name or IP address (nginx server_name, DASHBOARD_ORIGIN, certificate name)
#   --no-nginx                 do not set up nginx (another proxy or a tunnel fronts the application); the site template path
#                              is printed
#   --cert FILE --key FILE     use this TLS certificate and key (copied to /etc/nginx/ssl, mode 0600)
#   --self-signed              make a temporary self-signed certificate (825 days; browsers warn until a trusted one is installed)
#   --backend-port N           the application's port on 127.0.0.1 (default 8766)
#   --release-info FILE        the verification result of get-ocw.sh: recorded as the release's provenance
#   --revocation FILE          a verified key revocation to apply to root's trust list and hand to the application (repeatable)
#   --release-base-url URL     the https mirror the updater should use (written to the updater's settings)
#   --revocation-url URL       an owner-controlled https source for key revocations (written to the settings files)
#   --disable-default-site     also remove the distribution's `default` nginx site link (get-ocw.sh passes it when it installed nginx
#                              in this very run, so only this application's site answers; an nginx that was already there is left alone)
#   --plan-shown               (get-ocw.sh) the plan was just printed by a dry run: do not print it again before doing it
#   --log FILE                 append everything this prints to FILE (created 0600)
#   --uninstall --keep-data    remove the software (units, command, /opt tree, updater, its account, the nginx site) after you type
#                              UNINSTALL; the data directory, environment file, session key, TLS files, application account and
#                              packages stay. Removing the data is a manual step (docs/hosting.md).
#
# Everything below that is a path can be redirected for testing (OCW_OPT_DIR, OCW_DATA_DIR, OCW_UNIT_DIR, OCW_BIN_DIR,
# OCW_ENV_FILE, OCW_SUDOERS_DIR, OCW_ARTIFACTS_DIR, OCW_NGINX_SITES_DIR, OCW_NGINX_ENABLED_DIR, OCW_NGINX_SSL_DIR,
# OCW_SESSION_KEY_FILE); a test run also sets OCW_INSTALL_TEST=1 to skip root-only steps.
#
# Exit status: 0 done; 2 refused, nothing was changed; 3 failed and everything was put back; 4 failed, an operator must act.
set -euo pipefail
# The release tree, the virtualenv and every directory this makes must be readable by the application account whatever umask the
# caller has (get-ocw.sh runs with 077): 022 here, and every secret-bearing write below sets its own mode explicitly (0600/0640
# from the first byte, or inside a `umask 077` subshell).
umask 022

# The release whose install.sh an EXISTING install needs (tools/release.py reads this line into the manifest's
# install_sh_min_version; the updater asks for `install.sh --refresh-updater` only while the version it last recorded is older).
# 5.50.0: the second-gate deny rules and --regenerate-second-sites, the newest change to what an existing install runs.
# 5.52.0 added the fresh-install path, --uninstall and --log, which existing installs do not need. Bump it when an existing
# install needs the new install.sh (docs/releasing.md).
OCW_INSTALL_SH_REQUIRED_SINCE="5.50.0"
: "$OCW_INSTALL_SH_REQUIRED_SINCE"

OPT_DIR="${OCW_OPT_DIR:-/opt/opa-compliance-wizard}"
DATA_DIR="${OCW_DATA_DIR:-/var/lib/opa-compliance-wizard}"
UNIT_DIR="${OCW_UNIT_DIR:-/etc/systemd/system}"
BIN_DIR="${OCW_BIN_DIR:-/usr/local/bin}"
ENV_FILE="${OCW_ENV_FILE:-/etc/opa-compliance-wizard.env}"
NGINX_SITES_DIR="${OCW_NGINX_SITES_DIR:-/etc/nginx/sites-available}"
SUDOERS_DIR="${OCW_SUDOERS_DIR:-/etc/sudoers.d}"
ARTIFACTS_DIR="${OCW_ARTIFACTS_DIR:-/var/lib/ocw-updater/artifacts}"
NGINX_ENABLED_DIR="${OCW_NGINX_ENABLED_DIR:-/etc/nginx/sites-enabled}"
NGINX_SSL_DIR="${OCW_NGINX_SSL_DIR:-/etc/nginx/ssl}"
SESSION_KEY_FILE="${OCW_SESSION_KEY_FILE:-/etc/opa-secrets-wizard-session.key}"
UPDATER_ENV="${OCW_UPDATER_ENV:-/etc/ocw-updater.env}"
UPDATER_USER="ocw-updater"
TESTING="${OCW_INSTALL_TEST:-}"

DRY_RUN=""
ASSUME_YES=""
APP_USER=""
SOURCE_DIR=""
LEGACY_DIR=""
WHEELHOUSE=""
REMOVE_SUDOERS=""
APPLY_NGINX=""
REFRESH_UPDATER=""
REGEN_SECOND=""
CREATE_APP_USER=""
SERVER_NAME=""
BACKEND_PORT_ARG=""
NO_NGINX=""
CERT_FILE=""
KEY_FILE=""
SELF_SIGNED=""
RELEASE_INFO=""
REVOCATIONS=()
LOG_FILE=""
UNINSTALL=""
KEEP_DATA=""
DISABLE_DEFAULT_SITE=""
RELEASE_BASE_URL_ARG=""
REVOCATION_URL_ARG=""
ORIG_ARGS=("$@")

usage() { sed -n '2,/^set -euo pipefail/{/^set -euo pipefail/!p;}' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }
# 2 = refused before anything was changed; the "doing it" part raises it to 4 (an operator must act); a rolled-back
# migration exits 3
DIE_CODE=2
die() { echo "ERROR: $*" >&2; exit "$DIE_CODE"; }
PLAN_QUIET=""   # --plan-shown: the plan was printed by the dry run just before; the real run does not print it a second time
note() { [ -n "$PLAN_QUIET" ] || echo "$*"; }
plan() { [ -n "$PLAN_QUIET" ] || echo "  - $*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --yes | -y) ASSUME_YES=1; shift ;;
    --app-user) [ $# -ge 2 ] || die "--app-user needs a name"; APP_USER="$2"; shift 2 ;;
    --source) [ $# -ge 2 ] || die "--source needs a directory"; SOURCE_DIR="$2"; shift 2 ;;
    --legacy-dir) [ $# -ge 2 ] || die "--legacy-dir needs a directory"; LEGACY_DIR="$2"; shift 2 ;;
    --wheelhouse) [ $# -ge 2 ] || die "--wheelhouse needs a directory"; WHEELHOUSE="$2"; shift 2 ;;
    --remove-legacy-sudoers) REMOVE_SUDOERS=1; shift ;;
    --apply-nginx) APPLY_NGINX=1; shift ;;
    --refresh-updater) REFRESH_UPDATER=1; shift ;;
    --regenerate-second-sites) REGEN_SECOND=1; shift ;;
    --create-app-user) CREATE_APP_USER=1; shift ;;
    --server-name) [ $# -ge 2 ] || die "--server-name needs a name or address"; SERVER_NAME="$2"; shift 2 ;;
    --backend-port) [ $# -ge 2 ] || die "--backend-port needs a number"; BACKEND_PORT_ARG="$2"; shift 2 ;;
    --no-nginx) NO_NGINX=1; shift ;;
    --cert) [ $# -ge 2 ] || die "--cert needs a file"; CERT_FILE="$2"; shift 2 ;;
    --key) [ $# -ge 2 ] || die "--key needs a file"; KEY_FILE="$2"; shift 2 ;;
    --self-signed) SELF_SIGNED=1; shift ;;
    --release-info) [ $# -ge 2 ] || die "--release-info needs a file"; RELEASE_INFO="$2"; shift 2 ;;
    --revocation) [ $# -ge 2 ] || die "--revocation needs a file"; REVOCATIONS+=("$2"); shift 2 ;;
    --release-base-url) [ $# -ge 2 ] || die "--release-base-url needs an https address"; RELEASE_BASE_URL_ARG="$2"; shift 2 ;;
    --revocation-url) [ $# -ge 2 ] || die "--revocation-url needs an https address"; REVOCATION_URL_ARG="$2"; shift 2 ;;
    --log) [ $# -ge 2 ] || die "--log needs a file"; LOG_FILE="$2"; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    --keep-data) KEEP_DATA=1; shift ;;
    --plan-shown) PLAN_QUIET=1; shift ;;
    --disable-default-site) DISABLE_DEFAULT_SITE=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

# --log: run this script again with everything it prints also appended to the log (created 0600), and pass its exit status on
if [ -n "$LOG_FILE" ] && [ -z "${OCW_INSTALL_LOGGING:-}" ]; then
  _ld="$(dirname -- "$LOG_FILE")"
  if [ ! -d "$_ld" ]; then { mkdir -p "$_ld" && chmod 0700 "$_ld"; } || die "cannot create the log directory $_ld"; fi
  ( umask 077; : >>"$LOG_FILE" ) || die "cannot write the log file $LOG_FILE"
  chmod 0600 "$LOG_FILE"
  export OCW_INSTALL_LOGGING=1
  set +e
  bash "${BASH_SOURCE[0]}" "${ORIG_ARGS[@]}" 2>&1 | tee -a "$LOG_FILE"
  _rc="${PIPESTATUS[0]}"
  exit "$_rc"
fi

for _p in "$OPT_DIR" "$DATA_DIR" "$UNIT_DIR" "$BIN_DIR" "$ENV_FILE" "$SUDOERS_DIR" "$ARTIFACTS_DIR" "$NGINX_SITES_DIR" "$NGINX_ENABLED_DIR" "$NGINX_SSL_DIR" "$SESSION_KEY_FILE"; do
  case "$_p" in
    /*) ;;
    *) die "paths must be absolute (got '$_p')" ;;
  esac
  case "$_p" in
    *[[:space:]]* | *\|* | *\&* | *\\*) die "paths must not contain spaces or | & \\ (got '$_p')" ;;
  esac
done

if [ -z "$TESTING" ] && [ "$(id -u)" -ne 0 ]; then
  die "run as root (sudo server/install.sh), or add --dry-run to see the plan"
fi
for _cmd in systemctl python3 tar sed awk cmp seq find date grep wc cp mv rm chmod mkdir id diff; do
  command -v "$_cmd" >/dev/null 2>&1 || die "required command not found: $_cmd"
done
[ -n "$TESTING" ] || command -v runuser >/dev/null 2>&1 || die "required command not found: runuser (util-linux)"
PY3="$(command -v python3)"

# prompts go to the terminal, never to stdin (which may be a pipe); a test run can supply the answers in a file (OCW_TTY)
TTY_OPEN=""
tty_line() { # tty_line <prompt>: one line from the terminal in TTY_ANSWER; refuses when there is no terminal
  TTY_ANSWER=""
  local _in="/dev/tty"
  if [ -n "$TESTING" ] && [ -n "${OCW_TTY:-}" ]; then _in="$OCW_TTY"; fi
  if [ -z "$TTY_OPEN" ]; then
    if { exec 9<"$_in"; } 2>/dev/null; then TTY_OPEN=1; else die "no terminal to ask you on; nothing was changed. Add --yes (and the options it needs) to run without questions."; fi
  fi
  if [ -n "$TESTING" ] && [ -n "${OCW_TTY:-}" ]; then printf '%s' "$1" >&2; elif ! { printf '%s' "$1" >/dev/tty; } 2>/dev/null; then printf '%s' "$1" >&2; fi
  IFS= read -r TTY_ANSWER <&9 || TTY_ANSWER=""
}

# --- uninstall (--uninstall --keep-data) -------------------------------------------------------------------------
# Removes the software and keeps every data file. It reads only the layout's own paths and never touches DATA_DIR.
check_removable() { # check_removable <dir>: never "/", never a shallow or system path, never something that holds the data directory
  local _d="$1"
  case "$_d" in /?*/?*) ;; *) die "refusing to remove '$_d'" ;; esac
  case "${_d%/}" in
    /etc | /usr | /var | /var/lib | /var/log | /var/tmp | /opt | /home | /root | /bin | /sbin | /lib | /lib64 | /boot | /srv | /tmp | /run | /mnt | /media | /dev | /proc | /sys)
      die "refusing to remove '$_d'" ;;
  esac
  case "${_d%/}" in
    /usr/?* | /etc/?* | /home/?* | /var/?* | /root/?* | /boot/?* | /srv/?* | /run/?* | /lib/?* | /mnt/?* | /media/?*)
      case "${_d%/}" in
        /usr/?*/?* | /etc/?*/?* | /home/?*/?* | /var/?*/?* | /root/?*/?* | /srv/?*/?* | /mnt/?*/?* | /media/?*/?*) ;;   # two levels below a system directory: the layout's own paths and tests
        *) die "refusing to remove '$_d': it is a system directory, not a directory this installer made" ;;
      esac ;;
  esac
  case "$_d" in */../* | */.. | */./* | */.) die "refusing to remove '$_d'" ;; esac
  case "$DATA_DIR/" in "$_d"/*) die "refusing to remove $_d: it holds the data directory $DATA_DIR (use different directories, or move the data first)" ;; esac
}
looks_like_our_tree() { # the opt directory must be one this installer made: releases/ and updater/, and a `current` link into
  # releases/ (or the fresh-install marker), owned by root
  [ -d "$OPT_DIR/releases" ] && [ -d "$OPT_DIR/updater" ] || return 1
  if [ -L "$OPT_DIR/current" ]; then
    case "$(readlink "$OPT_DIR/current")" in releases/* | "$OPT_DIR"/releases/*) ;; *) return 1 ;; esac
  elif [ ! -e "$OPT_DIR/.fresh-install-incomplete" ]; then
    return 1
  fi
  [ -n "$TESTING" ] || [ "$(stat -c %u "$OPT_DIR" 2>/dev/null)" = "0" ]
}
safe_remove_tree() { # safe_remove_tree <dir>
  local _d="$1"
  check_removable "$_d"
  if [ -L "$_d" ]; then rm -f -- "$_d"; elif [ -e "$_d" ]; then rm -rf -- "$_d"; fi
}

uninstall_keep_data() {
  [ -n "$KEEP_DATA" ] || die "--uninstall needs --keep-data: this release removes the software only; removing the data is a manual step (docs/hosting.md, Uninstalling)"
  local _plain_units="ocw-upgrade.path ocw-upgrade.service ocw-upgrade-due.timer ocw-upgrade-due.service ocw-stage@.service"
  local _ours="" _u _f _wd _gates _site _enabled _kept_site="" _upd_home _app_acct _removed_link=""
  for _u in opa-compliance-wizard opa-secrets-wizard opa-auth-gate; do
    _f="$UNIT_DIR/$_u.service"
    [ -f "$_f" ] || continue
    _wd="$(sed -n -e 's/^[[:space:]]*WorkingDirectory=[[:space:]]*//p' "$_f" | head -n 1)"
    case "$_wd" in
      "$OPT_DIR" | "$OPT_DIR"/*) _ours="$_ours $_u" ;;
      *) note "NOTE: $_f runs the application from '$_wd', not from $OPT_DIR: it is not removed" ;;
    esac
  done
  _gates="$(systemctl list-unit-files 'opa-auth-gate-*.service' --no-legend 2>/dev/null | awk '{print $1}' | sed -e 's/\.service$//' -e 's/^opa-auth-gate-//' | tr '\n' ' ' || true)"
  _site="$NGINX_SITES_DIR/opa-secrets-wizard"
  [ ! -f "$OPT_DIR/updater/config.json" ] || _site="$("$PY3" -I -c 'import json, sys; print(json.load(open(sys.argv[1])).get("nginx_site") or "")' "$OPT_DIR/updater/config.json" 2>/dev/null || true)"
  [ -n "$_site" ] || _site="$NGINX_SITES_DIR/opa-secrets-wizard"
  _enabled="$NGINX_ENABLED_DIR/$(basename -- "$_site")"
  _app_acct=""
  [ ! -f "$OPT_DIR/updater/config.json" ] || _app_acct="$("$PY3" -I -c 'import json, sys; print(json.load(open(sys.argv[1])).get("app_user") or "")' "$OPT_DIR/updater/config.json" 2>/dev/null || true)"
  [ -n "$_app_acct" ] || _app_acct="the application account"
  note "OPA Compliance Wizard: uninstall, keeping the data"
  note ""
  note "Will remove:"
  plan "stop and disable the services:${_ours:- (no unit of the application found)} $_plain_units (those that exist)"
  plan "the unit files in $UNIT_DIR for them"
  plan "$BIN_DIR/ocw-updater and $UPDATER_ENV"
  plan "$OPT_DIR (the installed releases, the updater, staging, the maintenance page, install backups)"
  _upd_home="$ARTIFACTS_DIR"
  [ "$(basename -- "$(dirname -- "$ARTIFACTS_DIR")")" != "$UPDATER_USER" ] || _upd_home="$(dirname -- "$ARTIFACTS_DIR")"
  check_removable "$OPT_DIR"      # refused here, before anything is stopped or removed
  if [ -e "$OPT_DIR" ] && ! looks_like_our_tree; then
    die "$OPT_DIR does not look like an install made by this installer (it needs releases/ and updater/, a 'current' link into releases/, and root as owner); nothing was removed"
  fi
  check_removable "$_upd_home"
  plan "$_upd_home (the downloads of the staging account) and the account $UPDATER_USER"
  if [ -n "$_gates" ]; then
    plan "NOT the nginx site $_site: additional login gates ($_gates) reuse its rate-limit zone; remove them first (setup-second-gate.sh)"
    _kept_site=1
  elif [ -e "$_site" ] && ! grep -q 'nginx_proxy_secret' "$_site" 2>/dev/null; then
    plan "NOT the nginx site $_site: it is not this application's site (no proxy secret in it)"
    _kept_site=1
  elif [ -e "$_site" ] || [ -L "$_enabled" ]; then
    plan "the nginx site $_site and its link $_enabled (nginx is reloaded only if 'nginx -t' passes)"
  fi
  note ""
  note "Will keep:"
  plan "$DATA_DIR (the archive, audit log, access control, environments, upgrade backups, and the application account's home with its keyring)"
  plan "$ENV_FILE, $SESSION_KEY_FILE, the TLS files in $NGINX_SSL_DIR, the application account, the distribution packages"
  plan "every *.migrated-* file and the directory of a legacy install (they are not ours)"
  [ -z "$_gates" ] || plan "the additional login gates and everything of theirs"
  note ""
  if [ -n "$DRY_RUN" ]; then note "Dry run: nothing was changed."; return 0; fi
  if [ -z "$ASSUME_YES" ]; then
    tty_line "Type UNINSTALL to remove the software and keep the data: "
    [ "$TTY_ANSWER" = "UNINSTALL" ] || die "not confirmed; nothing was changed"
  fi
  DIE_CODE=4
  note "==> Stopping and removing the services"
  for _u in $_ours ocw-upgrade-due.timer ocw-upgrade.path ocw-upgrade.service ocw-upgrade-due.service; do
    systemctl stop "$_u" >/dev/null 2>&1 || true
    systemctl disable "$_u" >/dev/null 2>&1 || true
  done
  for _u in $_ours; do rm -f -- "$UNIT_DIR/$_u.service"; done
  for _u in $_plain_units; do rm -f -- "$UNIT_DIR/$_u"; done
  systemctl daemon-reload >/dev/null 2>&1 || true
  rm -f -- "$BIN_DIR/ocw-updater" "$UPDATER_ENV"
  if [ -z "$_kept_site" ] && { [ -e "$_site" ] || [ -L "$_enabled" ]; }; then
    note "==> nginx"
    local _keep="$_site.uninstall-keep.$$" _had_link="" _enabled_ours=1
    [ ! -f "$_site" ] || cp -p "$_site" "$_keep"
    if [ -L "$_enabled" ]; then
      _had_link="$(readlink "$_enabled")"
      if [ "$_had_link" != "$_site" ]; then note "NOTE: $_enabled points to $_had_link, not to this application's site: it was left in place"; _enabled_ours=""; fi
    fi
    if [ -n "$_enabled_ours" ]; then rm -f -- "$_enabled"; _removed_link=1; fi
    rm -f -- "$_site"
    if ! command -v nginx >/dev/null 2>&1 || nginx -t >/dev/null 2>&1; then
      systemctl reload nginx >/dev/null 2>&1 || note "NOTE: nginx did not reload; run 'sudo systemctl reload nginx' yourself"
      rm -f -- "$_keep"
      if [ -n "$_removed_link" ]; then note "    removed $_site and $_enabled"; else note "    removed $_site (the link $_enabled was kept: it points elsewhere)"; fi
    else
      [ ! -f "$_keep" ] || mv -- "$_keep" "$_site"
      [ -z "$_had_link" ] || [ -z "$_enabled_ours" ] || ln -sfn "$_had_link" "$_enabled"
      note "WARNING: 'nginx -t' failed without the site, so it was put back. Fix nginx's configuration and remove the site by hand."
    fi
  fi
  note "==> Removing the installed software"
  safe_remove_tree "$OPT_DIR"
  safe_remove_tree "$_upd_home"
  if id "$UPDATER_USER" >/dev/null 2>&1 && command -v userdel >/dev/null 2>&1; then
    userdel "$UPDATER_USER" >/dev/null 2>&1 || note "NOTE: could not remove the account $UPDATER_USER; remove it with 'userdel $UPDATER_USER'"
  fi
  note ""
  note "Done. The software is removed. Kept: $DATA_DIR (data), $ENV_FILE, $SESSION_KEY_FILE, $NGINX_SSL_DIR, the account that ran the application, the packages."
  note "Lingering stays on for $_app_acct (its account is kept); 'loginctl disable-linger <that account>' ends it when you remove the account."
  note "Installing again with get-ocw.sh finds the data and the settings and uses them. Removing the data too is a manual step (docs/hosting.md, Uninstalling):"
  note "it deletes the only copy of the archive and audit log, so be sure you have a backup."
}

if [ -n "$UNINSTALL" ]; then
  uninstall_keep_data
  exit 0
fi
[ -z "$KEEP_DATA" ] || die "--keep-data only goes with --uninstall"

_here="$(cd "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
SOURCE_DIR="$(cd "${SOURCE_DIR:-$_here}" && pwd -P)"
[ -f "$SOURCE_DIR/create_secret_folders.py" ] || die "$SOURCE_DIR is not an OPA Compliance Wizard checkout (no create_secret_folders.py)"
[ -d "$SOURCE_DIR/server/updater/root" ] || die "$SOURCE_DIR has no server/updater/root: install from a 5.47.0 or newer checkout"
[ -f "$SOURCE_DIR/frontend/dist/index.html" ] || die "$SOURCE_DIR/frontend/dist/index.html is missing: install from a signed release, or build the frontend first (npm ci && npx vite build in frontend/)"
[ -f "$SOURCE_DIR/requirements.lock" ] || die "$SOURCE_DIR/requirements.lock is missing"
VERSION="$(grep -m1 '^SCRIPT_VERSION = ' "$SOURCE_DIR/create_secret_folders.py" | sed -E 's/.*"([^"]+)".*/\1/')"
case "$VERSION" in
  [0-9]*.[0-9]*.[0-9]*) ;;
  *) die "cannot read SCRIPT_VERSION from $SOURCE_DIR/create_secret_folders.py" ;;
esac
case "$PY3" in
  /usr/bin/* | /usr/local/bin/* | /bin/* | /opt/*) ;;
  *) [ -n "$TESTING" ] || die "python3 resolves to $PY3, which is not a system location; root runs the updater with it" ;;
esac
"$PY3" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' || die "Python 3.9 or newer is required"

# --- discover the situation (read-only) -------------------------------------------------------------------

SERVICE_NAME=""
for _s in opa-secrets-wizard opa-compliance-wizard; do
  if systemctl cat "$_s" >/dev/null 2>&1; then SERVICE_NAME="$_s"; break; fi
done
unit_prop() { systemctl show -p "$2" --value "$1" 2>/dev/null || true; }

# rewrite_unit <unit> <input> <output>: the migrated copy of a unit file. Every edit tolerates leading whitespace (systemd
# does, and units written by hand are often indented) and keeps the line's own indentation. A key this has to find or add
# next to is REQUIRED: if it is missing the function fails with the reason instead of quietly skipping the edit, so a unit is
# never half migrated (it runs before anything is changed, in the dry run too).
rewrite_unit() {
  local _u="$1" _in="$2" _out="$3" _esc
  _esc="$(printf '%s' "$LEGACY_DIR" | sed -e 's/[][\.*^$|&]/\\&/g')"
  if ! grep -Eq '^[[:space:]]*WorkingDirectory=' "$_in"; then
    echo "ERROR: $_u: no WorkingDirectory= line in $_in, so the migrated unit could not be given OPA_DATA_DIR; nothing was changed. Add the line by hand (see docs/hosting.md) and re-run." >&2
    return 1
  fi
  if [ "$_u" = "$SERVICE_NAME" ] && ! grep -Eq '^[[:space:]]*ProtectSystem=' "$_in" && ! grep -Eq '^[[:space:]]*ProtectHome=' "$_in"; then
    echo "ERROR: $_u: neither ProtectSystem= nor ProtectHome= in $_in, so ProtectSystem=strict could not be placed; nothing was changed. Add ProtectSystem=strict by hand and re-run." >&2
    return 1
  fi
  sed -e "s|^\([[:space:]]*\)ReadWritePaths=${_esc}[[:space:]]*\$|\1ReadWritePaths=$DATA_DIR|" \
      -e "s|$_esc|$OPT_DIR/current|g" "$_in" > "$_out" || return 1
  if ! grep -Eq '^[[:space:]]*Environment=OPA_DATA_DIR=' "$_out"; then
    awk -v d="$DATA_DIR" '!done && /^[[:space:]]*WorkingDirectory=/ { print; match($0, /^[[:space:]]*/); ind = substr($0, 1, RLENGTH); print ind "Environment=OPA_DATA_DIR=" d; print ind "Environment=PYTHONDONTWRITEBYTECODE=1"; done=1; next } { print }' \
      "$_out" > "$_out.2" && mv "$_out.2" "$_out"
  fi
  if [ "$_u" = "$SERVICE_NAME" ] && ! grep -Eq '^[[:space:]]*ProtectSystem=' "$_out"; then
    awk '!done && /^[[:space:]]*ProtectHome=/ { match($0, /^[[:space:]]*/); print substr($0, 1, RLENGTH) "ProtectSystem=strict"; done=1 } { print }' "$_out" > "$_out.2" && mv "$_out.2" "$_out"
  fi
  # what was asked for must now be there
  if ! grep -Eq "^[[:space:]]*Environment=OPA_DATA_DIR=$DATA_DIR\$" "$_out" || { [ "$_u" = "$SERVICE_NAME" ] && ! grep -Eq '^[[:space:]]*ProtectSystem=' "$_out"; }; then
    echo "ERROR: $_u: the migrated copy of $_in does not have Environment=OPA_DATA_DIR=$DATA_DIR (and ProtectSystem= for the main service); nothing was changed." >&2
    return 1
  fi
}

# the additional login gates (setup-second-gate.sh): units opa-auth-gate-<name>, nginx site <sites dir>/opa-<name>
SECOND_GATES="$(systemctl list-unit-files 'opa-auth-gate-*.service' --no-legend 2>/dev/null | awk '{print $1}' | sed -e 's/\.service$//' -e 's/^opa-auth-gate-//' | tr '\n' ' ' || true)"
# every route an additional gate's site must answer 403 on, read from the one list the generator and the check use
DENIED_PREFIXES="$("$PY3" -I -c 'import sys; sys.path.insert(0, sys.argv[1]); import nginx_second_site as n; print(", ".join(n.SECOND_SITE_DENIED_PREFIXES))' "$SOURCE_DIR/server" 2>/dev/null || true)"
[ -n "$DENIED_PREFIXES" ] || DENIED_PREFIXES="/api/access_control, /api/shared_permissions, /api/archives, /api/upgrade, /api/overview"
second_site_status() { # second_site_status <name>: prints ok | missing-deny | no-site | unreadable
  local _site="$NGINX_SITES_DIR/opa-$1" _rc=0
  [ -f "$_site" ] || { echo "no-site"; return 0; }
  "$PY3" -I "$SOURCE_DIR/server/nginx_second_site.py" --check "$_site" >/dev/null 2>&1 || _rc=$?
  case "$_rc" in 0) echo "ok" ;; 1) echo "missing-deny" ;; *) echo "unreadable" ;; esac
}

LAYOUT_PRESENT=""
[ -L "$OPT_DIR/current" ] && LAYOUT_PRESENT=1

if [ -n "$SERVICE_NAME" ]; then
  _unit_user="$(unit_prop "$SERVICE_NAME" User)"
  _unit_wd="$(unit_prop "$SERVICE_NAME" WorkingDirectory)"
  # the unit FILE is what counts (a loaded copy can be stale until the next daemon-reload)
  _frag0="$(unit_prop "$SERVICE_NAME" FragmentPath)"
  if [ -f "$_frag0" ]; then
    _wd_file="$(sed -n -e 's/^[[:space:]]*WorkingDirectory=[[:space:]]*//p' "$_frag0" | head -n 1)"
    [ -z "$_wd_file" ] || _unit_wd="$_wd_file"
  fi
  [ -n "$APP_USER" ] || APP_USER="$_unit_user"
  if [ -z "$LEGACY_DIR" ] && [ -n "$_unit_wd" ] && [ "$_unit_wd" != "$OPT_DIR/current" ]; then
    case "$_unit_wd" in
      "$OPT_DIR"/*) ;;
      *) [ -f "$_unit_wd/create_secret_folders.py" ] && LEGACY_DIR="$_unit_wd" ;;
    esac
  fi
fi
RESUME=""
[ ! -e "$OPT_DIR/.fresh-install-incomplete" ] || RESUME=1   # an earlier fresh install did not finish: run it to the end
if [ -z "$APP_USER" ] && [ -n "$CREATE_APP_USER" ]; then APP_USER="ocw"; fi
[ -n "$APP_USER" ] || APP_USER="$(stat -c %U "$SOURCE_DIR" 2>/dev/null || stat -f %Su "$SOURCE_DIR")"
[ "$APP_USER" != "root" ] || die "the web application must not run as root; use its own account (--app-user)"
APP_WILL_CREATE=""
if id "$APP_USER" >/dev/null 2>&1; then
  APP_GROUP="$(id -gn "$APP_USER")"
else
  [ -n "$CREATE_APP_USER" ] || die "the application account '$APP_USER' does not exist (--app-user, or --create-app-user to create it)"
  case "$APP_USER" in
    [a-z_]*) ;;
    *) die "'$APP_USER' is not a usable account name (lower-case letters, digits, - and _, starting with a letter)" ;;
  esac
  case "$APP_USER" in *[!a-z0-9_-]*) die "'$APP_USER' is not a usable account name (lower-case letters, digits, - and _, starting with a letter)" ;; esac
  [ "${#APP_USER}" -le 32 ] || die "'$APP_USER' is too long for an account name (32 characters at most)"
  APP_WILL_CREATE=1
  APP_GROUP="$APP_USER"
fi
MODE="fresh"
if [ -n "$LAYOUT_PRESENT" ] && [ -n "$RESUME" ]; then
  MODE="fresh"
elif [ -z "$LEGACY_DIR" ] && [ -n "$LAYOUT_PRESENT" ]; then
  MODE="reinstall"
elif [ -n "$LEGACY_DIR" ]; then   # a unit that still runs from an in-home directory means the migration has not (successfully) happened
  MODE="migrate"
  [ -x "$LEGACY_DIR/.venv/bin/python" ] || note "NOTE: $LEGACY_DIR has no .venv/bin/python; migrating anyway (the new release gets its own)."
fi

for _p in "$LEGACY_DIR" "$SOURCE_DIR"; do
  case "$_p" in
    *[[:space:]]* | *\|* | *\&* | *\\*) die "paths must not contain spaces or | & \\ (got '$_p')" ;;
  esac
done
if [ -n "$APP_WILL_CREATE" ] && [ "$MODE" != "fresh" ]; then
  die "--create-app-user is only for a fresh install; the account of an existing install is the User= of its unit (--app-user)"
fi

# the settings deploy.sh read from <install dir>/.deploy.conf (parsed, never sourced)
CONF_NGINX_SITE="/etc/nginx/sites-available/opa-secrets-wizard"
CONF_PORT="8766"
CONF_RELEASE_BASE=""
CONF_REVOCATION_BASE=""
if [ -n "$LEGACY_DIR" ] && [ -f "$LEGACY_DIR/.deploy.conf" ]; then
  while IFS= read -r _line || [ -n "$_line" ]; do
    case "$_line" in "" | "#"*) continue ;; esac
    _k="${_line%%=*}"
    _v="${_line#*=}"
    case "$_v" in \"*\") _v="${_v#\"}"; _v="${_v%\"}" ;; \'*\') _v="${_v#\'}"; _v="${_v%\'}" ;; esac
    case "$_k" in
      OPA_NGINX_SITE) CONF_NGINX_SITE="$_v" ;;
      OPA_BACKEND_PORT) CONF_PORT="$_v" ;;
      OPA_RELEASE_BASE_URL) CONF_RELEASE_BASE="$_v" ;;
      OPA_REVOCATION_URL_BASE) CONF_REVOCATION_BASE="$_v" ;;
      *) ;;
    esac
  done < "$LEGACY_DIR/.deploy.conf"
fi
case "$CONF_PORT" in "" | *[!0-9]*) die "OPA_BACKEND_PORT in .deploy.conf is not a number" ;; esac
# a re-run on an installed layout (no legacy directory any more): the site and port the install recorded
if [ -z "$LEGACY_DIR" ] && [ "$MODE" = "reinstall" ] && [ -f "$OPT_DIR/updater/config.json" ]; then
  _recorded="$("$PY3" -I -c 'import json, re, sys
c = json.load(open(sys.argv[1]))
site, port = c.get("nginx_site"), c.get("backend_port")
if isinstance(site, str) and re.fullmatch(r"/[A-Za-z0-9._/-]+", site) and isinstance(port, int) and 0 < port < 65536:
    print(site, port)' "$OPT_DIR/updater/config.json" 2>/dev/null || true)"
  if [ -n "$_recorded" ]; then
    CONF_NGINX_SITE="${_recorded% *}"
    CONF_PORT="${_recorded##* }"
  fi
fi
URL_RE='^(https://|http://127\.0\.0\.1|http://localhost)[A-Za-z0-9._:/%~+-]+$'
for _u in "$RELEASE_BASE_URL_ARG" "$REVOCATION_URL_ARG"; do
  [ -z "$_u" ] || [[ "$_u" =~ $URL_RE ]] || die "'$_u' is not a plain https address (no user name or password in it, no query, no spaces)"
done
[ -z "$RELEASE_BASE_URL_ARG" ] || CONF_RELEASE_BASE="$RELEASE_BASE_URL_ARG"
if [ -n "$BACKEND_PORT_ARG" ] && [ "$MODE" != "fresh" ]; then note "NOTE: --backend-port is ignored: an existing install keeps its port ($CONF_PORT)"; fi
if [ "$MODE" = "fresh" ]; then
  if [ -n "$BACKEND_PORT_ARG" ]; then
    case "$BACKEND_PORT_ARG" in "" | *[!0-9]*) die "--backend-port must be a number between 1024 and 65535" ;; esac
    { [ "$BACKEND_PORT_ARG" -ge 1024 ] && [ "$BACKEND_PORT_ARG" -le 65535 ]; } || die "--backend-port must be between 1024 and 65535"
    case "$BACKEND_PORT_ARG" in 8767 | 8768) die "--backend-port $BACKEND_PORT_ARG is used by the login gate or the host-status helper" ;; esac
    CONF_PORT="$BACKEND_PORT_ARG"
  fi
  CONF_NGINX_SITE="$NGINX_SITES_DIR/opa-secrets-wizard"
fi

# --- fresh install: the choices (validated before the plan, so a dry run catches every bad one) ---------------------------

HELPERS="$SOURCE_DIR/server/install_helpers.py"
SERVER_KIND=""
if [ "$MODE" = "fresh" ]; then
  for _f in server/opa-compliance-wizard.service server/opa-auth-gate.service server/nginx-opa-secrets-wizard.conf server/install_helpers.py server/start-headless.sh; do
    [ -f "$SOURCE_DIR/$_f" ] || die "$SOURCE_DIR/$_f is missing: a fresh install needs a 5.52.0 or newer release"
  done
  [ -z "$NO_NGINX" ] || [ -z "$SELF_SIGNED$CERT_FILE$KEY_FILE" ] || die "--no-nginx and a certificate option (--cert/--key/--self-signed) are alternatives"
  [ -z "$CERT_FILE$KEY_FILE" ] || { [ -n "$CERT_FILE" ] && [ -n "$KEY_FILE" ]; } || die "--cert and --key go together"
  [ -z "$SELF_SIGNED" ] || [ -z "$CERT_FILE" ] || die "--self-signed and --cert/--key are alternatives"
  if [ -n "$CERT_FILE" ]; then
    [ -f "$CERT_FILE" ] && [ -r "$CERT_FILE" ] || die "the certificate file '$CERT_FILE' does not exist or cannot be read"
    [ -f "$KEY_FILE" ] && [ -r "$KEY_FILE" ] || die "the key file '$KEY_FILE' does not exist or cannot be read"
    "$PY3" -I "$HELPERS" check-cert --cert "$CERT_FILE" --key "$KEY_FILE" || exit "$DIE_CODE"
  fi
  if [ -z "$SERVER_NAME" ] && [ -z "$NO_NGINX" ]; then
    if [ -n "$ASSUME_YES" ]; then die "a fresh install needs --server-name HOST (the public DNS name or IP address), or --no-nginx"; fi
    if [ -z "$DRY_RUN" ]; then
      tty_line "Public name or IP address of this server (for the web address and the certificate): "
      SERVER_NAME="$TTY_ANSWER"
      [ -n "$SERVER_NAME" ] || die "no server name given; nothing was changed"
    fi
  fi
  if [ -n "$SERVER_NAME" ]; then
    SERVER_KIND="$("$PY3" -I "$HELPERS" validate-server-name "--name=$SERVER_NAME")" || exit "$DIE_CODE"
  fi
  if [ -z "$NO_NGINX" ] && [ -z "$SELF_SIGNED$CERT_FILE" ]; then
    if [ -n "$ASSUME_YES" ]; then die "a fresh install with --yes must choose its certificate: --cert FILE --key FILE, --self-signed, or --no-nginx"; fi
    if [ -z "$DRY_RUN" ]; then
      note "TLS certificate for the web site:"
      note "  1) I have a certificate and key"
      note "  2) make a temporary self-signed one for now (browsers warn until you install a trusted one)"
      note "  3) no nginx here (another proxy or a tunnel fronts the application)"
      tty_line "Choose [2]: "
      case "$TTY_ANSWER" in
        1)
          tty_line "Path of the certificate file (PEM, with any chain): "
          CERT_FILE="$TTY_ANSWER"
          tty_line "Path of the private key file (PEM): "
          KEY_FILE="$TTY_ANSWER"
          [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ] || die "the certificate or key file does not exist; nothing was changed"
          "$PY3" -I "$HELPERS" check-cert --cert "$CERT_FILE" --key "$KEY_FILE" || exit "$DIE_CODE" ;;
        3) NO_NGINX=1 ;;
        "" | 2) SELF_SIGNED=1 ;;
        *) die "'$TTY_ANSWER' is not a choice; nothing was changed" ;;
      esac
    fi
  fi
fi

# --- the plan ------------------------------------------------------------------------------------------------

DATA_FILES="audit_store.db audit_store.db-wal audit_store.db-shm audit_log.jsonl .audit_log.jsonl.lock access_control.json banner_config.json environments.json update_check.json release_keys.local.json"
ALL_UNITS=""
if [ -n "$SERVICE_NAME" ]; then
  ALL_UNITS="$SERVICE_NAME"
  for _u in opa-auth-gate $(systemctl list-unit-files 'opa-auth-gate-*.service' --no-legend 2>/dev/null | awk '{print $1}' | sed 's/\.service$//') opa-host-status; do
    systemctl cat "$_u" >/dev/null 2>&1 && ALL_UNITS="$ALL_UNITS $_u"
  done
fi

note "OPA Compliance Wizard $VERSION: install the upgrade layout ($MODE)"
note "  source        $SOURCE_DIR"
note "  code          $OPT_DIR   (root-owned)"
note "  data          $DATA_DIR   (owned by $APP_USER)"
note "  app account   $APP_USER:$APP_GROUP    updater account: $UPDATER_USER (created if missing)"
[ -z "$LEGACY_DIR" ] || note "  migrating from $LEGACY_DIR   (kept; nothing in it is deleted)"
note ""
note "Plan:"
id "$UPDATER_USER" >/dev/null 2>&1 && plan "account $UPDATER_USER exists" || plan "create the system account $UPDATER_USER (no login, no home)"
if [ "$MODE" = "fresh" ]; then
  if [ -n "$APP_WILL_CREATE" ]; then
    plan "create the application account $APP_USER (a regular account, home $DATA_DIR/home, shell nologin) and enable lingering for it (loginctl enable-linger), so its user manager and keyring run without a login"
  else
    plan "use the existing application account $APP_USER and enable lingering for it (loginctl enable-linger)"
  fi
fi
plan "create $OPT_DIR/{releases,updater,maintenance}, $DATA_DIR/upgrade/{inbox/requests,bundles,backups,schedule,rejections,requests-done,work,revocations,verified}, $ARTIFACTS_DIR with the right owners and modes"
if [ -z "$REFRESH_UPDATER" ] && [ -n "$LAYOUT_PRESENT" ]; then
  plan "keep the existing root-owned updater code (add --refresh-updater to replace it)"
else
  plan "install the root-owned updater files ($(find "$SOURCE_DIR/server/updater/root" -maxdepth 1 -name '*.py' | wc -l | tr -d ' ') + nginx_bake.py) into $OPT_DIR/updater"
fi
plan "write $OPT_DIR/updater/config.json (recording install_sh_version=$VERSION once the units and the command are in place) and (once) the root trust list from $SOURCE_DIR/server/release_keys.json"
if [ "$MODE" != "reinstall" ]; then
  plan "copy this checkout to $OPT_DIR/releases/$VERSION and build its virtualenv with 'pip install --require-hashes' as $UPDATER_USER${WHEELHOUSE:+ from $WHEELHOUSE only}; then make the tree root-owned"
  plan "point $OPT_DIR/current at releases/$VERSION"
fi
plan "install the units ocw-stage@.service ocw-upgrade.path ocw-upgrade.service ocw-upgrade-due.service ocw-upgrade-due.timer in $UNIT_DIR"
plan "install $BIN_DIR/ocw-updater"
if [ "$MODE" = "migrate" ]; then
  plan "stop: $ALL_UNITS"
  for _f in $DATA_FILES; do
    [ -e "$LEGACY_DIR/$_f" ] && plan "move $_f to $DATA_DIR (copy, verify, then rename the original to $_f.migrated-<time>)"
  done
  # shellcheck disable=SC2012
  [ -z "$(ls "$LEGACY_DIR"/*.csv 2>/dev/null)" ] || plan "copy the folder-template CSV files to $DATA_DIR"
  plan "edit $ENV_FILE: add OPA_DATA_DIR=$DATA_DIR (a copy is kept first)"
  for _u in $ALL_UNITS; do
    plan "rewrite $UNIT_DIR/$_u.service: WorkingDirectory/ExecStart under $OPT_DIR/current, ReadWritePaths=$DATA_DIR in place of the old code directory, keyring and /run/user paths unchanged"
  done
  plan "systemctl daemon-reload; start the units; check each is healthy; if not, put the old units, env file and data files back"
fi
if [ "$MODE" = "fresh" ]; then
  plan "write $ENV_FILE (owner $APP_USER, mode 0600) with three generated secrets that are never shown, DEPLOYMENT_MODE=hosted${SERVER_NAME:+, the origin https://$SERVER_NAME} and the Okta settings as commented lines (an existing file is kept as it is)"
  plan "write the login gate's session key $SESSION_KEY_FILE (32 random bytes, root:$APP_GROUP 0640; an existing one is kept)"
  plan "install $UNIT_DIR/opa-compliance-wizard.service and opa-auth-gate.service for $APP_USER (run directory /run/user/<its id>); enable the backend only: the login gate is neither enabled nor started (it needs your Okta settings, and an enabled unconfigured gate would crash-loop at every boot)"
  if [ -n "$NO_NGINX" ]; then
    plan "no nginx site (--no-nginx): the template stays at $OPT_DIR/current/server/nginx-opa-secrets-wizard.conf"
  else
    if [ -n "$CERT_FILE" ]; then
      plan "copy your certificate and key to $NGINX_SSL_DIR/opa-secrets-wizard.crt and .key (mode 0600)"
    else
      plan "make a temporary self-signed certificate for ${SERVER_NAME:-the server name you will give} in $NGINX_SSL_DIR (825 days; browsers will warn until you install a trusted one)"
    fi
    [ -z "$DISABLE_DEFAULT_SITE" ] || plan "remove the link $NGINX_ENABLED_DIR/default (the distribution's default site) because this run installed nginx"
    plan "write the nginx site $CONF_NGINX_SITE for ${SERVER_NAME:-the server name you will give} (root:$APP_GROUP 0640, carries the proxy secret), link it into $NGINX_ENABLED_DIR, run nginx -t, reload nginx; the distribution's default site is left alone"
  fi
  _hz=""
  [ -n "$NO_NGINX" ] || _hz=", and /healthz through nginx"
  plan "start the backend and check it: active with 0 restarts, /api/version = $VERSION on 127.0.0.1:$CONF_PORT$_hz"
  plan "on a failed check: stop and disable the backend, keep everything for inspection, exit 4 (running the same command again repairs)"
fi
[ -z "$APPLY_NGINX" ] || plan "bake and apply this release's nginx template (nginx -t first; rolled back on failure)"
if [ -n "$REMOVE_SUDOERS" ]; then
  plan "check $SUDOERS_DIR/opa-compliance-wizard-deploy only grants the old deploy commands, then move it aside"
else
  plan "leave any old deploy sudoers lines alone (add --remove-legacy-sudoers to remove them)"
fi
[ "${#REVOCATIONS[@]}" -eq 0 ] || plan "apply ${#REVOCATIONS[@]} verified key revocation(s) to root's trust list and to the application's key list (a root-owned copy in $OPT_DIR/updater/revocations)"
plan "enable ocw-upgrade.path and ocw-upgrade.service (boot-time resume)"
# every unit that would be rewritten must have the lines the rewrite works from: checked now, on a scratch copy, so a
# surprising unit stops the run (the dry run too) before anything has been changed
if [ "$MODE" = "migrate" ]; then
  _scratch="$(mktemp -d)"
  trap 'rm -rf "$_scratch"' EXIT
  _bad_units=""
  for _u in $ALL_UNITS; do
    _frag="$(unit_prop "$_u" FragmentPath)"
    case "$_frag" in "$UNIT_DIR"/*) ;; *) continue ;; esac
    [ -f "$_frag" ] || { echo "ERROR: $_u: $_frag does not exist" >&2; _bad_units=1; continue; }
    rewrite_unit "$_u" "$_frag" "$_scratch/$_u.service" || _bad_units=1
  done
  [ -z "$_bad_units" ] || die "a unit does not have the lines the migration edits (above); nothing was changed"
fi
if [ -n "$SECOND_GATES" ]; then
  note ""
  note "!! ADDITIONAL LOGIN GATES FOUND: $SECOND_GATES"
  for _g in $SECOND_GATES; do
    case "$(second_site_status "$_g")" in
      ok) note "   opa-$_g ($NGINX_SITES_DIR/opa-$_g): already denies every route in the current deny rules ($DENIED_PREFIXES)" ;;
      no-site) note "   opa-$_g: no nginx site at $NGINX_SITES_DIR/opa-$_g (OCW_NGINX_SITES_DIR=<dir> if it lives elsewhere); check it by hand" ;;
      unreadable) note "   opa-$_g: $NGINX_SITES_DIR/opa-$_g could not be read or parsed; check it by hand" ;;
      *) note "   opa-$_g: $NGINX_SITES_DIR/opa-$_g does NOT deny every route in the current deny rules ($DENIED_PREFIXES): through that hostname an admin of that org could reach the whole-backend admin routes among them" ;;
    esac
  done
  if [ -n "$REGEN_SECOND" ]; then
    plan "regenerate those nginx sites from the live main site ($CONF_NGINX_SITE) with nginx -t first and a restore on failure"
  else
    note "   Neither this installer nor the updater changes those sites. After this run, regenerate them with"
    note "       sudo bash $OPT_DIR/current/server/install.sh --regenerate-second-sites"
    note "   (add --apply-nginx in the same command to also apply the main site's maintenance page first)."
  fi
fi
note ""
if [ -n "$DRY_RUN" ]; then
  note "Dry run: nothing was changed."
  exit 0
fi
if [ -z "$ASSUME_YES" ]; then
  tty_line "Proceed? [y/N] "
  case "$TTY_ANSWER" in y | Y | yes | YES) ;; *) die "not confirmed; nothing was changed" ;; esac
fi

PLAN_QUIET=""
# --- doing it ---------------------------------------------------------------------------------------------------

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
STAMP0="$STAMP"
BACKUP_DIR="$OPT_DIR/install-backup-$STAMP"
own() { # own <owner:group> <mode> <path>
  if [ -z "$TESTING" ] || command -v chown >/dev/null 2>&1; then chown "$1" "$3" 2>/dev/null || { [ -n "$TESTING" ] || die "chown $1 $3 failed"; }; fi
  chmod "$2" "$3"
}
mkd() { mkdir -p "$3"; own "$1" "$2" "$3"; }
render() { # render <template> <output>: fill in the __NAME__ words
  sed -e "s|__OPT_DIR__|$OPT_DIR|g" -e "s|__DATA_DIR__|$DATA_DIR|g" -e "s|__APP_USER__|$APP_USER|g" -e "s|__PYTHON3__|$PY3|g" -e "s|__ARTIFACTS_DIR__|$ARTIFACTS_DIR|g" -e "s|__ENV_FILE__|$ENV_FILE|g" \
      -e "s|__APP_DIR__|$OPT_DIR/current|g" -e "s|__APP_UID__|${APP_UID:-0}|g" -e "s|__APP_USER_HOME__|${APP_HOME:-}|g" \
      -e "s|^EnvironmentFile=/etc/opa-compliance-wizard.env\$|EnvironmentFile=$ENV_FILE|" "$1" > "$2"
}
run_as() { # run_as <user> <cmd...>
  local _u="$1"; shift
  if [ -n "$TESTING" ]; then "$@"; else runuser -u "$_u" -- "$@"; fi
}

# --- fresh install: the pieces (5.52.0) -------------------------------------------------------------------------------

fresh_prerequisites() { # what a fresh install needs from the system, checked before anything is changed
  local _missing=""
  if [ -z "$NO_NGINX" ]; then
    command -v nginx >/dev/null 2>&1 || _missing="$_missing nginx"
    { [ -d "$NGINX_SITES_DIR" ] && [ -d "$NGINX_ENABLED_DIR" ]; } || _missing="$_missing nginx-site-directories($NGINX_SITES_DIR,$NGINX_ENABLED_DIR)"
  fi
  if [ -n "$SELF_SIGNED" ]; then command -v openssl >/dev/null 2>&1 || _missing="$_missing openssl"; fi
  command -v getent >/dev/null 2>&1 || _missing="$_missing getent"
  command -v loginctl >/dev/null 2>&1 || _missing="$_missing loginctl"
  if [ -z "$TESTING" ]; then
    [ -x /usr/bin/gnome-keyring-daemon ] || _missing="$_missing gnome-keyring"
    if command -v dpkg-query >/dev/null 2>&1 && ! dpkg-query -W -f='${Status}' dbus-user-session 2>/dev/null | grep -q 'install ok installed'; then _missing="$_missing dbus-user-session"; fi
  fi
  [ -z "$_missing" ] || die "this server lacks:$_missing. The get-ocw.sh installer installs the packages; by hand: apt-get install nginx gnome-keyring dbus-user-session openssl. Nothing was changed."
}

fresh_account() { # the application account, its lingering user manager, and the facts the units need
  if [ -n "$APP_WILL_CREATE" ]; then
    note "    creating the account $APP_USER (home $DATA_DIR/home, shell nologin)"
    mkdir -p "$DATA_DIR"
    local _grp=(--user-group)
    if getent group "$APP_USER" >/dev/null 2>&1; then _grp=(--gid "$APP_USER"); fi
    useradd "${_grp[@]}" --create-home --home-dir "$DATA_DIR/home" --shell /usr/sbin/nologin "$APP_USER" || die "could not create the account $APP_USER"
  else
    note "    using the existing account $APP_USER"
  fi
  id "$APP_USER" >/dev/null 2>&1 || die "the account $APP_USER does not exist after it was created"
  APP_GROUP="$(id -gn "$APP_USER")"
  APP_UID="$(id -u "$APP_USER")"
  APP_HOME="$(getent passwd "$APP_USER" | cut -d: -f6)"
  case "$APP_UID" in "" | *[!0-9]* | 0) die "the account $APP_USER has no usable numeric id ('$APP_UID')" ;; esac
  case "$APP_HOME" in
    /?*) ;;
    *) die "the account $APP_USER has no usable home directory ('$APP_HOME')" ;;
  esac
  case "$APP_HOME" in *[[:space:]]* | *\|* | *\&* | *\\*) die "the home directory of $APP_USER contains spaces or | & \\ ('$APP_HOME')" ;; esac
  if [ -n "$APP_WILL_CREATE" ]; then chmod 0700 "$APP_HOME"; fi   # the keyring and the application's files live under it
  loginctl enable-linger "$APP_USER" || die "could not enable lingering for $APP_USER (loginctl enable-linger)"
}

fresh_home() { # the directory the keyring daemon writes (the units' ReadWritePaths= names it, so it must exist)
  local _d
  [ -d "$APP_HOME" ] || mkd "$APP_USER:$APP_GROUP" 0700 "$APP_HOME"
  # below the home, which the application account owns, root creates nothing: each level is made BY that account, one at a
  # time, and a link anywhere on the way is refused (root following a planted link would write somewhere it must not)
  for _d in "$APP_HOME/.local" "$APP_HOME/.local/share" "$APP_HOME/.local/share/keyrings"; do
    [ ! -L "$_d" ] || die "$_d is a link; move it aside and run the same command again (the installer will not create directories through it)"
    [ -d "$_d" ] || run_as "$APP_USER" mkdir -m 0700 "$_d" || die "could not create $_d as $APP_USER"
  done
}

fresh_wait_runtime() { # lingering starts the user manager asynchronously; the units need /run/user/<uid> and its bus
  [ -z "$TESTING" ] || return 0
  local _i
  for _i in $(seq 1 30); do [ -d "/run/user/$APP_UID" ] && break; sleep 1; done
  [ -d "/run/user/$APP_UID" ] || note "WARNING: /run/user/$APP_UID does not exist yet (the user manager of $APP_USER has not started: systemctl status user@$APP_UID); the backend may fail to start"
  for _i in $(seq 1 15); do [ -S "/run/user/$APP_UID/bus" ] && break; sleep 1; done
  [ -S "/run/user/$APP_UID/bus" ] || note "WARNING: there is no user D-Bus at /run/user/$APP_UID/bus (is dbus-user-session installed?); the keyring may not start"
}

fresh_tls() { # the certificate and key the nginx site names
  local _crt="$NGINX_SSL_DIR/opa-secrets-wizard.crt" _key="$NGINX_SSL_DIR/opa-secrets-wizard.key" _san _out _f
  mkd root:root 0700 "$NGINX_SSL_DIR"
  if [ -n "$CERT_FILE" ]; then
    mkdir -p "$BACKUP_DIR"
    chmod 0700 "$BACKUP_DIR"
    for _f in "$_crt" "$_key"; do [ ! -f "$_f" ] || cp -p "$_f" "$BACKUP_DIR/$(basename -- "$_f")"; done
    ( umask 077; cat -- "$KEY_FILE" >"$_key.new" && cat -- "$CERT_FILE" >"$_crt.new" ) || die "could not copy the certificate and key into $NGINX_SSL_DIR"
    own root:root 0600 "$_key.new"
    own root:root 0600 "$_crt.new"
    mv -- "$_key.new" "$_key"
    mv -- "$_crt.new" "$_crt"
    note "    installed your certificate and key in $NGINX_SSL_DIR"
  elif [ -f "$_crt" ] && [ -f "$_key" ]; then
    own root:root 0600 "$_key"
    note "    kept the certificate and key already in $NGINX_SSL_DIR (delete both to have a new self-signed pair made)"
  else
    case "$SERVER_KIND" in ip4 | ip6) _san="IP:$SERVER_NAME" ;; *) _san="DNS:$SERVER_NAME" ;; esac
    command -v openssl >/dev/null 2>&1 || die "openssl is needed to make the self-signed certificate (apt-get install openssl)"
    if ! _out="$( umask 077; openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=$SERVER_NAME" -addext "subjectAltName=$_san" -keyout "$_key" -out "$_crt" 2>&1 )"; then
      rm -f -- "$_key" "$_crt"
      die "openssl could not make the self-signed certificate: $_out"
    fi
    own root:root 0600 "$_key"
    own root:root 0600 "$_crt"
    note "    made a self-signed certificate for $SERVER_NAME (825 days): your browser will warn until you install a trusted one; HSTS stays off"
  fi
}

fresh_nginx() { # the site, linked and loaded; put back if nginx refuses it
  local _site="$CONF_NGINX_SITE" _link _had_site="" _had_link="" _out
  _link="$NGINX_ENABLED_DIR/$(basename -- "$_site")"
  mkdir -p "$BACKUP_DIR"
  chmod 0700 "$BACKUP_DIR"
  if [ -e "$_site" ]; then _had_site=1; cp -p "$_site" "$BACKUP_DIR/opa-secrets-wizard.site.before"; fi
  [ ! -L "$_link" ] || _had_link=1
  if [ -e "$_link" ] && [ -z "$_had_link" ]; then die "$_link exists and is not a link; move it aside and run the same command again"; fi
  "$PY3" -I "$HELPERS" render-site --template "$SOURCE_DIR/server/nginx-opa-secrets-wizard.conf" --out "$_site" --server-name "$SERVER_NAME" \
    --env-file "$ENV_FILE" --group "$APP_GROUP" --port "$CONF_PORT" || die "could not write the nginx site (above)"
  ln -sfn "$_site" "$_link"
  undo_nginx() {
    if [ -n "$_had_site" ]; then cp -p "$BACKUP_DIR/opa-secrets-wizard.site.before" "$_site"; else rm -f -- "$_site"; fi
    [ -n "$_had_link" ] || rm -f -- "$_link"
  }
  if ! _out="$(nginx -t 2>&1)"; then
    undo_nginx
    die "nginx -t rejected the new site, which was taken out again: $_out"
  fi
  systemctl enable nginx >/dev/null 2>&1 || true
  if ! systemctl reload nginx >/dev/null 2>&1 && ! systemctl restart nginx; then
    undo_nginx
    systemctl reload nginx >/dev/null 2>&1 || true
    die "nginx would not load the new site (is another service using port 80 or 443? journalctl -u nginx -n 50); the site was taken out again"
  fi
  note "    nginx serves $SERVER_NAME (site $_site, link $_link)"
  local _def="$NGINX_ENABLED_DIR/default"
  if [ -n "$DISABLE_DEFAULT_SITE" ] && [ -L "$_def" ]; then
    local _def_target
    _def_target="$(readlink "$_def")"
    rm -f -- "$_def"
    if systemctl reload nginx >/dev/null 2>&1; then
      note "    removed the distribution's default site link $_def (nginx was installed by this run, so only this site answers); it was pointing to $_def_target"
    else
      ln -sfn "$_def_target" "$_def"
      note "WARNING: nginx would not reload without the default site, so its link was put back"
    fi
  fi
}

install_app_unit() { # install_app_unit <file name>: rendered from the release's template; a different existing unit is kept in the backup
  local _dst="$UNIT_DIR/$1"
  render "$SOURCE_DIR/server/$1" "$_dst.new"
  own root:root 0644 "$_dst.new"
  if [ -f "$_dst" ] && cmp -s "$_dst" "$_dst.new"; then
    rm -f -- "$_dst.new"
    note "    $1 is already current"
    return 0
  fi
  if [ -f "$_dst" ]; then
    mkdir -p "$BACKUP_DIR"
    chmod 0700 "$BACKUP_DIR"
    cp -p "$_dst" "$BACKUP_DIR/$1"
    echo "--- $_dst (changes; the old unit is in $BACKUP_DIR)"
    diff -u "$_dst" "$_dst.new" || true
  fi
  mv -- "$_dst.new" "$_dst"
  note "    installed $_dst"
}

app_can_run_release() { # the application account must be able to exec the interpreter and read the application
  run_as "$APP_USER" sh -c 'test -x "$1" && test -r "$2" && test -x "$3"' sh "$OPT_DIR/current/.venv/bin/python" "$OPT_DIR/current/server/serve.py" "$OPT_DIR/current/server/start-headless.sh"
}

fresh_health() { # true when the backend is active with no restarts and answers (and nginx answers /healthz)
  local _try _bad _hargs
  _hargs=(health --port "$CONF_PORT" --version "$VERSION")
  if [ -z "$NO_NGINX" ] && { [ -z "$TESTING" ] || [ -n "${OCW_TEST_NGINX_PORT:-}" ]; }; then
    _hargs+=(--nginx-host "$SERVER_NAME" --nginx-port "${OCW_TEST_NGINX_PORT:-443}")
  fi
  for _try in $(seq 1 45); do
    sleep 2
    _bad=""
    [ "$(unit_prop opa-compliance-wizard ActiveState)" = "active" ] || _bad=1
    [ "$(unit_prop opa-compliance-wizard NRestarts)" = "0" ] || _bad=1
    if [ -z "$_bad" ] && "$PY3" -I "$HELPERS" "${_hargs[@]}"; then return 0; fi
  done
  return 1
}

apply_revocations() { # verified key revocations: root's trust list now, the application's key state through its own CLI
  local _r _kept
  [ "${#REVOCATIONS[@]}" -gt 0 ] || return 0
  HELPERS_RUN="$SOURCE_DIR/server/install_helpers.py"
  note "==> Key revocations"
  for _r in "${REVOCATIONS[@]}"; do
    [ -f "$_r" ] || die "the revocation file $_r does not exist"
    # a root-owned, world-readable copy (never inside the application's directories): the application's own CLI, run as its
    # account by `trust apply`, must be able to open it
    _kept="$("$PY3" -I "$HELPERS_RUN" keep-revocation --src "$_r" --dest-dir "$OPT_DIR/updater/revocations")" || die "could not keep a copy of the verified key revocation $_r (above)"
    "$PY3" -I "$OPT_DIR/updater/ocw_activate.py" cli trust apply "$_kept" || die "could not apply the verified key revocation $_r to root's trust list (above)"
  done
}

fresh_finish() { # after the layout, the updater and its units are in place: settings, certificate, site, units, start, check
  note "==> Settings, certificate and web site"
  local _env=(write-env --path "$ENV_FILE" --owner "$APP_USER" --data-dir "$DATA_DIR" --port "$CONF_PORT")
  [ -z "$SERVER_NAME" ] || _env+=(--server-name "$SERVER_NAME")
  [ -z "$REVOCATION_URL_ARG" ] || _env+=(--revocation-url "$REVOCATION_URL_ARG")
  "$PY3" -I "$HELPERS" "${_env[@]}" || die "could not write the settings file $ENV_FILE (above)"
  "$PY3" -I "$HELPERS" write-session-key --path "$SESSION_KEY_FILE" --group "$APP_GROUP" || die "could not write the session key (above)"
  if [ -n "$NO_NGINX" ]; then
    note "skipped: nginx not set up here (--no-nginx). The site template is at $OPT_DIR/current/server/nginx-opa-secrets-wizard.conf; the proxy secret it must carry is NGINX_PROXY_SECRET in $ENV_FILE."
  else
    fresh_tls
    fresh_nginx
  fi
  note "==> The application units"
  install_app_unit opa-compliance-wizard.service
  install_app_unit opa-auth-gate.service
  systemctl daemon-reload
  # the gate is installed DISABLED: without the Okta settings it refuses to start, and Restart=on-failure would loop at every boot
  systemctl enable opa-compliance-wizard >/dev/null 2>&1 || note "WARNING: could not enable opa-compliance-wizard"
  fresh_wait_runtime
  app_can_run_release || die "the account $APP_USER cannot run the installed release at $OPT_DIR/current (it cannot execute .venv/bin/python or read the application's files), so the backend was not started. Something was changed: the account, directories, settings file and units exist. Fix the modes along the path ('namei -l $OPT_DIR/current/.venv/bin/python' shows them) and run the same command again; it resumes."
  note "==> Starting the backend"
  systemctl start opa-compliance-wizard || note "WARNING: systemctl start opa-compliance-wizard reported a failure (the check below says whether it came up)"
  if ! fresh_health; then
    systemctl stop opa-compliance-wizard >/dev/null 2>&1 || true
    systemctl disable opa-compliance-wizard >/dev/null 2>&1 || true
    note "!! The backend did not come up healthy; it was stopped and disabled. Everything this run made is still in place for inspection:"
    note "!!   $OPT_DIR, $DATA_DIR, $ENV_FILE, $UNIT_DIR/opa-compliance-wizard.service, the account $APP_USER"
    note "!! See: journalctl -u opa-compliance-wizard -n 100 --no-pager"
    note "!! Run the same command again to repair, or remove the software with: sudo bash get-ocw.sh --uninstall --keep-data"
    die "the backend did not pass its health check; nothing was rolled back (a fresh install has no earlier version to go back to)"
  fi
  note "    the backend is active and answers /api/version as $VERSION"
  rm -f -- "$OPT_DIR/.fresh-install-incomplete"
}

print_fresh_done() {
  local _origin="https://${SERVER_NAME:-<your server name>}"
  note ""
  note "Done. OPA Compliance Wizard $VERSION is installed and the backend is running."
  note "  What changed: $OPT_DIR (code, root-owned), $DATA_DIR (data, owned by $APP_USER),"
  note "                $ENV_FILE (settings and generated secrets, 0600), $UNIT_DIR/opa-compliance-wizard.service,"
  note "                opa-auth-gate.service (installed, not enabled, not started), ocw-*.service, $BIN_DIR/ocw-updater,"
  if [ -z "$NO_NGINX" ]; then
    if [ -n "$CERT_FILE" ]; then
      note "                $CONF_NGINX_SITE (your certificate),"
    else
      note "                $CONF_NGINX_SITE (self-signed certificate: your browser will warn until you install a trusted one),"
    fi
  fi
  note "                accounts $APP_USER and $UPDATER_USER.${LOG_FILE:+ Log: $LOG_FILE}"
  note "  Not done yet (nothing works in a browser until this is):"
  note "  1. Register the Okta OIDC web app (docs/hosting.md, step 1): redirect $_origin/authorization-code/callback"
  note "  2. As root: sudoedit $ENV_FILE and fill OKTA_ORG_URL, OKTA_OIDC_CLIENT_ID, OKTA_ADMIN_GROUP_ID"
  if [ -n "$SERVER_NAME" ]; then
    note "     (DASHBOARD_ORIGIN is already set to $_origin)"
  else
    note "     and DASHBOARD_ORIGIN (the public https origin of this server; it is not set because --no-nginx came without --server-name)"
  fi
  note "  3. Put the client secret and the read-only admin-check token in the application's keyring (docs/hosting.md steps 3 and \"Admin access\"):"
  note "     sudo -u $APP_USER env XDG_RUNTIME_DIR=/run/user/$APP_UID DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$APP_UID/bus $OPT_DIR/current/.venv/bin/python -c \"import getpass, keyring; keyring.set_password('opa-compliance-wizard:default', 'okta_client_secret', getpass.getpass('client secret: '))\""
  note "     Run it while the backend service is running (it is, right now): the service's session keeps the keyring unlocked and the command reaches it through that session."
  note "     (the same for 'okta_admin_check_token'; both prompts hide what you type and nothing is written to the shell history)"
  note "  4. sudo systemctl enable --now opa-auth-gate && sudo systemctl status opa-auth-gate"
  note "     (it was installed disabled on purpose: until step 2 is done it would crash-loop; this command starts it now and at every boot)"
  note "  5. Open $_origin, sign in, add your first environment (the dashboard walks you through it)."
  if [ -z "$NO_NGINX" ] && { [ -e "$NGINX_ENABLED_DIR/default" ] || [ -L "$NGINX_ENABLED_DIR/default" ]; }; then
    note "  Note: nginx's own 'default' site ($NGINX_ENABLED_DIR/default) is still enabled; other sites on this server are none of this installer's business."
    note "        If you want only this application's site to answer, remove that link ('sudo rm $NGINX_ENABLED_DIR/default && sudo systemctl reload nginx')."
  fi
  note "  Later: upgrades from the Updates page or 'sudo ocw-updater apply <version>'; status: 'ocw-updater status'; uninstall: 'sudo bash get-ocw.sh --uninstall --keep-data'."
}

[ "$MODE" != "fresh" ] || fresh_prerequisites
DIE_CODE=4   # from here on something has been changed: a failure needs an operator
note "==> Accounts and directories"
if ! id "$UPDATER_USER" >/dev/null 2>&1; then
  if [ -n "$TESTING" ]; then note "    (test run: not creating $UPDATER_USER)"; else
    useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$UPDATER_USER" || die "could not create $UPDATER_USER"
  fi
fi
UPD_OWNER="$UPDATER_USER:$UPDATER_USER"
id "$UPDATER_USER" >/dev/null 2>&1 || UPD_OWNER="root:root"
APP_UID="" APP_HOME=""
[ "$MODE" != "fresh" ] || fresh_account
mkd root:root 0755 "$OPT_DIR"
[ "$MODE" != "fresh" ] || : >"$OPT_DIR/.fresh-install-incomplete"   # removed when the install has passed its health check
# releases/ is ROOT-owned: only root can rename, replace or remove a release. The staging account builds in staging/<version>
# and root moves the tree into releases/ before it takes ownership of it and checks it.
mkd root:root 0755 "$OPT_DIR/releases"
mkd "$UPD_OWNER" 0755 "$OPT_DIR/staging"
# where `ocw-updater stage <file>` hands an operator's file to the staging account: root writes, the account only reads
if id "$UPDATER_USER" >/dev/null 2>&1; then mkd "root:$UPDATER_USER" 0750 "$OPT_DIR/handoff"; else mkd root:root 0750 "$OPT_DIR/handoff"; fi
mkd root:root 0755 "$OPT_DIR/updater"
mkd root:root 0755 "$OPT_DIR/maintenance"
# root-owned with the sticky bit and group write for the application's account: it can create and replace ITS files
# here (the archive, the audit log) but cannot rename or remove the root-owned upgrade/ directory, so root never
# works inside a directory the application controls.
mkd "root:$APP_GROUP" 1770 "$DATA_DIR"
[ "$MODE" != "fresh" ] || fresh_home
mkd root:root 0755 "$DATA_DIR/upgrade"
mkd "$APP_USER:$APP_GROUP" 0700 "$DATA_DIR/upgrade/inbox"
mkd "$APP_USER:$APP_GROUP" 0700 "$DATA_DIR/upgrade/inbox/requests"
mkd "root:$APP_GROUP" 0750 "$DATA_DIR/upgrade/bundles"
mkd root:root 0700 "$DATA_DIR/upgrade/backups"
mkd root:root 0700 "$DATA_DIR/upgrade/schedule"
mkd root:root 0755 "$DATA_DIR/upgrade/rejections"
mkd root:root 0700 "$DATA_DIR/upgrade/requests-done"
mkd root:root 0700 "$DATA_DIR/upgrade/verified"
mkd "$APP_USER:$APP_GROUP" 0700 "$DATA_DIR/upgrade/work"
mkd "$APP_USER:$APP_GROUP" 0700 "$DATA_DIR/upgrade/revocations"
mkd "$UPD_OWNER" 0750 "$(dirname -- "$ARTIFACTS_DIR")"
mkd "$UPD_OWNER" 0750 "$ARTIFACTS_DIR"
# The audit log and its lock file belong to the application account from the start, so a root process that appends to the
# log can never leave a root-owned lock file that locks the application out of its own cross-process lock.
for _af in audit_log.jsonl .audit_log.jsonl.lock; do
  [ -e "$DATA_DIR/$_af" ] || : > "$DATA_DIR/$_af"
  own "$APP_USER:$APP_GROUP" 0600 "$DATA_DIR/$_af"
done

note "==> The root-owned updater"
if [ -z "$LAYOUT_PRESENT" ] || [ -n "$REFRESH_UPDATER" ]; then
  # The code goes into a new versioned directory and <updater>/current is flipped to it (the same way a self-update works);
  # <updater>/ocw_activate.py is the fixed launcher that follows that link.
  _lib="$OPT_DIR/updater/lib/install-$STAMP0"
  mkdir -p "$_lib"
  for _f in "$SOURCE_DIR"/server/updater/root/*.py; do
    _name="$(basename -- "$_f")"
    [ "$_name" != "ocw_launcher.py" ] || continue
    cp "$_f" "$_lib/$_name"
    own root:root 0644 "$_lib/$_name"
  done
  cp "$SOURCE_DIR/server/nginx_bake.py" "$_lib/nginx_bake.py"
  own root:root 0644 "$_lib/nginx_bake.py"
  own root:root 0755 "$_lib/ocw_activate.py"
  own root:root 0755 "$_lib"
  ln -sfn "lib/install-$STAMP0" "$OPT_DIR/updater/current"
  cp "$SOURCE_DIR/server/updater/root/ocw_launcher.py" "$OPT_DIR/updater/ocw_activate.py.new"
  own root:root 0755 "$OPT_DIR/updater/ocw_activate.py.new"
  mv "$OPT_DIR/updater/ocw_activate.py.new" "$OPT_DIR/updater/ocw_activate.py"
  own root:root 0755 "$OPT_DIR/updater/lib"
fi
_cfg_tmp="$OPT_DIR/updater/config.json.tmp"
# keep the version install.sh recorded earlier until this run has finished replacing the units and the command
_prev_isv=""
if [ -f "$OPT_DIR/updater/config.json" ]; then
  _prev_isv="$("$PY3" -I -c 'import json, re, sys
try:
    v = json.load(open(sys.argv[1])).get("install_sh_version", "")
except Exception:
    v = ""
print(v if isinstance(v, str) and re.fullmatch(r"[0-9]+[.][0-9]+[.][0-9]+", v) else "")' "$OPT_DIR/updater/config.json")"
fi
_isv_json=""
[ -z "$_prev_isv" ] || _isv_json=", \"install_sh_version\": \"$_prev_isv\""
cat > "$_cfg_tmp" <<EOF
{"app_user": "$APP_USER", "app_group": "$APP_GROUP", "stage_user": "$UPDATER_USER",
 "backend_service": "${SERVICE_NAME:-opa-compliance-wizard}", "gate_service": "opa-auth-gate",
 "nginx_site": "$CONF_NGINX_SITE", "backend_port": $CONF_PORT, "second_gate_sites_dir": "$NGINX_SITES_DIR",
 "artifacts_dir": "$ARTIFACTS_DIR", "env_file": "$ENV_FILE"$_isv_json}
EOF
own root:root 0644 "$_cfg_tmp"
mv "$_cfg_tmp" "$OPT_DIR/updater/config.json"
export OCW_OPT_DIR="$OPT_DIR" OCW_DATA_DIR="$DATA_DIR" OCW_ARTIFACTS_DIR="$ARTIFACTS_DIR" OCW_ENV_FILE="$ENV_FILE"
if [ ! -f "$OPT_DIR/updater/trust.json" ]; then
  _seed_args=(cli trust seed --source "$SOURCE_DIR/server/release_keys.json")
  if [ -n "$LEGACY_DIR" ] && [ -f "$LEGACY_DIR/release_keys.local.json" ]; then _seed_args+=(--local-state "$LEGACY_DIR/release_keys.local.json"); fi
  "$PY3" -I "$OPT_DIR/updater/ocw_activate.py" "${_seed_args[@]}" || die "could not create root's trust list (see above)"
else
  note "    root's trust list already exists; left as it is"
fi

if [ "$MODE" != "reinstall" ]; then
  note "==> Release $VERSION"
  REL="$OPT_DIR/releases/$VERSION"
  if [ ! -f "$REL/.installed-from-source" ] && [ ! -f "$REL/.installed-from-release" ]; then
    rm -rf "$REL"
    mkd "$UPD_OWNER" 0755 "$REL"
    tar -C "$SOURCE_DIR" \
      --exclude=./.git --exclude=./.venv --exclude=./frontend/node_modules --exclude=__pycache__ --exclude=./.pytest_cache \
      --exclude='./audit_store.db*' --exclude=./audit_log.jsonl --exclude=./.audit_log.jsonl.lock --exclude=./access_control.json \
      --exclude=./banner_config.json --exclude=./environments.json --exclude=./update_check.json --exclude=./release_keys.local.json \
      --exclude=./.env --exclude=./.deploy.conf --exclude=./.deploy.lock --exclude=./.nginx-deploy-backup --exclude='./*.csv' \
      --exclude=./TestCreds.txt --exclude=./ubuntuserver.txt --exclude=./frontend/dist.new --exclude=./frontend/dist.old \
      -cf - . | tar -C "$REL" -xf -
    [ -f "$SOURCE_DIR/folders_template.csv" ] && cp "$SOURCE_DIR/folders_template.csv" "$REL/folders_template.csv"
    own "$UPD_OWNER" 0755 "$REL"
    if [ -z "$TESTING" ]; then chown -Rh "$UPD_OWNER" "$REL"; fi
    _pip=(--require-hashes --only-binary=:all: -r "$REL/requirements.lock")
    [ -z "$WHEELHOUSE" ] || _pip=(--no-index --find-links "$WHEELHOUSE" "${_pip[@]}")
    run_as "$UPDATER_USER" "$PY3" -m venv "$REL/.venv" || die "could not create the virtual environment in $REL/.venv"
    run_as "$UPDATER_USER" env HOME=/var/lib/ocw-updater PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1 "$REL/.venv/bin/pip" install -q "${_pip[@]}" \
      || die "pip install --require-hashes failed in $REL (the old install is untouched)"
    find "$REL" -path "$REL/.venv" -prune -o -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
    if [ -n "$RELEASE_INFO" ]; then
      "$PY3" -I "$SOURCE_DIR/server/install_helpers.py" record-release --release-dir "$REL" --info "$RELEASE_INFO" --stamp "$STAMP" || die "could not record the provenance of release $VERSION (above)"
    else
      printf '{"version": "%s", "source": "install.sh", "installed_at": "%s", "signed": false}\n' "$VERSION" "$STAMP" > "$REL/.installed-from-source"
    fi
    if [ -z "$TESTING" ]; then chown -Rh root:root "$REL"; fi
    chmod -R go-w "$REL"
  else
    note "    $REL is already installed"
  fi
fi
for _f in ocw-stage@.service ocw-upgrade.path ocw-upgrade.service ocw-upgrade-due.service ocw-upgrade-due.timer; do
  render "$SOURCE_DIR/server/$_f" "$UNIT_DIR/$_f"
  own root:root 0644 "$UNIT_DIR/$_f"
done
render "$SOURCE_DIR/server/ocw-updater.sh" "$BIN_DIR/ocw-updater"
own root:root 0755 "$BIN_DIR/ocw-updater"
if [ ! -f "$UPDATER_ENV" ]; then
  {
    echo "# Optional settings for the unprivileged staging step (ocw-stage@.service). No secrets here."
    echo "# https_proxy=http://proxy.example.com:3128"
    echo "# no_proxy=localhost,127.0.0.1"
    [ -z "$CONF_RELEASE_BASE" ] || echo "OPA_RELEASE_BASE_URL=$CONF_RELEASE_BASE"
    [ -z "$CONF_REVOCATION_BASE" ] || echo "OPA_REVOCATION_URL_BASE=$CONF_REVOCATION_BASE"
    [ -z "$REVOCATION_URL_ARG" ] || echo "OPA_REVOCATION_URL=$REVOCATION_URL_ARG"
  } > "$UPDATER_ENV"
  own root:root 0644 "$UPDATER_ENV"
fi

if [ "$MODE" = "migrate" ]; then
  note "==> Migrating $LEGACY_DIR"
  mkdir -p "$BACKUP_DIR"
  chmod 0700 "$BACKUP_DIR"
  MOVED=()
  UNIT_BACKUPS=()
  restore_migration() {
    note "!! The migrated install did not come up healthy: putting the old layout back"
    local _i
    for _i in "${UNIT_BACKUPS[@]:-}"; do
      [ -n "$_i" ] || continue
      cp -p "$BACKUP_DIR/$(basename -- "$_i")" "$_i"
    done
    [ ! -f "$BACKUP_DIR/$(basename -- "$ENV_FILE")" ] || cp -p "$BACKUP_DIR/$(basename -- "$ENV_FILE")" "$ENV_FILE"
    for _i in "${MOVED[@]:-}"; do
      [ -n "$_i" ] || continue
      rm -f "$DATA_DIR/$_i"
      mv "$LEGACY_DIR/$_i.migrated-$STAMP" "$LEGACY_DIR/$_i"
    done
    systemctl daemon-reload || true
    for _i in $ALL_UNITS; do systemctl restart "$_i" || true; done
    # the new layout was not switched to: take its `current` link away, so nothing treats this server as migrated and a later run
    # offers the migration again (the release itself, the updater and the data copies' originals stay where they are)
    rm -f -- "$OPT_DIR/current"
    DIE_CODE=3
    die "migration rolled back; the install is as it was. Nothing was lost. Send the output above to the maintainers."
  }
  for _u in $ALL_UNITS; do systemctl stop "$_u" || true; done
  for _f in $DATA_FILES; do
    [ -e "$LEGACY_DIR/$_f" ] || continue
    cp -p "$LEGACY_DIR/$_f" "$DATA_DIR/$_f" || restore_migration
    cmp -s "$LEGACY_DIR/$_f" "$DATA_DIR/$_f" || restore_migration
    own "$APP_USER:$APP_GROUP" 0600 "$DATA_DIR/$_f"
    MOVED+=("$_f")
  done
  for _csv in "$LEGACY_DIR"/*.csv; do
    [ -f "$_csv" ] || continue
    cp -p "$_csv" "$DATA_DIR/" && own "$APP_USER:$APP_GROUP" 0600 "$DATA_DIR/$(basename -- "$_csv")"
  done
  if [ -f "$DATA_DIR/audit_store.db" ]; then
    "$PY3" -I - "$DATA_DIR/audit_store.db" <<'PY' || restore_migration
import sqlite3, sys
conn = sqlite3.connect("file:" + sys.argv[1] + "?immutable=1", uri=True)
sys.exit(0 if conn.execute("PRAGMA quick_check").fetchone()[0] == "ok" else 1)
PY
  fi
  for _f in "${MOVED[@]:-}"; do
    [ -n "$_f" ] || continue
    mv "$LEGACY_DIR/$_f" "$LEGACY_DIR/$_f.migrated-$STAMP"
  done
  # the environment file: add OPA_DATA_DIR; an archive path that pointed into the old directory follows the move
  if [ -f "$ENV_FILE" ]; then
    cp -p "$ENV_FILE" "$BACKUP_DIR/$(basename -- "$ENV_FILE")"
    grep -Eq '^[[:space:]]*OPA_DATA_DIR=' "$ENV_FILE" || printf '\nOPA_DATA_DIR=%s\n' "$DATA_DIR" >> "$ENV_FILE"
    _envesc="$(printf '%s' "$LEGACY_DIR" | sed -e 's/[][\\.*^$|&]/\\&/g')"
    sed -i.ocwbak -e "s|^\([[:space:]]*\)OPA_AUDIT_DB_PATH=${_envesc}/|\1OPA_AUDIT_DB_PATH=$DATA_DIR/|" "$ENV_FILE" && rm -f "$ENV_FILE.ocwbak"
  else
    note "NOTE: $ENV_FILE does not exist; create it as docs/hosting.md describes (OPA_DATA_DIR=$DATA_DIR is the new line)"
  fi
  # the units
  ln -sfn "releases/$VERSION" "$OPT_DIR/current"
  for _u in $ALL_UNITS; do
    _frag="$(unit_prop "$_u" FragmentPath)"
    case "$_frag" in "$UNIT_DIR"/*) ;; *) note "NOTE: $_u is defined in '$_frag', outside $UNIT_DIR: not rewritten (edit it as docs/hosting.md describes)"; continue ;; esac
    cp -p "$_frag" "$BACKUP_DIR/$(basename -- "$_frag")"
    UNIT_BACKUPS+=("$_frag")
    rewrite_unit "$_u" "$BACKUP_DIR/$(basename -- "$_frag")" "$_frag.new" || restore_migration
    echo "--- $_frag (changes)"; diff -u "$BACKUP_DIR/$(basename -- "$_frag")" "$_frag.new" || true
    mv "$_frag.new" "$_frag"
  done
  systemctl daemon-reload
  for _u in $ALL_UNITS; do systemctl start "$_u" || restore_migration; done
  note "==> Checking the migrated install"
  _ok=""
  for _try in $(seq 1 45); do
    sleep 2
    _bad=""
    for _u in $ALL_UNITS; do
      [ "$(unit_prop "$_u" ActiveState)" = "active" ] || _bad=1
      [ "$(unit_prop "$_u" NRestarts)" = "0" ] || _bad=1
    done
    if [ -z "$_bad" ] && "$PY3" -I - "$CONF_PORT" "$VERSION" <<'PY'
import http.client, json, sys
try:
    c = http.client.HTTPConnection("127.0.0.1", int(sys.argv[1]), timeout=3)
    c.request("GET", "/api/version")
    sys.exit(0 if json.loads(c.getresponse().read().decode()).get("version") == sys.argv[2] else 1)
except Exception:
    sys.exit(1)
PY
    then _ok=1; break; fi
  done
  [ -n "$_ok" ] || restore_migration
  note "    all units are active and the application answers as $VERSION"
  note "    the old directory $LEGACY_DIR is untouched except that its data files were renamed *.migrated-$STAMP;"
  note "    delete it yourself when you are satisfied. Unit/env backups are in $BACKUP_DIR."
elif [ "$MODE" = "fresh" ]; then
  ln -sfn "releases/$VERSION" "$OPT_DIR/current"
fi

if [ -n "$APPLY_NGINX" ]; then
  note "==> nginx"
  "$PY3" -I "$OPT_DIR/updater/ocw_activate.py" cli nginx-sync || note "WARNING: the nginx template was not applied (see above); the maintenance page will not show until it is"
fi

regenerate_second_sites() {
  command -v nginx >/dev/null 2>&1 || { note "WARNING: nginx is not installed here; the second-gate sites were not regenerated"; return 1; }
  [ -f "$CONF_NGINX_SITE" ] && [ ! -L "$CONF_NGINX_SITE" ] || { note "WARNING: the main nginx site $CONF_NGINX_SITE is not a regular file; the second-gate sites were not regenerated (they are generated from it)"; return 1; }
  mkdir -p "$BACKUP_DIR"
  chmod 0700 "$BACKUP_DIR"
  local _g _site _new _params _port _listen _host _extra _failed="" _changed=() _s
  for _g in $SECOND_GATES; do
    _site="$NGINX_SITES_DIR/opa-$_g"
    if [ ! -f "$_site" ] || [ -L "$_site" ]; then note "    opa-$_g: no regular file at $_site: not regenerated (check it by hand)"; _failed=1; continue; fi
    if ! _params="$("$PY3" -I "$SOURCE_DIR/server/nginx_second_site.py" --params "$_site")"; then
      note "    opa-$_g: could not read the gate port, listen address and host from $_site: not regenerated"; _failed=1; continue
    fi
    read -r _port _listen _host <<<"$_params"
    _extra=()
    case "$_listen" in 127.*) ;; *) _extra=(--allow-public-listen) ;; esac   # keep the choice the operator made when the site was created
    _new="$BACKUP_DIR/opa-$_g.site.new"
    cp -p "$_site" "$BACKUP_DIR/opa-$_g.site.before"
    if ! "$PY3" -I "$SOURCE_DIR/server/nginx_second_site.py" "$CONF_NGINX_SITE" "$_new" "$_port" "$_listen" "$_host" "$_g" ${_extra[@]+"${_extra[@]}"}; then
      note "    opa-$_g: the generator refused the main site (above): not regenerated"; _failed=1; continue
    fi
    cat "$_new" > "$_site"   # same inode, owner and mode as before
    if nginx -t >/dev/null 2>&1; then
      note "    opa-$_g: regenerated ($_listen, $_host, gate port $_port); the old copy is $BACKUP_DIR/opa-$_g.site.before"
      _changed+=("$_g")
    else
      cat "$BACKUP_DIR/opa-$_g.site.before" > "$_site"
      note "    opa-$_g: nginx -t rejected the regenerated site; the old one was put back"
      nginx -t >/dev/null 2>&1 || note "WARNING: nginx -t still fails with the old site restored: fix nginx's configuration (nothing was reloaded)"
      _failed=1
    fi
  done
  if [ "${#_changed[@]}" -gt 0 ]; then
    if systemctl reload nginx; then
      note "    nginx reloaded"
    else
      for _s in "${_changed[@]}"; do cat "$BACKUP_DIR/opa-$_s.site.before" > "$NGINX_SITES_DIR/opa-$_s"; done
      note "WARNING: nginx would not reload; the previous second-gate sites were put back"
      _failed=1
    fi
  fi
  [ -z "$_failed" ]
}

if [ -n "$REGEN_SECOND" ]; then
  note "==> Second-gate nginx sites"
  if [ -z "$SECOND_GATES" ]; then
    note "    no additional login gates (opa-auth-gate-*) on this server: nothing to regenerate"
  else
    regenerate_second_sites || SECOND_FAILED=1
  fi
fi

if [ -n "$REMOVE_SUDOERS" ]; then
  note "==> Old deploy sudoers"
  _sf="$SUDOERS_DIR/opa-compliance-wizard-deploy"
  if [ ! -f "$_sf" ]; then
    note "    $_sf does not exist: nothing to remove"
  elif grep -Ev '^[[:space:]]*(#|$)' "$_sf" | grep -Ev '(systemctl (restart|reload) |/nginx -t|[ /]cp .*(nginx|opa))' | grep -q .; then
    note "    $_sf contains lines this installer does not recognise; it was NOT removed. Review it by hand."
  else
    mkdir -p "$BACKUP_DIR"
    mv "$_sf" "$BACKUP_DIR/opa-compliance-wizard-deploy.sudoers"
    if [ -z "$TESTING" ] && command -v visudo >/dev/null 2>&1 && ! visudo -c >/dev/null 2>&1; then
      mv "$BACKUP_DIR/opa-compliance-wizard-deploy.sudoers" "$_sf"
      die "visudo -c failed after the removal; the file was put back"
    fi
    note "    removed (kept in $BACKUP_DIR). The application account can no longer restart services or write the nginx site."
  fi
fi

# the units and the command above are now this release's: record that, so the updater stops asking for this run
"$PY3" -I - "$OPT_DIR/updater/config.json" "$VERSION" <<'PY' || die "could not record install_sh_version in $OPT_DIR/updater/config.json"
import json, os, sys
path, version = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as fh:
    cfg = json.load(fh)
cfg["install_sh_version"] = version
tmp = path + ".tmp"
with open(tmp, "w", encoding="utf-8") as fh:
    json.dump(cfg, fh)
    fh.flush()
    os.fsync(fh.fileno())
os.chmod(tmp, 0o644)
os.replace(tmp, path)
PY
note "    recorded install_sh_version=$VERSION in $OPT_DIR/updater/config.json"
systemctl daemon-reload
systemctl enable ocw-upgrade.path ocw-upgrade.service >/dev/null 2>&1 || note "WARNING: could not enable ocw-upgrade.path / ocw-upgrade.service"
systemctl start ocw-upgrade.path || note "WARNING: could not start ocw-upgrade.path"
apply_revocations
if [ "$MODE" = "fresh" ]; then
  fresh_finish
  print_fresh_done
else
  note ""
  note "Done. Next:"
  note "  ocw-updater status                      what is installed and ready"
  note "  sudo ocw-updater apply <version>        upgrade (staging, backup, switch, health checks, automatic rollback)"
  note "  sudo server/install.sh --apply-nginx    (if you did not pass it) once, so other users see a maintenance page while it switches"
fi
if [ -n "$SECOND_GATES" ]; then
  _unfixed=""
  for _g in $SECOND_GATES; do [ "$(second_site_status "$_g")" = "ok" ] || _unfixed="$_unfixed $_g"; done
  if [ -n "$_unfixed" ]; then
    note ""
    note "!! ACTION NEEDED: the nginx site of these additional login gates does not deny every route in the current deny rules ($DENIED_PREFIXES):$_unfixed"
    note "!! Through that hostname an administrator of that org could reach the whole-backend admin routes among them (host upgrades, shared permissions, the Overview). Run"
    note "!!     sudo bash $OPT_DIR/current/server/install.sh --regenerate-second-sites"
    note "!! (it rebuilds each site from the live main site, runs nginx -t, and puts the old site back if it fails)."
  fi
fi
[ -z "${SECOND_FAILED:-}" ] || die "the second-gate nginx sites were not all regenerated (see above); the rest of the install is done"
