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
#   fresh install     no layout and no running install: installs the release in this checkout.
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
#   --refresh-updater          (re-run) replace the root-owned updater code with this checkout's
#   --yes                      do not ask for confirmation
#
# Everything below that is a path can be redirected for testing (OCW_OPT_DIR, OCW_DATA_DIR, OCW_UNIT_DIR, OCW_BIN_DIR,
# OCW_ENV_FILE, OCW_SUDOERS_DIR, OCW_ARTIFACTS_DIR); a test run also sets OCW_INSTALL_TEST=1 to skip root-only steps.
set -euo pipefail

OPT_DIR="${OCW_OPT_DIR:-/opt/opa-compliance-wizard}"
DATA_DIR="${OCW_DATA_DIR:-/var/lib/opa-compliance-wizard}"
UNIT_DIR="${OCW_UNIT_DIR:-/etc/systemd/system}"
BIN_DIR="${OCW_BIN_DIR:-/usr/local/bin}"
ENV_FILE="${OCW_ENV_FILE:-/etc/opa-compliance-wizard.env}"
SUDOERS_DIR="${OCW_SUDOERS_DIR:-/etc/sudoers.d}"
ARTIFACTS_DIR="${OCW_ARTIFACTS_DIR:-/var/lib/ocw-updater/artifacts}"
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

usage() { sed -n '2,44p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }
die() { echo "ERROR: $*" >&2; exit 1; }
note() { echo "$*"; }
plan() { echo "  - $*"; }

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
    -h | --help) usage; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

for _p in "$OPT_DIR" "$DATA_DIR" "$UNIT_DIR" "$BIN_DIR" "$ENV_FILE" "$SUDOERS_DIR" "$ARTIFACTS_DIR"; do
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
PY3="$(command -v python3)"
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

LAYOUT_PRESENT=""
[ -L "$OPT_DIR/current" ] && LAYOUT_PRESENT=1

if [ -n "$SERVICE_NAME" ]; then
  _unit_user="$(unit_prop "$SERVICE_NAME" User)"
  _unit_wd="$(unit_prop "$SERVICE_NAME" WorkingDirectory)"
  [ -n "$APP_USER" ] || APP_USER="$_unit_user"
  if [ -z "$LEGACY_DIR" ] && [ -n "$_unit_wd" ] && [ "$_unit_wd" != "$OPT_DIR/current" ]; then
    case "$_unit_wd" in
      "$OPT_DIR"/*) ;;
      *) [ -f "$_unit_wd/create_secret_folders.py" ] && LEGACY_DIR="$_unit_wd" ;;
    esac
  fi
fi
[ -n "$APP_USER" ] || APP_USER="$(stat -c %U "$SOURCE_DIR" 2>/dev/null || stat -f %Su "$SOURCE_DIR")"
id "$APP_USER" >/dev/null 2>&1 || die "the application account '$APP_USER' does not exist (--app-user)"
[ "$APP_USER" != "root" ] || die "the web application must not run as root; use its own account (--app-user)"
APP_GROUP="$(id -gn "$APP_USER")"
MODE="fresh"
if [ -n "$LAYOUT_PRESENT" ]; then
  MODE="reinstall"
elif [ -n "$LEGACY_DIR" ]; then
  MODE="migrate"
  [ -x "$LEGACY_DIR/.venv/bin/python" ] || note "NOTE: $LEGACY_DIR has no .venv/bin/python; migrating anyway (the new release gets its own)."
fi

for _p in "$LEGACY_DIR" "$SOURCE_DIR"; do
  case "$_p" in
    *[[:space:]]* | *\|* | *\&* | *\\*) die "paths must not contain spaces or | & \\ (got '$_p')" ;;
  esac
done

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
plan "create $OPT_DIR/{releases,updater,maintenance}, $DATA_DIR/upgrade/{inbox/requests,bundles,backups,schedule,rejections,requests-done,work,revocations,verified}, $ARTIFACTS_DIR with the right owners and modes"
if [ -z "$REFRESH_UPDATER" ] && [ -n "$LAYOUT_PRESENT" ]; then
  plan "keep the existing root-owned updater code (add --refresh-updater to replace it)"
else
  plan "install the root-owned updater files ($(find "$SOURCE_DIR/server/updater/root" -maxdepth 1 -name '*.py' | wc -l | tr -d ' ') + nginx_bake.py) into $OPT_DIR/updater"
fi
plan "write $OPT_DIR/updater/config.json and (once) the root trust list from $SOURCE_DIR/server/release_keys.json"
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
[ -n "$APPLY_NGINX" ] && plan "bake and apply this release's nginx template (nginx -t first; rolled back on failure)"
if [ -n "$REMOVE_SUDOERS" ]; then
  plan "check $SUDOERS_DIR/opa-compliance-wizard-deploy only grants the old deploy commands, then move it aside"
else
  plan "leave any old deploy sudoers lines alone (add --remove-legacy-sudoers to remove them)"
fi
plan "enable ocw-upgrade.path and ocw-upgrade.service (boot-time resume)"
note ""
if [ -n "$DRY_RUN" ]; then
  note "Dry run: nothing was changed."
  exit 0
fi
if [ -z "$ASSUME_YES" ]; then
  printf 'Proceed? [y/N] '
  read -r _ans || _ans=""
  case "$_ans" in y | Y | yes | YES) ;; *) die "not confirmed; nothing was changed" ;; esac
fi

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
  sed -e "s|__OPT_DIR__|$OPT_DIR|g" -e "s|__DATA_DIR__|$DATA_DIR|g" -e "s|__APP_USER__|$APP_USER|g" -e "s|__PYTHON3__|$PY3|g" -e "s|__ARTIFACTS_DIR__|$ARTIFACTS_DIR|g" -e "s|__ENV_FILE__|$ENV_FILE|g" "$1" > "$2"
}
run_as() { # run_as <user> <cmd...>
  local _u="$1"; shift
  if [ -n "$TESTING" ]; then "$@"; else runuser -u "$_u" -- "$@"; fi
}

note "==> Accounts and directories"
if ! id "$UPDATER_USER" >/dev/null 2>&1; then
  if [ -n "$TESTING" ]; then note "    (test run: not creating $UPDATER_USER)"; else
    useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$UPDATER_USER" || die "could not create $UPDATER_USER"
  fi
fi
UPD_OWNER="$UPDATER_USER:$UPDATER_USER"
id "$UPDATER_USER" >/dev/null 2>&1 || UPD_OWNER="root:root"
mkd root:root 0755 "$OPT_DIR"
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
cat > "$_cfg_tmp" <<EOF
{"app_user": "$APP_USER", "app_group": "$APP_GROUP", "stage_user": "$UPDATER_USER",
 "backend_service": "${SERVICE_NAME:-opa-compliance-wizard}", "gate_service": "opa-auth-gate",
 "nginx_site": "$CONF_NGINX_SITE", "backend_port": $CONF_PORT,
 "artifacts_dir": "$ARTIFACTS_DIR", "env_file": "$ENV_FILE"}
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
  if [ ! -f "$REL/.installed-from-source" ]; then
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
    printf '{"version": "%s", "source": "install.sh", "installed_at": "%s", "signed": false}\n' "$VERSION" "$STAMP" > "$REL/.installed-from-source"
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
    grep -q '^OPA_DATA_DIR=' "$ENV_FILE" || printf '\nOPA_DATA_DIR=%s\n' "$DATA_DIR" >> "$ENV_FILE"
    sed -i.ocwbak -e "s|^OPA_AUDIT_DB_PATH=$LEGACY_DIR/|OPA_AUDIT_DB_PATH=$DATA_DIR/|" "$ENV_FILE" && rm -f "$ENV_FILE.ocwbak"
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
    _esc="$(printf '%s' "$LEGACY_DIR" | sed -e 's/[][\.*^$|&]/\\&/g')"
    sed -e "s|^[[:space:]]*ReadWritePaths=${_esc}[[:space:]]*\$|ReadWritePaths=$DATA_DIR|" \
        -e "s|$_esc|$OPT_DIR/current|g" "$BACKUP_DIR/$(basename -- "$_frag")" > "$_frag.new"
    if ! grep -q '^Environment=OPA_DATA_DIR=' "$_frag.new"; then
      awk -v d="$DATA_DIR" '!done && /^WorkingDirectory=/ { print; print "Environment=OPA_DATA_DIR=" d; print "Environment=PYTHONDONTWRITEBYTECODE=1"; done=1; next } { print }' \
        "$_frag.new" > "$_frag.new2" && mv "$_frag.new2" "$_frag.new"
    fi
    if [ "$_u" = "$SERVICE_NAME" ] && ! grep -q '^ProtectSystem=' "$_frag.new"; then
      awk '!done && /^ProtectHome=/ { print "ProtectSystem=strict"; done=1 } { print }' "$_frag.new" > "$_frag.new2" && mv "$_frag.new2" "$_frag.new"
    fi
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
  note "    Fresh install: create the environment file ($ENV_FILE) and the units per docs/hosting.md, using"
  note "    WorkingDirectory=$OPT_DIR/current and OPA_DATA_DIR=$DATA_DIR (server/opa-compliance-wizard.service has both)."
fi

if [ -n "$APPLY_NGINX" ]; then
  note "==> nginx"
  "$PY3" -I "$OPT_DIR/updater/ocw_activate.py" cli nginx-sync || note "WARNING: the nginx template was not applied (see above); the maintenance page will not show until it is"
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

systemctl daemon-reload
systemctl enable ocw-upgrade.path ocw-upgrade.service >/dev/null 2>&1 || note "WARNING: could not enable ocw-upgrade.path / ocw-upgrade.service"
systemctl start ocw-upgrade.path || note "WARNING: could not start ocw-upgrade.path"
note ""
note "Done. Next:"
note "  ocw-updater status                      what is installed and ready"
note "  sudo ocw-updater apply <version>        upgrade (staging, backup, switch, health checks, automatic rollback)"
note "  sudo server/install.sh --apply-nginx    (if you did not pass it) once, so other users see a maintenance page while it switches"
