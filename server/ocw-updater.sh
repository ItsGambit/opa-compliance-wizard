#!/bin/bash
# ocw-updater: the operator's command line for upgrades.
#
# server/install.sh renders this file (the __NAME__ words below are filled in)
# into /usr/local/bin/ocw-updater. It is only a dispatcher:
#
#   - commands that change the installation (stage, apply, cancel, rollback,
#     restore, bundle, clear-failure, trust, nginx-sync) and `status` are run by
#     the root-owned updater (<opt>/updater/ocw_activate.py), which is Python
#     standard library only and executes nothing from a release; the ones that
#     change anything refuse to run unless you are root (use sudo);
#   - the update check, `verify`, `audit` and `keys` are the application's own
#     `python -m server.updater`, run as the APPLICATION account (as root this
#     script drops to it with runuser, so files are never created root-owned).
#
# Run `ocw-updater help` for the list. See README, "Upgrading".
set -euo pipefail

OPT="__OPT_DIR__"
DATA="__DATA_DIR__"
APP_USER="__APP_USER__"
PY3="__PYTHON3__"
ARTIFACTS="__ARTIFACTS_DIR__"
ENV_FILE="__ENV_FILE__"

usage() {
  cat <<'EOF'
ocw-updater status [--json]                         what is installed, staged, scheduled; last run; keys; backups
ocw-updater stage <ocw-X.Y.Z.tar.gz | X.Y.Z>        verify + stage a signed release (air-gapped: from a file)   [root]
ocw-updater apply <X.Y.Z> [--at "YYYY-MM-DD HH:MM" [--tz ZONE]]   install a staged release (typed confirmation) [root]
ocw-updater cancel                                  cancel a scheduled upgrade                               [root]
ocw-updater rollback                                put the previous CODE back (typed ROLLBACK)              [root]
ocw-updater restore --confirm RESTORE               put the pre-upgrade ARCHIVE copy back (loses newer data) [root]
ocw-updater bundle [--correlation ID] [--include-hosts]   build a redacted support bundle                    [root]
ocw-updater clear-failure                           allow a version that failed to be tried again            [root]
ocw-updater prune-backups --keep N | --name FILE ... --confirm PRUNE   delete old pre-upgrade copies (never the newest) [root]
ocw-updater trust list | seed | add FILE | apply FILE   the signing keys root trusts                          [root to change]
ocw-updater nginx-sync                              apply the current release's nginx template (maintenance page) [root]
ocw-updater check [--force] | enable-check | disable-check | verify TAR SIG | audit | keys list | keys apply-revocation FILE
                                                    the update check and key tools (run as the application account)
EOF
}

as_app() {
  # Run the application's own Python module as the application account.
  cd "$OPT/current"
  if [ "$(id -u)" -eq 0 ]; then
    exec runuser -u "$APP_USER" -- env OPA_DATA_DIR="$DATA" PYTHONDONTWRITEBYTECODE=1 "$OPT/current/.venv/bin/python" -m server.updater "$@"
  fi
  exec env OPA_DATA_DIR="$DATA" PYTHONDONTWRITEBYTECODE=1 "$OPT/current/.venv/bin/python" -m server.updater "$@"
}

cmd="${1:-status}"
[ $# -gt 0 ] || set -- status
case "$cmd" in
  status | stage | apply | cancel | rollback | restore | bundle | clear-failure | prune-backups | trust | nginx-sync)
    # A CLEAN environment: whatever the caller exported (or sudo was told to keep) never reaches the root-run updater, which
    # also ignores OCW_* test and path overrides unless a root-owned marker file exists. This wrapper is the only supported
    # sudo target.
    exec env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C.UTF-8 SUDO_USER="${SUDO_USER:-}" \
      OCW_OPT_DIR="$OPT" OCW_DATA_DIR="$DATA" OCW_ARTIFACTS_DIR="$ARTIFACTS" OCW_ENV_FILE="$ENV_FILE" \
      "$PY3" -I -B "$OPT/updater/ocw_activate.py" cli "$@"
    ;;
  check | enable-check | disable-check | verify | audit | keys)
    as_app "$@"
    ;;
  help | -h | --help)
    usage
    ;;
  *)
    echo "ocw-updater: unknown command '$cmd'" >&2
    usage >&2
    exit 2
    ;;
esac
