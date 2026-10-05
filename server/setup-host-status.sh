#!/usr/bin/env bash
# One-time setup of the optional read-only host status service (server/host_status.py, 5.39.0).
# It answers GET /__status on 127.0.0.1 only; publish it behind your access gate (e.g. a Cloudflare
# Tunnel path rule protected by Cloudflare Access) -- never directly. See docs/hosting.md
# "Host status for monitoring".
#
# Run ON THE SERVER as the app user (not root); it uses sudo itself:
#   bash server/setup-host-status.sh --services "nginx opa-secrets-wizard opa-auth-gate cloudflared" [--port 8790]
#
# Installs unit opa-host-status (runs as the app user, sandboxed read-only, no capabilities) and a
# sudoers line so server/deploy.sh can restart it. Safe to re-run: the unit is regenerated each time.
set -euo pipefail

SERVICES="" PORT=8790
while [ $# -gt 0 ]; do
  case "$1" in
    --services) SERVICES=$2; shift 2;;
    --port) PORT=$2; shift 2;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
done

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '   \033[32mOK\033[0m %s\n' "$*"; }
die()  { printf '   \033[31mSTOP\033[0m %s\n' "$*"; exit 1; }

UNIT_NAME=opa-host-status
UNIT=/etc/systemd/system/$UNIT_NAME.service
SUDOERS=/etc/sudoers.d/$UNIT_NAME

say "1. Checks"
[ "$(id -u)" != 0 ] || die "run as the app user, not root (the script uses sudo itself)"
APP_USER=$(id -un)
APP=$(cd "$(dirname "$0")/.." && pwd -P)
[ -f "$APP/server/host_status.py" ] || die "this checkout has no server/host_status.py (needs 5.39.0+)"
[ -x /usr/bin/python3 ] || die "/usr/bin/python3 not found"
sudo -v || die "sudo needed"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
# build_unit validates the app dir, user, port and service names; any bad value stops here.
/usr/bin/python3 "$APP/server/host_status.py" --port "$PORT" --print-unit "$APP" "$APP_USER" "$SERVICES" > "$T/unit" \
  || die "invalid --services/--port (service names: letters, digits, @._- ; port not 8766-8768)"
ok "$APP_USER, port $PORT, services: $SERVICES"

say "2. Unit + sudoers"
sudo install -m 644 "$T/unit" "$UNIT"
echo "$APP_USER ALL=(root) NOPASSWD: /usr/bin/systemctl restart $UNIT_NAME" > "$T/sudoers"
sudo visudo -cqf "$T/sudoers" || die "generated sudoers line failed validation"
sudo install -m 440 "$T/sudoers" "$SUDOERS"
sudo systemctl daemon-reload
sudo systemctl enable --quiet "$UNIT_NAME"
sudo systemctl restart "$UNIT_NAME"
ok "$UNIT_NAME enabled and (re)started; deploy.sh restarts it on each deploy"

say "3. Check"
for _ in 1 2 3 4 5; do
  if BODY=$(curl -sf --max-time 70 "http://127.0.0.1:$PORT/__status"); then
    ok "answering on 127.0.0.1:$PORT: $(printf '%s' "$BODY" | /usr/bin/python3 -c 'import json,sys; d=json.load(sys.stdin); print("state", d["state"], "|", d["os"], "|", ", ".join(f"{k} {v}" for k, v in d["services"].items()))')"
    exit 0
  fi
  sleep 1
done
die "no answer on 127.0.0.1:$PORT -- see: journalctl -u $UNIT_NAME -n 30"
