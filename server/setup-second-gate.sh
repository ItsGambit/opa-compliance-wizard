#!/usr/bin/env bash
# One-time setup of an ADDITIONAL auth gate for a second Okta org on this server (5.38.1).
# The existing gate, its env file and its nginx site are not replaced; the only shared-file change is
# adding the new origin to EXTRA_ALLOWED_ORIGINS. See docs/hosting.md "Serving a second Okta org".
#
# Run ON THE SERVER as the app user (not root, not with sudo); it uses sudo itself:
#   bash server/setup-second-gate.sh \
#     --name second --org-url https://login.example.com --auth-server org \
#     --client-id 0oa... --admin-group 00g... --origin https://opa.example.com \
#     [--port 8768] [--listen 127.0.0.1:8080] [--allow-public-listen] [--env-name <keyring namespace>] [--tunnel]
#
#   --name         short id: unit opa-auth-gate-<name>, env file /etc/opa-compliance-wizard-<name>.env,
#                  session-key folder /etc/opa-auth-gate-<name>, nginx site opa-<name>
#   --auth-server  default | org | <custom authorization server id>   (OKTA_AUTH_SERVER)
#   --listen       where the new nginx site listens (default 127.0.0.1:8080, loopback for a tunnel;
#                  TLS is expected to end in front of it, so X-Forwarded-Proto is set to https).
#                  Must be 127.x.x.x unless --allow-public-listen is also given (5.40.5, GATE-15): the
#                  site is plain HTTP and carries the proxy secret path.
#   --tunnel       also install cloudflared and connect a Cloudflare Tunnel with the token staged in
#                  ~/.opa-setup/tunnel-token (shredded after use, whether or not the install worked)
# Secrets never go on THIS script's or sudo's command line: the Okta client secret is read from
# ~/.opa-setup/<name>-client-secret (shredded after use), the read-only admin-check token is asked for with
# hidden input, and the tunnel token is handed to `sudo sh -c` as a file path (sudo logs the full command
# line it runs; OPS-13). Note that `cloudflared service install <token>` itself writes the token into its
# own unit's ExecStart (/etc/systemd/system/cloudflared.service, normally world-readable) and the running
# connector shows it in its process arguments; see docs/hosting.md for keeping it in a root-only file.
# Safe to re-run: every step checks before changing anything; a generated nginx site that fails `nginx -t`
# is backed up and removed, never left enabled (OPS-14).
set -euo pipefail

# Temp/staged secret files this run must not leave behind, whatever happens.
_CLEANUP_FILES=()
_cleanup() {
  local f
  for f in ${_CLEANUP_FILES[@]+"${_CLEANUP_FILES[@]}"}; do
    [ -e "$f" ] || continue
    shred -u "$f" 2>/dev/null || rm -f "$f"
  done
}
trap _cleanup EXIT

NAME="" ORG_URL="" AUTH_SERVER="default" CLIENT_ID="" ADMIN_GROUP="" ORIGIN="" PORT=8768
LISTEN=127.0.0.1:8080 ENV_NAME="" TUNNEL=0 PUBLIC_LISTEN=0
while [ $# -gt 0 ]; do
  case "$1" in
    --name) NAME=$2; shift 2;;            --org-url) ORG_URL=$2; shift 2;;
    --auth-server) AUTH_SERVER=$2; shift 2;; --client-id) CLIENT_ID=$2; shift 2;;
    --admin-group) ADMIN_GROUP=$2; shift 2;; --origin) ORIGIN=$2; shift 2;;
    --port) PORT=$2; shift 2;;            --listen) LISTEN=$2; shift 2;;
    --env-name) ENV_NAME=$2; shift 2;;    --tunnel) TUNNEL=1; shift;;
    --allow-public-listen) PUBLIC_LISTEN=1; shift;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
done
ENV_NAME=${ENV_NAME:-$NAME}

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '   \033[32mOK\033[0m %s\n' "$*"; }
warn() { printf '   \033[33m!!\033[0m %s\n' "$*"; }
die()  { printf '   \033[31mSTOP\033[0m %s\n' "$*"; exit 1; }

say "1. Checks"
[[ "$NAME" =~ ^[a-z0-9]{1,20}$ ]] || die "--name: 1-20 lowercase letters/digits"
[[ "$ORG_URL" =~ ^https://[A-Za-z0-9.-]+$ ]] || die "--org-url: https://host (no path)"
[[ "$ORIGIN" =~ ^https://[A-Za-z0-9.-]+$ ]] || die "--origin: https://host (no path)"
[[ "$CLIENT_ID" =~ ^[A-Za-z0-9]{10,40}$ ]] || die "--client-id looks wrong"
[[ "$ADMIN_GROUP" =~ ^[A-Za-z0-9]{10,40}$ ]] || die "--admin-group looks wrong"
[[ "$AUTH_SERVER" =~ ^[A-Za-z0-9]{1,64}$ ]] || die "--auth-server: default, org or a server id"
[[ "$PORT" =~ ^[0-9]{4,5}$ ]] && [ "$PORT" != 8766 ] && [ "$PORT" != 8767 ] || die "--port: free port, not 8766/8767"
[[ "$LISTEN" =~ ^[0-9.]+:[0-9]{2,5}$ ]] || die "--listen: address:port"
[ "$PUBLIC_LISTEN" = 1 ] || [[ "$LISTEN" =~ ^127(\.[0-9]{1,3}){3}: ]] \
  || die "--listen: not a loopback address; add --allow-public-listen to publish this plain-HTTP site"
PUBLIC_LISTEN_ARG=()
[ "$PUBLIC_LISTEN" = 1 ] && PUBLIC_LISTEN_ARG=(--allow-public-listen)
[[ "$ENV_NAME" =~ ^[A-Za-z0-9_-]{1,40}$ ]] || die "--env-name looks wrong"
[ "$(id -u)" != 0 ] || die "run as the app user, not root (the script uses sudo itself)"
APP_USER=$(id -un); APP_GROUP=$(id -gn); APP_UID=$(id -u)
APP=$(cd "$(dirname "$0")/.." && pwd -P)
MAIN_ENV=/etc/opa-compliance-wizard.env
MAIN_SITE=/etc/nginx/sites-available/opa-secrets-wizard
MAIN_UNIT=/etc/systemd/system/opa-auth-gate.service
NEW_ENV=/etc/opa-compliance-wizard-$NAME.env
KEY_DIR=/etc/opa-auth-gate-$NAME
UNIT_NAME=opa-auth-gate-$NAME
UNIT=/etc/systemd/system/$UNIT_NAME.service
NEW_SITE=/etc/nginx/sites-available/opa-$NAME
SUDOERS=/etc/sudoers.d/opa-auth-gate-$NAME
STAGE=$HOME/.opa-setup
HOST=${ORIGIN#https://}
# BUG FIX (external review, 2026-10-05, OPS-01): the backend service unit
# was renamed opa-secrets-wizard -> opa-compliance-wizard at 5.20.0; this
# script hardcoded the OLD name in three places (the main-env restart
# below, and the final status table), which only works on an install
# that predates the rename. Detect which one is ACTUALLY installed, same
# approach as deploy.sh's own OPS-01 fix.
if systemctl cat opa-secrets-wizard >/dev/null 2>&1; then
  MAIN_SERVICE=opa-secrets-wizard
elif systemctl cat opa-compliance-wizard >/dev/null 2>&1; then
  MAIN_SERVICE=opa-compliance-wizard
else
  die "neither opa-secrets-wizard.service nor opa-compliance-wizard.service is installed"
fi
[ -f "$APP/server/gate_config.py" ] || die "this checkout has no server/gate_config.py (needs 5.38.0+)"
[ -f "$MAIN_ENV" ] && [ -f "$MAIN_SITE" ] && [ -f "$MAIN_UNIT" ] || die "main env file, nginx site or gate unit not found"
systemctl is-active --quiet opa-auth-gate || die "the main gate (opa-auth-gate) is not running; fix that first"
sudo -v || die "sudo needed"
ok "$APP_USER, $(grep -m1 '^SCRIPT_VERSION' "$APP/create_secret_folders.py" | cut -d'"' -f2), main gate running"

say "2. Backups"
B=$HOME/opa-backups/second-gate-$NAME-$(date +%Y%m%d-%H%M%S); mkdir -p "$B"; chmod 700 "$B"
sudo cp -p "$MAIN_ENV" "$MAIN_SITE" "$B/"; sudo chown "$APP_USER:$APP_GROUP" "$B"/*
ok "$B"

# OPS-13: the token goes to cloudflared through a root shell that reads the staged file -- sudo logs its full
# command line (journal / auth.log), so it records only the path. root can read the app user's 0600 file.
# The staged file is shredded whether or not the install works (the EXIT trap), and cloudflared's output,
# shown only on failure, has the token masked.
_install_tunnel_connector() {
  local staged="$1" out tok
  _CLEANUP_FILES+=("$staged")
  # shellcheck disable=SC2016  # $1 is expanded by the root shell, on purpose
  if ! out=$(sudo sh -c 'exec cloudflared service install "$(cat -- "$1")"' _ "$staged" 2>&1); then
    tok=$(cat -- "$staged")
    out=${out//"$tok"/<token>}
    unset tok
    printf '%s\n' "$out" | tail -n 15 >&2
    die "cloudflared service install failed (output above); the staged token was deleted -- stage it again and re-run"
  fi
  shred -u "$staged"
  ok "tunnel connector installed (staged token deleted)"
}

if [ "$TUNNEL" = 1 ]; then
  say "3. cloudflared"
  if ! command -v cloudflared >/dev/null; then
    sudo install -d -m 0755 /usr/share/keyrings
    curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
    echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" \
      | sudo tee /etc/apt/sources.list.d/cloudflared.list >/dev/null
    sudo apt-get update -qq && sudo apt-get install -y -qq cloudflared
  fi
  ok "$(cloudflared --version | head -1)"
  if systemctl is-enabled --quiet cloudflared 2>/dev/null; then
    ok "tunnel connector service already installed"
  elif [ -s "$STAGE/tunnel-token" ]; then
    _install_tunnel_connector "$STAGE/tunnel-token"
  else
    warn "no staged tunnel token in $STAGE/tunnel-token; stage it and re-run"
  fi
fi

say "4. Gate for $ORG_URL"
if [ ! -f "$NEW_ENV" ]; then
  tmp=$(mktemp); chmod 600 "$tmp"; _CLEANUP_FILES+=("$tmp")
  {
    echo "# Additional OPA auth gate '$NAME': $ORG_URL on $ORIGIN (setup-second-gate.sh, $(date +%F))"
    echo "OKTA_ORG_URL=$ORG_URL"
    echo "OKTA_AUTH_SERVER=$AUTH_SERVER"
    echo "OKTA_OIDC_CLIENT_ID=$CLIENT_ID"
    echo "OKTA_ADMIN_GROUP_ID=$ADMIN_GROUP"
    echo "OKTA_ENV_NAME=$ENV_NAME"
    echo "DASHBOARD_ORIGIN=$ORIGIN"
    echo "OPA_SESSION_KEY_PATH=$KEY_DIR/session.key"
    echo "OPA_ACCESS_CONTROL_PATH=$KEY_DIR/access_control.json"
    echo "DEPLOYMENT_MODE=hosted"
    # Shared with the main gate: the same keyring unlock password and nginx-to-backend secret.
    grep -E '^(KEYRING_UNLOCK_PASSWORD|NGINX_PROXY_SECRET)=' "$MAIN_ENV"
  } > "$tmp"
  sudo install -o "$APP_USER" -g "$APP_GROUP" -m 600 "$tmp" "$NEW_ENV"; rm -f "$tmp"
  ok "created $NEW_ENV (600)"
else
  ok "$NEW_ENV already exists (left as is)"
fi
sudo install -d -o "$APP_USER" -g "$APP_GROUP" -m 700 "$KEY_DIR"
ok "own session-key folder $KEY_DIR"
# Own access control (5.38.3): this org's admin group, sign-in restricted to it. The main
# access_control.json holds the main org's group IDs and must not be used by this gate.
AC_FILE=$KEY_DIR/access_control.json
if [ ! -f "$AC_FILE" ]; then
  printf '{"admin_group_id": "%s", "user_group_id": null, "restrict_login": true}\n' "$ADMIN_GROUP" > "$AC_FILE"
  chmod 600 "$AC_FILE"
  ok "own access control $AC_FILE (admins: $ADMIN_GROUP, sign-in restricted to them)"
else
  ok "own access control $AC_FILE already exists (left as is)"
fi
if ! grep -q "^OPA_ACCESS_CONTROL_PATH=" "$NEW_ENV"; then
  echo "OPA_ACCESS_CONTROL_PATH=$AC_FILE" >> "$NEW_ENV"
  ok "added OPA_ACCESS_CONTROL_PATH to $NEW_ENV"
fi

keyring_py() {
  env XDG_RUNTIME_DIR=/run/user/$APP_UID DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$APP_UID/bus \
    "$APP/.venv/bin/python" -c "$1" "opa-compliance-wizard:$ENV_NAME" "$2"
}
store_secret() { keyring_py 'import sys, keyring; keyring.set_password(sys.argv[1], sys.argv[2], sys.stdin.read().strip())' "$1"; }
has_secret()   { keyring_py 'import sys, keyring; sys.exit(0 if keyring.get_password(sys.argv[1], sys.argv[2]) else 1)' "$1"; }
if [ -s "$STAGE/$NAME-client-secret" ]; then
  store_secret okta_client_secret < "$STAGE/$NAME-client-secret"; shred -u "$STAGE/$NAME-client-secret"
  ok "Okta client secret stored in the keyring (staged copy deleted)"
elif has_secret okta_client_secret; then
  ok "Okta client secret already in the keyring"
else
  warn "no client secret staged in $STAGE/$NAME-client-secret or stored; stage it and re-run"
fi
if has_secret okta_admin_check_token; then
  ok "admin-check token already in the keyring"
else
  echo "   Paste the READ-ONLY Okta API token for the admin-group check (hidden; Enter to skip for now):"
  read -r -s ADMIN_TOKEN; echo
  if [ -n "$ADMIN_TOKEN" ]; then
    printf '%s' "$ADMIN_TOKEN" | store_secret okta_admin_check_token; unset ADMIN_TOKEN
    ok "admin-check token stored in the keyring"
  else
    warn "skipped: this gate can't start until it's stored (re-run this script)"
  fi
fi

# The unit is generated by server/unit_second_gate.py from the LIVE main unit (handles indented units;
# 5.38.1's sed skipped indented lines and left this gate on the main env file). An existing unit that
# doesn't use $NEW_ENV is backed up and regenerated, never kept.
if [ -f "$UNIT" ] && grep -Eq "^[[:space:]]*EnvironmentFile=${NEW_ENV}[[:space:]]*$" "$UNIT" \
   && ! grep -Eq "^[[:space:]]*EnvironmentFile=$MAIN_ENV" "$UNIT"; then
  ok "$UNIT_NAME.service already exists and uses $NEW_ENV"
else
  if [ -f "$UNIT" ]; then
    sudo systemctl disable --now "$UNIT_NAME" >/dev/null 2>&1 || true
    sudo cp -p "$UNIT" "$B/$UNIT_NAME.service.wrong"
    warn "existing $UNIT_NAME.service did not use $NEW_ENV: stopped it, backed it up, regenerating"
  fi
  python3 "$APP/server/unit_second_gate.py" "$MAIN_UNIT" "$B/$UNIT_NAME.service" "$NEW_ENV" "$PORT" "$KEY_DIR" \
    "OPA Compliance Wizard auth gate '$NAME' ($ORG_URL on $ORIGIN)" || die "could not generate $UNIT_NAME.service"
  sudo install -m 644 "$B/$UNIT_NAME.service" "$UNIT"
  sudo systemctl daemon-reload
  ok "created $UNIT_NAME.service (port $PORT, $NEW_ENV)"
fi
# server/deploy.sh restarts every enabled opa-auth-gate-* unit with `sudo -n`; grant exactly that.
if [ ! -f "$SUDOERS" ]; then
  # sudoers rules name a binary path; use this host's systemctl rather than assuming /usr/bin.
  echo "$APP_USER ALL=(root) NOPASSWD: $(command -v systemctl) restart $UNIT_NAME" > "$B/sudoers"
  sudo visudo -cqf "$B/sudoers" || die "generated sudoers line failed validation"
  sudo install -m 440 "$B/sudoers" "$SUDOERS"
  ok "sudoers: $APP_USER may restart $UNIT_NAME (for deploy.sh)"
fi

say "5. nginx site for $ORIGIN on $LISTEN"
LINK=/etc/nginx/sites-enabled/opa-$NAME
CREATED=0
if [ ! -f "$NEW_SITE" ]; then
  # Built from the LIVE main site, so the proxy secret is copied, never typed: keep its HTTPS server block,
  # listen on $LISTEN, and send the sign-in routes to this gate.
  sudo python3 "$APP/server/nginx_second_site.py" "$MAIN_SITE" "$NEW_SITE" "$PORT" "$LISTEN" "$HOST" "$NAME" \
    ${PUBLIC_LISTEN_ARG[@]+"${PUBLIC_LISTEN_ARG[@]}"}
  sudo chmod 640 "$NEW_SITE"; sudo chown root:www-data "$NEW_SITE" 2>/dev/null || true
  sudo ln -sf "$NEW_SITE" "$LINK"
  CREATED=1
  ok "created $NEW_SITE"
else
  [ -e "$LINK" ] || sudo ln -sf "$NEW_SITE" "$LINK"
  ok "$NEW_SITE already exists"
fi
# OPS-14: never leave a site enabled that breaks `nginx -t` -- every later reload (deploy.sh's included) and
# nginx's own start at boot would fail. If the config is invalid, find out whether this site is the cause by
# disabling it and testing again. (A function so tests/test_setup_second_gate_sh.py can run it with stubs.)
_validate_site_or_back_out() {
  local out
  if ! out=$(sudo nginx -t 2>&1); then
    printf '%s\n' "$out" >&2
    sudo rm -f "$LINK"
    if sudo nginx -t >/dev/null 2>&1; then
      sudo cp -p "$NEW_SITE" "$B/opa-$NAME.failed-site"; sudo chown "$APP_USER:$APP_GROUP" "$B/opa-$NAME.failed-site"
      chmod 600 "$B/opa-$NAME.failed-site"
      sudo rm -f "$NEW_SITE"
      die "the generated site $NEW_SITE failed 'nginx -t' (output above); it was removed (copy in $B) and nginx was not reloaded. Re-run after fixing the cause."
    fi
    if [ "$CREATED" = 1 ]; then
      sudo rm -f "$NEW_SITE"
    else
      sudo ln -sf "$NEW_SITE" "$LINK"
    fi
    die "nginx's configuration is invalid even without this site (output above) -- fix that first; nothing was reloaded."
  fi
}
_validate_site_or_back_out
sudo systemctl reload nginx
ok "nginx reloaded"

say "6. Allow $ORIGIN in the backend"
# The origin must be a whole comma-separated item (OPS-14: `opa.example.com` used to match an existing
# `xopa.example.com`).
_origin_already_allowed() {
  grep -Eq "^EXTRA_ALLOWED_ORIGINS=(.*,)?https://${1//./\\.}(,|$)" "$2"
}
if _origin_already_allowed "$HOST" "$MAIN_ENV"; then
  ok "already allowed"
elif grep -q "^EXTRA_ALLOWED_ORIGINS=" "$MAIN_ENV"; then
  sudo sed -i "s#^EXTRA_ALLOWED_ORIGINS=\(.*\)#EXTRA_ALLOWED_ORIGINS=\1,$ORIGIN#" "$MAIN_ENV"
  sudo systemctl restart "$MAIN_SERVICE"; ok "added; backend restarted"
else
  echo "EXTRA_ALLOWED_ORIGINS=$ORIGIN" | sudo tee -a "$MAIN_ENV" >/dev/null
  sudo systemctl restart "$MAIN_SERVICE"; ok "added; backend restarted"
fi

say "7. Start the gate"
if has_secret okta_client_secret && has_secret okta_admin_check_token; then
  systemctl show -p EnvironmentFiles "$UNIT_NAME" | grep -q "$NEW_ENV" \
    || die "$UNIT_NAME is not configured with $NEW_ENV; not starting it"
  out=$(sudo systemctl enable --now "$UNIT_NAME" 2>&1) || { printf '%s\n' "$out" >&2; die "could not enable $UNIT_NAME"; }
  sudo systemctl restart "$UNIT_NAME"; sleep 3
  systemctl is-active --quiet "$UNIT_NAME" && ok "$UNIT_NAME running" \
    || { warn "not running; last log lines:"; sudo journalctl -u "$UNIT_NAME" -n 8 --no-pager -o cat; }
else
  warn "not started (needs the client secret and the admin-check token in the keyring)"
fi

say "8. Verify"
main=$(curl -sk -o /dev/null -w '%{redirect_url}' https://127.0.0.1/login || true)
ok "main gate login -> ${main%%/oauth2*}  (should be unchanged)"
if systemctl is-active --quiet "$UNIT_NAME"; then
  r=$(curl -s -o /dev/null -w '%{redirect_url}' -H "Host: $HOST" "http://$LISTEN/login" || true)
  case "$r" in
    "$ORG_URL"/oauth2/*client_id=$CLIENT_ID*) ok "$ORIGIN login -> $ORG_URL (client $CLIENT_ID)";;
    *) sudo systemctl disable --now "$UNIT_NAME" >/dev/null 2>&1 || true
       die "$ORIGIN login goes to ${r%%\?*}, not $ORG_URL: stopped and disabled $UNIT_NAME";;
  esac
fi
[ "$TUNNEL" = 1 ] && { systemctl is-active --quiet cloudflared && ok "cloudflared running" || warn "cloudflared not running"; }
for s in nginx "$MAIN_SERVICE" opa-auth-gate "$UNIT_NAME" cloudflared; do
  printf '   %-24s %s\n' "$s" "$(systemctl is-active "$s" 2>/dev/null || true)"
done
echo; echo "Done. Backups: $B"
