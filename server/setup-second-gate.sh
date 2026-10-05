#!/usr/bin/env bash
# One-time setup of an ADDITIONAL auth gate for a second Okta org on this server (5.38.1).
# The existing gate, its env file and its nginx site are not replaced; the only shared-file change is
# adding the new origin to EXTRA_ALLOWED_ORIGINS. See docs/hosting.md "Serving a second Okta org".
#
# Run ON THE SERVER as the app user (not root, not with sudo); it uses sudo itself:
#   bash server/setup-second-gate.sh \
#     --name second --org-url https://login.example.com --auth-server org \
#     --client-id 0oa... --admin-group 00g... --origin https://opa.example.com \
#     [--port 8768] [--listen 127.0.0.1:8080] [--env-name <keyring namespace>] [--tunnel]
#
#   --name         short id: unit opa-auth-gate-<name>, env file /etc/opa-compliance-wizard-<name>.env,
#                  session-key folder /etc/opa-auth-gate-<name>, nginx site opa-<name>
#   --auth-server  default | org | <custom authorization server id>   (OKTA_AUTH_SERVER)
#   --listen       where the new nginx site listens (default 127.0.0.1:8080, loopback for a tunnel;
#                  TLS is expected to end in front of it, so X-Forwarded-Proto is set to https)
#   --tunnel       also install cloudflared and connect a Cloudflare Tunnel with the token staged in
#                  ~/.opa-setup/tunnel-token (shredded after use)
# Secrets never go on the command line: the Okta client secret is read from ~/.opa-setup/<name>-client-secret
# (shredded after use) and the read-only admin-check token is asked for with hidden input.
# Safe to re-run: every step checks before changing anything.
set -euo pipefail

NAME="" ORG_URL="" AUTH_SERVER="default" CLIENT_ID="" ADMIN_GROUP="" ORIGIN="" PORT=8768
LISTEN=127.0.0.1:8080 ENV_NAME="" TUNNEL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --name) NAME=$2; shift 2;;            --org-url) ORG_URL=$2; shift 2;;
    --auth-server) AUTH_SERVER=$2; shift 2;; --client-id) CLIENT_ID=$2; shift 2;;
    --admin-group) ADMIN_GROUP=$2; shift 2;; --origin) ORIGIN=$2; shift 2;;
    --port) PORT=$2; shift 2;;            --listen) LISTEN=$2; shift 2;;
    --env-name) ENV_NAME=$2; shift 2;;    --tunnel) TUNNEL=1; shift;;
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
[[ "$ENV_NAME" =~ ^[A-Za-z0-9_-]{1,40}$ ]] || die "--env-name looks wrong"
[ "$(id -u)" != 0 ] || die "run as the app user, not root (the script uses sudo itself)"
APP_USER=$(id -un); APP_UID=$(id -u)
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
[ -f "$APP/server/gate_config.py" ] || die "this checkout has no server/gate_config.py (needs 5.38.0+)"
[ -f "$MAIN_ENV" ] && [ -f "$MAIN_SITE" ] && [ -f "$MAIN_UNIT" ] || die "main env file, nginx site or gate unit not found"
systemctl is-active --quiet opa-auth-gate || die "the main gate (opa-auth-gate) is not running; fix that first"
sudo -v || die "sudo needed"
ok "$APP_USER, $(grep -m1 '^SCRIPT_VERSION' "$APP/create_secret_folders.py" | cut -d'"' -f2), main gate running"

say "2. Backups"
B=$HOME/opa-backups/second-gate-$NAME-$(date +%Y%m%d-%H%M%S); mkdir -p "$B"; chmod 700 "$B"
sudo cp -p "$MAIN_ENV" "$MAIN_SITE" "$B/"; sudo chown "$APP_USER:$APP_USER" "$B"/*
ok "$B"

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
    sudo cloudflared service install "$(cat "$STAGE/tunnel-token")" >/dev/null 2>&1
    shred -u "$STAGE/tunnel-token"
    ok "tunnel connector installed (staged token deleted)"
  else
    warn "no staged tunnel token in $STAGE/tunnel-token; stage it and re-run"
  fi
fi

say "4. Gate for $ORG_URL"
if [ ! -f "$NEW_ENV" ]; then
  tmp=$(mktemp); chmod 600 "$tmp"
  {
    echo "# Additional OPA auth gate '$NAME': $ORG_URL on $ORIGIN (setup-second-gate.sh, $(date +%F))"
    echo "OKTA_ORG_URL=$ORG_URL"
    echo "OKTA_AUTH_SERVER=$AUTH_SERVER"
    echo "OKTA_OIDC_CLIENT_ID=$CLIENT_ID"
    echo "OKTA_ADMIN_GROUP_ID=$ADMIN_GROUP"
    echo "OKTA_ENV_NAME=$ENV_NAME"
    echo "DASHBOARD_ORIGIN=$ORIGIN"
    echo "OPA_SESSION_KEY_PATH=$KEY_DIR/session.key"
    echo "DEPLOYMENT_MODE=hosted"
    # Shared with the main gate: the same keyring unlock password and nginx-to-backend secret.
    grep -E '^(KEYRING_UNLOCK_PASSWORD|NGINX_PROXY_SECRET)=' "$MAIN_ENV"
  } > "$tmp"
  sudo install -o "$APP_USER" -g "$APP_USER" -m 600 "$tmp" "$NEW_ENV"; rm -f "$tmp"
  ok "created $NEW_ENV (600)"
else
  ok "$NEW_ENV already exists (left as is)"
fi
sudo install -d -o "$APP_USER" -g "$APP_USER" -m 700 "$KEY_DIR"
ok "own session-key folder $KEY_DIR"

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
  echo "$APP_USER ALL=(root) NOPASSWD: /usr/bin/systemctl restart $UNIT_NAME" > "$B/sudoers"
  sudo visudo -cqf "$B/sudoers" || die "generated sudoers line failed validation"
  sudo install -m 440 "$B/sudoers" "$SUDOERS"
  ok "sudoers: $APP_USER may restart $UNIT_NAME (for deploy.sh)"
fi

say "5. nginx site for $ORIGIN on $LISTEN"
if [ ! -f "$NEW_SITE" ]; then
  # Built from the LIVE main site, so the proxy secret is copied, never typed: keep its HTTPS server block,
  # listen on $LISTEN, and send the sign-in routes to this gate.
  sudo python3 "$APP/server/nginx_second_site.py" "$MAIN_SITE" "$NEW_SITE" "$PORT" "$LISTEN" "$HOST" "$NAME"
  sudo chmod 640 "$NEW_SITE"; sudo chown root:www-data "$NEW_SITE" 2>/dev/null || true
  sudo ln -sf "$NEW_SITE" "/etc/nginx/sites-enabled/opa-$NAME"
  ok "created $NEW_SITE"
else
  ok "$NEW_SITE already exists"
fi
sudo nginx -t 2>&1 | tail -1
sudo systemctl reload nginx
ok "nginx reloaded"

say "6. Allow $ORIGIN in the backend"
if grep -q "^EXTRA_ALLOWED_ORIGINS=.*${HOST//./\\.}" "$MAIN_ENV"; then
  ok "already allowed"
elif grep -q "^EXTRA_ALLOWED_ORIGINS=" "$MAIN_ENV"; then
  sudo sed -i "s#^EXTRA_ALLOWED_ORIGINS=\(.*\)#EXTRA_ALLOWED_ORIGINS=\1,$ORIGIN#" "$MAIN_ENV"
  sudo systemctl restart opa-secrets-wizard; ok "added; backend restarted"
else
  echo "EXTRA_ALLOWED_ORIGINS=$ORIGIN" | sudo tee -a "$MAIN_ENV" >/dev/null
  sudo systemctl restart opa-secrets-wizard; ok "added; backend restarted"
fi

say "7. Start the gate"
if has_secret okta_client_secret && has_secret okta_admin_check_token; then
  systemctl show -p EnvironmentFiles "$UNIT_NAME" | grep -q "$NEW_ENV" \
    || die "$UNIT_NAME is not configured with $NEW_ENV; not starting it"
  sudo systemctl enable --now "$UNIT_NAME" >/dev/null 2>&1; sudo systemctl restart "$UNIT_NAME"; sleep 3
  systemctl is-active --quiet "$UNIT_NAME" && ok "$UNIT_NAME running" \
    || { warn "not running; last log lines:"; sudo journalctl -u "$UNIT_NAME" -n 8 --no-pager -o cat; }
else
  warn "not started (needs the client secret and the admin-check token in the keyring)"
fi

say "8. Verify"
main=$(curl -sk -o /dev/null -w '%{redirect_url}' https://127.0.0.1/login)
ok "main gate login -> ${main%%/oauth2*}  (should be unchanged)"
if systemctl is-active --quiet "$UNIT_NAME"; then
  r=$(curl -s -o /dev/null -w '%{redirect_url}' -H "Host: $HOST" "http://$LISTEN/login")
  case "$r" in
    "$ORG_URL"/oauth2/*client_id=$CLIENT_ID*) ok "$ORIGIN login -> $ORG_URL (client $CLIENT_ID)";;
    *) sudo systemctl disable --now "$UNIT_NAME" >/dev/null 2>&1 || true
       die "$ORIGIN login goes to ${r%%\?*}, not $ORG_URL: stopped and disabled $UNIT_NAME";;
  esac
fi
[ "$TUNNEL" = 1 ] && { systemctl is-active --quiet cloudflared && ok "cloudflared running" || warn "cloudflared not running"; }
for s in nginx opa-secrets-wizard opa-auth-gate "$UNIT_NAME" cloudflared; do
  printf '   %-24s %s\n' "$s" "$(systemctl is-active "$s" 2>/dev/null || true)"
done
echo; echo "Done. Backups: $B"
