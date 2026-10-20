#!/bin/bash
# =====================================================================================================================
# tests/integration/updater-vm.sh -- a REAL-systemd integration test of the upgrade layout (server/install.sh, the
# root-owned updater, the units, the nginx maintenance page, the signed-release flow).
#
# RUN IT LOCALLY, AS ROOT, ON A THROWAWAY DEBIAN/UBUNTU VM THAT HAS NO REAL DATA. It is NOT run by CI (it needs systemd,
# installs packages and services, and takes several minutes).
#
# SYNTHETIC DATA ONLY (owner rule: the test VM "will never have real data or environments"). Everything this script creates
# is made up for the run and removed at the end:
#   * a throwaway test environment named "vm-test-example" with the fake tenant "vm-test-example.example.com" and no credentials;
#   * dummy secrets generated here with openssl (the proxy secret, the keyring unlock password): never real Okta/OPA credentials,
#     never a real keyring entry;
#   * TEST-ONLY signing keys generated here (tests/integration/make_test_release.py keygen) and installed as the server's trust
#     list. The project's real release and standby keys are never used, read or needed: this script cannot sign a real release.
#   * a stand-in login gate (a few lines of Python answering 401 on /verify) instead of the real Okta gate; a self-signed
#     certificate for vm-test.example.com; a throwaway account ocwvm.
# It refuses to run if it finds anything that looks like a real install (the unit, the env file, /opt/opa-compliance-wizard,
# the ocw-updater account, an nginx site) unless that is its OWN leftover from an earlier run (marker file).
#
# WHAT IT INSTALLS (apt: nginx gnome-keyring dbus-user-session python3-venv python3-cryptography curl openssl; the packages stay)
#   accounts ocwvm (the web application's account) and ocw-updater; /opt/opa-compliance-wizard; /var/lib/opa-compliance-wizard;
#   /var/lib/ocw-updater; the units opa-compliance-wizard, opa-auth-gate (stand-in), ocw-stage@, ocw-upgrade.*, ocw-upgrade-due.*;
#   /usr/local/bin/ocw-updater; an nginx site and /etc/nginx/ssl test certificate; /etc/opa-compliance-wizard.env;
#   /etc/ocw-updater.env; work files in /var/tmp/ocw-vm-test. It needs the network (PyPI for `pip install --require-hashes`).
#
# WHAT IT DOES (each line is an assertion; a summary and a non-zero exit status at the end if any failed)
#   1  builds a "legacy" in-home install (version 98.0.1) the way docs/hosting.md describes, with seeded synthetic data
#   2  install.sh --dry-run changes nothing; install.sh migrates (data moved, units rewritten with the keyring and /run/user
#      carve-outs kept, the app comes back healthy, original data kept as *.migrated-*)
#   3  stages and applies a good signed release (98.0.2) while polling the site: the maintenance page (503, no version number)
#      is seen, the final answer is 200; backup taken; audit events and a state file exist; the activator updated itself
#   4  stages and applies a release whose application crashes at start (98.0.3): automatic code-only rollback, exit 3, a
#      support bundle exists and contains NONE of the synthetic secrets; the failed version is refused until clear-failure
#   5  a release signed by a stranger's key is refused (exit 2); a tampered staged tree is refused by root
#   6  power loss: the updater is killed at a step boundary by fault injection (a systemd drop-in, only honoured with
#      OCW_TEST_MODE=1), then resumed by starting ocw-upgrade.service; no reboot is needed (--reboot-test also does a real one)
#   7  rollback (typed) and restore (typed) work; a scheduled upgrade (--at) runs from the timer
#   8  records `systemctl show` for the root unit's sandbox so the capability set can be tightened from what actually ran
#
# CLEAN UP: the script removes everything it created when it ends (also on failure or Ctrl-C), in reverse order: units,
# the nginx site, /opt/opa-compliance-wizard, /var/lib/opa-compliance-wizard, /var/lib/ocw-updater, the env files, the accounts,
# the work directory. Re-run `sudo tests/integration/updater-vm.sh --cleanup-only` to clean up after a crash. --keep leaves it all in
# place for inspection (then --cleanup-only removes it). Installed apt packages are not removed.
#
# USAGE (as root, from a checkout of the version under test):
#   OCW_VM_TEST_CONFIRM=I-UNDERSTAND-THIS-INSTALLS-AND-REMOVES-TEST-SERVICES sudo -E tests/integration/updater-vm.sh [--keep] [--skip-apt] [--reboot-test]
#   sudo tests/integration/updater-vm.sh --cleanup-only
# =====================================================================================================================
set -euo pipefail

CHECKOUT="$(cd "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
WORK=/var/tmp/ocw-vm-test
MARKER="$WORK/.created-by-updater-vm-test"
TEST_USER=ocwvm
TEST_HOME=/home/ocwvm
LEGACY="$TEST_HOME/opa"
OPT=/opt/opa-compliance-wizard
DATA=/var/lib/opa-compliance-wizard
SITE_NAME=vm-test.example.com
FAKE_ENV=vm-test-example
ENV_FILE=/etc/opa-compliance-wizard.env
NGINX_SITE=/etc/nginx/sites-available/opa-secrets-wizard
KEEP="" SKIP_APT="" REBOOT_TEST="" CLEANUP_ONLY=""
PASS=0 FAIL=0
FAILED_NAMES=()

for a in "$@"; do
  case "$a" in
    --keep) KEEP=1 ;;
    --skip-apt) SKIP_APT=1 ;;
    --reboot-test) REBOOT_TEST=1 ;;
    --cleanup-only) CLEANUP_ONLY=1 ;;
    -h | --help) sed -n '2,52p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument $a" >&2; exit 2 ;;
  esac
done

say() { printf '\n==> %s\n' "$*"; }
ok() { PASS=$((PASS + 1)); printf '  ok    %s\n' "$*"; }
bad() { FAIL=$((FAIL + 1)); FAILED_NAMES+=("$*"); printf '  FAIL  %s\n' "$*"; }
DIAG_N=0
diag() { # what to look at when a check failed (printed, and kept in $WORK/diag-N.txt): the updater's own view of the run
  DIAG_N=$((DIAG_N + 1))
  [ "$DIAG_N" -le 8 ] || return 0
  {
    echo "---- diagnostics #$DIAG_N ----"
    echo "-- ocw-updater status --json"; /usr/local/bin/ocw-updater status --json 2>&1 | tail -n 60
    echo "-- state.json"; cat "$DATA/upgrade/state.json" 2>&1 | tail -n 60
    echo "-- journal: ocw-upgrade.service (last 50)"; journalctl -u ocw-upgrade.service --no-pager -o cat -n 50 2>&1
    echo "-- journal: opa-compliance-wizard (last 50)"; journalctl -u opa-compliance-wizard --no-pager -o cat -n 50 2>&1
    echo "-- ls releases / staging"; ls -la "$OPT/releases" "$OPT/staging" 2>&1
  } 2>&1 | tee "$WORK/diag-$DIAG_N.txt" | sed 's/^/        /'
}
check() { # check "description" command...   (on failure: the exit status, the command's output tail, and the diagnostics above)
  local d="$1" out rc
  shift
  out="$("$@" 2>&1)" && rc=0 || rc=$?
  if [ "$rc" -eq 0 ]; then ok "$d"; else
    bad "$d"
    printf '        exit status %s; command: %s\n' "$rc" "$*"
    printf '%s\n' "$out" | tail -n 15 | sed 's/^/        | /'
    diag
  fi
}
check_not() {
  local d="$1" out rc
  shift
  out="$("$@" 2>&1)" && rc=0 || rc=$?
  if [ "$rc" -ne 0 ]; then ok "$d"; else
    bad "$d"
    printf '        unexpectedly succeeded; command: %s\n' "$*"
    printf '%s\n' "$out" | tail -n 15 | sed 's/^/        | /'
    diag
  fi
}
die() { echo "ERROR: $*" >&2; exit 1; }

# --------------------------------------------------------------------------------------------------------------------
cleanup() {
  local rc=${1:-0}
  set +e
  if [ -n "$KEEP" ] && [ -z "$CLEANUP_ONLY" ]; then
    echo "--keep: leaving the test install in place; remove it with: sudo $0 --cleanup-only"
    return $rc
  fi
  if [ ! -f "$MARKER" ]; then
    [ -z "$CLEANUP_ONLY" ] || echo "no marker file: nothing of this script's to clean up (it never removes anything else)"
    return $rc
  fi
  say "Cleaning up everything this script created"
  systemctl stop ocw-upgrade.path ocw-upgrade-due.timer ocw-upgrade.service opa-compliance-wizard opa-auth-gate 2>/dev/null
  systemctl disable ocw-upgrade.path ocw-upgrade.service ocw-upgrade-due.timer opa-compliance-wizard opa-auth-gate 2>/dev/null
  rm -f /etc/systemd/system/{opa-compliance-wizard,opa-auth-gate,ocw-stage@,ocw-upgrade,ocw-upgrade-due}.service \
    /etc/systemd/system/ocw-upgrade.path /etc/systemd/system/ocw-upgrade-due.timer
  rm -rf /etc/systemd/system/ocw-upgrade.service.d
  systemctl daemon-reload
  rm -f /etc/nginx/sites-enabled/opa-secrets-wizard "$NGINX_SITE" /etc/nginx/ssl/opa-secrets-wizard.crt /etc/nginx/ssl/opa-secrets-wizard.key
  systemctl reload nginx 2>/dev/null
  rm -rf "$OPT" "$DATA" /var/lib/ocw-updater /var/cache/ocw-updater /opt/ocw-vm-test
  rm -f /usr/local/bin/ocw-updater "$ENV_FILE" /etc/ocw-updater.env "$ENV_FILE".bak*
  loginctl disable-linger "$TEST_USER" 2>/dev/null
  userdel -r "$TEST_USER" 2>/dev/null
  userdel ocw-updater 2>/dev/null
  rm -rf "$WORK"
  echo "clean."
  return $rc
}
trap 'cleanup $?' EXIT

[ "$(id -u)" -eq 0 ] || die "run as root"
if [ -n "$CLEANUP_ONLY" ]; then exit 0; fi
[ "${OCW_VM_TEST_CONFIRM:-}" = "I-UNDERSTAND-THIS-INSTALLS-AND-REMOVES-TEST-SERVICES" ] || die "set OCW_VM_TEST_CONFIRM=I-UNDERSTAND-THIS-INSTALLS-AND-REMOVES-TEST-SERVICES (read the header of this file first)"
[ "$(ps -p 1 -o comm= 2>/dev/null)" = "systemd" ] || die "this needs a real systemd host (a throwaway VM)"
. /etc/os-release
case "${ID:-}${ID_LIKE:-}" in *debian* | *ubuntu*) ;; *) die "written for Debian/Ubuntu (apt)" ;; esac

if [ -f "$MARKER" ]; then
  echo "found this script's own leftovers from an earlier run: cleaning them first"
  KEEP_SAVED="$KEEP"; KEEP=""
  cleanup 0
  KEEP="$KEEP_SAVED"
  mkdir -p "$WORK"
fi
for p in "$OPT" "$DATA" "$ENV_FILE" /etc/systemd/system/opa-compliance-wizard.service /etc/systemd/system/opa-secrets-wizard.service \
  /etc/systemd/system/opa-auth-gate.service "$NGINX_SITE" /etc/nginx/sites-enabled/opa-secrets-wizard /var/lib/ocw-updater; do
  [ ! -e "$p" ] || die "$p exists and is not from an earlier run of this script: this does not look like a throwaway VM. Refusing."
done
id ocw-updater >/dev/null 2>&1 && die "the ocw-updater account exists: this does not look like a throwaway VM. Refusing."
id "$TEST_USER" >/dev/null 2>&1 && die "the $TEST_USER account exists: refusing."
mkdir -p "$WORK"
touch "$MARKER"

# --------------------------------------------------------------------------------------------------------------------
say "Packages"
if [ -z "$SKIP_APT" ]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq nginx gnome-keyring dbus-user-session python3-venv python3-cryptography curl openssl rsync >/dev/null
fi
for c in nginx curl openssl python3 rsync runuser loginctl; do command -v "$c" >/dev/null || die "missing command $c"; done
systemctl stop nginx 2>/dev/null || true
rm -f /etc/nginx/sites-enabled/default

say "Synthetic data: account, secrets, keys, releases"
useradd --create-home --home-dir "$TEST_HOME" --shell /usr/sbin/nologin "$TEST_USER"
TEST_UID="$(id -u "$TEST_USER")"
loginctl enable-linger "$TEST_USER"
for _ in $(seq 1 20); do [ -d "/run/user/$TEST_UID" ] && break; sleep 1; done
[ -d "/run/user/$TEST_UID" ] || die "/run/user/$TEST_UID did not appear (dbus-user-session / linger)"
mkdir -p "$TEST_HOME/.local/share/keyrings"
chown -R "$TEST_USER:$TEST_USER" "$TEST_HOME/.local"
PROXY_SECRET="$(openssl rand -hex 24)"
KEYRING_PW="$(openssl rand -hex 16)"
KEYS="$WORK/keys"
REL="$WORK/releases"
python3 "$CHECKOUT/tests/integration/make_test_release.py" keygen "$KEYS"
python3 "$CHECKOUT/tests/integration/make_test_release.py" build "$CHECKOUT" "$KEYS" "$REL" 98.0.2
python3 "$CHECKOUT/tests/integration/make_test_release.py" build "$CHECKOUT" "$KEYS" "$REL" 98.0.3 --break crash
python3 "$CHECKOUT/tests/integration/make_test_release.py" build "$CHECKOUT" "$KEYS" "$REL" 98.0.4 --sign-with other
python3 "$CHECKOUT/tests/integration/make_test_release.py" build "$CHECKOUT" "$KEYS" "$REL" 98.0.5
python3 "$CHECKOUT/tests/integration/make_test_release.py" build "$CHECKOUT" "$KEYS" "$REL" 98.0.6
python3 "$CHECKOUT/tests/integration/make_test_release.py" build "$CHECKOUT" "$KEYS" "$REL" 98.0.7
umask 022

say "1. A legacy in-home install (98.0.1) with seeded synthetic data"
mkdir -p "$LEGACY"
rsync -a --exclude .git --exclude .venv --exclude node_modules --exclude __pycache__ --exclude '*.db*' --exclude audit_log.jsonl \
  --exclude 'tests/integration' --exclude .claude "$CHECKOUT/" "$LEGACY/"
sed -i -E 's/^SCRIPT_VERSION = "[^"]+"/SCRIPT_VERSION = "98.0.1"/' "$LEGACY/create_secret_folders.py"
cp "$KEYS/release_keys.json" "$LEGACY/server/release_keys.json"
mkdir -p "$LEGACY/frontend/dist"
echo '<!doctype html><title>vm test build</title>' > "$LEGACY/frontend/dist/index.html"
python3 -m venv "$LEGACY/.venv"
"$LEGACY/.venv/bin/pip" install -q --require-hashes --only-binary=:all: -r "$LEGACY/requirements.lock"
chown -R "$TEST_USER:$TEST_USER" "$LEGACY"
chmod +x "$LEGACY"/server/*.sh
umask 077
cat > "$ENV_FILE" <<EOF
DEPLOYMENT_MODE=hosted
NGINX_PROXY_SECRET=$PROXY_SECRET
KEYRING_UNLOCK_PASSWORD=$KEYRING_PW
EOF
umask 022
# the unit the way docs/hosting.md installed it before 5.47.0: code, data and the three ReadWritePaths in the home directory
sed -e "s|__APP_DIR__|$LEGACY|g" -e "s|__APP_USER_HOME__|$TEST_HOME|g" -e "s|__APP_USER__|$TEST_USER|g" -e "s|/run/user/1000|/run/user/$TEST_UID|g" \
  -e "s|__DATA_DIR__|$LEGACY|g" -e '/^Environment=OPA_DATA_DIR=/d' -e '/^Environment=PYTHONDONTWRITEBYTECODE=/d' -e '/^ProtectSystem=/d' \
  "$CHECKOUT/server/opa-compliance-wizard.service" > /etc/systemd/system/opa-compliance-wizard.service
# the stand-in gate: answers 401 on /verify like the real gate does without a cookie
mkdir -p /opt/ocw-vm-test
cat > /opt/ocw-vm-test/fake_gate.py <<'EOF'
import http.server, sys
port = int(sys.argv[sys.argv.index("--port") + 1])
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        self.send_response(401); self.send_header("Content-Length", "0"); self.end_headers()
http.server.ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
EOF
cat > /etc/systemd/system/opa-auth-gate.service <<EOF
[Unit]
Description=Stand-in login gate for the updater VM test (answers 401 on /verify)
[Service]
User=$TEST_USER
WorkingDirectory=$LEGACY
ExecStart=/usr/bin/python3 /opt/ocw-vm-test/fake_gate.py --port 8767
Restart=on-failure
RestartSec=3
ReadWritePaths=$LEGACY
EOF
# nginx: a site built from the repo template with synthetic values and a self-signed certificate
mkdir -p /etc/nginx/ssl
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=$SITE_NAME" -keyout /etc/nginx/ssl/opa-secrets-wizard.key \
  -out /etc/nginx/ssl/opa-secrets-wizard.crt >/dev/null 2>&1
chmod 600 /etc/nginx/ssl/opa-secrets-wizard.key
sed -e "s|REPLACE_WITH_SERVER_NAME|$SITE_NAME|g" -e "s|REPLACE_WITH_NGINX_PROXY_SECRET_VALUE|$PROXY_SECRET|" \
  "$CHECKOUT/server/nginx-opa-secrets-wizard.conf" > "$NGINX_SITE"
chmod 640 "$NGINX_SITE"
ln -s "$NGINX_SITE" /etc/nginx/sites-enabled/opa-secrets-wizard
nginx -t >/dev/null 2>&1 || die "the synthetic nginx site does not pass nginx -t"
systemctl daemon-reload
systemctl enable --now opa-auth-gate opa-compliance-wizard >/dev/null 2>&1
systemctl start nginx
for _ in $(seq 1 40); do curl -sf http://127.0.0.1:8766/api/version >/dev/null 2>&1 && break; sleep 1; done
check "legacy install answers as 98.0.1" bash -c "curl -sf http://127.0.0.1:8766/api/version | grep -q '\"98.0.1\"'"
# synthetic seed rows: one fake environment (no credentials), one chain head, one audit line
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
runuser -u "$TEST_USER" -- "$LEGACY/.venv/bin/python" - "$LEGACY/audit_store.db" "$FAKE_ENV" "$NOW" <<'PY' || echo "  (note: could not seed every synthetic row; the test continues)"
import sqlite3, sys
db, env, now = sys.argv[1:4]
c = sqlite3.connect(db)
try:
    c.execute("INSERT OR IGNORE INTO app_environments (environment_id, owner_id, display_name, base_domain, team_name, key_id, okta_url, shared, created_at, updated_at) "
              "VALUES (?, 'vm-test-owner', ?, 'example.com', 'vm-test-team', 'vm-test-key-id', NULL, 0, ?, ?)", ("vm-test-env-id", env, now, now))
except sqlite3.Error as e:
    print("environment seed:", e)
c.execute("INSERT OR IGNORE INTO chain_heads (environment_id, manifest_id, head_hash, updated_at) VALUES (?, 'vm-m1', 'vm-head-1', ?)", ("vm-test-env-id", now))
c.commit()
PY
echo "{\"timestamp\":\"$NOW\",\"actor_email\":\"vm-test-admin@example.com\",\"actor_sub\":null,\"action\":\"vm.test.seed\",\"details\":{\"environment\":\"$FAKE_ENV\"},\"client_ip\":null,\"user_agent\":null}" >> "$LEGACY/audit_log.jsonl"
chown "$TEST_USER:$TEST_USER" "$LEGACY/audit_log.jsonl"

say "2. install.sh: dry run, then migration"
UPDATER_CMD=/usr/local/bin/ocw-updater
bash "$LEGACY/server/install.sh" --dry-run --app-user "$TEST_USER" > "$WORK/dryrun.txt"
check "dry run printed a plan" grep -q "Dry run: nothing was changed" "$WORK/dryrun.txt"
check "dry run created no layout" test ! -e "$OPT"
bash "$LEGACY/server/install.sh" --yes --app-user "$TEST_USER" --apply-nginx > "$WORK/install.txt" 2>&1 || { cat "$WORK/install.txt"; bad "install.sh exited non-zero"; }
check "current points at the migrated release" test "$(readlink "$OPT/current")" = "releases/98.0.1"
check "the root-owned code is not writable by the application account" bash -c "! runuser -u $TEST_USER -- touch $OPT/current/x 2>/dev/null"
check "the data moved to /var/lib" test -f "$DATA/audit_store.db"
check "the original data is kept, renamed" bash -c "ls $LEGACY/audit_store.db.migrated-* >/dev/null"
check "unit keeps the keyring carve-out" grep -q "ReadWritePaths=$TEST_HOME/.local/share/keyrings" /etc/systemd/system/opa-compliance-wizard.service
check "unit keeps the /run/user carve-out" grep -q "ReadWritePaths=/run/user/$TEST_UID" /etc/systemd/system/opa-compliance-wizard.service
check "application is active after the migration" systemctl is-active --quiet opa-compliance-wizard
wait_version() { for _ in $(seq 1 60); do curl -sf http://127.0.0.1:8766/api/version 2>/dev/null | grep -q "\"$1\"" && return 0; sleep 1; done; return 1; }
check "application answers as 98.0.1 from /opt" wait_version 98.0.1
check "nginx serves /healthz" bash -c "curl -sk --resolve $SITE_NAME:443:127.0.0.1 https://$SITE_NAME/healthz | grep -q status"
check "ocw-updater status works" bash -c "$UPDATER_CMD status | grep -q 'installed      98.0.1'"
check "the path unit is active" systemctl is-active --quiet ocw-upgrade.path
check "the stage unit template is installed" test -f /etc/systemd/system/ocw-stage@.service

# --------------------------------------------------------------------------------------------------------------------
poll_site() { # poll_site <seconds> <outfile>: record the HTTP status of /healthz every 0.2 s
  local end=$((SECONDS + $1))
  : > "$2"
  while [ $SECONDS -lt $end ]; do
    code="$(curl -sk -o "$WORK/poll.body" -w '%{http_code}' --resolve "$SITE_NAME:443:127.0.0.1" "https://$SITE_NAME/healthz" 2>/dev/null || true)"
    if [ "$code" = "503" ]; then cp "$WORK/poll.body" "$WORK/maintenance-page.html"; fi
    echo "$code $(grep -c 'Upgrading' "$WORK/poll.body" 2>/dev/null || true)" >> "$2"
    sleep 0.2
  done
}

watch_page() { # watch_page <seconds>: did the updater ever create the maintenance file? (separates "not written" from "not served")
  local end=$((SECONDS + $1))
  rm -f "$WORK/page-seen"
  while [ $SECONDS -lt $end ]; do [ ! -e "$OPT/maintenance/active.html" ] || cp "$OPT/maintenance/active.html" "$WORK/page-seen" 2>/dev/null; sleep 0.05; done
}

say "3. A good signed release (98.0.2), with the site polled during the switch"
check "the live nginx site carries the maintenance-page block" grep -q ocw_maintenance_page "$NGINX_SITE"
"$UPDATER_CMD" stage "$REL/ocw-98.0.2.tar.gz" > "$WORK/stage2.txt" 2>&1 || { cat "$WORK/stage2.txt"; bad "stage 98.0.2"; }
check "98.0.2 is staged under staging/, still owned by the staging account, and not yet in releases/" bash -c "test -f $OPT/staging/98.0.2/.staged && test \"\$(stat -c %U $OPT/staging/98.0.2/create_secret_folders.py)\" = ocw-updater && test ! -e $OPT/releases/98.0.2"
poll_site 150 "$WORK/poll2.txt" &
POLL=$!
watch_page 150 &
WATCH=$!
"$UPDATER_CMD" apply 98.0.2 --confirm-text 98.0.2 > "$WORK/apply2.txt" 2>&1 && RC=0 || RC=$?
sleep 3
kill "$POLL" "$WATCH" 2>/dev/null || true
wait "$POLL" "$WATCH" 2>/dev/null || true
cat "$WORK/apply2.txt" | sed 's/^/        apply: /'
check "apply 98.0.2 exits 0" test "$RC" -eq 0
check "the updater wrote the maintenance page while switching" test -s "$WORK/page-seen"
check "98.0.2 is live" wait_version 98.0.2
check "the maintenance page (503 with the 'Upgrading' text) was served while switching" grep -q '^503 [1-9]' "$WORK/poll2.txt"
check "the page contains no version number" bash -c "test -s $WORK/maintenance-page.html && ! grep -qE '[0-9]+\\.[0-9]+\\.[0-9]+' $WORK/maintenance-page.html"
check "the site ends at 200" bash -c "tail -1 $WORK/poll2.txt | grep -q '^200'"
check "the maintenance page file is gone" test ! -e "$OPT/maintenance/active.html"
check "a pre-upgrade backup exists, root-only" bash -c "test \"\$(stat -c %a $DATA/upgrade/backups/audit_store-pre-98.0.2-*.db)\" = 600"
check "state.json says completed" bash -c "grep -q '\"result\": \"completed\"' $DATA/upgrade/state.json"
check "audit log has upgrade.completed with a correlation id" bash -c "grep -q 'upgrade.completed' $DATA/audit_log.jsonl && grep -q 'upg-' $DATA/audit_log.jsonl"
check "previous points at 98.0.1" test "$(readlink "$OPT/previous")" = "releases/98.0.1"

say "4. A release whose application crashes at start (98.0.3): automatic rollback and a redacted bundle"
"$UPDATER_CMD" stage "$REL/ocw-98.0.3.tar.gz" >/dev/null 2>&1 || bad "stage 98.0.3"
"$UPDATER_CMD" apply 98.0.3 --confirm-text 98.0.3 > "$WORK/apply3.txt" 2>&1 && RC=0 || RC=$?
check "apply 98.0.3 exits 3 (rolled back)" test "$RC" -eq 3
check "98.0.2 is serving again" wait_version 98.0.2
BUNDLE="$(ls -1 "$DATA"/upgrade/bundles/ocw-support-98.0.2-to-98.0.3-*.tar.gz 2>/dev/null | head -1 || true)"
check "a support bundle was written" test -n "$BUNDLE"
if [ -n "$BUNDLE" ]; then
  mkdir -p "$WORK/bundle" && tar -xzf "$BUNDLE" -C "$WORK/bundle"
  check "the bundle holds none of the synthetic secrets" bash -c "! grep -rqE '$PROXY_SECRET|$KEYRING_PW' $WORK/bundle"
  check "the bundle holds no e-mail address, host name or environment name" bash -c "! grep -rqE 'vm-test-admin@example.com|$SITE_NAME|$FAKE_ENV|vm-test-team' $WORK/bundle"
  check "the bundle is under 5 MB" test "$(stat -c %s "$BUNDLE")" -lt 5242880
fi
"$UPDATER_CMD" stage "$REL/ocw-98.0.3.tar.gz" >/dev/null 2>&1 || true
"$UPDATER_CMD" apply 98.0.3 --confirm-text 98.0.3 > "$WORK/apply3b.txt" 2>&1 && RC=0 || RC=$?
check "the failed version is refused until clear-failure (exit 2)" test "$RC" -eq 2
check "clear-failure works" "$UPDATER_CMD" clear-failure

say "5. A stranger's signature, and a tampered staged tree"
"$UPDATER_CMD" stage "$REL/ocw-98.0.4.tar.gz" >/dev/null 2>&1 && RC=0 || RC=$?
check "a release signed by an unknown key is refused (exit 2)" test "$RC" -eq 2
"$UPDATER_CMD" stage "$REL/ocw-98.0.5.tar.gz" >/dev/null 2>&1
chmod u+w "$OPT/releases/98.0.5/requirements.lock" 2>/dev/null || true
echo "# tampered" >> "$OPT/releases/98.0.5/requirements.lock" 2>/dev/null || true
"$UPDATER_CMD" apply 98.0.5 --confirm-text 98.0.5 > "$WORK/apply5.txt" 2>&1 && RC=0 || RC=$?
check "a modified staged tree is refused by root (exit 2 or 3, never 0)" test "$RC" -ne 0
check "the running version did not change" wait_version 98.0.2

say "6. Power loss: killed at a step boundary, then resumed"
rm -rf "$OPT/releases/98.0.5" 2>/dev/null || true
"$UPDATER_CMD" stage "$REL/ocw-98.0.6.tar.gz" >/dev/null 2>&1 || bad "stage 98.0.6"
mkdir -p /etc/systemd/system/ocw-upgrade.service.d
printf '[Service]\nEnvironment=OCW_TEST_MODE=1\nEnvironment=OCW_UPDATER_FAULT=kill_at:restarting\n' > /etc/systemd/system/ocw-upgrade.service.d/fault.conf
systemctl daemon-reload
"$UPDATER_CMD" apply 98.0.6 --confirm-text 98.0.6 > "$WORK/apply6.txt" 2>&1 || true
sleep 3
check "the CLI told the operator the updater stopped (exit 4)" bash -c "grep -q 'stopped before finishing' $WORK/apply6.txt"
check "the updater was killed mid-flight (state has no result)" bash -c "grep -q '\"result\": null' $DATA/upgrade/state.json"
check "current already points at 98.0.6 (switched before the kill)" test "$(readlink "$OPT/current")" = "releases/98.0.6"
rm -rf /etc/systemd/system/ocw-upgrade.service.d
systemctl daemon-reload
systemctl start ocw-upgrade.service
check "the resume completed the upgrade" wait_version 98.0.6
check "state.json says completed after the resume" bash -c "grep -q '\"result\": \"completed\"' $DATA/upgrade/state.json"
if [ -n "$REBOOT_TEST" ]; then
  say "6b. A real reboot (the script cannot continue after it: re-run with --keep to inspect)"
  echo "reboot requested; after it, ocw-upgrade.service resumes at boot. Check: ocw-updater status"
  systemctl reboot
fi

say "7. Rollback, restore and a scheduled upgrade"
printf 'no\n' | "$UPDATER_CMD" rollback >/dev/null 2>&1 && RC=0 || RC=$?
check "rollback without the typed word is refused" test "$RC" -eq 2
"$UPDATER_CMD" rollback --confirm-text ROLLBACK > "$WORK/rollback.txt" 2>&1 && RC=0 || RC=$?
check "rollback (typed) succeeds" test "$RC" -eq 0
check "the previous code is serving" wait_version 98.0.2
"$UPDATER_CMD" restore --confirm RESTORE > "$WORK/restore.txt" 2>&1 && RC=0 || RC=$?
check "restore with the typed word succeeds" test "$RC" -eq 0
check "the replaced database was moved aside, not deleted" bash -c "ls $DATA/audit_store.db.pre-restore-* >/dev/null"
"$UPDATER_CMD" stage "$REL/ocw-98.0.7.tar.gz" >/dev/null 2>&1 || bad "stage 98.0.7"
WHEN="$(date -u -d '+2 minutes' '+%Y-%m-%d %H:%M')"
"$UPDATER_CMD" apply 98.0.7 --at "$WHEN" --tz UTC --confirm-text 98.0.7 > "$WORK/sched.txt" 2>&1 || bad "schedule 98.0.7"
check "the due timer is enabled while an upgrade is scheduled" systemctl is-enabled --quiet ocw-upgrade-due.timer
wait_version_for() { for _ in $(seq 1 "$2"); do curl -sf http://127.0.0.1:8766/api/version 2>/dev/null | grep -q "\"$1\"" && return 0; sleep 2; done; return 1; }
check "the scheduled upgrade ran from the timer" wait_version_for 98.0.7 150

say "8. The root unit's sandbox (for tightening CapabilityBoundingSet)"
systemctl show ocw-upgrade.service -p CapabilityBoundingSet -p ProtectSystem -p IPAddressDeny > "$WORK/sandbox.txt" || true
cat "$WORK/sandbox.txt"
check "no permission errors in the updater's journal" bash -c "! journalctl -u ocw-upgrade.service --no-pager 2>/dev/null | grep -qiE 'permission denied|operation not permitted'"
journalctl -u 'ocw-upgrade.service' -u 'ocw-stage@*' --no-pager -o cat 2>/dev/null | tail -n 40 > "$WORK/journal-tail.txt" || true

# --------------------------------------------------------------------------------------------------------------------
say "Summary: $PASS passed, $FAIL failed"
if [ "$FAIL" -gt 0 ]; then
  printf '  failed: %s\n' "${FAILED_NAMES[@]}"
  echo "  evidence is in $WORK until the clean-up at exit (use --keep to look around)"
  exit 1
fi
