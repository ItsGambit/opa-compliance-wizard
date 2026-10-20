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
#   7f the requests the web application may leave in the inbox, written as its account: a bundle for another run leaves
#      state.json byte-identical, a rollback outside 24 hours and a restore naming the wrong copy are refused, a 200-request
#      burst leaves bounded files, the quiesce file is renewed at every step, deleting backups is refused through the inbox
#      and works from the command line
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
  rm -f /etc/ocw-updater-test-mode
  systemctl daemon-reload
  rm -f /etc/nginx/sites-enabled/opa-secrets-wizard "$NGINX_SITE" /etc/nginx/ssl/opa-secrets-wizard.crt /etc/nginx/ssl/opa-secrets-wizard.key
  systemctl reload nginx 2>/dev/null
  rm -rf "$OPT" "$DATA" /var/lib/ocw-updater /var/cache/ocw-updater /opt/ocw-vm-test
  rm -f /usr/local/bin/ocw-updater "$ENV_FILE" /etc/ocw-updater.env "$ENV_FILE".bak*
  loginctl disable-linger "$TEST_USER" 2>/dev/null
  # The account's systemd user manager keeps running briefly after linger is off; userdel refuses while it does.
  loginctl terminate-user "$TEST_USER" 2>/dev/null
  for _ in $(seq 1 20); do pgrep -u "$TEST_USER" >/dev/null 2>&1 || break; sleep 0.5; done
  if id "$TEST_USER" >/dev/null 2>&1 && ! userdel -r "$TEST_USER" 2>/dev/null; then
    echo "WARNING: could not remove the $TEST_USER account; remove it with: sudo userdel -r $TEST_USER" >&2
  fi
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
python3 "$CHECKOUT/tests/integration/make_test_release.py" build "$CHECKOUT" "$KEYS" "$REL" 98.0.8 --template-comment
python3 "$CHECKOUT/tests/integration/make_test_release.py" build "$CHECKOUT" "$KEYS" "$REL" 98.0.9
python3 "$CHECKOUT/tests/integration/make_test_release.py" build "$CHECKOUT" "$KEYS" "$REL" 98.0.10 --break unhealthy
python3 "$CHECKOUT/tests/integration/make_test_release.py" build "$CHECKOUT" "$KEYS" "$REL" 98.0.11
python3 "$CHECKOUT/tests/integration/make_test_release.py" build "$CHECKOUT" "$KEYS" "$REL" 98.0.12
python3 "$CHECKOUT/tests/integration/make_test_release.py" revoke "$KEYS" "$REL/revocation.json"
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

say "3b. releases/ is root-only: the staging account cannot swap or add a release (the guarantee that nothing changes after the check)"
check "releases/ is root:root 0755" bash -c "test \"\$(stat -c '%U:%G %a' $OPT/releases)\" = 'root:root 755'"
check "staging/ belongs to the staging account" bash -c "test \"\$(stat -c %U $OPT/staging)\" = ocw-updater"
check "the applied tree is root-owned" bash -c "test \"\$(stat -c %U $OPT/releases/98.0.2/create_secret_folders.py)\" = root"
check_not "the staging account cannot move the current release away" runuser -u ocw-updater -- mv "$OPT/releases/98.0.2" /tmp/ocw-vm-moved
check_not "the staging account cannot add an entry to releases/" runuser -u ocw-updater -- touch "$OPT/releases/x"
check_not "the staging account cannot add a file to a release" runuser -u ocw-updater -- touch "$OPT/releases/98.0.2/x"
check "no release entry is setuid, setgid or group/other-writable" bash -c "test -z \"\$(find $OPT/releases ! -type l -perm /6022)\""
check "no link under a release leaves it (except .venv/bin/python*)" python3 -c '
import os, sys
bad = []
for rel in os.listdir(sys.argv[1]):
    root = os.path.realpath(os.path.join(sys.argv[1], rel))
    for base, dirs, files in os.walk(root):
        for n in dirs + files:
            p = os.path.join(base, n)
            if os.path.islink(p):
                t = os.path.realpath(p)
                ok = t == root or t.startswith(root + os.sep) or (os.path.relpath(p, root).startswith(".venv/bin/python") and t.startswith("/usr/"))
                if not ok:
                    bad.append(p + " -> " + t)
print("\n".join(bad))
sys.exit(1 if bad else 0)' "$OPT/releases"
check "the audit lock file belongs to the application account" bash -c "test \"\$(stat -c %U $DATA/.audit_log.jsonl.lock)\" = $TEST_USER"

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
  check "nginx -t ran inside the root unit's sandbox and passed (nginx-test.txt starts with exit 0)" bash -c "head -1 $WORK/bundle/nginx-test.txt | grep -qx 'exit 0'"
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
echo "# tampered" >> "$OPT/staging/98.0.5/requirements.lock"
"$UPDATER_CMD" apply 98.0.5 --confirm-text 98.0.5 > "$WORK/apply5.txt" 2>&1 && RC=0 || RC=$?
check "a modified staged tree is refused by root (exit 2 or 3, never 0)" test "$RC" -ne 0
check "the running version did not change" wait_version 98.0.2

say "6. Power loss: killed at a step boundary, then resumed"
rm -rf "$OPT/staging/98.0.5" "$OPT/releases/98.0.5" 2>/dev/null || true
"$UPDATER_CMD" stage "$REL/ocw-98.0.6.tar.gz" >/dev/null 2>&1 || bad "stage 98.0.6"
mkdir -p /etc/systemd/system/ocw-upgrade.service.d
# the root updater honours test-mode variables only when this root-owned marker exists (removed again below)
touch /etc/ocw-updater-test-mode && chmod 644 /etc/ocw-updater-test-mode
printf '[Service]\nEnvironment=OCW_TEST_MODE=1\nEnvironment=OCW_UPDATER_FAULT=kill_at:restarting\n' > /etc/systemd/system/ocw-upgrade.service.d/fault.conf
systemctl daemon-reload
"$UPDATER_CMD" apply 98.0.6 --confirm-text 98.0.6 > "$WORK/apply6.txt" 2>&1 || true
sleep 3
check "the CLI told the operator the updater stopped (exit 4)" bash -c "grep -q 'stopped before finishing' $WORK/apply6.txt"
check "the updater was killed mid-flight (state has no result)" bash -c "grep -q '\"result\": null' $DATA/upgrade/state.json"
check "current already points at 98.0.6 (switched before the kill)" test "$(readlink "$OPT/current")" = "releases/98.0.6"
rm -rf /etc/systemd/system/ocw-upgrade.service.d
rm -f /etc/ocw-updater-test-mode
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

say "7b. A release whose nginx template differs (a comment): nginx -t must work inside the root unit"
"$UPDATER_CMD" stage "$REL/ocw-98.0.8.tar.gz" > "$WORK/stage8.txt" 2>&1 || bad "stage 98.0.8"
"$UPDATER_CMD" apply 98.0.8 --confirm-text 98.0.8 > "$WORK/apply8.txt" 2>&1 && RC=0 || RC=$?
cat "$WORK/apply8.txt" | sed 's/^/        apply: /'
check "apply of the changed-template release exits 0" test "$RC" -eq 0
check "the live nginx site now carries the new template's comment" grep -q "vm test: template changed" "$NGINX_SITE"
check "nginx still passes its own test" nginx -t
check "the journal shows no read-only or permission errors from nginx -t" bash -c "! journalctl -u ocw-upgrade.service --no-pager -o cat 2>/dev/null | grep -qE 'Read-only file system|nginx.*(Permission denied|Operation not permitted)'"
check "the site is still served" bash -c "curl -sk --resolve $SITE_NAME:443:127.0.0.1 https://$SITE_NAME/healthz | grep -q status"

say "7c. Hostile accounts: the application account and the staging account plant links, pipes and strays"
runuser -u "$TEST_USER" -- bash -c "mkfifo $DATA/upgrade/revocations/pipe.json; ln -s /etc/hostname $DATA/upgrade/revocations/9.json; touch $DATA/upgrade/inbox/requests/x.txt; mkdir $DATA/upgrade/inbox/requests/adir"
HOSTNAME_SUM="$(sha256sum /etc/hostname | cut -d' ' -f1)"
TRUST_SUM="$(sha256sum $OPT/updater/trust.json | cut -d' ' -f1)"
T0=$SECONDS
timeout 60 systemctl start ocw-upgrade.service && RC=0 || RC=$?
check "the root service finished within 60 s with stray entries present" bash -c "test $RC -eq 0 && test $((SECONDS - T0)) -lt 60"
check "/etc/hostname is unchanged" bash -c "test \"\$(sha256sum /etc/hostname | cut -d' ' -f1)\" = $HOSTNAME_SUM"
check "the stray inbox entries were moved away" bash -c "test -z \"\$(ls -A $DATA/upgrade/inbox/requests)\""
sleep 3
check "the service is not in a start loop (not failed)" bash -c "! systemctl is-failed --quiet ocw-upgrade.service"
runuser -u ocw-updater -- bash -c "ln -s $OPT/updater/trust.json /var/lib/ocw-updater/artifacts/ocw-98.0.9.tar.gz; ln -s $OPT/updater/trust.json /var/lib/ocw-updater/artifacts/ocw-98.0.9.tar.gz.minisig"
"$UPDATER_CMD" stage "$REL/ocw-98.0.9.tar.gz" > "$WORK/stage9.txt" 2>&1 || true
check "trust.json is unchanged and still root-owned after staging past planted links" bash -c "test \"\$(sha256sum $OPT/updater/trust.json | cut -d' ' -f1)\" = $TRUST_SUM && test \"\$(stat -c %U $OPT/updater/trust.json)\" = root"
runuser -u ocw-updater -- bash -c "rm -f /var/lib/ocw-updater/artifacts/ocw-98.0.9.tar.gz*; mv /var/lib/ocw-updater/artifacts /var/lib/ocw-updater/artifacts.real; ln -s $OPT/updater /var/lib/ocw-updater/artifacts"
"$UPDATER_CMD" stage "$REL/ocw-98.0.9.tar.gz" > "$WORK/stage9b.txt" 2>&1 || true
check "the updater directory was not chowned or filled through a replaced artifacts link" bash -c "test \"\$(stat -c %U $OPT/updater)\" = root && test \"\$(stat -c %U $OPT/updater/trust.json)\" = root && ! ls $OPT/updater/*.tar.gz >/dev/null 2>&1"
rm -f /var/lib/ocw-updater/artifacts
mv /var/lib/ocw-updater/artifacts.real /var/lib/ocw-updater/artifacts
rm -rf "$OPT/staging/98.0.9" "$OPT/handoff"/* 2>/dev/null || true

say "7d. failed_needs_operator blocks a different version until clear-failure"
"$UPDATER_CMD" clear-failure >/dev/null 2>&1 || true
touch /etc/ocw-updater-test-mode && chmod 644 /etc/ocw-updater-test-mode
mkdir -p /etc/systemd/system/ocw-upgrade.service.d
printf '[Service]\nEnvironment=OCW_TEST_MODE=1\nEnvironment=OCW_UPDATER_FAULT=rollback_fail\n' > /etc/systemd/system/ocw-upgrade.service.d/fault.conf
systemctl daemon-reload
"$UPDATER_CMD" stage "$REL/ocw-98.0.10.tar.gz" >/dev/null 2>&1 || bad "stage 98.0.10"
"$UPDATER_CMD" apply 98.0.10 --confirm-text 98.0.10 > "$WORK/apply10.txt" 2>&1 && RC=0 || RC=$?
check "the unhealthy release with a failing rollback exits 4 (operator needed)" test "$RC" -eq 4
rm -rf /etc/systemd/system/ocw-upgrade.service.d
rm -f /etc/ocw-updater-test-mode
systemctl daemon-reload
"$UPDATER_CMD" stage "$REL/ocw-98.0.11.tar.gz" >/dev/null 2>&1 || bad "stage 98.0.11"
"$UPDATER_CMD" apply 98.0.11 --confirm-text 98.0.11 > "$WORK/apply11.txt" 2>&1 && RC=0 || RC=$?
check "another version is refused with failed_before (exit 2)" bash -c "test $RC -eq 2 && grep -q failed_before $WORK/apply11.txt"
check "clear-failure lets it through" "$UPDATER_CMD" clear-failure
"$UPDATER_CMD" apply 98.0.11 --confirm-text 98.0.11 > "$WORK/apply11b.txt" 2>&1 && RC=0 || RC=$?
check "98.0.11 applies after clear-failure" test "$RC" -eq 0

say "7f. Requests from the web application (the inbox), written as the application account"
INBOX="$DATA/upgrade/inbox/requests"
state_field() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2]) or "")' "$DATA/upgrade/state.json" "$1"; }
send_req() { # send_req <name> <json body, without schema/requested_at/origin>: dropped as the application account, mode 0600
  local body
  body="$(python3 -c 'import json,sys,time; d=json.loads(sys.argv[1]); d.update(schema=1, origin="app", actor="vm-test", requested_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())); print(json.dumps(d))' "$2")"
  runuser -u "$TEST_USER" -- bash -c "umask 077; printf '%s' '$body' > '$INBOX/$1.json'"
}
run_updater() { timeout 300 systemctl start ocw-upgrade.service; }
rejection_code() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["code"])' "$DATA/upgrade/rejections/$1.json" 2>/dev/null; }
audit_has() { grep -q "\"action\":\"$1\"" "$DATA/audit_log.jsonl"; }

# the quiesce file covers the whole run: its end time is renewed at every step (poll it while 98.0.12 is applied)
check "stage 98.0.12" "$UPDATER_CMD" stage "$REL/ocw-98.0.12.tar.gz"   # (before 7e: that step revokes the test signing key)
: > "$WORK/quiesce-seen.txt"
( while [ ! -e "$WORK/quiesce-stop" ]; do grep -h '"until"' "$DATA/upgrade/quiesce.json" >> "$WORK/quiesce-seen.txt" 2>>"$WORK/quiesce-poll.err" || true; sleep 0.1; done ) &
POLL_PID=$!
"$UPDATER_CMD" apply 98.0.12 --confirm-text 98.0.12 > "$WORK/apply12.txt" 2>&1 && RC=0 || RC=$?
touch "$WORK/quiesce-stop"; wait "$POLL_PID" 2>/dev/null || true; rm -f "$WORK/quiesce-stop"
check "98.0.12 applies" bash -c "test $RC -eq 0 || { cat $WORK/apply12.txt; exit 1; }"
check "the quiesce file was seen during the run and its end time was renewed (two or more different values)" bash -c "test \$(sort -u $WORK/quiesce-seen.txt | grep -c .) -ge 2 || { sort -u $WORK/quiesce-seen.txt; tail -n 3 $WORK/quiesce-poll.err; exit 1; }"
check "the quiesce file is gone when the run is over" test ! -e "$DATA/upgrade/quiesce.json"

# a bundle for another run must leave state.json byte-identical; a rollback outside the 24 hours is refused
LAST_CID="$(state_field correlation_id)"
cp -p "$DATA/upgrade/state.json" "$WORK/state-good.json"
BEFORE="$(sha256sum "$DATA/upgrade/state.json" | cut -d' ' -f1)"
send_req upg-f0000001 '{"action":"bundle","correlation_id":"upg-f0000001","action_id":"aid_vmtest_foreign_0001","for_correlation_id":"upg-00000009"}'
run_updater || true
check "a bundle request for another run's id was refused" test "$(rejection_code upg-f0000001)" = request_invalid
check "state.json is byte-identical after it" test "$(sha256sum "$DATA/upgrade/state.json" | cut -d' ' -f1)" = "$BEFORE"
python3 - "$DATA/upgrade/state.json" <<'PY'
import json, sys, time
p = sys.argv[1]
d = json.load(open(p))
d["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 3 * 86400))
json.dump(d, open(p, "w"))
PY
CUR_BEFORE="$(readlink "$OPT/current")"
send_req upg-f0000002 '{"action":"rollback","correlation_id":"upg-f0000002","action_id":"aid_vmtest_window_0002","confirm":"ROLLBACK"}'
run_updater || true
check "a rollback request three days after the upgrade is refused (rollback_unavailable)" test "$(rejection_code upg-f0000002)" = rollback_unavailable
check "the code was not switched" test "$(readlink "$OPT/current")" = "$CUR_BEFORE"
cp -p "$WORK/state-good.json" "$DATA/upgrade/state.json"

# in the window: the bundle for the last run, clear_failure, rollback, then restore naming the copy that upgrade took
send_req upg-f0000003 '{"action":"bundle","correlation_id":"upg-f0000003","action_id":"aid_vmtest_bundle_0003"}'
run_updater || true
check "a bundle request for the last run builds a bundle and the audit log says so" bash -c "$(declare -f audit_has); DATA=$DATA; audit_has upgrade.bundle_created"
check "state.json still describes the same upgrade" test "$(state_field correlation_id)" = "$LAST_CID"
send_req upg-f0000004 '{"action":"clear_failure","correlation_id":"upg-f0000004","action_id":"aid_vmtest_clear_0004"}'
run_updater || true
check "clear_failure from the inbox is audited as coming from the web application" bash -c "grep -q 'upgrade.clear_failure.*web application' $DATA/audit_log.jsonl"
BACKUP_NAME="$(python3 -c 'import json,os,sys; l=[json.loads(x) for x in open(sys.argv[1])]; print(os.path.basename([h for h in l if h.get("action")=="apply" and h.get("backup")][-1]["backup"]))' "$DATA/upgrade/history.jsonl")"
PREV="$(readlink "$OPT/previous" | sed 's#.*/##')"
send_req upg-f0000005 '{"action":"rollback","correlation_id":"upg-f0000005","action_id":"aid_vmtest_rollback_0005","confirm":"ROLLBACK"}'
run_updater || true
check "an in-window rollback from the inbox switched the code back" wait_version "$PREV"
send_req upg-f0000006 '{"action":"restore","correlation_id":"upg-f0000006","action_id":"aid_vmtest_restore_0006","confirm":"RESTORE","backup":"audit_store-pre-98.9.9-20000101T000000Z.db"}'
run_updater || true
check "a restore naming another copy than the one it would restore is refused (target_changed)" test "$(rejection_code upg-f0000006)" = target_changed
send_req upg-f0000007 "{\"action\":\"restore\",\"correlation_id\":\"upg-f0000007\",\"action_id\":\"aid_vmtest_restore_0007\",\"confirm\":\"RESTORE\",\"backup\":\"$BACKUP_NAME\"}"
run_updater || true
check "a restore naming the right copy is carried out" bash -c "test \"\$(grep -c '\"action\":\"upgrade.restored\"' $DATA/audit_log.jsonl)\" -ge 1 && ls $DATA/audit_store.db.pre-restore-* >/dev/null"
check "the site answers after the restore" wait_version "$PREV"

# a hostile burst: 200 bundle requests at once leave a bounded number of files behind
for n in $(seq 1 15); do touch -d "2020-01-01 00:00:$((n + 10))" "$DATA/upgrade/bundles/ocw-support-98.0.1-to-98.0.2-2020010100000${n}Z-aaaa.tar.gz"; done
runuser -u "$TEST_USER" -- bash -c 'umask 077; now=$(date -u +%Y-%m-%dT%H:%M:%SZ); for i in $(seq 1 200); do
  cid=$(printf "upg-%08x" $((0xb0000000 + i))); printf "{\"schema\":1,\"action\":\"bundle\",\"correlation_id\":\"%s\",\"action_id\":\"aid_vmtest_burst_%08d\",\"origin\":\"app\",\"requested_at\":\"%s\"}" "$cid" "$i" "$now" > '"$INBOX"'/$cid.json; done'
T0=$SECONDS
run_updater && RC=0 || RC=$?
check "the burst was processed within 5 minutes and the service did not fail" bash -c "test $RC -eq 0 && test $((SECONDS - T0)) -lt 300 && ! systemctl is-failed --quiet ocw-upgrade.service"
check "the inbox is empty after the burst" bash -c "test -z \"\$(ls -A $INBOX)\""
check "at most 10 support bundles remain" bash -c "test \$(ls $DATA/upgrade/bundles/ocw-support-*.tar.gz | wc -l) -le 10"
check "at most 200 handled-request files remain" bash -c "test \$(find $DATA/upgrade/requests-done -maxdepth 1 -type f | wc -l) -le 200"
check "at most 200 refusal records remain" bash -c "test \$(find $DATA/upgrade/rejections -maxdepth 1 -type f | wc -l) -le 200"

# deleting pre-upgrade backups is the command line's alone
NBK_BEFORE="$(ls "$DATA"/upgrade/backups/audit_store-pre-*.db | wc -l)"
send_req upg-f0000008 '{"action":"prune_backups","correlation_id":"upg-f0000008","action_id":"aid_vmtest_prune_0008","confirm":"PRUNE","keep_last":1}'
run_updater || true
check "a prune request through the inbox is refused as an unknown kind" test "$(rejection_code upg-f0000008)" = request_invalid
check "no backup was deleted by it" test "$(ls "$DATA"/upgrade/backups/audit_store-pre-*.db | wc -l)" -eq "$NBK_BEFORE"
check "backups-status.json is 0644 and readable by the application account" bash -c "test \"\$(stat -c %a $DATA/upgrade/backups-status.json)\" = 644 && runuser -u $TEST_USER -- cat $DATA/upgrade/backups-status.json >/dev/null"
check "the backups directory stays root-only (0700)" test "$(stat -c %a "$DATA/upgrade/backups")" = 700
"$UPDATER_CMD" prune-backups --keep 1 --confirm PRUNE > "$WORK/prune.txt" 2>&1 && RC=0 || RC=$?
check "the command-line prune works" test "$RC" -eq 0
check "it kept the newest copy" test "$(ls "$DATA"/upgrade/backups/audit_store-pre-*.db | wc -l)" -eq 1

say "7e. A revoked key: a back-dated release by the revoked key is refused, and the revocation file is not written anywhere the application owns"
"$UPDATER_CMD" trust apply "$REL/revocation.json" > "$WORK/trustapply.txt" 2>&1 && RC=0 || RC=$?
check "trust apply of the test revocation succeeds" test "$RC" -eq 0
"$UPDATER_CMD" stage "$REL/ocw-98.0.9.tar.gz" > "$WORK/stage9c.txt" 2>&1 && RC=0 || RC=$?
check "a release signed by the revoked key (with an old timestamp) is refused (exit 2)" test "$RC" -eq 2
check "the refusal says the key is revoked" bash -c "grep -qi 'revoked' $WORK/stage9c.txt"
check "the applied revocation was not copied into the application's directory" test ! -e "$DATA/upgrade/revocations/1.json"

say "8. The root unit's sandbox (for tightening CapabilityBoundingSet)"
systemctl show ocw-upgrade.service -p CapabilityBoundingSet -p ProtectSystem -p IPAddressDeny -p IPAddressAllow > "$WORK/sandbox.txt" || true
cat "$WORK/sandbox.txt"
check "the sandbox allows nginx -t to bind and the updater to kill a child" bash -c "grep -qi cap_net_bind_service $WORK/sandbox.txt && grep -qi cap_kill $WORK/sandbox.txt"
check "no permission errors in the updater's journal" bash -c "! journalctl -u ocw-upgrade.service --no-pager 2>/dev/null | grep -qiE 'permission denied|operation not permitted'"
journalctl -u 'ocw-upgrade.service' -u 'ocw-stage@*' --no-pager -o cat 2>/dev/null | tail -n 40 > "$WORK/journal-tail.txt" || true

# --------------------------------------------------------------------------------------------------------------------
say "Summary: $PASS passed, $FAIL failed"
if [ "$FAIL" -gt 0 ]; then
  printf '  failed: %s\n' "${FAILED_NAMES[@]}"
  echo "  evidence is in $WORK until the clean-up at exit (use --keep to look around)"
  exit 1
fi
