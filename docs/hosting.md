# Hosting and the CLI

Two ways to run this tool beyond the default single-machine dashboard:
hosting it as a shared, always-on service for a team (below), or using
the standalone CLI for scripted folder creation. See the main
[README](../README.md) for the default `launch.py` desktop setup, and
[features.md](features.md) for what the dashboard itself does.

## Hosting on a server (optional)

The dashboard can also run as a persistent, centrally-reachable service
instead of only on someone's own machine, for a small team sharing access
to the same OPA/Okta tenants. This is deliberately optional -- the default
experience (`launch.py`, see the main README) needs none of this.

**Architecture:** `server/serve.py` still only ever binds `127.0.0.1` --
it is never directly reachable from the network, hosted or not. A
reverse proxy (nginx, see `server/nginx-opa-secrets-wizard.conf` as a
starting template) terminates TLS and gates access with real **Okta OIDC
login** (`server/auth_gate.py`) before anything reaches the app. Plain
HTTP Basic Auth was tried first and abandoned -- some managed
Edge/Chromium browser policies restrict `AuthSchemes` to
`ntlm`/`negotiate`, which silently swallows Basic Auth's login popup
entirely (the server sends a correct 401 challenge; the browser just never
shows it). OIDC's own hosted login page sidesteps that failure mode
completely.

**What the nginx template enforces (5.40.5+):** `nosniff`, `X-Frame-Options:
DENY` / `frame-ancestors 'none'` and `Referrer-Policy: same-origin` on every
response (declared once at server level -- a `location` that adds its own
`add_header` stops inheriting them, so don't); `server_tokens off`; TLS 1.2+;
an exact-match `/healthz` that drops client identity headers; and a
per-address rate limit (30/min, burst 60, `429`) on `/step-up` and
`/authorization-code/callback`, the routes that make the gate call Okta.
HSTS is left commented out: browsers ignore it for an IP address, and on a
hostname with a self-signed certificate it removes the option to click
through the warning -- enable it once the site has a trusted certificate.
`tests/test_nginx_template.py` runs the real nginx against the template.

**Why hosting matters for Compliance Reports specifically:** the daily
sync job that keeps the audit archive current (see
[Compliance Reports Dashboard](features.md#compliance-reports-dashboard)) runs as a
background thread inside `server/serve.py` — it only fires while that
process is running. On the desktop/standalone path (`launch.py`), that
means sync only happens while the app is open on someone's machine.
Hosting this on a server that stays up around the clock is what makes
"scheduled daily sync, unattended" actually mean unattended. The
scheduler is also restart-safe by design: it re-checks each
environment's persisted sync state on every poll rather than keeping an
in-memory countdown, so a `systemctl restart` (from a deploy, a crash
recovery, or a manual restart) never causes a missed or duplicate sync.

**The daily job is a refresh (5.51.0).** The scheduled run is the same job as the Overview's **Refresh** button: one job per environment with three
parts that are reported separately, the OPA scan, the Okta scan (admin roles, lifecycle status, inventory counts, sign-in figures) and the System
Log sync. The OPA scan and the log sync run side by side; the Okta scan follows the log so the two do not share Okta's rate budget. One part
failing, being refused or timing out never hides the others, and a failed OPA part alone does not delay tomorrow's run: the retry back-off (one
hour after a failed attempt) follows the log part, as before. Each part has its own deadline (OPA scan 45 minutes, System Log 90, Okta scan 30);
a part that runs out is stopped at its next checkpoint and its previous data is kept. The OPA scan is stored in the archive database (one
replaceable row per environment), so a restart no longer loses it, and a sealed record of the day's OPA access state joins the evidence chain
(once a day, from the scan just read). `ocw-updater` waits up to 10 minutes for a running refresh, OPA scan included, before it refuses with
`sync_in_progress`. Where the data folder is matters for the stored scan: keep the data directory (`OPA_DATA_DIR`) on an encrypted disk, and on Windows
outside folders other users of the computer can read (the app warns at start if it is in one).

**Why SQLite, not a "real" database server, for the audit archive:**
this came up explicitly during design — wouldn't MySQL or Postgres
scale better for a growing, multi-year archive? For this tool's actual
usage pattern, no: SQLite's write path is single-writer by design,
which is exactly what one background sync thread per server process
needs, and its read performance on an indexed, mostly-append table
(this archive's actual shape) is not meaningfully different from a
client-server database at the row counts a single tenant's audit trail
realistically reaches. Standing up and operating MySQL/Postgres would
add a second service to install, patch, back up, and secure, for a
workload that doesn't need it — the honest tradeoff isn't "SQLite vs.
a faster database," it's "one file vs. a whole extra service," and for
this tool's single-server-process design, the file wins.

**What the installer does for you (5.52.0).** On a clean Debian 12 or newer or Ubuntu 22.04 or newer server (run end to end on a real Debian 13 x86-64 server only) one command does everything
in the list below that needs root, in the right order, and starts the backend:
`curl -fsSLO https://github.com/ItsGambit/opa-compliance-wizard/releases/latest/download/get-ocw.sh && sudo bash get-ocw.sh`
(see the README's [Installing on a server](../README.md#installing-on-a-server) for what is checked and what you trust). It installs
the packages (`nginx`, `gnome-keyring`, `dbus-user-session`, `python3-venv`, `openssl`) after you confirmed the plan; creates the
application account `ocw` (a regular account, home `/var/lib/opa-compliance-wizard/home`, shell `nologin`) and turns on lingering for
it; writes `/etc/opa-compliance-wizard.env` (mode 0600) with `DEPLOYMENT_MODE=hosted`, three generated secrets, the allowed origin
and the Okta lines commented out; writes the two application units with the account's real numeric id in `/run/user/<uid>` (the
unit templates carry `__APP_UID__` and `__APP_USER_HOME__`; the installer fills them in); writes the login gate's session key;
makes the nginx site from the release's template with your server name, the proxy secret and a certificate (yours, or a temporary
self-signed one); starts the backend and checks it, also through nginx. The login gate is installed but **neither enabled nor started** (`sudo systemctl enable --now opa-auth-gate` once the Okta settings are in):
it refuses to start without the Okta settings, which you enter (steps 1-4 below; the last lines of the installer's output name the
exact commands). Behind a proxy or with a mirror, pass the settings through sudo (`sudo https_proxy=... OCW_RELEASE_BASE_URL=... OCW_REVOCATION_URL=... bash get-ocw.sh --version X.Y.Z`); with a mirror also set `OCW_REVOCATION_URL` to a page you control, because a mirror answers for the revocation files too. Run it again after a failure and it resumes; it never overwrites a data or settings file.

**By hand (other distributions, or to see what the installer does).** **First install: what the server needs** (Debian/Ubuntu commands; adapt
for your distro). The hosted services can't start without these, and an
improvised fix on the login path tends to be an insecure one, so do them
before the numbered steps below:
- Packages: `sudo apt-get install nginx python3-venv gnome-keyring
  dbus-user-session rsync git curl` and a Node.js the build accepts
  (`^20.19.0 || >=22.12.0`; a distro's own `nodejs` is often older -- use
  nodejs.org or NodeSource).
- The code, as the app user (no sudo): `git clone
  https://github.com/ItsGambit/opa-compliance-wizard.git ~/opa-compliance-wizard`,
  then in it `python3 -m venv .venv && .venv/bin/pip install
  --require-hashes -r requirements.lock` (5.46.0: every package must match
  a recorded sha256; `requirements.txt` is the source it is generated from)
  and `cd frontend && npm ci --ignore-scripts && npx vite build`.
- The app user's systemd "user manager" must keep running without a login
  session, because the keyring daemon lives in `/run/user/<uid>`: `sudo
  loginctl enable-linger <app-user>`. The unit templates carry `__APP_UID__`
  (and `__APP_USER_HOME__`) where the directory is named; `server/install.sh`
  fills them in from `id -u <app-user>`. Installing a unit by hand, replace
  them yourself in both units (older releases hardcoded `1000`).
- The environment file holds secrets (`KEYRING_UNLOCK_PASSWORD`,
  `NGINX_PROXY_SECRET`, `INTERNAL_API_SHARED_SECRET`): create it owner-only
  before writing anything into it, `sudo install -m 600 -o <app-user> -g
  <app-user's group> /dev/null /etc/opa-compliance-wizard.env`, then edit it
  as the app user. `KEYRING_UNLOCK_PASSWORD` is the password
  `server/start-headless.sh` unlocks (or, the first time, creates) the
  app user's login keyring with; the backend refuses to start without it.
- A TLS certificate for the nginx site (the template expects
  `/etc/nginx/ssl/opa-secrets-wizard.crt` and `.key`; any path works, as
  long as the site names it). For a test install on an IP address, a
  self-signed one: `sudo install -d -m 700 /etc/nginx/ssl && sudo openssl
  req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=<ip or host>"
  -addext "subjectAltName=IP:<ip>" -keyout /etc/nginx/ssl/opa-secrets-wizard.key
  -out /etc/nginx/ssl/opa-secrets-wizard.crt` (use `DNS:<host>` for a
  name).
- The nginx site, readable only by root and the app user's group (it will
  hold `NGINX_PROXY_SECRET`; nginx's master process reads its config as
  root, so `www-data` needs no access, and `deploy.sh` reads it through the
  group to carry the secret forward): `sudo install -m 0640 -o root -g
  <app-user's group> server/nginx-opa-secrets-wizard.conf
  /etc/nginx/sites-available/opa-secrets-wizard`, then `sudoedit` it to
  set your `server_name` (both blocks), certificate paths and the proxy
  secret, and `sudo ln -s /etc/nginx/sites-available/opa-secrets-wizard
  /etc/nginx/sites-enabled/ && sudo nginx -t && sudo systemctl reload
  nginx`. `deploy.sh` keeps those values (it carries them from the live
  site into every new version of the template) and keeps the file's owner
  and mode.
- The shell scripts are executable in git (5.41.0); on a checkout where
  they aren't (e.g. one edited from Windows), `chmod +x server/*.sh
  start-wizard.sh`.

**Setup, at a high level** (see `server/*.service`, `server/start-headless.sh`,
and `server/nginx-opa-secrets-wizard.conf` for the concrete pieces):
1. Register a **Web Application** OIDC integration in your Okta org
   (Admin Console -> Applications -> Create App Integration -> OIDC ->
   Web Application). Grant type: Authorization Code only. Sign-in
   redirect URI: `https://<your-dashboard-origin>/authorization-code/callback`.
   Sign-out redirect URI: `https://<your-dashboard-origin>/login`. Note the
   resulting **Client ID** and **Client secret**.
2. If using a **custom** Okta authorization server (not the org
   authorization server), confirm it actually has an access policy + rule
   granting your new app's client access -- a brand-new custom
   authorization server can have zero policies, which silently denies
   every token request (`access_denied — Policy evaluation failed`) and
   looks like an MFA/access problem rather than a missing-setup-step one.
3. Store the client secret in the OS keyring under this project's existing
   per-environment convention:
   `keyring.set_password(f"opa-compliance-wizard:{env_name}", "okta_client_secret", "<secret>")`
   (`env_name` matches whatever `OKTA_ENV_NAME` you set in step 4). Run it as the app user **while the backend service is running**:
   the service's session keeps the keyring unlocked and the command reaches it through that session. An
   install from before the 5.20.0 rename can leave existing credentials
   stored under the old `opa-secrets-wizard:{env_name}` prefix as-is —
   they're still read via a fallback and need no migration.
4. Set these environment variables for `server/auth_gate.py` (e.g. in the
   systemd unit's `EnvironmentFile`, created owner-only as above) -- the
   process refuses to start without the first four, rather than silently
   pointing at the wrong org:
   - `OKTA_ORG_URL` — e.g. `https://your-org.oktapreview.com`
   - `OKTA_OIDC_CLIENT_ID` — the Client ID from step 1 (not secret, but
     still specific to your deployment)
   - `DASHBOARD_ORIGIN` — the public origin this dashboard is reachable
     at, e.g. `https://192.168.1.10` or `https://opa.example.com`
   - `OKTA_ADMIN_GROUP_ID` — see "Admin access" below.
   - `OKTA_ENV_NAME` (optional, defaults to `"default"`)
   - `KEYRING_UNLOCK_PASSWORD` — required by `server/start-headless.sh`
     (the backend's start script): it unlocks the app user's login keyring,
     where the Okta client secret and the tenants' API credentials live.
     Pick a long random value; it is only ever read from this file.
   - `INTERNAL_API_SHARED_SECRET` (optional) — a random string, set
     identically in the SAME `EnvironmentFile` used by both
     `server/serve.py` and `server/auth_gate.py` (they already share one,
     `/etc/opa-compliance-wizard.env`). Enables the Audit Log page's
     Refresh button to backfill Okta MFA System Log corroboration for
     `access_control.update` entries that missed it at save time (Okta
     indexing lag) — without it, `POST /api/audit_log/backfill_mfa`
     silently no-ops (0 updated) rather than erroring, so this is safe to
     leave unset. Generate one with e.g. `openssl rand -hex 32`.
   - `NGINX_PROXY_SECRET` — **required** (not optional) for `server/serve.py`
     specifically, same `EnvironmentFile`. This is a completely different
     secret from `INTERNAL_API_SHARED_SECRET` above (that one authenticates
     serve.py calling INTO auth_gate.py; this one authenticates nginx
     calling INTO serve.py — don't reuse the same value for both). Without
     this set and matched in `nginx-opa-secrets-wizard.conf`'s
     `$nginx_proxy_secret` (see that file's own setup comment), `serve.py`
     trusts `X-Auth-Is-Admin`/`X-Auth-Sub` from ANY request that can reach
     its loopback port directly — bypassing nginx, `auth_gate.py`'s login,
     and step-up MFA entirely (confirmed exploitable by multiple
     independent security reviews, 2026-09-30). Generate one with
     `openssl rand -hex 32` and set the SAME value as `nginx-opa-secrets-
     wizard.conf`'s `set $nginx_proxy_secret "...";` line. If you only ever
     run this app standalone/locally with no nginx in front at all (this
     app's other explicitly supported mode), leave this unset — nothing
     is weakened in that mode, since there's no proxy boundary to spoof.
   - `DEPLOYMENT_MODE` (optional, defaults to `local`) — set to `hosted`
     for any real nginx-fronted deployment. In `hosted` mode, `serve.py`
     refuses to start at all unless `NGINX_PROXY_SECRET` (above) is also
     set — turning "forgot to set `NGINX_PROXY_SECRET`" from a silent,
     easy-to-never-notice trust downgrade into a loud startup failure.
     Leave unset (or `local`) for standalone/local-only runs — behavior is
     unchanged either way.
5. If `server/serve.py` itself will be reached through a hostname/IP other
   than `127.0.0.1`/`localhost` (true for any reverse-proxied deployment),
   also set `EXTRA_ALLOWED_ORIGINS` (comma-separated) to that public
   origin -- otherwise every write request is rejected with `403 Origin
   '...' is not allowed to call this API"` once real browser traffic
   arrives from that origin.
6. **5.47.0 and newer: let `server/install.sh` do steps 6 and 7 (recommended).** It installs the upgrade layout
   (code in `/opt/opa-compliance-wizard/releases/<version>`, owned by root; data in
   `/var/lib/opa-compliance-wizard`, the only place the application writes; the root-run updater and its units;
   the `ocw-updater` command) and, on a server that already runs from a home directory, migrates it with a rollback
   if the result is not healthy. Run `sudo server/install.sh --dry-run` first. Prerequisites you still do yourself: the
   environment file (steps 2-5), the units' own keyring and `/run/user` carve-outs (they stay as they are), the nginx site
   (`install.sh --apply-nginx` then adds the maintenance-page directives to it), and the gate. With the new layout:
   * **no sudoers rules for deploys are needed** and the web application's account can no longer restart services or write
     the nginx site (`install.sh --remove-legacy-sudoers` removes an old deploy rule; see step 7);
   * the unit templates in `server/` use `__APP_DIR__` = `/opt/opa-compliance-wizard/current` and `__DATA_DIR__` =
     `/var/lib/opa-compliance-wizard`; the backend unit also has `ProtectSystem=strict` (the gate unit does not: it creates its
     session key under `/etc` on first start);
   * the app's archive path (`OPA_AUDIT_DB_PATH`, below) and every other data file follow `OPA_DATA_DIR`;
   * a second gate's site generated before 5.50.0 also lacks the `/api/overview` deny block (the admin-only Overview, with its people lists); regenerate as below (the installer's note now names every denied route);
   * the per-environment routes of 5.50.0 (Okta Admins, cross-checks, snapshots, capture) are shared-environment routes like the reports: through an
     additional gate they answer only for a verified-issuer per-user exception that holds the capability they check (`view_archive` plus `live_read`);
   * a second gate's site generated before 5.47.0 lacks the `/api/upgrade` deny block. `setup-second-gate.sh` never rewrites an existing
     site, and neither `install.sh` nor the updater changes one by itself: `install.sh` lists every `opa-auth-gate-*` unit with the status of
     its site, and `sudo server/install.sh --regenerate-second-sites` rebuilds them from the live main site (add `--apply-nginx` to apply the
     main site's maintenance page first; `nginx -t` runs before the reload and the old site is put back if it fails). The sites are looked for in
     `/etc/nginx/sites-available/opa-<name>` (`OCW_NGINX_SITES_DIR` if they live elsewhere);
   * the unit files may be indented (systemd allows it): `install.sh` edits them either way and stops before changing anything if
     `WorkingDirectory=` (or, for the backend unit, `ProtectSystem=` / `ProtectHome=`) is missing;
   * after a release that changes the units or `install.sh`, the updater asks for `sudo server/install.sh --refresh-updater` (README, "Upgrading");
   * the units `ocw-stage@.service` (unprivileged staging; optional proxy settings in `/etc/ocw-updater.env`), `ocw-upgrade.path` and
     `ocw-upgrade.service` (root: activate, roll back, resume at boot) are documented in the README ("Upgrading").

   The rest of this step describes the manual installation the old layout (and `install.sh`'s migration) is based on.

   Install and enable the two systemd units (`opa-compliance-wizard.service`,
   `opa-auth-gate.service`) and the nginx site config, adjusting paths/IPs
   for your own server. (An install predating the 5.20.0 rename can keep
   its existing `opa-secrets-wizard.service` unit name as-is — nothing
   requires renaming a unit that's already running; this filename is the
   template a fresh install starts from.)

   Both `.service` files use `__APP_USER__`/`__APP_DIR__`/`__DATA_DIR__`/
   `__APP_USER_HOME__` placeholders (set `__DATA_DIR__` to the same path as `__APP_DIR__`
   for the old in-place layout and delete the `OPA_DATA_DIR` and `ProtectSystem` lines) (not a real username/path — this repo
   is public and doesn't hardcode either), so fill those in before
   installing, e.g.:
   ```bash
   sed -e "s|__APP_USER__|$(whoami)|g" \
       -e "s|__APP_DIR__|$(pwd)|g" \
       -e "s|__APP_USER_HOME__|$HOME|g" -e "s|__DATA_DIR__|$(pwd)|g" \
       server/opa-compliance-wizard.service | sudo tee /etc/systemd/system/opa-compliance-wizard.service
   sed -e "s|__APP_USER__|$(whoami)|g" \
       -e "s|__APP_DIR__|$(pwd)|g" \
       -e "s|__APP_USER_HOME__|$HOME|g" -e "s|__DATA_DIR__|$(pwd)|g" \
       server/opa-auth-gate.service | sudo tee /etc/systemd/system/opa-auth-gate.service
   sudo systemctl daemon-reload
   ```
   Run these from the repo root so `$(pwd)` resolves to the real
   `$APP_DIR`. `sudo tee` creates the unit files owned by root, which is
   what they must stay: systemd runs them as root, so a unit file the app
   user can edit is a way to root at the next reload or boot (`deploy.sh`
   warns, with the fix, when it finds one). `server/setup-second-gate.sh` copies the LIVE unit at
   `/etc/systemd/system/opa-auth-gate.service` to build an additional
   gate's unit (see `server/unit_second_gate.py`), not this repo
   template, so it's unaffected by these placeholders either way.

   **This step is a ONE-TIME manual install, not something `server/deploy.sh`
   ever automates for you** (confirmed the hard way, 2026-10-02): unlike
   the nginx site config, which `deploy.sh` actively diffs and re-applies
   on every run (see that script's own nginx-apply logic), these two
   unit files are NEVER re-copied to `/etc/systemd/system/` automatically.
   **Any time you pull a future release that changes either `.service`
   file** (a new hardening directive, a new `EnvironmentFile=` path,
   etc.), you must manually re-run this step's `cp`/`daemon-reload`/
   `restart` sequence yourself — `deploy.sh` only ever restarts the
   units that are ALREADY installed; it has no way to know their
   on-disk definition changed. Check `diff server/*.service
   /etc/systemd/system/` after any deploy whose CHANGELOG entry says a
   unit file changed.
   Also confirm your
   server's live `EnvironmentFile=` path actually matches what's in
   `/etc/systemd/system/*.service` right now (`systemctl cat
   opa-secrets-wizard | grep EnvironmentFile`) before copying a new unit
   file over it — an older install's unit may point at a DIFFERENT env
   file path than what ships in a fresh template (this project's own
   real server did, historically: `/etc/opa-secrets-wizard.env` vs.
   `/etc/opa-compliance-wizard.env`), and blindly overwriting the unit
   file without first merging that env file's real contents into
   whichever path the new template expects will start the service with
   none of its actual secrets set.

   **Session-signing key (5.40.5+).** `auth_gate.py` signs its cookies with
   the key at `OPA_SESSION_KEY_PATH` (default
   `/etc/opa-secrets-wizard-session.key`). The gate refuses to start if
   that file holds fewer than 32 bytes (an empty file -- e.g. from `touch`
   -- used to be accepted, which made every cookie forgeable). Either let
   the gate create it (its directory must be writable by the app user; it
   is created `0600`), or create it yourself:
   ```bash
   sudo sh -c 'umask 027; head -c 32 /dev/urandom > /etc/opa-secrets-wizard-session.key'
   sudo chown root:<app-user> /etc/opa-secrets-wizard-session.key
   sudo chmod 0640 /etc/opa-secrets-wizard-session.key
   ```
   **Emergency sign-out of everyone:** sessions are signed cookies with no
   server-side store, so replacing this key (same commands, then
   `sudo systemctl restart opa-auth-gate`) is the way to end every session
   at once -- e.g. after offboarding an admin, since a session keeps the
   admin flag it was issued with until it expires (12 h). Each additional
   gate has its own key (`/etc/opa-auth-gate-<name>/session.key`) and
   unit (`opa-auth-gate-<name>`).
7. **No sudoers rule is needed any more (5.48.0).** The 5.47.0 upgrade layout (`server/install.sh`) gives the web application's
   account no right to restart services or write the nginx site; upgrades are done by the root-owned updater, started from the
   Updates page or with `sudo ocw-updater`. A server set up before that may still carry the old `deploy.sh` sudoers file: moving it
   to the upgrade layout (`sudo server/install.sh`, README "Upgrading") keeps it working, and `--remove-legacy-sudoers` removes it
   afterwards. This guide no longer walks through creating one; a deploy account with that grant is effectively an administrator
   (the `cp` into nginx's configuration is a path to root).

**Upgrading on the 5.47.0 upgrade layout:** `sudo ocw-updater stage <version>` then `sudo ocw-updater apply <version>`
(or `server/deploy.sh --release <version>`, which now only calls those two): README, "Upgrading". The paragraph below
describes the old in-place `deploy.sh`.

**Air-gapped servers (5.49.0).** `server/deploy.sh --release <version> --from-dir <dir>` accepts the offline bundle
`ocw-<version>-offline.tar.gz` (a signed release plus hash-pinned wheels) in place of the tarball and its `.minisig`: it
unpacks the bundle with the installed copy's own checker, verifies the release inside like any other and installs the Python
packages with `pip install --no-index --require-hashes` from the bundle (README, "Upgrading without internet access"). On the upgrade
layout the updater stages the release only; it cannot yet install packages from the bundle, so deploy.sh refuses a bundle there.
**Local (laptop) installs** are upgraded with `python launch.py upgrade`; a `DEPLOYMENT_MODE=hosted` install refuses it.

**Redeploying: `server/deploy.sh`.** Run it on the server as the app user.
For production use a signed release: `<install dir>/server/deploy.sh
--release <version>` (README, "Upgrading": it checks the download against the
project's pinned signing key, refuses anything unsigned, altered or older than
what is installed, and needs no Node.js on the server; `--from-dir <dir>`
installs from files you carried in, for a server without internet access;
`--reinstall` allows the same version again). A bare run, or `--ref`, installs
**unsigned** source straight from the repository, prints a warning, and is
meant for maintainers and test servers. Everything below applies to both. It works out the install directory from
its own location (5.41.0; nothing to edit), takes a lock so two deploys
can't overlap, checks the sudo grants and that it can read the live nginx
site, and only then clones, syncs, rebuilds, restarts and applies the
nginx site (with `nginx -t` and rollback). The grant check requires each
command to be allowed; where sudo can show it (classic sudo 1.9.15+), also
without a password -- sudo-rs, Ubuntu's default since 25.10, can't, and a
rule that prompts then stops the deploy at the step that uses it. The live
site is checked against the new template's layout
before anything changes. Each restarted service must
stay up: the backend must answer `/api/version` with the new version from
a new process, each gate must answer its `/verify` with `401`, and none
may be restarted by systemd on its own afterwards (checked again a few
seconds after the last restart). Every run that gets
past the clone writes one `deploy.started` and one `deploy.completed` or
`deploy.failed` (with the stage that failed) to the Audit Log.
Optional settings, from the environment or from `<install dir>/.deploy.conf`
(`KEY=VALUE` lines; read, never executed; kept across deploys):
- `OPA_REPO_URL` — deploy from your fork instead of upstream (unsigned
  `--ref` installs only).
- `OPA_RELEASE_BASE_URL` / `OPA_REVOCATION_URL_BASE` — where `--release`
  downloads from, e.g. a mirror inside your network (https only). A mirror
  can delay an upgrade but cannot alter one: the signature is still checked.
- `OPA_REVOCATION_URL` — an owner-controlled https URL that serves the current `revocation.json`
  (checked in addition to the project's GitHub releases). Set it on every install: it is the
  one channel for a second revocation that does not depend on GitHub's release tags.
- `OPA_DEPLOY_REF` (or `--ref <x>`) — a branch, tag or full commit to
  deploy instead of the default branch's tip (unsigned). `--ref <previous
  commit>` is also the quickest way back after a bad deploy (a signed
  `--release` refuses to install an older version), to 5.41.0 or later: an
  older release's `deploy.sh` only works in its own hardcoded directory, so
  it is refused anywhere else.
- `OPA_BACKEND_PORT` — if `serve.py` doesn't listen on 8766.
- `OPA_NGINX_SITE` — the live site file, if not
  `/etc/nginx/sites-available/opa-secrets-wizard`.
- Create `.deploy.conf` only after your first deploy of 5.41.0 or later:
  that first run still syncs with the previous release's exclude list,
  which doesn't keep the file. For that one run, pass settings as
  environment variables instead.
- `OPA_DEPLOY_BACKUP_DIR` — take an online copy of the archive and the
  audit log (owner-only) into this directory, outside the install, before
  the services restart. Nothing there is ever deleted by `deploy.sh`;
  prune old copies yourself.

What it may print, and why:
- *"The unit file ... changed on disk. Run 'systemctl daemon-reload'"* after
  a restart, with a NOTE that this is pending for every unit: some other
  tool (snapd refreshing a snap, a package install) enabled or disabled a
  unit without reloading systemd, which marks every unit until the next
  `daemon-reload`. Harmless for the deploy; `sudo systemctl daemon-reload`
  clears it. If instead the WARNING names an OPA unit, that unit's file
  changed since systemd loaded it and the restart used the old definition:
  run `sudo systemctl daemon-reload` and deploy again.
- A WARNING that the nginx site is readable by every local account, or
  that it or a unit file can be changed by a non-root account, with the
  one-time `chown`/`chmod` that fixes it; and one about
  `sites-available/opa-secrets-wizard.deploy-backup`, a rollback copy left
  by `deploy.sh` before 5.36.0 (it holds an old copy of the proxy secret;
  remove it).

### Evidence packages on the server (5.53.0)

An evidence package is built from the archive by a background job and written to `packages/` in the data directory
(`/var/lib/opa-compliance-wizard/packages` on the installer's layout): the folder is `0700`, each package sits in its own
folder as a `0600` file, and the whole thing belongs to the application account.

| | |
|---|---|
| Lifetime | A package is kept for **15 minutes** after it is finished (the download window), then its folder is deleted. Everything under `packages/` is also deleted when the application starts, so a restart or an upgrade never leaves one behind. A failed build deletes its half-written file at once. |
| Disk | Allow **free space on the data volume** of about half of the estimated uncompressed size of the period's events, plus 256 MB; the build checks this first and refuses with the numbers if there is not enough. The estimate covers the events only: the report files add more (they compress well, so the rule leaves room). A sync running at the same time can still use space; a disk that fills mid-build fails the build with a plain message and removes the file. A full year of 1,000,000 events produced a package of about 115 MB (built in about 40 seconds, using under 70 MB of memory; the auditor's check of it used about 650 MB). A hard limit of 2 GiB applies to the finished zip (`OPA_EVIDENCE_MAX_BYTES` changes it); a build that would exceed it fails and the person is told to choose a shorter period. |
| Concurrency | One build at a time on the whole server (a second asks to try again in a few minutes). |
| Upgrades | The upgrade preflight refuses while a build runs, **and while a finished package is still inside its 15 minutes** ("a package is waiting to be downloaded (until HH:MM UTC)"), because the restart an upgrade needs deletes finished packages. A scheduled upgrade waits for a running build only as long as it waits for a sync (10 minutes), then goes ahead; a restart at any time (an upgrade, a crash, `systemctl restart`) deletes the packages still in their window. |
| Backups | Not part of the backup set: do not back up `packages/` (the tar command below excludes it). A package is a copy of data that is in the archive. |
| Support bundles | Never included: the bundle holds only the upgrade's own summary, journal lines and audit entries. |
| Uninstall | `--uninstall --keep-data` keeps the data directory; if it was run during the 15 minutes a package may be in it. Delete `packages/` yourself when you remove the data. |
| Where the record is | The Audit Log and the journal: `evidence_package.build` (who, from which address, which environment and period, whether gaps were acknowledged, local mode or MFA), `.build_finished` (rows, bytes, duration, sha256, chain head) or `.build_failed`, and one `.downloaded` for every fetch. Never row content. |

Behind nginx a download is an ordinary proxied response; the template is unchanged. nginx buffers a large response to a temporary
file (its `proxy_max_temp_file_size`, 1 GB by default) and then passes the rest on synchronously, which is fine for a package
within the size limit.

### Backups and restore

The archive, the audit log and the stored credentials exist nowhere else, and
`audit_store.db` is the only copy of evidence older than Okta's 90-day System
Log retention. The paths below are those of a server made by the installer (the
upgrade layout); on an older in-home install the same files sit in the install
folder and the keyring in the application account's `~/.local/share/keyrings`.

**The backup set.**

| What | Where (defaults) | If you lose it | How to copy |
|---|---|---|---|
| The archive: events, sealed manifests, the environments (the `app_environments` table: names, base domain, team, key id, Okta URL), sync schedules, the stored OPA scan, Okta snapshots | `/var/lib/opa-compliance-wizard/audit_store.db` (and `audit_store.db-wal`, `-shm` beside it; or the path `OPA_AUDIT_DB_PATH` names) | Evidence older than 90 days is gone for good | SQLite's online backup only (below). A plain `cp` while the server writes can miss the newest events (they live in the `-wal` file until a checkpoint) or give an inconsistent file |
| The audit log of write actions | `/var/lib/opa-compliance-wizard/audit_log.jsonl` (`.audit_log.jsonl.lock` is only a lock: do not copy it) | The record of who changed what is gone | Copy after the database. It is appended to; the file has no integrity protection of its own |
| Access control, announcement banner | `/var/lib/opa-compliance-wizard/access_control.json`, `banner_config.json` | The admin group and sign-in restriction, and the banner, are reset | Plain copy |
| Key list and revocations this install has learned | `/var/lib/opa-compliance-wizard/release_keys.local.json` | A published key revocation has to be applied again (README, "If the signing key is compromised") | Plain copy |
| The credentials: each environment's OPA key secret and Okta API token, the Okta client secret and the admin-check token | The application account's login keyring: `/var/lib/opa-compliance-wizard/home/.local/share/keyrings/` | Every credential has to be entered again | Copy the directory (it changes only when someone saves a credential; copy again after you change one) |
| The settings and the three generated secrets, **including `KEYRING_UNLOCK_PASSWORD`**, which opens the keyring above | `/etc/opa-compliance-wizard.env` (mode 0600, owned by the application account) | The restored keyring cannot be opened; you would enter every credential again | Plain copy, kept with the keyring but guarded as strictly as a password: the two together open every environment's credentials |
| The login gate's session key | `/etc/opa-secrets-wizard-session.key` (root, group-readable) | A new 32-byte key works, but every session ends and everyone signs in again | Plain copy |
| The nginx site (it carries the proxy secret, which must equal `NGINX_PROXY_SECRET`) and the TLS certificate and key | `/etc/nginx/sites-available/opa-secrets-wizard`, `/etc/nginx/ssl/opa-secrets-wizard.crt` and `.key` | Make the site again with the installer, and the certificate again | Plain copy |
| Each additional login gate (`setup-second-gate.sh`) | `/etc/opa-compliance-wizard-<name>.env`, the folder `/etc/opa-auth-gate-<name>/` (its session key), `/etc/nginx/sites-available/opa-<name>` | That gate has to be set up again | Plain copy |
| Older installs only | `environments.json`, `update_check.json` in the data directory | `environments.json` was imported into the database and deleted by an older release; `update_check.json` is re-made by the next check | Plain copy if present |

Not needed: `/opt/opa-compliance-wizard` (the installed releases and the root-owned
updater: install the release again), the `upgrade/` folder of the data directory (the updater's own
pre-upgrade copies and bundles; large; not a substitute for the backup above), the `packages/` folder
(evidence packages are temporary; see "Evidence packages on the server") and
`/var/lib/ocw-updater` (downloads).

A backup holds people's names and e-mails (the archive) and secrets (the keyring, the settings
file): keep it on an encrypted disk or encrypt it, and give it the same access list as the
server.

**Taking a backup** (as a user with `sudo`; `ocw` is the application account, and `sqlite3` the
command-line tool, `sudo apt-get install sqlite3`). The database is copied as the application
account so SQLite's `-wal` and `-shm` files keep their owner:

```bash
B=/var/backups/opa-compliance-wizard/$(date +%F)
sudo install -d -o ocw -g ocw -m 0700 /var/backups/opa-compliance-wizard "$B"
sudo -u ocw sqlite3 /var/lib/opa-compliance-wizard/audit_store.db ".backup '$B/audit_store.db'"
sudo tar -C /var/lib/opa-compliance-wizard -czpf "$B/data-files.tar.gz" \
  --exclude=./upgrade --exclude=./packages --exclude=./audit_store.db --exclude='./audit_store.db-*' --exclude=./.audit_log.jsonl.lock .
sudo tar -czpf "$B/etc-files.tar.gz" /etc/opa-compliance-wizard.env /etc/opa-secrets-wizard-session.key \
  /etc/nginx/sites-available/opa-secrets-wizard /etc/nginx/ssl/opa-secrets-wizard.crt /etc/nginx/ssl/opa-secrets-wizard.key
sudo sh -c 'chmod 0600 "$1"/*' _ "$B"
```

The second command is SQLite's online backup, safe while the app runs (`VACUUM INTO '<file>'`
makes a compacted copy instead). The first `tar` takes the audit log, the access-control and banner files,
`release_keys.local.json` and the whole `home/` folder with the keyring. Add the files of any
additional login gate to the second `tar`. Then move `$B` off the server.

**Restore drill.** Do it once on a spare server before you need it. Restore into the same
release or a newer one: the app migrates the database forward when it starts. (Restoring into an older
release than the backup came from is a different matter: see "Rolling back past 5.40.4" below.)

1. **A new server only.** Install as in the README ("Installing on a server") with the same
   `--server-name`. That leaves a working backend, an empty archive and newly generated secrets.
2. Stop the services: `sudo systemctl stop opa-compliance-wizard opa-auth-gate` (and every
   `opa-auth-gate-<name>` you run).
3. Put the current files aside rather than deleting them:
   `sudo mkdir /root/ocw-before-restore && sudo mv /var/lib/opa-compliance-wizard/audit_store.db* /var/lib/opa-compliance-wizard/home /root/ocw-before-restore/`.
4. Restore the data files and the database, then the ownership and modes:

   ```bash
   B=<the backup folder>
   sudo tar -C /var/lib/opa-compliance-wizard -xzpf "$B/data-files.tar.gz"
   sudo install -o ocw -g ocw -m 0600 "$B/audit_store.db" /var/lib/opa-compliance-wizard/audit_store.db
   sudo chown -R ocw:ocw /var/lib/opa-compliance-wizard/home
   sudo chown ocw:ocw /var/lib/opa-compliance-wizard/*.json*
   sudo chmod 0700 /var/lib/opa-compliance-wizard/home
   ```
5. Restore the settings, the session key, the nginx site and the certificate together, so the proxy
   secret in the site and in the settings file are the same ones:
   `sudo tar -C / -xzpf "$B/etc-files.tar.gz"`, then check the modes the installer sets:
   `sudo chown ocw:ocw /etc/opa-compliance-wizard.env && sudo chmod 0600 /etc/opa-compliance-wizard.env`
   (`/etc/opa-secrets-wizard-session.key` is root-owned with the application group and mode 0640, the site
   0640 with that group, the TLS key 0600). Then `sudo nginx -t && sudo systemctl reload nginx`.
6. Check the database before anything uses it:
   `sudo -u ocw sqlite3 /var/lib/opa-compliance-wizard/audit_store.db "PRAGMA integrity_check"` must print `ok`.
7. Start: `sudo systemctl start opa-compliance-wizard opa-auth-gate` (the gate only if it was enabled before).
8. **Check the restore.**
   - `systemctl is-active opa-compliance-wizard` says `active`, and
     `curl -s http://127.0.0.1:8766/api/version` answers with the version.
   - `curl -s https://<your-host>/healthz` (add `-k` for a temporary self-signed certificate) answers
     `"status": "ok"`: the active environment's stored credentials can be read back and the archive is reachable.
     `"degraded"` names the failing check (a keyring that does not open usually means the settings file and the
     keyring come from different backups).
   - In the app, **Environments** lists your environments; open one and run **Sync now**. It continues from the
     last event in the restored archive, so only events still inside Okta's 90-day window can fill the gap since the backup.
   - Run the integrity check on each environment (below), and compare its `head_hash` with the last
     `evidence_chain.sealed` entry in the restored `audit_log.jsonl`.
   - Sign in from a private window to see the login gate works.
9. Apply any key revocation published since the backup, if the project has published one (README).
   Delete `/root/ocw-before-restore` once you are satisfied.

**Checking the archive afterwards.** Each environment's integrity check
(`GET /api/environments/<name>/integrity`; the admin-only `?deep=1` additionally re-hashes every
sealed curated event).
Evidence chain v2 is on by default since 5.40.4. For manifests
written from then on, an edited or deleted manifest and (with `?deep=1`)
an edited or deleted curated event show as a broken chain; for the whole
chain, v1 and v2, manifests removed from the end after the upgrade show
as broken, because
each environment's newest link is recorded separately (`chain_heads`)
and new manifests link to it. The hashes are unkeyed: this catches
changes made without rewriting the chain to match, not a deliberate edit
by someone with database write access (who can recompute the hashes, or
simply rewrite the `chain_heads` row). For that, compare the result's
`head_hash` with the last `evidence_chain.sealed` entry in
`audit_log.jsonl`. Manifests written before 5.40.4 are legacy v1 rows --
a continuity check over event ids only -- and are never re-sealed; the
response's `legacy_manifests` counts them and `deep_applicable` says
whether any sealed rows exist to re-read.

Since 5.40.7 the same check is in the app too: **Environments → the
calendar icon on your environment → Evidence chain → Verify** (the
**Deep check** button is shown to admins, and to the operator of a local
run; it keeps asking while the server answers `202`).

**Archives left by deleted environments (5.40.7+).** Deleting an
environment without purging its archive leaves those events in
`audit_store.db` with no environment to show them. Admins (and a local
run's operator) see them under **Orphaned archives** in the sidebar and
can purge one after typing the first 8 characters of its id; the server
refuses while the environment still exists or a sync is running, and the
purge is written to the audit log with per-table counts. Purging is
permanent -- take a backup first (above) if you might need the evidence.

**A deep check on a large archive (5.40.6+).** `?deep=1` re-reads every
sealed curated event, and curated events are never pruned, so its cost
grows with the archive (roughly 8-20 s per million sealed events). It runs
in the background, one at a time per environment. The request waits up to
20 s: a check that finishes in time is answered with `200` and the result,
as before. A longer one answers `202 {"status": "running", ...}`; call the
same URL again (every ~10 s) until it answers `200` -- or `500` if the
check failed (reported once; the next call starts a new check). The finished result
carries `checked_at` and is served to repeat calls for 2 minutes; after
that the next call starts a fresh check. For example (`$BASE` and
`$AUTH` stand for however you already call the API):

```bash
until code=$(curl -s -o result.json -w '%{http_code}' -H "$AUTH" \
      "$BASE/api/environments/<name>/integrity?deep=1") && [ "$code" != 202 ]; do sleep 10; done
cat result.json
```

**Rolling back past 5.40.4.** Once a 5.40.4+ sync has run, code from
5.40.3 or earlier cannot read the sealed entries (its deep check fails on
every new manifest) and its next sync writes an unsealed row after a
sealed one (a "downgraded" chain). Take a backup before upgrading (as
above) and restore it together with the old code if you roll back --
knowing that this drops every event synced since the upgrade, and only
events still inside Okta's 90-day System Log window can be fetched again.

Set
`OPA_AUDIT_DB_PATH=/var/lib/opa-compliance-wizard/audit_store.db` (or any
path outside the code checkout) in the service's environment file to keep
the archive out of the directory `deploy.sh` rsyncs over: create that
directory first, owned by the app user (`install -d -o <app-user> -g
<app-user> -m 0700 /var/lib/opa-compliance-wizard`), and add it to the
unit's `ReadWritePaths=` (the shipped unit uses `ProtectHome` /
`ProtectSystem`, so an unlisted path is read-only to the service). The app
creates the file owner-only (`0600`) wherever it lives.

**Health check.** `GET /healthz` (unauthenticated by design, same
`auth_request off` treatment as `/login`) returns `{"status": "ok"|
"degraded", "version": ..., "checks": {...}}` in local mode. In `hosted`
mode (5.40.5+) anyone who can reach the HTTPS port can call it, so it
answers only `{"status": ...}`: the version is on `GET /api/version`
(loopback, `curl -s http://127.0.0.1:8766/api/version`) and a failed
check's detail is a `WARN` line in the service's journal. Point an external uptime
monitor or load balancer at `https://<your-host>/healthz` instead of `/`
(which always 200s, even with zero environments configured or a broken
archive, so it can't actually tell you anything is wrong). Checks are
local-only (no live Okta API call, so polling it doesn't cost rate
limit): whether the active environment's stored credentials can be read
back, and whether the compliance archive (`audit_store.db`) is
reachable. A failing check degrades `status` to `"degraded"` (still a
200 — partial health info is more useful to a monitor than an opaque
500) and names which check failed.

**Per-user environments.** Once behind the login gate, each logged-in
Okta identity gets their own private set of environments by default (an
environment created by user A is invisible to user B) -- opt an
environment into being visible to every other logged-in user via the
**Shared / Private** badge in the environment manager (or directly:
`POST /api/environments/{name}/share`). Every write action (environment
changes, folder/resource-group/policy/group creates and deletes, sync
starts, admin overrides) is appended to `audit_log.jsonl`, attributed to
the real logged-in identity. The file is created owner-only (`0600`; an
older, wider file is narrowed on its next write), and
every process that writes it takes a lock on `.audit_log.jsonl.lock`
next to it (5.40.6). If an entry cannot be written (disk full, read-only
file), the action it describes has already happened, so it is not turned
into an error: the journal gets an `Audit log append FAILED` line with the
action, the actor's id and the time. The file has no rotation and no
integrity protection of its own; keep it in your backups. Running the CLI or `launch.py` directly (no
login gate in front of them at all) is entirely unaffected by any of
this -- there's exactly one shared, unscoped environment list, matching
this tool's original single-user design.

**What shared users may do (5.42.0).** Sharing is the owner's decision;
what a shared user may then do with someone else's environment is an
admin's. A shared user acts with the owner's stored OPA key and Okta
token, so each of these is a separate setting: view archived reports,
live read queries, write to the OPA tenant / Okta org (resource groups,
projects, folders, policies, group membership, new Okta groups), import a
CSV into the archive, reset the sync watermark, run Sync now, change sync
settings. Admins set a global default in **Shared permissions** (sidebar)
and can override any of them per environment (**Environments → Shared
permissions** on a row): inherit, allow or don't allow. Owners are never
limited, and retention (which deletes archived events) stays the owner's
even for a shared user allowed to change sync settings. The server enforces every setting on every route (a refused call
answers `403` with `"reason": "shared_permission_denied"`); the UI only
mirrors it. **Built-in defaults (5.43.0):** view archived reports, live
read queries and reset the sync watermark are allowed; write to the OPA
tenant / Okta org, import a CSV, Sync now and the sync settings are not.
(In 5.42.0 the tenant writes and CSV import were allowed too, as before
that release.) Admins using someone else's shared environment get the same
limits as anyone else (they can change the setting, which is audited).
Every change is logged as `shared_permissions.update` with each
capability's stored value before and after.

**Per-user exceptions (5.43.0).** Under **Environments → Shared
permissions → Per-user exceptions** an admin can allow or refuse one
capability for one user on one environment, above that environment's
setting: a user exception beats the environment's override, which beats
the global default, which beats the built-in default. A user is the pair
the login gate vouches for -- the gate's Okta issuer (sent to the backend
as `X-Auth-Issuer`, alongside `X-Auth-Sub`; nginx adds
`X-Nginx-Issuer-Forwarded` = the proxy secret where it overwrote it, and
`serve.py` believes the issuer only with that marker) and the user's Okta
id (`sub`)
in that org: an Okta id alone is only unique within one org (OpenID Connect
Core 1.0, section 5.7), and an additional gate (below) fronts another org.
So the same person signing in through two gates is two users, and an
exception never applies to a request that arrives without an issuer (local
mode, or an nginx site / gate older than 5.43.0). The picker lists every
user a gate has vouched for since 5.43.0 (`known_identities`, refreshed when
a user reaches the backend, at most once a day; a user not
recorded for 400 days whom no exception names is dropped) by e-mail, org
and id; you can also type an issuer and id. Saving uses the same MFA
approval and `shared_permissions.update` audit entry (`"scope": "user"`)
as the other settings. Changing a gate's `OKTA_AUTH_SERVER` changes its
issuer: its users' exceptions stop matching and must be set again.

**Every change in the Environments area needs a fresh MFA approval
(5.42.0).** Creating, editing (credentials and rename included), deleting
(with or without the archive), sharing or unsharing an environment, saving
sync settings, resetting the sync watermark, importing a CSV into the
archive, purging an orphaned archive and changing shared permissions all
use the Access Control save's step-up flow below, for every user, not just
admins: the server checks the change and stores it as a pending action
(`pending_admin_actions`, bound to your Okta `sub`, single use, 15 minutes),
the browser goes through the gate's `/step-up`, and the change is applied
on the way back through `/api/environment_changes/save` -- an nginx
location with `auth_request /verify_stepup`, like
`/api/access_control/save`. The approval covers exactly the change that
was stored; whatever the browser sends with the save is ignored, and every
check runs again when it is applied. The environment form's secrets are
never written to the pending action (credentials stay in the keychain
only): they wait in the server's memory, and a restart during the round
trip asks for them again. Activating an environment, Sync now and
read-only views are not gated. **Local mode** has no login gate and no
identity provider to step up with, so there these changes apply at once,
as before.

**Opening Settings and Updates needs a fresh MFA too (5.53.0).** Behind
the login gate, the Access control, Shared permissions, Orphaned archives
and Environments screens (the environment details: OPA domain, team, key
ID, Okta URL, sync schedule) and the whole Updates page, including its
signing-key page and the support-bundle download, show nothing until you
pass the same step-up. The screen offers **Continue with Okta**; the
browser goes through the gate's `/step-up` and comes back to
`/api/environment_changes/save` as `settings.unlock`, whose only effect
is a row in `settings_unlocks` (migration 012) that says *this person, in
this login session, through this gate* may read Settings until it
expires **10 minutes** later. The server checks that row on every
protected request (a refused read answers `403` with `"scope":
"settings"` and `"reason": "settings_locked"`); the browser only explains
it, with a countdown and a **Lock now** link. Every save and every
upgrade still asks for its own fresh MFA, and a completed save of the
kinds listed in the changelog (every Environments change, the Access
control save, the announcement banner, the update settings and upgrade
requests) also restarts the 10 minutes, because it just proved the same
thing. The approval of a Settings unlock can open Settings and nothing
else, and no other approval, such as an evidence package build,
opens or extends it. The window belongs to one sign-in: signing out and
in again, or another person, starts locked. A restart of the application
(an upgrade) keeps it. The announcement banner is also a step-up change
now. The list every screen uses to switch environments no longer carries
the OPA domain, team, key ID, Okta URL or sync schedule; those come with
the unlock. The audit log records `settings.unlocked`, `settings.locked`
(`reason`: `manual`, `expired` when the first refused request after
expiry notices it, or `operator`) and, in local mode,
`settings.access_without_mfa_local`. **Local mode** has no login gate and
no identity provider, so Settings and Updates open without a second
factor there, say so in a notice, and record each opening (at most one
entry per area per 10 minutes). An additional login gate's nginx site
generated before 5.42.0 has no step-up location, so its users cannot
unlock Settings (or approve any change): `setup-second-gate.sh` and the
updater's pre-upgrade checks warn about such a site, and
`sudo bash <install>/current/server/install.sh --regenerate-second-sites`
repairs it. The audit log page itself is not behind the unlock.

**Locked out of Settings (break-glass).** The unlock only guards *reading*
Settings and Updates in the browser; the people who run the server keep
every tool they had. If Okta or the second factor is unavailable, the
browser cannot open Settings, Access control or Updates until it is back,
by design (every save and upgrade would need the same MFA anyway), and
nothing else is affected: reports, the Overview and the Audit Log keep
working. Root on the host can still upgrade, roll back and restore with
`sudo ocw-updater ...` (it does not use the browser), and can change the
Okta group IDs by editing `access_control.json` in the data directory
(the gate reads it at each login). To end **every open Settings and
Updates window now** (for example after a suspected stolen session), run
the application's own command as the application account, then check the
Audit Log for the `settings.locked` entry with `"reason": "operator"`:

```bash
sudo runuser -u <application account> -- env OPA_DATA_DIR=/var/lib/opa-compliance-wizard \
  /opt/opa-compliance-wizard/current/.venv/bin/python -m server.updater settings-unlocks list
sudo runuser -u <application account> -- env OPA_DATA_DIR=/var/lib/opa-compliance-wizard \
  /opt/opa-compliance-wizard/current/.venv/bin/python -m server.updater settings-unlocks clear --confirm CLEAR
```

Clearing only removes access: nobody can read Settings again until they
pass a new MFA, and it can never open one. There is no command that opens
a window without MFA, on purpose. (`ocw-updater` does not forward this
command yet; use the form above.)

**Admin access.** Members of one designated Okta group get full admin
rights across the whole dashboard: every environment becomes visible and
editable (not just their own or explicitly shared ones), and a new
Audit Log panel (sidebar, admin-only) shows every write action ever
logged, by anyone. (A local run, with no login gate, shows the Audit Log
and banner settings to its operator; Access control needs the hosted
step-up flow and stays hosted-admin-only.) To set this up:
1. Create (or reuse) an Okta group for admins of this tool, and note its
   **group ID** (Admin Console -> Directory -> Groups -> click the
   group -> the ID is in the URL, `.../groups/<id>/...`) -- a group ID,
   not its display name, is what `OKTA_ADMIN_GROUP_ID` (step 4 above)
   expects, so this check is one direct API call per login rather than
   a name-to-id lookup every time.
2. Store an Okta API token in the keyring for the admin-membership check
   itself -- this is deliberately separate from any environment's own
   Okta token, since the check must work for every logged-in user
   regardless of which environment(s) they've personally configured:
   ```bash
   python3 -c "import keyring; keyring.set_password('opa-compliance-wizard:<OKTA_ENV_NAME>', 'okta_admin_check_token', '<token>')"
   ```
   A read-only token (Users + Groups read scope) is enough and is the
   right choice for a real deployment -- reusing a broader admin token
   works too but widens the blast radius if this process or its stored
   credential were ever compromised.
3. `OKTA_ADMIN_GROUP_ID` is only a **bootstrap default** now -- it's used
   as-is (with no user group, and login open to any authenticated Okta
   user) only until an admin saves real settings via the dashboard's new
   **Access control** panel (sidebar, admin-only), described next. No
   restart is needed for a group ID saved through that panel to take
   effect -- it's read fresh on every login. The env var still needs to
   be set for first boot, before anyone has admin rights to open that
   panel at all (chicken-and-egg).

**Restricting who can log in at all (User Group), and changing either
group ID from the dashboard.** Beyond admin rights, a second Okta group
("User Group") can be required for login itself -- open the **Access
control** panel (sidebar, admin-only) to set:
- **Admin Group ID** -- same group as above, now editable here instead
  of only via the env var.
- **User Group ID** -- a second Okta group; members get ordinary
  (non-admin) access.
- **Restrict login to these groups** -- off by default. When off (the
  safe default for a fresh deployment), any authenticated Okta user can
  log in, same as always -- only admin rights are gated. When on, anyone
  in *neither* group is denied at login with a clear message, not just
  denied admin rights. Turn this on only after confirming real users are
  actually covered by one of the two groups, since flipping it on with
  an empty/wrong User Group ID would lock out every non-admin user on
  their next login.

Saving a change in this panel requires completing a **fresh Okta MFA
challenge immediately before the save** -- clicking Save redirects you
through Okta again (even if you're already logged in) to prove you, right
now, still control this identity, then returns you to the dashboard to
finish saving. This is a real Okta Identity Engine step-up request
(`max_age=0` + `acr_values=urn:okta:loa:2fa:any`) -- **it depends on your
OIDC app's own Authentication Policy actually permitting/requiring a
second factor.** If that policy doesn't, Okta may silently satisfy the
step-up from your existing session without ever prompting for MFA; check
this in the Okta Admin Console (Security -> Authentication Policies) if
step-up doesn't seem to be challenging you. Every save is logged as
`access_control.update` with a `step_up_verified: true` marker, alongside
the usual `admin_override` marker convention for admin actions -- and,
where Okta's own System Log has already indexed it (usually within
seconds, but not guaranteed instant), an `okta_mfa_log_event` field
carrying Okta's own `user.authentication.auth_via_mfa` record for that
exact challenge, so the audit trail isn't just this tool's self-reported
marker. A `null` value there means Okta hadn't indexed the event yet at
save time (or the lookup failed transiently) -- it does NOT mean the MFA
challenge itself didn't happen; the save was already gated by a verified,
short-lived step-up cookie before this lookup ever ran.

As with the admin-group check, a change to either group ID or to
`restrict_login` takes effect on each affected user's next login/session
refresh, not instantly -- same accepted tradeoff this project has always
had for the admin-group check.

Every admin override action is logged with an `admin_override: true`
marker, so an admin's own activity is just as visible in the audit
trail as anyone else's -- this is meant to support compliance work, not
to be a quiet backdoor.

---

A login gate configured only through a systemd drop-in (not the shared settings file) looks unconfigured to the upgrade preflight's check for an unset gate (see the README, "Upgrading"); finish the gate setup in the settings file, or run the refresh command it names.

## Uninstalling

`sudo bash get-ocw.sh --uninstall --keep-data` (or `sudo server/install.sh --uninstall --keep-data` from the installed release) stops and
removes the services, the `ocw-updater` command, `/opt/opa-compliance-wizard`, the staging account, its downloads and its pip cache (`/var/cache/ocw-updater`), and the nginx
site (it keeps the site while an additional login gate exists, because those sites reuse its rate-limit zone), after you type
`UNINSTALL`. It **keeps** everything that holds your data or settings, so installing again finds them:

| Kept | Path (defaults) |
|---|---|
| The archive, audit log, access control, environments, upgrade backups and the application account's home with its keyring | `/var/lib/opa-compliance-wizard` |
| The settings file (with the generated secrets) and the login gate's session key | `/etc/opa-compliance-wizard.env`, `/etc/opa-secrets-wizard-session.key` |
| The TLS certificate and key | `/etc/nginx/ssl/opa-secrets-wizard.crt` and `.key` |
| The application account, the distribution packages, every `*.migrated-*` file and the directory of a legacy install | `ocw` (`userdel`), `apt` |

An evidence package built in the last 15 minutes may still be in `packages/` under the data directory; it is temporary and holds
personal data, so delete that folder together with the rest when you remove the data.

**Removing the data too is a manual step**, on purpose: it deletes the only copy of evidence that may be older than Okta's own log
retention. Make a backup first (see "Backing up and restoring the archive"), then remove the paths above yourself when you are sure.
Additional login gates (`opa-auth-gate-*`, their environment files, sites and session keys, `cloudflared`) were created by
`setup-second-gate.sh` and are left alone: remove them first.

## Running it as a CLI instead

Everything below is a second, independent way to use this project's
folder-creation engine: a scriptable command-line tool
(`create_secret_folders.py`), separate from the dashboard above. Same
engine code, same credentials, no dashboard required.

## CLI Setup

The CLI needs the four OPA credentials available via one of three
resolution sources (see the main [README](../README.md)'s "Security:
encrypted credential storage" section for the full priority order).
Easiest is to just use the dashboard once (see
[Environments](features.md#environments-dev--uat--prod-etc)) — the CLI
will then automatically follow whatever you activated there. To set them
up independently of the dashboard:

**OS environment variables:**
```bash
export OPA_BASE_DOMAIN="yourorg.pam.okta.com"   # or *.pam.oktapreview.com etc.
export OPA_TEAM_NAME="yourteam-pam"
export OPA_KEY_ID="<service user API key ID>"
export OPA_KEY_SECRET="<service user API key secret>"
```

**Or a local `.env` file** (legacy, plaintext, fully opt-in): copy
`.env.example` to `.env` and fill in the same four values. Real OS
environment variables always take priority over it if both are set.

Auth is a two-step exchange: the script POSTs `key_id`/`key_secret` to
`/v1/teams/{team}/service_token` to get a short-lived bearer token,
then uses that token (`Authorization: Bearer ...`) for every
subsequent call. If a call ever gets a 401, the script refreshes the
token once automatically and retries.

## CSV format

One row per **leaf** folder. `path` uses `/` to express nesting; any
depth is supported. Missing intermediate ancestors are created
automatically (with a blank description, unless you also give that
ancestor its own row).

```csv
path,description
Prod-Servers,Top-level prod credentials
Prod-Servers/DB,DB tier creds
Prod-Servers/DB/Postgres,Postgres-specific
Prod-Servers/App,App tier creds
```

See `folders_template.csv` for a ready-to-edit starting point.

**Folder name character rule (enforced by OPA, validated locally
before any API call):** names may contain only letters, digits, `.`,
`_`, and `-` — no spaces or other punctuation. The script checks every
path segment up front and refuses to run (listing every offender) if
any name violates this, rather than failing midway through a run.

## CLI Usage

Dry-run (default — no changes made, just a preview):

```bash
python create_secret_folders.py \
  --csv folders_template.csv \
  --resource-group-id <resource_group_id> \
  --project-id <project_id>
```

Actually create the folders:

```bash
python create_secret_folders.py \
  --csv folders_template.csv \
  --resource-group-id <resource_group_id> \
  --project-id <project_id> \
  --execute
```

Output: prints an indented tree marking `[exists]` vs `[will create]`
for every path. When run with `--execute`, also writes a results CSV
(`--output`, default `folders_result_<timestamp>.csv`) with columns
`path,folder_id,status,error_message` — `status` is one of `created`,
`skipped_exists`, or `error`.


## Serving a second Okta org (optional, 5.38.0+)

One server can sign people in through two Okta orgs, sharing the same app
and data: a second `auth_gate.py` instance with its own settings, and an
nginx site per hostname. The first gate, its env file and nginx site are
untouched.

**Set it up with `server/setup-second-gate.sh`** (5.38.1), as the app user. On a server
made by the installer, run it from the installed release
(`/opt/opa-compliance-wizard/current/server/setup-second-gate.sh`); on an older in-home install it is in your
checkout. The script uses the account that runs it as the new gate's account (it owns the new settings file and
key folder) and calls `sudo` itself, so that account needs `sudo`; the application account the installer
creates (`ocw`) has no login shell, and the script has not been adapted to it, so check the plan it prints
before you accept:

```bash
mkdir -p ~/.opa-setup && chmod 700 ~/.opa-setup
# put the new Okta app's client secret in ~/.opa-setup/<name>-client-secret (chmod 600)
bash /opt/opa-compliance-wizard/current/server/setup-second-gate.sh \
  --name <name> --org-url https://<org or custom domain> --auth-server org \
  --client-id <Okta client id> --admin-group <Okta group id> --origin https://<hostname> \
  [--port 8768] [--listen 127.0.0.1:8080] [--allow-public-listen] [--tunnel]
```

`--listen` must be a loopback address (`127.x.x.x`) unless
`--allow-public-listen` is also given (5.40.5+): the generated site speaks
plain HTTP and expects TLS to end in front of it.

It asks for sudo and for the read-only Okta admin-check token (hidden),
backs up first, and is safe to re-run. What it creates:

- `/etc/opa-compliance-wizard-<name>.env`: that org's `OKTA_ORG_URL`,
  `OKTA_OIDC_CLIENT_ID`, `OKTA_ADMIN_GROUP_ID`, `DASHBOARD_ORIGIN`,
  `OKTA_ENV_NAME` (its own keyring namespace), `OKTA_AUTH_SERVER`,
  `OPA_SESSION_KEY_PATH` (its own key: neither gate accepts the other's
  sessions), `OPA_ACCESS_CONTROL_PATH` (its own access control: admin group =
  `--admin-group`, sign-in restricted to it), plus the same
  `KEYRING_UNLOCK_PASSWORD` and
  `NGINX_PROXY_SECRET` as the main file.
- systemd unit `opa-auth-gate-<name>` (copy of the main unit on another
  port); on an install that still uses the old in-place layout it also adds the sudoers grant `server/deploy.sh` needs.
- nginx site `opa-<name>` built by `server/nginx_second_site.py` from the
  live main site: same rules, listening on `--listen` (loopback by default,
  for a Cloudflare Tunnel; TLS ends in front of it), sign-in routes pointed
  at the new gate. `deploy.sh` doesn't manage this file.
- The hostname added to `EXTRA_ALLOWED_ORIGINS` for `serve.py`.

**Access control is main-org-only (GATE-04, 5.39.4+).** `serve.py` shares
one backend across every gate and has no notion of which gate authenticated
a request, so an admin in the SECOND org's admin group would otherwise be a
full admin of the shared backend -- including the MAIN org's own
`access_control.json` (its admin group, user group, and `restrict_login`).
`server/nginx_second_site.py` closes this at the edge: the generated site
for an additional gate answers `403` on `/api/access_control` (read and
write) instead of proxying it, so that route is reachable only through the
main gate's own site. There is no per-gate equivalent to redirect it to --
the dashboard's Access control page only ever edits the one, default file.

**Shared permissions and archive purges are main-gate-only too (SP-5,
5.43.0).** The same way, the generated site answers `403` on
`/api/shared_permissions` (read and write) and `/api/archives` (the
orphaned-archive list and purge), and on any `DELETE` whose raw query
string mentions `purge` or carries a percent-escape -- deleting an
environment together with its archive (`?purge_archive=1`); a location
can't match a query string, so that one is a server-level check on the
request exactly as sent, before any location. Ordinary deletes (the UI
sends at most `?id=<uuid>`) pass. (`serve.py` also refuses any `/api/`
path with a `.` or `..` segment, so nginx's normalised path and the one
it routes on can't differ.) Admins change these settings
from the main gate's site. A site generated before 5.43.0 has none of
these blocks (nor the `X-Auth-Issuer` forwarding per-user exceptions need)
until it is rebuilt as described below.

`server/deploy.sh` restarts every enabled `opa-auth-gate-*` unit after the
main gate, so deploys keep both gates on the same code.

**Environments changes through an additional gate (5.42.0).** The
generated site keeps the main site's `/api/environment_changes/save`
step-up location (pointed at the additional gate, which serves `/step-up`
the same way), so its users approve Environments changes with their own
org's MFA. A site generated before 5.42.0 doesn't have that location: there
those changes are refused (`"reason": "step_up_unavailable"`) until the site
is rebuilt as described below -- serve.py accepts the save only with a
header that location alone sets. An admin of the additional org's admin
group is otherwise an admin of the shared backend (audit log, banner);
since 5.43.0 the shared-permission settings and archive purges are not
reachable through that site (above).

**The generated site is a snapshot.** It is built once from the live main
site and `deploy.sh` never updates it, so changes to the main template
(e.g. 5.40.5's security headers and sign-in rate limit) reach an additional
gate's site only when you rebuild it: run
`sudo bash /opt/opa-compliance-wizard/current/server/install.sh --regenerate-second-sites`
(5.50.0+). It rebuilds the nginx site of every additional login gate (`opa-auth-gate-*`) from the live main site
with this release's deny rules, runs `nginx -t` first and puts the old site back if nginx refuses it. (Before
5.50.0 the way was to remove `/etc/nginx/sites-available/opa-<name>` and `/etc/nginx/sites-enabled/opa-<name>` and
re-run the same `setup-second-gate.sh` command; every other step is skipped.) Behind a tunnel every request reaches nginx from `127.0.0.1`, so
the per-address sign-in rate limit is shared by everyone using that site.

## Host status for monitoring (optional, 5.39.0+)

`server/host_status.py` reports the server's health as JSON at `GET /__status`, on
`127.0.0.1:8790` only: OS, uptime, load, memory, disk, the state of the systemd services you list,
pending apt updates (security counted separately), reboot-required, the app's version and an
overall `state` (`ok` / `warn` / `down`). It holds no secrets and takes no input.

    bash server/setup-host-status.sh --services "nginx opa-compliance-wizard opa-auth-gate cloudflared"

Publish it only behind an access gate. With a Cloudflare Tunnel, add an ingress rule for your
hostname with path `^/__status$` → `http://127.0.0.1:8790` **above** the hostname's main rule, with
the same `originRequest.access` settings, so Cloudflare Access protects it like the rest of the
site; a monitor can then read it with an Access service token. `server/deploy.sh` restarts the
service on every deploy once it's installed.
