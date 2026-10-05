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
   (`env_name` matches whatever `OKTA_ENV_NAME` you set in step 4). An
   install from before the 5.20.0 rename can leave existing credentials
   stored under the old `opa-secrets-wizard:{env_name}` prefix as-is —
   they're still read via a fallback and need no migration.
4. Set these environment variables for `server/auth_gate.py` (e.g. in the
   systemd unit's `EnvironmentFile`) -- the process refuses to start
   without all three, rather than silently pointing at the wrong org:
   - `OKTA_ORG_URL` — e.g. `https://your-org.oktapreview.com`
   - `OKTA_OIDC_CLIENT_ID` — the Client ID from step 1 (not secret, but
     still specific to your deployment)
   - `DASHBOARD_ORIGIN` — the public origin this dashboard is reachable
     at, e.g. `https://192.168.1.10` or `https://opa.example.com`
   - `OKTA_ADMIN_GROUP_ID` — see "Admin access" below.
   - `OKTA_ENV_NAME` (optional, defaults to `"default"`)
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
6. Install and enable the two systemd units (`opa-compliance-wizard.service`,
   `opa-auth-gate.service`) and the nginx site config, adjusting paths/IPs
   for your own server. (An install predating the 5.20.0 rename can keep
   its existing `opa-secrets-wizard.service` unit name as-is — nothing
   requires renaming a unit that's already running; this filename is the
   template a fresh install starts from.)

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
   /etc/systemd/system/` after any deploy that touches these files, same
   spirit as `deploy.sh`'s own nginx-drift warning. Also confirm your
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
7. **One-time sudoers setup, only if you'll use `server/deploy.sh` to
   redeploy later** (recommended — it's the repeatable path; see that
   file's own header comment). This grants the deploying user just the
   few commands that script needs, nothing broader — it's deliberately a
   one-time, human-reviewed step done directly on the server, not
   something `deploy.sh` ever does to itself. (Why not have the script do
   this automatically? Because it pulls and runs code from GitHub on
   every invocation — letting it also edit sudoers would mean any future
   commit could silently grant itself more privilege than this exact
   list, which defeats the entire point of scoping sudo narrowly in the
   first place.) **This step is no longer optional as of Phase 8
   (2026-10-02)** — `deploy.sh` used to continue (with a printed warning)
   if the `opa-auth-gate` restart specifically couldn't run, since
   auth_gate.py is this app's own OIDC auth gate and a deploy that ships
   new auth logic but silently fails to restart the process running it
   is the wrong thing to call "completed." That restart is now
   unconditional and fatal — skip this sudoers setup and a deploy with
   any code change at all will fail outright at that step, not just
   warn. (nginx config drift, the other thing this grants, still only
   warns-and-prints-the-manual-command if its own narrower sudoers gap
   is hit — only the auth-gate restart was escalated.)

   Step 7a. Find the exact paths to `systemctl`, `nginx`, and `cp` on
   *your* server — sudoers rules match an exact binary path, not just a
   command name, and these vary by distro:
   ```bash
   which systemctl nginx cp
   ```
   Note the three paths this prints — you'll use them in step 7c below.
   (The example in step 7c uses the common Debian/Ubuntu paths
   `/bin/systemctl`, `/usr/sbin/nginx`, `/bin/cp` — replace them if your
   `which` output differs.)

   Step 7b. Confirm the deploying Linux username (the account that will
   actually run `./deploy.sh` — e.g. `rparikh`) and the real path to this
   repo on the server (e.g. `/home/rparikh/opa-secrets-folders`) — you'll
   substitute both into step 7c.

   Step 7c. Open a new sudoers file for editing. **Always use `visudo`**
   (never edit the file directly) — it validates syntax before saving, so
   a typo here can't lock out `sudo` entirely:
   ```bash
   sudo visudo -f /etc/sudoers.d/opa-compliance-wizard-deploy
   ```
   Paste the following into the editor that opens, then replace every
   `rparikh` with your actual deploying username (step 7b) and every
   `/home/rparikh/opa-secrets-folders` with your actual repo path (step
   7b) — leave `opa-secrets-wizard` and `opa-auth-gate` exactly as-is,
   those are fixed systemd unit names, not placeholders. Note there are
   **two separate `cp` lines**, not one — `deploy.sh` applies the new
   nginx config over the live path, and (only if `nginx -t` or the
   reload then fails) rolls its own backup — kept in the repo's own
   `$APP_DIR`, not under `/etc/nginx`, so creating/deleting it never
   needs sudo at all — back over the live path; sudoers matches each
   exact argument list separately, so a rule for only one of these two
   leaves the other silently denied:
   ```
   rparikh ALL=(ALL) NOPASSWD: /bin/systemctl restart opa-secrets-wizard, \
     /bin/systemctl restart opa-auth-gate, \
     /bin/cp /home/rparikh/opa-secrets-folders/server/nginx-opa-secrets-wizard.conf /etc/nginx/sites-available/opa-secrets-wizard, \
     /bin/cp /home/rparikh/opa-secrets-folders/.nginx-deploy-backup /etc/nginx/sites-available/opa-secrets-wizard, \
     /usr/sbin/nginx -t, \
     /bin/systemctl reload nginx
   ```
   Save and exit (same keys as your system's default editor — usually
   `nano`: Ctrl+O then Enter, then Ctrl+X). `visudo` will refuse to save a
   file with a syntax error and tell you so — if that happens, fix the
   reported line rather than forcing a save.

   Step 7d. Verify the rule actually works, logged in AS the deploying
   user (not as root or your own login) — `-l` only lists what you're
   allowed to run, without actually running (and so without restarting
   the live app or touching nginx):
   ```bash
   sudo -n -l
   ```
   You should see all six commands from step 7c listed under
   `NOPASSWD:`, with no password prompt. If you instead get a password
   prompt, a `sudo: a password is required` error, or the list doesn't
   include all six, re-open the file from step 7c and check for a typo
   — most commonly the username, or a binary path that doesn't match
   step 7a's `which` output exactly.

**Health check.** `GET /healthz` (unauthenticated by design, same
`auth_request off` treatment as `/login`) returns `{"status": "ok"|
"degraded", "version": ..., "checks": {...}}` — point an external uptime
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
the real logged-in identity. Running the CLI or `launch.py` directly (no
login gate in front of them at all) is entirely unaffected by any of
this -- there's exactly one shared, unscoped environment list, matching
this tool's original single-user design.

**Admin access.** Members of one designated Okta group get full admin
rights across the whole dashboard: every environment becomes visible and
editable (not just their own or explicitly shared ones), and a new
Audit Log panel (sidebar, admin-only) shows every write action ever
logged, by anyone. To set this up:
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

**Set it up with `server/setup-second-gate.sh`** (5.38.1), as the app user:

```bash
mkdir -p ~/.opa-setup && chmod 700 ~/.opa-setup
# put the new Okta app's client secret in ~/.opa-setup/<name>-client-secret (chmod 600)
bash ~/opa-secrets-folders/server/setup-second-gate.sh \
  --name <name> --org-url https://<org or custom domain> --auth-server org \
  --client-id <Okta client id> --admin-group <Okta group id> --origin https://<hostname> \
  [--port 8768] [--listen 127.0.0.1:8080] [--tunnel]
```

It asks for sudo and for the read-only Okta admin-check token (hidden),
backs up first, and is safe to re-run. What it creates:

- `/etc/opa-compliance-wizard-<name>.env`: that org's `OKTA_ORG_URL`,
  `OKTA_OIDC_CLIENT_ID`, `OKTA_ADMIN_GROUP_ID`, `DASHBOARD_ORIGIN`,
  `OKTA_ENV_NAME` (its own keyring namespace), `OKTA_AUTH_SERVER`,
  `OPA_SESSION_KEY_PATH` (its own key: neither gate accepts the other's
  sessions), plus the same `KEYRING_UNLOCK_PASSWORD` and
  `NGINX_PROXY_SECRET` as the main file.
- systemd unit `opa-auth-gate-<name>` (copy of the main unit on another
  port) and a sudoers grant so `server/deploy.sh` can restart it.
- nginx site `opa-<name>` built by `server/nginx_second_site.py` from the
  live main site: same rules, listening on `--listen` (loopback by default,
  for a Cloudflare Tunnel; TLS ends in front of it), sign-in routes pointed
  at the new gate. `deploy.sh` doesn't manage this file.
- The hostname added to `EXTRA_ALLOWED_ORIGINS` for `serve.py`.

`server/deploy.sh` restarts every enabled `opa-auth-gate-*` unit after the
main gate, so deploys keep both gates on the same code.
