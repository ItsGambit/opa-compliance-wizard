# OPA Secrets Wizard

Creates a tree of Okta Privileged Access (OPA) vault **secret folders**
(root / sub / sub-sub / ... any depth) — and, if needed, the resource
group / project / access group they live under — from a CSV file or an
interactive dashboard.

- **CLI** (`create_secret_folders.py`) — scriptable, CSV in, CSV out.
- **Interactive dashboard** ("OPA Secrets Wizard", `frontend/` + `server/`)
  — pick or create the resource group/project/group from live dropdowns,
  build the folder tree visually, save it to a CSV, then Preview/Create
  right from the page. See "Interactive Dashboard" below.

Both share the exact same engine code (`create_secret_folders.py` is
imported by the dashboard server, not reimplemented) — no logic is
duplicated between them.

Model: **Resource Group -> Project -> Folder** (folders can nest under
other folders via `parent_folder_id`). Resource groups require at least
one **group** for access delegation; per this tool's design, groups are
always created in **Okta** (core API) and synced into OPA via **Group
Push** — never via OPA's own local-group endpoint. See "Groups" below.

All endpoints, auth flows, and field names in this tool were
**live-verified** against a real tenant (not just inferred from
documentation) — see "Confirmed tenant behavior" below.

> **This is an early, community-testing release.** It has been used and
> live-tested against a real OPA tenant throughout development, but it
> is not an official Okta product and comes with no support commitment.
> See "No warranty" below, and please open a GitHub issue with any
> feedback or problems you run into.

## Prerequisites

| Requirement | Minimum version | Why |
|---|---|---|
| Python | 3.9+ | `keyring` (encrypted credential storage) requires it |
| Node.js | 20.19+ or 22.12+ | Vite 8 (the frontend build tool) requires it |
| npm | bundled with Node | frontend dependency install/build |
| pip | bundled with Python | installs `keyring` |

You don't need to check these yourself — `launch.py` (and therefore
every launcher below) checks on every run and, if something is missing
or too old, offers to install/upgrade it for you via whatever package
manager your OS already has (`winget` on Windows, `brew` on macOS,
`apt`/`dnf`/`pacman` on Linux), asking for confirmation before running
anything. If none of those are available, or you'd rather not, it
prints the exact manual install command and exits cleanly instead of
failing partway through a build.

## No warranty

This tool is provided **as-is, with no warranty of any kind** — see
[LICENSE](LICENSE) (MIT). It creates and deletes real objects in your
OPA/Okta tenant via real API calls; **you are responsible for
reviewing what it does before running it against a production
environment**, and assume all risk of using it. The same notice is
shown in the dashboard itself via the ⓘ icon next to the gear/settings
icon.

## Security: encrypted credential storage

**No secret is ever written to disk in plaintext.** The dashboard's
multi-environment store (`environments.json`, next to this README) holds
only non-secret metadata (base domain, team name, key ID, Okta URL).
The two actual secrets — the OPA service-user **key secret** and the
**Okta API token** — are stored exclusively in your OS's encrypted
credential store via the `keyring` package:

| OS | Backend |
|---|---|
| Windows | Credential Locker (Credential Manager) |
| macOS | Keychain |
| Linux | Secret Service (GNOME Keyring, KWallet, etc.) |

Install with `pip install -r requirements.txt` (just `keyring`). The
CLI resolves credentials in this order: (1) OS environment variables,
(2) a local `.env` file (legacy, plaintext, fully opt-in — only used if
you create one yourself; nothing in this tool writes one anymore, and
it's already excluded via `.gitignore` if you do), (3) the dashboard's
encrypted environment store — whichever environment is active there.
This means the CLI automatically follows whatever environment you last
activated in the dashboard, with zero plaintext involved.

This only protects the secrets at rest on disk. The OS keychain
backends above unlock with your OS login session — on an unlocked,
logged-in workstation, any process running as you (including this
tool itself) can read what's stored there, the same as any other app
using your OS's native credential store. Lock your workstation like
you would for any other credential-bearing session.

## Interactive Dashboard

A local React app + Python backend (same stack as the
`okta-privilege-dashboard` project: React 19 + Vite + TypeScript +
Tailwind v4 + Radix UI + TanStack Query). **No credentials are needed
to launch it** — see "Environments" below.

**First-time setup:**
```bash
pip install -r requirements.txt
cd frontend && npm install
```

**Run it — cross-platform.** All build/launch logic lives in one place,
`launch.py`; the OS-specific files are thin wrappers around it (nothing
to keep in sync between them):

| OS | How to run |
|---|---|
| Windows | Double-click `Start OPA Secrets Wizard.bat` |
| Mac / Linux | Run `./start-wizard.sh` (or double-click it if your file manager runs `.sh` files) |
| Any OS | `python launch.py` (or `python3 launch.py`) directly |

Or run the two steps manually:
```bash
cd frontend && npm run build
cd ../server && python3 serve.py   # "python" on Windows
```
The server binds `127.0.0.1` only. If the port is already taken by
another running instance, it fails fast with a clear message instead
of silently double-serving (see changelog).

### Environments (dev / uat / prod, etc.)

On first launch (or whenever no environment is active) the dashboard
shows a **setup screen** asking for a label (e.g. `dev`) and:
- **Base Domain**, **Team Name**, **Key ID**, **Key Secret** — the OPA
  service-user credentials (required).
- **Okta URL**, **Okta API Token** — optional, only needed if you want
  to create new groups from the dashboard (see "Groups" below).

Saving tests the connection immediately and, once it succeeds, unlocks
the rest of the dashboard. You can save **multiple named
environments** and switch between them via the **gear icon** in the
header, which opens a manager to activate / edit / delete saved
environments. Editing always shows both secret fields blank — leave
blank to keep the existing value, or type a new one to rotate it.
Deleting the active environment locks the dashboard again until
another is activated.

### Resource Groups, Projects, and Groups

Dropdowns for **Resource Group** and **Project** are populated live
from OPA. Each has a **"+ Create new..."** option:

- **New Project**: just asks for a name (OPA's Project object has no
  group requirement — confirmed live).
- **New Resource Group**: asks for a name/description plus a
  **required Group** (OPA rejects resource-group creation with no
  associated group — confirmed live: `"at least one user group should
  be associated with the resource group"`). The group picker has its
  own **"+ New Group"**, which:
  1. Creates the group in **Okta** (core API `POST /api/v1/groups`) —
     never via OPA's own group endpoint, by design.
  2. Pushes it into the Okta Privileged Access app via Okta's
     **Group Push Mapping API** (`POST /api/v1/apps/{appId}/group-push/mappings`),
     auto-discovering the app by its stable catalog name
     (`okta_privileged_access_sso`) rather than its user-editable label.
  3. Polls OPA's group list for a few seconds waiting for the pushed
     group to appear (usually near-instant, occasionally a few seconds)
     before returning it as selectable — with a manual refresh button
     as a fallback if propagation is unusually slow.

  Creating groups requires the environment's Okta URL + API token (see
  Environments above); the picker/manager shows a clear error if
  they're not configured.

### Building the folder tree

1. Load an existing CSV into the tree editor, or build one from
   scratch — add root folders, add subfolders under any node, edit
   names/descriptions inline. Invalid characters and per-project name
   collisions are flagged as you type.
2. **Save** the tree back to a CSV file (same format the CLI uses).
3. **Preview (dry-run)** — calls the same engine code as
   `python create_secret_folders.py` (no `--execute`), shows
   exists/will-create status inline on the tree.
4. **Create Folders** — behind a confirmation dialog (mirrors the
   CLI's `--execute` opt-in); calls the real OPA API, shows
   created/skipped/error per folder, and writes the same
   `folders_result_<timestamp>.csv` the CLI produces.

**Dev mode** (hot reload): `npm run dev` in `frontend/` (proxies `/api`
to `http://localhost:8766`) with `python serve.py` running separately.

### Access Explorer

A second top-level tab (next to Folder Builder) for answering "who has
access to what." Backed by a background job
(`build_access_model`/`POST /api/access/bootstrap/start`, polled via
`GET /api/access/bootstrap/status`) that fetches every resource group,
project, group, user (+ their groups), and security policy once,
resolves each policy rule down to a specific project where possible,
and caches the result client-side — fetched once per session, with a
manual **Refresh** button. This is not a cheap call — one API request
per folder/secret discovered, per project's server/SaaS/Okta-UD list,
and per user's group membership; expect it to take up to a minute on a
tenant with real data volume — so both the first load and Refresh show
real step-by-step progress (which step is running, what's done, what's
left) rather than a bare spinner, with a Retry button if a step fails.
On Refresh, the previous result stays visible and interactive while a
compact progress panel runs at the bottom of the screen.

- **Resource Groups** — pick one, see its delegated admin group(s),
  its projects (with active/stale resource counts), and every policy
  scoped to it (aggregated principal groups + resource types covered).
- **Projects** — pick a resource group then a project, see every field
  OPA returns for it, and every policy that resolves to that specific
  project.
- **Policies** — the full list (a separate "Team-wide" bucket for
  policies with no resource group at all — these exist; live-confirmed
  on a real tenant). Click one for principals, resource group, and
  every rule (resource type, what it applies to, privileges,
  conditions).
- **Users** / **Groups** — pick one, see everything it has access to
  via policies naming its group(s) as a principal.

Every tab (plus the header) has **Export CSV** / **Export MD**
buttons — per-tab exports cover whatever's currently selected; the
header's export covers the whole access model in one file, regardless
of what's on screen.

**What "resolved to a specific project" means, and why some rules show
plain-English text instead:** security policies are scoped to a
*resource group*, never a project — there's no API that answers "what
does this project have access to" directly. Where a policy's rule
selector names one specific resource (a secret/folder, an individual
server, an individual SaaS/Okta account), the project is derived by
checking that resource's own project membership. Where the selector is
a *dynamic pattern match* instead of a specific resource — server
labels, Active Directory accounts (a name/domain condition, or a
specific-shared-account-by-SID shape — see "Confirmed tenant behavior"
below, both non-resolvable), Database accounts — there's nothing to
resolve to one project, so the condition itself is shown as readable
text (e.g. "Servers labeled `system.os_type=linux`") at the
resource-group level.

### Secrets Access Dashboard

A third top-level tab: pick a resource group and project, see every
secret and secret folder in it — including ones since deleted — with
who created, updated, retrieved (secrets only, up to 5 most recent),
and deleted each one, and when.

Two sources merged into one report: the live folder/secret tree (same
walk Folder Builder's "Load Current Structure" uses) for what exists
right now, plus a single Okta System Log query scoped to the project
(`pam.secret.create/.update/.delete/.reveal` and
`pam.secret_folder.create/.update/.delete` — see "Confirmed tenant
behavior" below) for the full history, including resources that no
longer exist and therefore aren't in the live tree at all. A row
absent from the live tree is only ever marked **deleted** when the log
actually contains a delete event for it — otherwise it's **unknown**
(most likely just older than the 90-day System Log retention window),
never guessed. Requires an Okta API token configured on the active
environment (same requirement as Access Explorer's "last accessed"
lookup), since the audit trail comes entirely from Okta's System Log,
not OPA's own API.

Has its own **Export CSV** / **Export MD** buttons, covering both the
Secrets and Folders sections of whatever resource group/project is
currently selected, plus a **Refresh** button to re-pull the report
on demand without changing the resource group/project selection.

**Preserving history past Okta's 90-day retention.** Okta's System Log
only ever retains 90 days — this tool can't extend that on Okta's side,
but each saved environment (gear icon → environment row) can opt in to
**"preserve logs locally"**: once enabled, every report fetch for that
environment merges newly-seen System Log events into a local cache file
(`secrets_log_cache.json`, next to `environments.json`, git-ignored like
it) instead of discarding them once Okta ages them out. A clear
shield icon (green "Preserving logs locally" / grey "Local log
preservation off") appears both in the environment manager and on the
Secrets Access Dashboard itself, so it's never ambiguous whether a given
report's history is capped at 90 days or extended locally. This cannot
retroactively recover events that were already older than 90 days the
first time the toggle is turned on for a given project — only what's
captured from that point forward accumulates; the dashboard's own
"based on the last N days" note is replaced with the actual local
coverage start date once enabled, rather than continuing to imply a
hard 90-day ceiling.

`secrets_log_cache.json` is **encrypted at rest** (Fernet/AES128-CBC via
the `cryptography` package) — it's audit metadata (who/what/when, secret
*names/paths*), never secret values, but it's still local history worth
protecting from casual disk access. The encryption key itself is never
written to disk in plaintext, and is resolved the same "server override,
desktop fallback" way this tool already resolves OPA/Okta credentials
(see "CLI Setup" below):

- **Standalone (desktop) use** — the key is generated once and stored in
  the OS keychain (Windows Credential Locker / macOS Keychain / Linux
  Secret Service), exactly like `key_secret`/`okta_api_token`. Nothing to
  configure.
- **Server-hosted use** — set `OPA_SECRETS_WIZARD_LOG_CACHE_KEY` to a
  Fernet key (`python -c "from cryptography.fernet import Fernet;
  print(Fernet.generate_key().decode())"`) via whatever your deployment
  already uses to inject secrets (systemd `LoadCredential=`, a secrets
  manager, etc.) — checked *before* the OS keychain, since a headless
  Linux server has no desktop secret-service session for `keyring` to use
  at all. Only the server process ever sees this key; it's never sent to
  the browser.

A cache file that fails to decrypt under whichever key is active (lost/
rotated key, or none configured) is treated as unreadable history and
started fresh — logged as a warning, never a crash. A pre-encryption
plaintext cache file from an older version of this tool is read once as
plaintext and transparently re-encrypted on its next write, with no data
loss and no manual migration step.

### Policy assignment (Folder Builder)

Every folder row in the tree editor carries a small access badge
("🔒 2 policies · Admins, DBAs" / "No policy") — greyed out until the
folder has a real OPA ID (from **Load Current Structure**, or from a
completed Preview/Execute; a tree edit clears IDs for safety, since an
edit can shift what a path even refers to). Click a badge to open
**Assign access**:

- **Use existing policy** — pick from every policy scoped to the
  current resource group. Shows the policy's current principals and
  rules, and if your chosen group/role isn't already one of them,
  warns exactly how many *other* rules in that policy would also gain
  access — principals apply to the whole policy in OPA, not per rule,
  so there's no way around this; the warning just makes it visible
  before you commit.
- **Create new policy** — name/description, group and/or workload-role
  picker (multi-select; the `everyone` group is filtered out — OPA
  rejects it as a principal outright), the 8 secret privileges as
  checkboxes (List / Secrets: Create/Update/Delete/Reveal / Folders:
  Create/Update/Delete), and an optional MFA requirement (re-auth
  frequency + ACR values).

Assigning a folder that a policy *already* has a rule for edits that
rule in place rather than adding a duplicate — matched by the rule's
`secret_folder` ID, confirmed live (create → attach-with-different-
privileges → refetch showed one updated rule, not two).

## Hosting on a server (optional)

The dashboard can also run as a persistent, centrally-reachable service
instead of only on someone's own machine, for a small team sharing access
to the same OPA/Okta tenants. This is deliberately optional -- the default
experience (`launch.py`, described above) needs none of this.

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
   `keyring.set_password(f"opa-secrets-wizard:{env_name}", "okta_client_secret", "<secret>")`
   (`env_name` matches whatever `OKTA_ENV_NAME` you set in step 4).
4. Set these environment variables for `server/auth_gate.py` (e.g. in the
   systemd unit's `EnvironmentFile`) -- the process refuses to start
   without all three, rather than silently pointing at the wrong org:
   - `OKTA_ORG_URL` — e.g. `https://your-org.oktapreview.com`
   - `OKTA_OIDC_CLIENT_ID` — the Client ID from step 1 (not secret, but
     still specific to your deployment)
   - `DASHBOARD_ORIGIN` — the public origin this dashboard is reachable
     at, e.g. `https://192.168.1.10` or `https://opa.example.com`
   - `OKTA_ENV_NAME` (optional, defaults to `"default"`)
5. If `server/serve.py` itself will be reached through a hostname/IP other
   than `127.0.0.1`/`localhost` (true for any reverse-proxied deployment),
   also set `EXTRA_ALLOWED_ORIGINS` (comma-separated) to that public
   origin -- otherwise every write request is rejected with `403 Origin
   '...' is not allowed to call this API"` once real browser traffic
   arrives from that origin.
6. Install and enable the two systemd units (`opa-secrets-wizard.service`,
   `opa-auth-gate.service`) and the nginx site config, adjusting paths/IPs
   for your own server.

**Per-user environments.** Once behind the login gate, each logged-in
Okta identity gets their own private set of environments by default (an
environment created by user A is invisible to user B) -- opt an
environment into being visible to every other logged-in user via
`PUT /api/environments/{name}/share`. Every write action (environment
changes, folder/resource-group/policy/group creates and deletes) is
appended to `audit_log.jsonl`, attributed to the real logged-in identity.
Running the CLI or `launch.py` directly (no login gate in front of them at
all) is entirely unaffected by any of this -- there's exactly one shared,
unscoped environment list, matching this tool's original single-user
design.

## CLI Setup

The CLI needs the four OPA credentials available via one of the three
resolution sources described above. Easiest is to just use the
dashboard once (Environments, above) — the CLI will then automatically
follow whatever you activated there. To set them up independently of
the dashboard:

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

## Confirmed tenant behavior (found via live testing, not docs)

1. **Folder names must be unique per PROJECT, not just per parent
   folder.** Creating a folder whose name matches any other folder
   already in the same project — even one nested somewhere else in
   the tree — fails with `409: secrets or folders that are in the
   same folder may not have the same name`. Design your CSV so no two
   folders (at any depth) in the same project share a name. The
   script/dashboard detects this risk up front and warns (it does not
   block, since it's a warning about your data) — the second folder
   with a repeated name will simply error out in the results.

2. **The plain "list folders" endpoint only returns top-level (root)
   folders** — despite reading like it should return everything, it's
   really `ListTopLevelSecretFoldersForProject`. Confirmed live: a
   folder with 5 real sub-folders showed only itself there. Neither
   list nor get-single-folder ever includes a `parent_id` field, but
   there IS a per-folder children endpoint
   (`.../secret_folders/{id}/items`) that returns direct children
   (sub-folders and secrets, distinguished by a `type` field). Walking
   it recursively from each root (`fetch_all_folders` in the engine)
   is how the CLI and dashboard see the whole tree — existing-folder
   detection still matches **by name only, project-wide**, which is
   safe given constraint #1 above, but now it's checked against every
   folder in the project, not just the roots.

3. **Folder name character restriction:** only `A-Z a-z 0-9 . _ -`, no
   spaces. Validated locally before any API call.

4. **Resource groups require at least one group** (`delegated_resource_admin_groups`)
   to be created; **projects require only a name** — no group field on
   the Project object itself.

5. **Groups must come from Okta, not OPA's own `/groups` POST**, per
   this tool's design — OPA's local group-create endpoint produces
   RBAC-only groups with no real Okta membership, which isn't useful
   for real access control. The Okta Group Push Mapping API
   (`POST /api/v1/apps/{appId}/group-push/mappings`) both creates the
   downstream group and syncs it into OPA in one call; it typically
   appears in OPA's group list within 1-2 seconds.

6. **Rate limits:** every response carries `x-ratelimit-limit` /
   `-remaining` / `-reset` headers (unix-seconds reset). The engine
   tracks these per host and proactively sleeps out the window once
   headroom is nearly gone, rather than waiting to get hit with a
   `429` — relevant now that a folder-tree walk is one API call per
   folder instead of one call per project. A `429` that slips through
   anyway is retried using `Retry-After` (or `x-ratelimit-reset`) for
   an accurate wait, not blind backoff.

7. **Security policies are scoped to a resource group, never a
   project** — and that scope is optional. Confirmed live: 13 of 14
   real policies on the test tenant had a `resource_group`; one had
   none at all (a genuinely "team-wide" policy). There's no API to ask
   "what does this project have access to" directly; the Access
   Explorer derives it by resolving each rule's resource selector (see
   "Access Explorer" above).

8. **A policy selector referencing an individual SaaS or Okta app
   account uses that account's Okta/SaaS-side ID, not the OPA
   account's own `id`.** Live-verified: the two differ, but the
   account's `privileged_resource_id` (SaaS) or `okta_user_id` (Okta)
   field matches the selector's ID exactly. Matching on `id` directly
   (the same-ID assumption that holds for secrets and servers) finds
   nothing for these two types.

9. **Active Directory selectors have two distinct shapes**, not one:
   a name/domain *condition* (`individual_accounts.by_condition` /
   `by_domain` — CONTAINS/STARTS_WITH/etc. against a name, or a domain
   list) and a *specific shared account* shape
   (`shared_accounts.specific_accounts`, identified by domain + SID +
   account name, optionally scoped to a `server_label` sub-selector
   naming which servers it applies to). Neither is a lookup by a
   single resource ID — both describe as text rather than resolving to
   one project.

10. **`PUT /security_policy/{id}` is a full replace, not a patch** —
    confirmed live (returns `204`, no body; a follow-up `GET` reflects
    exactly what was sent). Changing one field means fetching the whole
    policy, modifying the in-memory object, and submitting the complete
    thing back — there's no partial-update endpoint.

11. **The `everyone` group can't be a security policy principal** —
    the API rejects it outright (`400`, "You may not add 'everyone'
    group as a principal"), confirmed live. Worth filtering out of any
    group picker for a principal field before the user even tries.

12. **`CreateSecretFolder`'s nesting field is `parent_folder_id`, not
    `parent_id`.** This script used the wrong name from 5.0.0 through
    5.4.0 — since OPA silently ignores unrecognized body fields, every
    folder ever created with an intended parent came out top-level
    instead, with no error. Fixed in 5.5.0. Separately (and
    unaffected by that fix): **nested creation additionally requires a
    security policy granting the caller the `folder_create` privilege
    scoped to the parent folder** — top-level creation only needs the
    `resource_admin`/`delegated_resource_admin` role, which is a
    coarser grant. A service account with only the latter can create
    root folders but will get a `404 resource_does_not_exist` ("not
    found, or you are not authorized") on any `parent_folder_id`
    creation attempt until that policy exists. If nested folders 404
    from this dashboard, this is why — check the service account's
    principal has `folder_create` on the target folder(s).

13. **Deleting a secret folder gives no cascade guarantee for one that
    still has children.** Given #12 above, no nested folder created by
    this tool before 5.5.0 was ever really nested — so cascade-on-delete
    couldn't be safely tested by experiment even after the fix, since
    creating a real nested folder requires the `folder_create` grant
    from #12, which this tool's test tenant didn't have. Rather than
    guess, the dashboard's delete route pre-checks
    `list_folder_items()` and refuses (`409`) to delete a non-empty
    folder — remove or move its contents first. This is a deliberate
    safety choice, not a confirmed cascade/orphan finding either way.

14. **A security policy's `user_groups` principal can only ever be an
    Okta-sourced group, but group MEMBERSHIP isn't exclusively Okta's
    domain the way group CREATION is.** `GET /current_user` (whoami)
    confirms this dashboard's own service-user API key is an OPA-native
    **Service User** — `GET /service_users` shows `user_type: "service"`
    with no Okta linkage at all, so it can never itself be a real Okta
    group member. But OPA exposes its own direct group-membership API,
    entirely separate from Okta Group Push: `POST
    /groups/{group_name}/users` (`AddUserToGroup`) and `DELETE
    /groups/{group_name}/users/{user_name}` (`RemoveUserFromGroup`),
    confirmed live to work for a service user on a real Okta-sourced/
    pushed group, not just OPA's own local groups. Both require the
    caller to hold the `pam_admin` role — this tenant's service account
    already has it (via membership in a group whose own `roles` include
    `pam_admin`), so it can grant itself membership elsewhere without
    any human intervention; a service account without `pam_admin`
    anywhere would need a human to run this once first.

15. **Secret/folder create/update/delete/reveal all show up as real,
    distinct System Log eventTypes** — `pam.secret.create`,
    `pam.secret.update`, `pam.secret.delete`, `pam.secret.reveal`,
    `pam.secret_folder.create`, `pam.secret_folder.update`,
    `pam.secret_folder.delete` — confirmed via a full unfiltered
    90-day `eventType sw "pam."` scan against a real tenant with
    genuine history (a shallower 5-page scan initially looked like
    these events didn't exist at all; they were just further back).
    Every one of these events' `target[]` already carries the
    resource's own id + name (`Secret` / `Secret Folder`), its full
    path (`Secret Path`), and its Resource Group/Project as co-targets
    — so a single System Log query filtered by `target.id eq
    "{project_id}"` (a project-scoped event's target array always
    includes the project as a co-target — also confirmed live) is all
    the Secrets Access Dashboard needs, no per-secret calls. For a
    service-account actor, `alternateId` is an opaque `users/<uuid>`
    with no human-readable value at all — `displayName` is the only
    field that's readable for both service accounts and real humans,
    so it's what the dashboard attributes actions to.

## Idempotency

Existing folders are detected by recursively walking the full folder
tree (`fetch_all_folders`, one API call per folder — see constraint #2
above) and matching by name (safe given constraint #1). Re-running the
CLI/dashboard with the same CSV is safe at every depth — anything that
already exists is skipped, not duplicated.

## Version

5.18.0 — The dashboard's UI now visually matches the **Okta Admin
Console** (Odyssey design system look): a persistent left sidebar with
an icon rail + expandable nav replaces the old top tab bar, and a new
light/dark theme toggle lets anyone switch away from the previous
dark-only look. See the changelog entry below for exactly what changed
and why.

### Changelog
- **5.18.0**:
  - **Okta Admin Console-style redesign.** New `SideNav` component
    replaces the top `TabBar` for all top-level navigation (Folder
    Builder / Access Explorer / Secrets Access Dashboard), rendered as
    a 48px icon rail + a 256px sidebar panel — matches the real Okta
    admin console's layout, confirmed against real screenshots of it
    rather than guessed. Access Explorer's 5 sub-tabs (Resource Groups/
    Projects/Policies/Users/Groups) now render as nested sidebar items
    under "Access Explorer" instead of their own separate tab row — sub-
    tab state moved from `AccessExplorer`'s internal `useState` up to
    `App.tsx` (`ACCESS_SUB_TABS` is now exported from `AccessExplorer`
    for `SideNav` to render). "Environments" in the sidebar opens the
    same `EnvironmentManagerDialog` as the existing gear icon rather than
    duplicating it as a page — the dialog gained optional `open`/
    `onOpenChange` props (falls back to its own internal state when
    omitted, so the gear-icon trigger is completely unaffected).
  - **Light/dark theme toggle**, docked directly under the nav items in
    the sidebar. Dark stays the default (unchanged from every prior
    version); light is opt-in and persists via `localStorage`. Implemented
    as a `html[data-theme="light"]` CSS override block in `index.css`
    with light-palette values for every existing `--color-*`/`--shadow-*`
    token — zero component-level changes were needed for this, since
    every component already routed all color through these Tailwind v4
    `@theme` variables rather than hardcoded hex values (confirmed via a
    full-codebase grep before starting: zero hardcoded hex colors existed
    in any `.tsx`/`.ts` file outside `index.css` itself).
  - Content areas lost their old `max-w-4xl`/`max-w-6xl mx-auto` centering
    wrappers and now stretch to fill the width beside the sidebar,
    matching Okta's own admin console layout, per explicit user
    preference over keeping a centered column.
  - Preceded by a standalone HTML mockup (three static screens: Folder
    Builder, Access Explorer/Policies, Environment Manager + user menu)
    built and iterated on with the user first — dark-mode contrast bug
    (buttons/inputs/dialogs hardcoded to `background: #fff`, invisible
    against a dark page) and toggle placement/transparency feedback were
    both fixed in the mockup before any real app code was touched.
  - Live-verified end-to-end via Playwright against the real running app
    (not just a clean build): sidebar renders, all 3 top-level tabs
    switch, Access Explorer's 5 sub-tabs switch from the sidebar, theme
    toggle flips `data-theme` and the actual computed background color,
    theme choice persists across a full page reload, the Environments
    dialog opens correctly from the new sidebar item, and zero browser
    console errors throughout. Scratch Playwright project (not a
    permanent dependency), deleted after — same pattern as prior
    Playwright verification passes on this project.
- **5.17.0**:
  - **Announcement banner.** New `engine.get_banner_config`/
    `set_banner_config`, backed by a standalone `banner_config.json`
    (gitignored — deployment-specific content, not credentials, but
    still local instance state). `GET /api/banner` is unauthenticated
    (same reasoning as `/api/whoami`/`/api/version` — it has to render
    even before an environment is configured) and `POST /api/banner`
    writes + audits the change (`banner.update`). New
    `BannerSettingsDialog` (megaphone icon, next to the ⓘ/⚙ header
    icons) lets an admin toggle it on/off, edit the message, pick a
    style (info/warning/danger), and choose whether viewers can dismiss
    it. New `AnnouncementBanner` renders it above everything else,
    including the loading and first-run setup screens — matches Okta's
    own admin console pattern (its "Preview Sandbox"/incident banners
    are one announcement for the whole org, not per-admin). Dismissal is
    per-browser-tab-session (`sessionStorage`) and keyed by the message
    text itself, so editing the message (even with the same
    enabled/style) reaches everyone again instead of staying hidden for
    anyone who'd dismissed the previous wording.
- **5.16.0**:
  - **Hosted deployment**: the dashboard can now run as a persistent,
    centrally-reachable service instead of only `launch.py` on someone's
    own machine. New `server/opa-secrets-wizard.service` (systemd unit,
    `Restart=on-failure`, enabled at boot) + `server/start-headless.sh`
    (unlocks a headless `gnome-keyring` Secret Service before `exec`'ing
    `serve.py`, since a hosted Linux box has no desktop/login session for
    `keyring`'s SecretService backend to attach to — `--login` mode is
    what actually persists the unlock across restarts, plain `--unlock`
    was not sufficient) + `server/nginx-opa-secrets-wizard.conf` (TLS
    termination with a self-signed cert, reverse-proxies to `serve.py`
    on `127.0.0.1:8766`, which keeps binding to localhost-only exactly as
    before — nginx is what's actually reachable on the network, not the
    app itself).
  - **Okta OIDC login gate, not HTTP Basic Auth.** Basic Auth was the
    original plan (`nginx auth_basic` + `.htpasswd`), but a real-world
    gap killed it: a managed Chromium/Edge policy on the machine used to
    test this restricted `AuthSchemes` to `ntlm`/`negotiate`, so the
    browser silently swallowed the Basic Auth challenge (server sent a
    correct `401` + `WWW-Authenticate`, browser never showed the login
    popup) — a real, hard-to-diagnose failure mode worth remembering for
    any future "gate a local tool with Basic Auth" plan. Replaced with a
    real Okta Authorization Code + PKCE flow: new standalone
    `server/auth_gate.py` (`127.0.0.1:8767`, fronted by nginx's
    `auth_request` module) exchanges a code for tokens, verifies the ID
    token's RS256 signature via Okta's JWKS (`pyjwt[crypto]`, new
    dependency — chosen over hand-rolling JWT/JWKS verification for this
    security-sensitive path), and sets a signed (HMAC-SHA256) session
    cookie. `/logout` clears the local session AND redirects through
    Okta's own logout endpoint, so it doesn't just forget the user
    locally while Okta's own SSO session silently logs them back in on
    the next visit.
  - **Real Okta org gotcha, worth remembering for any future OIDC work**:
    a brand-new custom authorization server's access policy list can be
    completely empty — with zero policies, every token request is denied
    by default (`access_denied — Policy evaluation failed`), which reads
    like an MFA/access problem but is actually just "nobody ever told
    this authorization server any client is allowed to use it." Fixed by
    adding a policy (`ALL_CLIENTS`) + a rule (all grant types, all
    scopes) — a normal one-time setup step for a fresh authorization
    server, not a bug in this tool.
  - **Per-user environments, not one shared list.** `environments.json`
    entries gained `owner` (Okta `sub`, `null` for local/CLI use) and
    `shared` (bool, default `false`); `"active"` became a dict keyed by
    owner instead of one global string. Every pre-existing environment
    migrates automatically on first load (`owner: null, shared: true` —
    preserves "everyone could already use these" instead of silently
    hiding them). Storage/keyring keys are now `owner::name`-namespaced so
    two different users can each have their own "dev" without colliding;
    a same-named environment a user actually owns always takes precedence
    over a same-named one merely shared by someone else. New
    `PUT /api/environments/{name}/share` lets an owner opt an environment
    into being visible (read/use, not edit/delete) to every other user.
    `serve.py`'s three module-level globals (`client`/`okta_client`/
    `active_env_name` — one shared session for the entire process) became
    a per-owner session table instead. **Local/direct runs and the CLI are
    completely unaffected** — no verified identity present means every
    call resolves through one fixed local sentinel, which is exactly
    today's original single-shared-environment behavior; this was the
    explicit hard constraint driving the whole design, not an
    afterthought.
  - **Audit log**, per explicit request: every write action (environment
    create/activate/share/delete, resource group/project/policy/group
    create, folder execute/delete, group membership changes) now appends
    to `audit_log.jsonl` via a new `engine.log_audit_event`, attributed to
    the real logged-in Okta identity when one is present (`null` for
    local/CLI-triggered actions, so those stay auditable too, just without
    a real identity attached). New `GET /api/audit_log` route, viewable by
    any logged-in user for now.
  - **Identity bridge, the missing piece that took real debugging to get
    right**: nginx's `auth_request` module does NOT forward the auth
    subrequest's response headers into the main proxied request by
    default — `auth_gate.py`'s `/verify` response sets `X-Auth-Sub`/
    `X-Auth-User`, but without `auth_request_set` + `proxy_set_header` in
    nginx, `serve.py` never saw them at all. Also: **the real Okta `sub`
    claim did NOT match this authorization server's documented claim
    override** (`(appuser != null) ? appuser.userName : app.clientId`,
    which reads like it should return the login/email) — live capture via
    a temporary debug log showed the real token's `sub` was actually the
    internal Okta user ID (e.g. `00uyqm6...`), not the login string. Cost
    real back-and-forth (private per-user environments were briefly
    created under the wrong, guessed owner key before this was caught and
    fixed) — the concrete lesson: verify a claim's real runtime value
    directly rather than trusting its configured expression, the same
    "live-verify over trust the config/docs" principle this project has
    hit before with the OPA API itself.
  - **Origin-check bug, real and would have blocked every write in the
    hosted deployment**: `serve.py`'s CORS/Origin allowlist
    (`_allowed_origins`) and its hardcoded `Access-Control-Allow-Origin`
    response header both predated hosting entirely — written when this
    app only ever ran at `127.0.0.1`/`localhost`. Once reverse-proxied
    behind nginx on a real LAN IP, the browser's real `Origin` header was
    never in the allowlist, so every mutating request (environment
    switch, preserve-logs toggle, etc.) failed with `403 Origin '...' is
    not allowed to call this API` — caught via live testing in the actual
    browser, not assumed from reading the code. Fixed with a new
    `EXTRA_ALLOWED_ORIGINS` env var (comma-separated, set via the
    systemd unit's `EnvironmentFile`) rather than hardcoding any specific
    IP/hostname into source — local/direct runs are unaffected since the
    var is empty by default there.
  - **Who's logged in + logout, in the UI.** New `GET /api/whoami`
    (echoes the same `X-Auth-User` header the identity bridge above
    established — `is_local: true` when absent, so the frontend can hide
    login-specific UI for local/direct runs instead of showing a
    logout button that does nothing) + new `UserMenu.tsx`, placed next to
    the existing About/gear icons per explicit request. Logout is a plain
    link to `/logout` (already routed to `auth_gate.py`'s real
    Okta-session-ending logic above), not a new mutation.
  - Live-verified end-to-end against the real hosted deployment and a
    real `patlabusp` Okta login throughout, not just locally: TLS
    handshake (including a real self-signed-cert SAN gap that broke Edge
    outright with a scrambled-credentials error, fixed by regenerating
    the cert with a proper `IP:` SAN), the full OIDC redirect/callback
    round trip, per-user environment isolation (two different owners each
    with their own same-named "dev", confirmed neither could see or
    delete the other's), the origin-check fix, and real folder/resource
    group API calls succeeding post-login.
- **5.15.0**:
  - **Refresh button on the Secrets Access Dashboard.** Re-pulls the
    report on demand (spinner via `isFetching`, same convention as
    `GroupPicker`'s existing refresh) without touching the RG/Project
    selection — previously the only way to re-fetch was reselecting
    the project.
  - **Opt-in local preservation of Secrets Access Dashboard history
    past Okta's 90-day System Log retention.** New per-environment
    `preserve_logs_locally` flag (toggled via a new
    `POST /api/environments/{name}/preserve_logs_locally` route,
    `engine.set_preserve_logs_locally`) — when on, every report fetch
    merges newly-seen System Log events into a local, git-ignored
    `secrets_log_cache.json` (keyed by environment → project → event
    uuid, deduped) via `engine._merge_system_log_events`, so events
    already captured survive Okta aging them out of its own 90-day
    window. `build_secrets_access_report` now returns
    `local_retention_enabled` and `oldest_captured_at` so the UI can
    say exactly how far back local coverage actually goes, rather than
    implying a hard 90-day ceiling once enabled. Cannot retroactively
    recover events already older than 90 days the first time this is
    turned on for a project — only forward accumulation.
  - New `LogRetentionIndicator` component: a shield icon + label
    (never color-alone) shown read-only next to the dashboard's
    "based on the last N days" note, and as a click-to-toggle in each
    environment's row in the environment manager dialog.
  - **`secrets_log_cache.json` is encrypted at rest** (new `cryptography`
    dependency, Fernet/AES128-CBC). Key resolution mirrors this tool's
    existing "server override, desktop fallback" pattern for credentials:
    `OPA_SECRETS_WIZARD_LOG_CACHE_KEY` env var checked first (server-
    hosted use, since a headless Linux box has no desktop secret-service
    session for `keyring` to use), falling back to a key generated once
    and stored in the OS keychain (standalone/desktop use, same as
    `key_secret`/`okta_api_token`). A pre-encryption plaintext cache file
    is read once and transparently re-encrypted on its next write — no
    manual migration, no data loss. A file that fails to decrypt under
    whichever key is active is logged as a warning and started fresh
    rather than crashing the dashboard.
  - Also fixed a pre-existing dead `return results` immediately after
    `build_secrets_access_report`'s real `return` — unreachable
    leftover from before the function's current return shape,
    unrelated to this feature but trivial to clean up while touching
    the function.
- **5.14.0**:
  - **New Secrets Access Dashboard tab.** `build_secrets_access_report`
    merges the live folder/secret walk ("what exists now") with one
    System Log query per report, scoped to the project and filtered to
    7 confirmed real eventTypes (`pam.secret.create/.update/.delete/
    .reveal`, `pam.secret_folder.create/.update/.delete` — see
    "Confirmed tenant behavior" #15). A resource missing from the live
    walk is only marked "deleted" with direct log evidence (a real
    delete event); otherwise it's "unknown" rather than guessed —
    most likely just older than the 90-day System Log retention
    window than it is truly untouched.
  - **`full_path` promoted from `serve.py` into the engine** so the new
    report and the pre-existing `/folders` route share one
    path-reconstruction walk instead of two copies of the same logic —
    verified the existing route's behavior is unchanged after the move.
  - New route `GET /api/resource_groups/{rg}/projects/{proj}/
    secrets_access_report`, guarded by both the OPA and Okta client
    requirements (same pair Access Explorer's "last accessed" lookup
    already needs) since the entire audit trail comes from Okta's
    System Log, not OPA's own API.
  - Frontend: `SecretsAccessDashboard.tsx` (new top-level tab, plain RG
    + Project `Select`s — deliberately not `ResourceGroupSelect`/
    `ProjectSelect`, whose "+ Create new" affordance doesn't belong in
    a read-only audit view), reusing the existing expand/collapse
    history interaction from `PolicyRuleCard`'s reveal-history display
    for both "updated" and "retrieved" columns. `StatusBadge` gained
    `active`/`deleted`/`unknown` variants.
  - Live-verified end-to-end: real create/update/reveal history from
    this project's own past sessions rendered correctly; a fresh
    throwaway secret was created and deleted live mid-session to
    confirm the "deleted" status path works for a brand-new event, not
    just historical data (and cleaned up immediately after). Full
    Playwright pass — tab navigation, RG/Project selection, both
    tables rendering with real active + deleted rows, reveal-history
    expand/collapse, CSV export, MD export (both downloaded and their
    contents spot-checked, not just "a file appeared") — zero console
    errors throughout.
- **5.13.0**:
  - **Service accounts now appear in Access Explorer.** `list_users()`
    wasn't passing `include_service_users=true` — confirmed live that
    the exact same `/users` endpoint (not a separate one) returns both
    kinds unified with that one flag, and every other part of the
    existing per-user resolution pipeline (group membership, policy
    matching) already worked correctly for a service user with zero
    changes once it's in the list at all. All 4 real service accounts
    in this tenant now show up, not just this dashboard's own — that's
    correct (they're real principals with real access; hiding them was
    the actual gap), not scope creep.
  - **Visually distinct, not just present.** A service account's name
    renders in `text-warn` (already `#fb923c` — literally Tailwind's
    orange-400 — reused as-is, no new color token) everywhere it
    appears in the Users tab, plus an explicit "Service account" tag
    next to it — color alone isn't relied on to carry the meaning.
  - **"Remove access" on any group-backed grant, for any user.** Every
    group shown as the reason a selected user (service or human) has a
    given policy's access now has a small remove action, confirm-first
    (same inline-banner pattern as the existing folder delete), with a
    blast-radius warning if that same group also backs other policies
    — removing it takes that access away too, not just the one you
    started from. New `DELETE /api/groups/{group_id}/members/{user_name}`
    (wraps `OpaClient.remove_user_from_group`, added but unused in the
    previous release). A removal patches the already-loaded Access
    Explorer model locally instead of forcing the ~30s+ full
    re-bootstrap, consistent with this feature's existing "fetch once,
    Refresh button" design.
  - **Skips a lookup known to fail instead of erroring visibly.** A
    service account has no Okta identity/email, so "last accessed"
    (System Log) can never resolve for it — the server already handled
    that gracefully (a clear message, not a crash), but the Users tab
    now skips firing that request at all for a service-type user
    rather than let it fail every time.
- **5.12.0**:
  - **Service account group membership.** A security policy can only
    grant a privilege (like the `folder_create` behind fact #12) to an
    Okta-sourced `user_group` principal — and this dashboard's own
    service-user API key has no Okta identity, so it was never a
    candidate for one. Turns out OPA has its own group-membership API,
    independent of Okta Group Push (`POST /groups/{name}/users`,
    confirmed live), that works for exactly this case: adding any user
    — service or human — to any group, Okta-sourced or not.
    - Any group this dashboard **creates itself** (as a resource
      group's admin group, or a policy principal) now automatically
      adds the running service account as a member the moment the
      group is confirmed visible in OPA — no manual step afterward.
      Non-blocking: if this fails (the account needs the `pam_admin`
      role for this specific write), the group is still created; you
      just get a warning toast instead of a silent gap.
    - For a group that **already existed** before the dashboard
      touched it (so there was never an automatic moment to do this),
      every group shown in the Group(s) picker (new-resource-group
      flow, Assign Access) and every principal group already on a
      policy you're about to reuse now shows "service account" if
      it's already a member, or a one-click "Add service account" if
      not — surfaced exactly where you'd want to notice it, before it
      turns into a 404 later.
    - New: `OpaClient.get_current_user()` (whoami — confirmed this
      returns the OPA-native Service User identity, not an Okta one),
      `.add_user_to_group()` / `.remove_user_from_group()`; server
      routes `GET /api/service_account`, `POST
      /api/service_account/groups`; frontend `ServiceAccountGroupStatus`.
  - **Rate-limit retries hardened for large tenants / shared
    credentials.** Checked live against this tenant:
    `x-ratelimit-limit: 2000` per short window — the wait mechanism
    itself was already correctness-safe at any tenant size (never
    crashes, always waits the authoritative amount), but two real gaps
    for actual large-scale use: 429 retries shared the same low budget
    as genuine 5xx/network error retries, even though a 429 isn't a
    failure in the same sense (the response says exactly how long to
    wait, so retrying is always correct) — 429s now get their own,
    much higher retry allowance, independent of the error-retry cap.
    Separately, the proactive throttle used to cruise right up to the
    last request in a window before pausing, which is fine for a
    single client but leaves no margin if this same service-user
    credential is used concurrently (multiple dashboard/CLI instances,
    or several people on a large team sharing one credential) — the
    safety margin is now wider. Flagged honestly in the same breath:
    this doesn't change the fact that a few code paths (the recursive
    folder-tree walk, Access Explorer's per-user group lookups) make
    roughly one API call per item, so wall-clock time on a very large
    tenant scales with its size — that's proportional, not a rate-limit
    bug, and out of scope for this pass.
- **5.11.0** (fixes from a full code review — see PR/review notes):
  - **Concurrency: request-scoped client snapshots.** `/api/preview`,
    `/api/execute`, and every other API route were reading the
    module-level `client`/`okta_client` globals directly, mid-request.
    Since the server is threaded, switching or deleting the active
    environment while a long `execute` was still running could make
    that in-flight request silently continue against a stale, `None`,
    or (worse) a *different* tenant partway through. Every request
    now snapshots `client`/`okta_client` into a local variable once at
    the start and uses only that snapshot for its entire duration.
  - **`.env` inline comments no longer corrupt values.**
    `OPA_KEY_SECRET="mysecret" # prod key` used to load the literal
    string `mysecret" # prod key` into the environment. The parser now
    takes a quoted value verbatim between its quotes (discarding
    anything after the closing quote) and only strips an *unquoted*
    trailing comment when the `#` is preceded by whitespace — a
    secret that legitimately contains `#` with no space before it
    (quoted or not) is left untouched either way.
  - **Rate-limit wait math is now immune to local clock skew.** The
    proactive pre-429 wait and the reactive 429 retry both used to
    compute `x-ratelimit-reset - time.time()`, which is wrong by
    however much this machine's clock is skewed from Okta's. Both now
    anchor the countdown to the response's own `Date` header (the
    server's clock, not this machine's) and track elapsed time via
    `time.monotonic()`, which can't be affected by wall-clock skew or
    adjustment. `Retry-After` (already a relative delta) is unaffected
    and remains the first choice on an actual 429.
  - **Local API hardening:** `_read_json_body` now rejects any request
    whose `Content-Length` exceeds 5 MB with a `413` *before* reading
    it into memory, instead of trusting an attacker-controlled header
    to size a buffer. Mutating requests (`POST`/`DELETE`) now check the
    `Origin` header against this dashboard's own frontend origins (the
    Vite dev server, or this same server's own origin in production)
    and reject anything else with a `403` — protects the credential-
    handling local API against another local process or a malicious
    page/DNS-rebinding attempt; requests with no `Origin` at all (curl,
    scripts) are still allowed, matching how CORS itself only
    constrains browsers.
  - **Group Push propagation window widened** from 5 retries x 1.5s
    (7.5s total) to 20 x 1.5s (30s) — real Okta Group Push/SCIM
    propagation can take longer than the old window under load.
  - **Code quality:** `server/serve.py` no longer reaches through the
    imported engine module for `datetime`/`timezone`
    (`engine.datetime.now(engine.timezone.utc)`) — it imports them
    directly, so it's no longer silently dependent on exactly how
    `create_secret_folders.py` happens to import them. The frontend's
    client-side ID fallback (used only if `crypto.randomUUID()` is
    unavailable, which requires a non-secure context — never true for
    this app, which only ever runs on `localhost`) now also mixes in a
    monotonic counter, so even that unreachable-in-practice path can't
    collide.
- **5.10.0**:
  - **"Last accessed" now covers SaaS app accounts and Okta service
    accounts.** These resource kinds resolve to an Okta-side
    identifier (an AppUser ID or Okta user ID) for display, but that
    ID is never logged as a System Log target for any account, in any
    tenant — confirmed against a full, unpaginated 90-day export
    (65,972 rows) after a live API scan had come up empty and looked
    like a dead end. The account's own internal ID (fetched from the
    same OPA API calls that already list these accounts) does show up,
    on `pam.service_account.password.reveal` and `pam.resource.checkout`
    — both consistently actor'd by the real requesting person, unlike
    `pam.resource.checkin.end`'s mostly-system actor. Resolved grants of
    these kinds now carry a separate `access_tracking_id` alongside
    their displayed `id`, used transparently for the lookup.
  - **Found this by reading a full CSV export instead of re-querying
    live.** A live, paginated System Log scan for these account IDs
    found nothing and risked more rate-limit exhaustion chasing a
    dead end. Given a full 90-day CSV export instead, the same search
    took seconds, with no API calls and no ambiguity about whether
    "found nothing" meant "doesn't exist" or "got rate-limited before
    finding it." A handful of individual `transaction.id`/event-based
    lookups (not broad rescans) filled in the raw JSON detail the CSV's
    flattened columns didn't carry.
- **5.9.0**:
  - **"Last accessed" now covers individual server-account grants.**
    Validated against a second, busier tenant with a richer resource
    mix. `pam.server.ssh_login` looked like the obvious mapping (its
    `target[]` does include the server's own ID) but its `actor.id` is
    the OS-level SSH username (e.g. `rootadmin`, or a per-user
    provisioned name), never the Okta identity ID this feature filters
    by — wiring it up as-is would have silently matched nothing for
    any real user. `pam.gateway_creds.issue` is the real fix: its
    `actor.id` is a genuine Okta identity, and the server being
    connected to is recoverable from
    `debugContext.debugData.nextHopServerIds` instead of `target[]`.
    The access-event matching logic is now pluggable per resource kind
    to support this (`extract_ids` per entry in
    `RESOURCE_ACCESS_EVENT_TYPES`, not just a fixed `target[]` lookup).
  - **Fixed silent System Log pagination truncation.** `get_system_log`
    only ever fetched one page; found because the second test tenant
    has far higher log volume (needed just to establish this) and a
    real one-off discovery query truncated at a hard 50-page safety
    cap. Also fixed a related bug in the pagination itself: this Okta
    org sends the `Link` response header as multiple separate header
    lines (one per `rel`) rather than one comma-joined value, so
    reading it with `.get("Link")` (which only returns the first line)
    silently dropped the `rel="next"` link whenever `rel="self"`
    happened to come first — `get_all("Link")` is required to see all
    of them. This same fix applies to the OPA API list-pagination
    helper too, in case any OPA endpoint sends Link the same way.
  - **SaaS and Okta service accounts remain unmapped, confirmed not
    just unlucky.** Real grants of both kinds exist in the second
    tenant's policies, but a full 90-day System Log scan (unfiltered
    and filtered) found zero events of any type referencing those
    specific resource IDs — the one Okta-account grant only shows up
    in password-rotation/lifecycle noise. These are left as
    `supported: false` rather than guessed.
- **5.8.0**:
  - **"Last accessed" for secret grants, backed by Okta's System
    Log.** For each policy grant that resolves to a secret (or a
    secret folder — see below), the Users tab now shows up to the 5
    most recent times the selected user revealed it, each with its
    Okta request ID, sourced from `pam.secret.reveal` events in the
    last 90 days (Okta's System Log retention window — confirmed live
    against the real tenant, not assumed). Grants with no matching
    event show "not accessed (or not within the last 90 days)"; grants
    of a resource kind with no verified, ID-matchable System Log event
    (servers, SaaS/Okta service accounts) show "access tracking not
    available for this resource type" instead of guessing.
  - **Folder-level grants are expanded to their underlying secrets.**
    Almost every real secret-based policy grant in a typical tenant is
    to a *folder*, not an individual secret — and a reveal event only
    ever references the secret's own ID, never its parent folder's. So
    a folder grant now lists (behind a collapsed "N secrets in this
    folder" toggle) the last-accessed status of every secret nested
    anywhere in that folder's subtree, resolved during the same
    bootstrap pass that already walks the folder tree.
  - **Fixed the identity mismatch between OPA and Okta.** A PAM user's
    own ID has no relationship to the Okta identity ID that System Log
    events are actually recorded against — this was found and fixed
    during live end-to-end testing, where it initially caused every
    lookup to silently return zero events. The server now resolves the
    PAM user's email against Okta's Users API (`GET
    /api/v1/users/{id|login|email}`) to get the real actor ID before
    querying the log.
- **5.7.0**:
  - **Packaged for a public GitHub release.** Added an MIT
    [LICENSE](LICENSE); expanded `.gitignore` to also exclude
    `frontend/node_modules/`, `frontend/dist/`, editor/OS junk files,
    and stray `*.log` files; removed leftover local test artifacts
    (`folders_result_*.csv`, `__pycache__/`) that had accumulated
    during development. This is an early, community-testing release —
    see the "No warranty" section above.
  - **`launch.py` now checks prerequisites before doing anything
    else**, cross-platform: Python (>=3.9, for `keyring`) and Node.js
    (^20.19.0 or >=22.12.0, Vite 8's own requirement — confirmed from
    its published `engines` field, not guessed). If either is missing
    or too old, it detects the OS's own package manager (`winget` /
    `brew` / `apt-get` / `dnf` / `pacman` / `zypper`, whichever is
    present), shows the exact install/upgrade command, and asks before
    running it — it never installs anything without that
    confirmation, and if no supported package manager is found it
    prints a manual install link instead of guessing further. A
    missing `keyring` (this tool's one Python dependency) or missing
    frontend `node_modules/` are handled the same way, but
    non-fatally, since both are recoverable later without blocking the
    dashboard from booting. New `--skip-checks` flag bypasses all of
    this for anyone who'd rather not be asked. Verified against real
    winget package IDs (`OpenJS.NodeJS.LTS`, `Python.Python.3.13`) —
    confirmed live via `winget search`, not assumed — and against the
    version-boundary cases of Vite's disjoint `^20.19.0 || >=22.12.0`
    requirement (20.18.x, 20.19.0, 21.x [deliberately excluded, an odd
    non-LTS release], 22.11.x, 22.12.0).
  - **No-warranty disclaimer**, in the dashboard itself: an ⓘ icon next
    to the gear/settings icon opens a dialog stating the tool is
    provided as-is with no warranty and the end user assumes all risk
    — same wording as the "No warranty" section above.
- **5.6.0**:
  - **Launcher auto-recovers from a stale server on the port.**
    `server/serve.py`'s `StrictBindHTTPServer` deliberately refuses to
    share a port (see 3.1.0 below) — correct for catching a real
    double-launch, but it meant any leftover process from a prior run
    (closed window, crashed session, one left running deliberately)
    made every subsequent launch fail to bind and exit before
    `webbrowser.open()` ever ran, with no dashboard and an easy-to-miss
    console message as the only clue. `launch.py` now checks whether
    the target port (`--port`, default 8766) is already accepting
    connections before starting; if so, it looks for processes whose
    command line matches `server/serve.py`'s own absolute path
    (Windows: `Get-CimInstance Win32_Process`; Mac/Linux: `pgrep -f`),
    kills any it finds, waits briefly for the OS to release the port,
    then proceeds. If the port is occupied by something that doesn't
    look like this project's own server, it's left alone — the
    existing bind-failure message still explains the conflict rather
    than the launcher guessing and killing an unrelated process by
    port number alone. `Start OPA Secrets Wizard.bat` / `start-wizard.sh`
    needed no changes — both are already thin wrappers that just call
    `launch.py`, so the fix applies through every entry point.
  - Live-verified by deliberately starting a leftover `serve.py`
    process, confirming it was bound (`netstat`/`Get-CimInstance`), then
    running `launch.py` and confirming it detected and stopped it (a
    run mid-session had actually accumulated 4 leftover instances from
    testing, all found and stopped in one pass) before binding cleanly
    and serving real API responses.
- **5.5.0**:
- **5.5.0**:
  - **Delete a folder from Folder Builder.** New engine method
    `OpaClient.delete_folder`; new route
    `DELETE /api/resource_groups/{rg}/projects/{proj}/folders/{folder_id}`,
    which calls `list_folder_items()` first and refuses (`409`) if the
    folder isn't empty — see "Confirmed tenant behavior" #13 for why.
    The tree's existing Trash icon now calls this route (with an
    inline "Delete from OPA? This can't be undone" confirm banner,
    matching the existing environment-delete UX pattern) for any
    folder that has a real `folder_id`; folders never saved to OPA
    still just disappear locally, as before.
  - **Fixed a real, longstanding bug found while building the above:**
    the engine's `create_folder` sent `parent_id` in the request body,
    but the API's field is `parent_folder_id` — OPA silently ignores
    unknown fields, so every folder created with an intended parent
    (via CLI or dashboard, 5.0.0 through 5.4.0) actually came out
    top-level. See "Confirmed tenant behavior" #12 for the fix and the
    separate `folder_create`-privilege requirement discovered testing
    it, and #13 for why that limited how far the delete feature's
    safety assumptions could be live-verified.
  - **New group creation inside `AssignAccessDialog`**, reusing the
    existing "create in Okta, push into OPA" flow from `GroupPicker`
    rather than duplicating it: extracted a shared `useCreateGroup`
    mutation hook and a shared `GroupCreateForm` presentational
    component, used by both. A "+ New Group" button next to the
    Group(s) MultiSelect opens the form inline; the created group is
    auto-selected once OPA confirms it's visible.
  - Live-verified end to end: created and deleted real throwaway
    folders via the new HTTP route directly and via a Playwright
    browser pass (create → save → delete → confirm banner → row gone,
    zero console errors); created a real Okta group from inside the
    dialog via Playwright and confirmed it appeared checked in the
    MultiSelect immediately, zero console errors. All test folders and
    the test Okta group were deleted afterward.
- **5.4.0**:
  - **Policy assignment for secret folders**, in Folder Builder (not
    Access Explorer, which stays read-only). New engine surface:
    `get_security_policy`, `create_security_policy`,
    `update_security_policy`, `delete_security_policy`,
    `list_workload_roles`, `build_secret_privilege`,
    `build_secret_folder_selector`, `build_mfa_condition`,
    `upsert_folder_rule_in_policy` (edits an existing rule in place if
    one already targets the folder, else appends), `merge_principals`
    (dedups groups/workload-roles into a policy's principals — additive
    only, never removes), `summarize_security_policy` (presentation
    shape for the UI, deliberately separate from Access Explorer's
    `build_access_model` output — this context never needs cross-
    project resolution).
  - New routes: `GET /api/resource_groups/{rg}/security_policies`,
    `GET /api/workload_roles`,
    `POST /api/resource_groups/{rg}/projects/{proj}/folders/{folder_id}/policy`
    (`mode: "new"|"existing"`). The existing `/folders` route now
    includes each row's real `folder_id` — previously only used by the
    frontend for tree-loading, now also the key that makes policy
    assignment possible at all.
  - Frontend: a `FolderAccessBadge` per tree row (disabled — a `—`,
    not a button — until the folder has a real ID from Load/Preview/
    Execute; a tree edit clears IDs, since a path's meaning can shift),
    and `AssignAccessDialog` with the existing-policy/new-policy split
    described above, including a blast-radius warning when attaching
    to an existing policy would grant a new principal access to that
    policy's other rules too (inherent OPA behavior: principals are
    policy-wide, not per-rule).
  - Two real API facts confirmed live before writing a line of engine
    code (not assumed): `PUT /security_policy/{id}` is a full replace
    (fetch-modify-resubmit is the only way to change one field), and
    the `everyone` group is rejected outright as a principal — both
    now documented in "Confirmed tenant behavior" and handled
    (`everyone` filtered out of the picker; full-replace semantics
    built into `upsert_folder_rule_in_policy`/`merge_principals` from
    the start rather than discovered as a bug).
  - Live-verified end to end multiple times: pure-function unit tests,
    a full create → summarize → attach-to-existing (privileges
    replaced, not duplicated) → delete round trip directly against the
    engine, the same round trip again through the actual HTTP routes,
    and a Playwright-driven browser pass (10/10 checks: badges render
    with real policy/group data after Load, new-policy creation, the
    blast-radius warning actually appearing, Cancel provably not
    mutating anything, zero console errors). All test policies deleted
    afterward; the one real policy touched during the blast-radius
    test (Cancelled, not saved) was independently confirmed unchanged
    — 6 rules, 1 principal group, exactly as before the test.
- **5.3.0**:
  - **Step-by-step progress for the bootstrap job.** `build_access_model`
    now takes an `on_progress(key, status, detail)` callback and reports
    start/progress/done for each of 8 canonical steps
    (`ACCESS_MODEL_STEPS`), including per-item detail for the two
    expensive loops (indexing each project's resources; fetching each
    user's groups). The bootstrap is no longer one blocking request —
    `POST /api/access/bootstrap/start` kicks off a background thread,
    `GET /api/access/bootstrap/status` is polled every second, and
    `GET /api/access/bootstrap/result` returns the model once done. The
    frontend renders real progress (not just elapsed time) on first
    load (full-page) and on Refresh (a compact panel at the bottom of
    the screen, while the previous result stays visible/interactive) —
    both with a Retry button on failure that restarts the job cleanly
    from scratch, since steps build on each other and resuming mid-way
    isn't worth the complexity for what should be a rare failure. This
    replaces the single blocking `GET /api/access/bootstrap` route from
    5.2.0 with `POST .../start` + `GET .../status` (polled) +
    `GET .../result`.
  - **CSV / Markdown export.** Every Access Explorer tab and the header
    (whole-model export) got Export CSV / Export MD buttons. Multiple
    logical tables render as separate titled sections in one file for
    both formats (blank-line-separated blocks for CSV, `##` headings
    for MD) — no server round-trip, pure client-side `Blob` download.
  - Live end-to-end tested via a Playwright-driven browser (not just
    curl/API-level checks this time): full first-load progress flow,
    all 5 sub-tabs with a real selection made in each, CSV export from
    a per-tab button and MD export from another, the whole-model
    export, and Refresh's bottom-panel-while-old-data-stays-visible
    behavior — 16/16 checks passed with zero browser console errors.
    Downloaded CSV/MD content spot-checked directly, not just "did a
    file appear."
- **5.2.0**:
  - **Access Explorer** — new top-level dashboard tab with 5 sub-tabs
    (Resource Groups, Projects, Policies, Users, Groups). See "Access
    Explorer" above for what each shows and how policy-to-project
    resolution works (and why some rules show plain-English text
    instead of a resolved resource).
  - New engine surface: `build_access_model` (the orchestrator),
    `fetch_all_folders_and_secrets`, `list_users`, `list_user_groups`,
    `list_security_policies`, `list_project_servers`,
    `list_project_saas_app_accounts`, `list_project_okta_ud_accounts`,
    `describe_dynamic_selector`. New server route:
    `GET /api/access/bootstrap`.
  - **Generic Link-header pagination** folded directly into `_list()`
    (used by every list-returning method, old and new) — no endpoint
    in this tool ever wants only page 1, so this closes a latent
    completeness gap on any tenant with more results than one page
    holds, not just the new Access Explorer calls.
  - Two real API-shape surprises found and handled while building the
    resolution engine, both live-verified against the test tenant, not
    assumed: (1) SaaS/Okta individual-account selectors reference an
    Okta/SaaS-side ID, not the OPA account's own `id` — resolved via
    each account's `privileged_resource_id`/`okta_user_id` field
    instead. (2) Active Directory selectors have a second "shared
    account" shape (specific accounts by SID, optionally scoped to a
    server-label sub-selector) distinct from the name/domain-condition
    shape found first — both are described as text, per design, but
    the shared-account shape needed its own description branch to
    avoid a vague fallback.
  - Live-verified end to end against the test tenant's real 14
    policies: every secret/SaaS/Okta-account selector resolved to the
    correct project; every server-label/AD/database selector produced
    accurate human-readable text; one genuinely stale server reference
    in an existing policy surfaced as "project unknown" rather than
    crashing or silently mis-attributing — confirming the graceful-
    degradation path works, not just the happy path.
- **5.1.0**:
  - **Fixed a real gap in existing-folder detection.** The engine's own
    docstring claimed the plain "list folders" call returned every
    folder in a project; live-verified that's wrong — it's
    `ListTopLevelSecretFoldersForProject`, top-level only. Any existing
    *nested* folder was invisible to `resolve_existing_folders` (the
    CLI's idempotency check) and to the dashboard's "Load Current
    Structure" button, which is why that button only ever loaded roots.
    Added `fetch_all_folders`, which walks the real per-folder children
    endpoint (`.../secret_folders/{id}/items`) recursively from each
    root to see the whole tree. "Load Current Structure" now
    reconstructs true nested paths from the walk instead of flattening
    everything to root; the CLI's dry-run/execute plan now correctly
    shows nested existing folders as `[exists]` instead of
    `[will create]`. Live-verified end to end against the test tenant:
    discovered a real 14-folder, 3-level-deep tree that the old code
    only ever saw 3 of; created one genuinely-new leaf, confirmed the 5
    pre-existing nested folders it was also asked to create were
    skipped with zero errors (previously would have 409'd), then
    confirmed a second dry-run showed the whole tree, including the new
    leaf, as `[exists]`. Cleaned up the test artifact afterward.
  - **Proactive rate-limit handling.** The recursive tree walk is one
    API call per folder instead of one per project, so the shared HTTP
    helper now tracks the `x-ratelimit-limit/-remaining/-reset` headers
    every OPA/Okta response carries and sleeps out the window
    proactively once headroom is nearly gone, instead of waiting to get
    hit with a `429`. A `429` that slips through anyway is retried
    using `Retry-After`/`x-ratelimit-reset` for an accurate wait rather
    than blind fixed backoff. Verified the wait logic fires for the
    right duration when headroom is low and doesn't fire at all when
    it's fine; real tenant calls throughout this work never approached
    the limit (2000/window).
- **5.0.0**:
  - **Renamed** the dashboard to **OPA Secrets Wizard** throughout
    (page title, header, launchers `Start OPA Secrets Wizard.bat` /
    `start-wizard.sh`).
  - **Encrypted credential storage**: secrets (`key_secret`,
    `okta_api_token`) now live exclusively in the OS keychain via the
    `keyring` package, never in `environments.json` or any plaintext
    file. The dashboard no longer writes `.env` at all (that was a
    plaintext bridge for the CLI in v3.2/v4.0 — removed in favor of
    the CLI reading the encrypted store directly as a fallback
    resolution source). Migrated the one pre-existing plaintext
    secret from before this change into the keychain and deleted the
    leftover plaintext `.env`. Found and fixed a real bug during this
    work: the environment-upsert logic never stripped a lingering
    plaintext secret field from an old-format entry when only
    "preserving" it — fixed to always strip secret fields from the
    JSON metadata dict before saving, regardless of whether a new
    value was provided.
  - **Resource group / project / group creation from the dashboard**:
    `OpaClient.create_resource_group`, `.create_project`,
    `.list_groups` and a new `OktaClient` (`.create_group`,
    `.find_privileged_access_app`, `.create_group_push_mapping`) added
    to the engine — endpoints and required fields confirmed by
    downloading and reading Okta's actual OpenAPI specs from
    `okta/okta-management-openapi-spec` on GitHub (the `opa-minimal.yaml`
    and `management-minimal.yaml` specs) rather than guessing, then
    live-verifying every call end-to-end (including the exact 400
    error text that confirmed resource groups require a group).
    `ResourceGroupSelect`/`ProjectSelect` gained "+ Create new..."
    inline forms; new `GroupPicker` component handles the
    create-in-Okta-then-push flow with automatic propagation-delay
    retries. New server endpoints: `POST /api/resource_groups`,
    `POST /api/resource_groups/{id}/projects`, `GET/POST /api/groups`.
  - Environment form/storage extended with optional `okta_url` /
    `okta_api_token` fields (only required for the group-creation
    flow); environment listing now reports `has_okta_token` instead of
    ever exposing the token itself.
  - Full end-to-end live test performed after all changes: fresh
    group created in Okta → pushed to OPA → new resource group created
    with it → new project created → folder tree previewed and
    executed for real → everything deleted afterward, confirmed clean.
- **4.0.0**: Dashboard needs zero pre-configuration — prompts for
  credentials in-UI on first boot, supports multiple named
  environments (dev/uat/prod) via a gear-icon manager. New endpoints:
  `GET/POST /api/environments`, `POST /api/environments/{name}/activate`,
  `DELETE /api/environments/{name}`. All OPA-dependent endpoints return
  `409` with a clear message if no environment is active.
- **3.2.0**: Added `.env` file support after hitting a real Windows
  friction point (double-clicking a `.bat` doesn't inherit temporary
  terminal env vars). Superseded by the encrypted store in 5.0.0.
- **3.1.0**: Fixed the launcher being Windows-only (`.bat` doesn't run
  on Mac/Linux) by extracting all logic into cross-platform
  `launch.py`. Also fixed a real Windows-specific bug:
  `http.server.HTTPServer`'s default `allow_reuse_address=True` lets a
  second process silently bind to a port already in active use on
  Windows (unlike POSIX) — disabled it so port conflicts fail fast and
  visibly on every OS.
- **3.0.0**: Added the interactive dashboard (`frontend/` + `server/`,
  React + Tailwind v4 + TanStack Query) reusing the CLI engine with
  zero duplication (`create_secret_folders.py` imported directly by
  the server).
- **2.0.0**: Replaced the single-token auth model with the real
  two-step service-user token exchange; fixed the endpoint paths
  (missing `/v1/teams/{team}/` prefix), the list response envelope key
  (`list`, not `items`/`results`/`data`), and the nesting field name
  (`parent_id`, not `parent_folder_id`). All discovered by live-testing
  against a real OPA tenant.
- **1.0.0**: Initial version, based on architecture described in
  Okta's own blog posts (endpoint paths/fields unverified at the
  time):
  https://iamse.blog/2024/09/19/using-the-secrets-api-with-okta-privileged-access
  https://iamse.blog/2025/02/03/automating-individual-secret-folders-in-opa-with-workflows
