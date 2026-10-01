# OPA Compliance Wizard

**A compliance evidence generator for Okta Privileged Access (OPA) and
core Okta** — continuously archives Okta System Log history beyond
Okta's own 90-day retention window and turns it into 14 pre-built,
SOC 2 / SOX / ISO 27001-mapped reports (MFA enforcement, provisioning,
privileged access, policy changes, and more), so you're never stuck
answering an audit request for evidence Okta itself has already aged
out. It also includes the tools this project started as: building and
managing OPA vault secret folders, resource groups, projects, and
access policies.

Ships as both a CLI for scripting and an interactive dashboard for
everyday use, so whether you're a security engineer wiring this into a
pipeline or an admin who just wants a clean UI, there's a path that
fits.

At its core, it does two things:

1. **Generates compliance-ready audit reports** (SOC 2 / SOX / ISO 27001
   evidence: MFA enforcement, provisioning, privileged access, policy
   changes, and more) by continuously archiving Okta System Log history
   beyond Okta's own 90-day retention window — see
   [Compliance Reports Dashboard](#compliance-reports-dashboard) below.
   **This is the primary use case — start here.**
2. **Creates a tree of OPA vault secret folders** (root / sub / sub-sub /
   ... any depth) — and, if needed, the resource group / project / access
   group they live under — from a CSV file or the dashboard's visual tree
   editor. See [Resource Groups, Projects, and Groups](#resource-groups-projects-and-groups)
   and [Building the folder tree](#building-the-folder-tree) below.

- **Interactive dashboard** ("OPA Compliance Wizard", `frontend/` +
  `server/`) — the compliance reports, the full secrets-management
  feature set, and admin/audit tooling for hosted multi-user
  deployments. See [Interactive Dashboard](#interactive-dashboard)
  below.
- **CLI** (`create_secret_folders.py`) — scriptable, CSV in, CSV out,
  for the secret-folder-management side specifically.

Both share the exact same engine code (`create_secret_folders.py` is
imported by the dashboard server, not reimplemented) — no logic is
duplicated between them.

Model: **Resource Group -> Project -> Folder** (folders can nest under
other folders via `parent_folder_id`). Resource groups require at least
one **group** for access delegation; per this tool's design, groups are
always created in **Okta** (core API) and synced into OPA via **Group
Push** — never via OPA's own local-group endpoint. See
[Resource Groups, Projects, and Groups](#resource-groups-projects-and-groups)
below.

All endpoints, auth flows, and field names in this tool were
**live-verified** against a real tenant (not just inferred from
documentation) — see
[Confirmed tenant behavior](#confirmed-tenant-behavior-found-via-live-testing-not-docs)
below.

> **This is an early, community-testing release.** It has been used and
> live-tested against a real OPA tenant throughout development, but it
> is not an official Okta product and comes with no support commitment.
> See [No warranty](#no-warranty) below, and please open a GitHub issue
> with any feedback or problems you run into.

## Table of Contents

- [Prerequisites](#prerequisites)
- [No warranty](#no-warranty)
- [Security: encrypted credential storage](#security-encrypted-credential-storage)
- [Interactive Dashboard](#interactive-dashboard)
  - [Environments](#environments-dev--uat--prod-etc)
  - [Compliance Reports Dashboard](#compliance-reports-dashboard)
  - [Admin roles and the audit log](#admin-roles-and-the-audit-log-hosted-deployments)
  - [Resource Groups, Projects, and Groups](#resource-groups-projects-and-groups)
  - [Building the folder tree](#building-the-folder-tree)
  - [Access Explorer](#access-explorer)
  - [Secrets Access Dashboard](#secrets-access-dashboard)
  - [Policy assignment (Folder Builder)](#policy-assignment-folder-builder)
- [Hosting on a server (optional)](#hosting-on-a-server-optional)
- [CLI Setup](#cli-setup)
- [CSV format](#csv-format)
- [CLI Usage](#cli-usage)
- [Confirmed tenant behavior](#confirmed-tenant-behavior-found-via-live-testing-not-docs)
- [Idempotency](#idempotency)
- [Version](#version)
  - [Changelog](#changelog)

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
| Windows | Double-click `Start OPA Compliance Wizard.bat` |
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

### Compliance Reports Dashboard

**This is the tab most people using this tool will live in day-to-day** —
it's the primary reason this project exists. It answers the question
auditors actually ask — *"prove that X happened, for every occurrence,
over the period we're auditing"* — for both OPA and core Okta activity,
without you needing to know Okta's System Log event-type names or write
a single query.

**Why this exists, in plain terms:** Okta's own System Log only keeps
90 days of history. Most audits (SOC 2, SOX, ISO 27001) cover a
12-month period. Without something standing between "Okta's 90-day
window" and "your auditor's 12-month ask," you simply can't produce
the evidence — no amount of clicking around the Okta Admin Console
fixes that gap. This dashboard closes it by continuously archiving
System Log events into a local, indefinitely-retained store (SQLite —
see [Hosting on a server](#hosting-on-a-server-optional) for why that
choice, not a bigger database, is the right one here), then serving
14 pre-built reports on top of that archive.

**The 14 reports, grouped by SOC 2 Trust Services Criteria** (each maps
to a specific, live-verified set of real Okta/OPA event types — nothing
here is a guess or a report card that will silently always read zero):

- **CC6 — Access Controls:** MFA Enforcement, Session Activity,
  Provisioning & De-provisioning, Role/Group Changes, Admin Privilege
  Grants, JIT Access Requests
- **CC7 — System Operations:** Threat Detection, API Token Lifecycle
- **CC8 — Change Management:** Policy Modifications
- **Privileged Access (OPA/PAM):** Secrets Activity, PAM JIT
  Checkout/Checkin, Session Logins, Credential Reveals, PAM Policy
  Modifications

Click any report card to open its detail view: a date-range filter and
a results table in the **four-field audit standard** — **User**,
**Action**, **Timestamp**, **Affected Resource** — plus a color-coded
outcome (success/failure/denied) column, which is the shape most audit
evidence requests are written around. Every report supports
**Export CSV** (via the same export mechanism used throughout the rest
of this tool) both from its detail view and directly from its card on
the picker screen (hover to reveal the export icon) — there's also a
single **Export all reports** button at the top of the picker for
pulling the entire evidence set in one pass.

**Getting data into the archive — the sync settings dialog** (gear
icon → environment row → sync settings, next to the existing local log
retention indicator):

- **Ingestion scope** — a real either/or choice made at the point data
  is written in, not a filter applied afterward:
  - *Curated only* — store just the ~20 event types the 14 reports
    above actually use. Smallest footprint; the right default for most
    deployments, especially larger tenants with high daily event
    volume.
  - *Everything* — store every System Log event type, for teams who
    want the full tenant history available for ad-hoc investigation
    beyond these 14 reports. Bigger archive, same reports.
- **Retention** — a separate setting layered on top of whichever scope
  you picked: a time window (e.g. "keep 2 years"), a size cap, or both.
  Curated events are the evidence trail itself, so they're **never**
  auto-pruned by this setting regardless of scope — retention only
  ever prunes non-curated ("everything" scope) events past the
  configured window/size.
- **Schedule** — enable a daily sync, choose the run time (shown in
  UTC), and the background job keeps the archive current with
  delta-only pulls (it only asks Okta for events published after the
  last successful sync — never a full re-fetch). This runs as a
  server-side background thread, so it works unattended on a hosted
  deployment; see [Hosting on a server](#hosting-on-a-server-optional).
- **First run, three ways in** — the first time sync is enabled for an
  environment, you're asked how to seed the archive:
  1. **Backfill the last 90 days** via the live Okta API (chunked
     day-by-day under the hood so it works reliably even on tenants
     with thousands of events/day, without hitting API pagination
     limits).
  2. **Import a System Log CSV** you've already exported from the Okta
     Admin Console — useful if you want to seed the archive from a
     specific date range, or simply avoid the API calls entirely.
  3. **Start fresh** — no backfill; the archive just grows from today
     forward.

A manual **Sync now** action is always available alongside the
schedule, for kicking off an out-of-band sync without waiting for the
next scheduled run.

### Admin roles and the audit log (hosted deployments)

On a server-hosted deployment (behind Okta login — see
[Hosting on a server](#hosting-on-a-server-optional)), every saved
environment is private to whoever created it by default, with an
opt-in **Shared** toggle (visible right next to each environment's name
in the manager — a clickable badge showing **Shared** or **Private**)
that makes it usable by every other logged-in user. Environments you
don't own show as disabled for editing/deleting, so it's never
ambiguous whose credentials you're looking at.

For teams that need someone to see and manage *every* environment on a
shared server — for onboarding, cleanup, or troubleshooting another
admin's stuck sync — membership in a designated **Okta group** grants
full admin rights: every environment becomes visible and editable, not
just your own or shared ones, and a new **Audit Log** panel (sidebar,
admin-only) shows every write action ever taken, by whom, across every
user and environment — sourced from the same `audit_log.jsonl` this
tool has always written, just newly given a UI. See
`OKTA_ADMIN_GROUP_ID` in [Hosting on a server](#hosting-on-a-server-optional)
for how to set this up. Every admin override action is itself logged
(with an `admin_override: true` marker), so an admin's own use of this
power is just as visible in the audit trail as anyone else's activity —
this is a compliance feature, not a backdoor.

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

A tab for a single, focused question: pick a resource group and
project, see every secret and secret folder in it — including ones
since deleted — with who created, updated, retrieved (secrets only),
and deleted each one, and when.

Two sources merged into one report: the live folder/secret tree (same
walk Folder Builder's "Load Current Structure" uses) for what exists
right now, plus the project's history from the compliance archive
above (`pam.secret.create/.update/.delete/.reveal` and
`pam.secret_folder.create/.update/.delete` — see "Confirmed tenant
behavior" below) for the full history, including resources that no
longer exist and therefore aren't in the live tree at all. A row
absent from the live tree is only ever marked **deleted** when the
archive actually contains a delete event for it — otherwise it's
**unknown** (most likely just older than however far back the archive
goes for that environment), never guessed.

Once an environment has run its first compliance sync (above), this
report reads from the archive with no 90-day ceiling and no cap on how
many reveal events are shown. Until then, it transparently falls back
to a live, on-demand Okta System Log query scoped to the project
(capped at 90 days and the 5 most recent reveals, same as this tool's
earlier versions) — so nothing regresses for an environment that hasn't
opted into compliance sync yet. Either way, it requires an Okta API
token configured on the active environment, since the audit trail
comes from Okta's System Log (live or archived), not OPA's own API.

Has its own **Export CSV** / **Export MD** buttons, covering both the
Secrets and Folders sections of whatever resource group/project is
currently selected, plus a **Refresh** button to re-pull the report
on demand without changing the resource group/project selection.

**Preserving history past Okta's 90-day retention (pre-compliance-sync
environments).** For an environment that hasn't yet enabled compliance
sync, each saved environment (gear icon → environment row) can still
opt in to the older, lighter-weight **"preserve logs locally"**
toggle: once enabled, every report fetch for that environment merges
newly-seen System Log events into a local cache file
(`secrets_log_cache.json`, next to `environments.json`, git-ignored
like it) instead of discarding them once Okta ages them out. A clear
shield icon (green "Preserving logs locally" / grey "Local log
preservation off") appears both in the environment manager and on the
Secrets Access Dashboard itself, so it's never ambiguous whether a given
report's history is capped at 90 days or extended locally. This cannot
retroactively recover events that were already older than 90 days the
first time the toggle is turned on for a given project — only what's
captured from that point forward accumulates; the dashboard's own
"based on the last N days" note is replaced with the actual local
coverage start date once enabled, rather than continuing to imply a
hard 90-day ceiling. **If you're setting up a new environment today,
enable compliance sync instead** (previous section) — it supersedes
this toggle with a single, tenant-wide archive rather than a
per-project cache file, and everything below in this section still
applies to it (encryption, key resolution, corrupt-cache handling).

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

**Why hosting matters for Compliance Reports specifically:** the daily
sync job that keeps the audit archive current (see
[Compliance Reports Dashboard](#compliance-reports-dashboard)) runs as a
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
   first place.) If you skip this step, `deploy.sh` still fully deploys
   the app and frontend either way — it just prints exactly which step it
   couldn't run and the manual command to run instead, rather than
   silently leaving `auth_gate.py` or nginx on stale code/config.

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
   **three separate `cp` lines**, not one — `deploy.sh` backs up the live
   nginx config to a fixed `.deploy-backup` path, applies the new one,
   and (only if `nginx -t` then fails) rolls the backup back over the
   live path; sudoers matches each exact argument list separately, so a
   rule for only one of these three leaves the other two silently
   denied:
   ```
   rparikh ALL=(ALL) NOPASSWD: /bin/systemctl restart opa-secrets-wizard, \
     /bin/systemctl restart opa-auth-gate, \
     /bin/cp /etc/nginx/sites-available/opa-secrets-wizard /etc/nginx/sites-available/opa-secrets-wizard.deploy-backup, \
     /bin/cp /home/rparikh/opa-secrets-folders/server/nginx-opa-secrets-wizard.conf /etc/nginx/sites-available/opa-secrets-wizard, \
     /bin/cp /etc/nginx/sites-available/opa-secrets-wizard.deploy-backup /etc/nginx/sites-available/opa-secrets-wizard, \
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
   You should see all seven commands from step 7c listed under
   `NOPASSWD:`, with no password prompt. If you instead get a password
   prompt, a `sudo: a password is required` error, or the list doesn't
   include all seven, re-open the file from step 7c and check for a typo
   — most commonly the username, or a binary path that doesn't match
   step 7a's `which` output exactly.

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

16. **Several of Okta's own guide-documented System Log eventType
    names don't actually exist on a real tenant, or exist under a
    different exact spelling** — found while building the Compliance
    Reports Dashboard's event-type mapping, and confirmed against two
    real tenants (not just one, to rule out a per-tenant fluke).
    `app.oauth2.authorize.success` doesn't exist; the real event is
    `app.oauth2.authorize.code`. `access.request.resolved` doesn't
    exist; the real event drops the trailing "d" —
    `access.request.resolve`. PAM security-policy events use the
    `pam.security_policy.create`/`.update` prefix, not `pam.policy.*`.
    There is no `policy.rule.delete` — rule removal isn't journaled as
    its own distinct event on this tenant. Genuinely absent from both
    test tenants entirely (not just low-volume): `user.account.lock`,
    `security.threat.detected`, `pam.session.start`/`.end`,
    `pam.policy.create`/`.update`. **Lesson generalized:** never ship a
    report or filter against a guessed/documented eventType name
    without confirming it against real System Log data first — the
    Compliance Reports Dashboard's entire event-type mapping
    (`COMPLIANCE_EVENT_TYPES` in `audit_store.py`) was built this way,
    one exact name at a time, not copied from any external guide.

## Idempotency

Existing folders are detected by recursively walking the full folder
tree (`fetch_all_folders`, one API call per folder — see constraint #2
above) and matching by name (safe given constraint #1). Re-running the
CLI/dashboard with the same CSV is safe at every depth — anything that
already exists is skipped, not duplicated.

## Version

5.24.3 — **Fixed `deploy.sh` running one version behind its own fixes.**
The self-modification fix added in 5.24.1 (re-exec from a frozen copy
before `rsync` can overwrite this file mid-run) protected the clone/sync
steps, but froze that copy BEFORE `rsync` pulled the newest code — so
every deploy's restart/nginx-apply logic actually ran the PREVIOUS
version's code, one version behind what had just been pulled. Confirmed
live: a run that correctly rsynced 5.24.2's nginx fix to disk still
printed 5.24.1's old warning text for the rest of that same run. Fixed
by re-executing a second time, right after `rsync`, so the steps that
follow run from the version just deployed, not the one before it. See
this version's changelog entry below.

5.24.2 — **Fixed `deploy.sh`'s nginx config backup path.** Found during
the first real deploy after widening the server's sudoers rule per
5.24.0/5.24.1's own instructions: the backup-before-apply step wrote to a
path inside a freshly-`mktemp -d`'d temp dir, which is different on
every single run — a sudoers rule naming one fixed `cp` argument list can
never match a path that changes every time, so the backup (and therefore
the apply) step was silently denied even with an otherwise-correct,
intentionally-widened rule. Fixed by backing up to a fixed path next to
the live config instead, so the sudoers rule in the README's "Hosting on
a server" setup can actually name it. If you already widened your
sudoers rule per the previous version's instructions, re-check it
against the (now 3-line, not 1-line) `cp` rule in that same section —
see this version's changelog entry below for exactly what changed.

5.24.1 — **Fixed a self-modification bug in `server/deploy.sh`** found
during the very first real deploy of 5.24.0: that script's own rsync
step overwrites itself on disk while still running, which (for the first
time, now that this script does more after that step than just print a
warning) made it silently keep executing its OLD in-memory tail instead
of the newly-deployed one — meaning the previous version's `opa-auth-gate`
restart and nginx-apply logic never actually ran, even though the app
itself deployed correctly. See that version's changelog entry below for
the fix (and 5.24.0's entry, right after it, for the security remediation
pass that exposed this).

### Changelog
- **5.24.3**:
  - **Fixed `deploy.sh` always running one version behind its own
    fixes.** 5.24.1's self-modification fix re-exec'd from a frozen copy
    taken BEFORE `rsync` pulled the newest code, so the restart/
    nginx-apply logic that followed always ran the version that was live
    before this deploy started, never the one it just pulled — confirmed
    live: a run that correctly rsynced 5.24.2's fix to disk still printed
    5.24.1's old (pre-fix) warning text for its own nginx step. Added a
    second re-exec, right after `rsync` and the executable-bit restore,
    so the rest of each run actually executes the version just deployed.
- **5.24.2**:
  - **Fixed `deploy.sh`'s nginx config backup landing in a path that
    changes every run.** The pre-apply backup of the live nginx config
    was written inside that run's own `mktemp -d` temp dir — a different
    path every single invocation, which a fixed-argument-list sudoers
    `cp` rule can never match twice. Moved the backup to a fixed path
    (`<live config>.deploy-backup`) next to the live file instead. The
    sudoers rule in "Hosting on a server" (step 7) is now 3 `cp` lines
    (backup, apply, rollback-on-failure), not 1 — re-check your rule
    against the updated version there if you set this up under 5.24.0/
    5.24.1's instructions.
- **5.24.1**:
  - **Fixed `server/deploy.sh` silently skipping its own newest logic.**
    Confirmed live: the rsync step overwrites this script's own file on
    disk while bash is still executing it, so anything added to the tail
    of a deploy (here, 5.24.0's `opa-auth-gate` restart + nginx apply)
    could silently never run — the process kept executing the OLD
    in-memory copy for the rest of that run. Fixed by having the script
    re-execute itself from a frozen temp copy before touching anything
    else, so the running process is never reading from the path rsync is
    about to overwrite.
- **5.24.0**:
  - **Critical: closed the nginx header-spoofing trust gap.** New
    required `NGINX_PROXY_SECRET` env var + matching nginx
    `X-Nginx-Proxy-Secret` header on every request proxied to
    `server/serve.py` — without it, that process trusted
    `X-Auth-Is-Admin`/`X-Auth-Sub` from any request reaching its loopback
    port directly, regardless of whether it actually went through
    nginx's login/step-up-MFA flow. See "Hosting on a server" for setup.
  - **Critical: fixed 3 cross-tenant data leaks.** Access Explorer job
    state, compliance-sync job state, and compliance report/history
    queries were all previously scoped by bare environment display name
    only — two different logged-in users with same-named environments
    (e.g. both named `dev`) could see or interfere with each other's
    results. Every one of these now uses the environment's existing
    owner-qualified stable ID (already computed everywhere internally,
    now also returned to the frontend and threaded through every
    mutation/lookup) instead of a bare name.
  - **Critical: config writes are now atomic.** `environments.json`,
    `banner_config.json`, `access_control.json`, and the encrypted System
    Log cache were all written via a plain truncating `open(path, "w")`
    — a crash or a login landing exactly mid-write could leave a
    corrupted file, and `auth_gate.py` previously treated a corrupted
    (but present) `access_control.json` as "no restrictions configured,"
    silently disabling the login-restriction gate. Writes now go through
    a tempfile + fsync + atomic rename, and a parse failure on an
    existing file now serves the last-known-good config from memory
    instead of falling back to unrestricted.
  - **High: admin environment edit/share/delete could silently target
    the wrong owner.** Previously resolved by scanning every owner for
    the first same-named match; now resolves directly by the stable ID
    above (an O(1) lookup) whenever the frontend provides one.
  - **High: `POST /api/banner` had no admin check at all** — any
    authenticated user could publish/edit the org-wide announcement
    banner. Added the same admin check its sibling (Access Control) already
    had; the sidebar's banner-settings pill is now also hidden from
    non-admins to match.
  - **High: CSV import (`sync/import_csv`) took a server filesystem path
    straight from the request body**, confined only by an `os.path.isfile`
    check — no path confinement at all. Now resolves through the same
    basename-only, project-root-confined helper the dashboard's other CSV
    picker already used; the "Import from a CSV export" first-run choice
    in Sync Settings now picks from that same project-folder file list
    instead of typing a free-text path. Also found and fixed: this route
    had **no ownership check at all** (unlike its sibling, sync status) —
    any authenticated user could inject rows into another owner's
    compliance archive just by guessing their environment's name.
  - **High: `server/deploy.sh` only ever restarted the main app
    service** — a change to `auth_gate.py` or to the nginx config could
    sit deployed-but-not-live until a separate, easy-to-forget manual
    step. It now also restarts `opa-auth-gate` and applies + validates
    (`nginx -t`) + reloads the nginx config (with an automatic rollback
    if validation fails), given a one-time, narrowly-scoped sudoers
    grant — see the new step-by-step setup in "Hosting on a server."
    Deploying without that grant still fully deploys the app; it just
    prints exactly which step was skipped and the manual command to run.
  - **Fixed a real SQLite connection leak.** `audit_store.py` kept one
    open connection per OS thread ID forever, with the dashboard's
    threaded HTTP server spawning a new thread per request — unbounded
    memory/file-descriptor growth on a long-running server. Now reuses
    exactly one connection per thread via `threading.local()`.
  - **Fixed log pruning only ever fully deleting, never partially
    pruning.** Retention-by-size pruning checked the on-disk file size to
    decide when to stop, but that size only shrinks after a `VACUUM` —
    which was running every loop iteration (a full database rewrite each
    time, badly slow) and, worse, meant the loop's own stopping condition
    could never actually trigger mid-run. Now checks live (non-freed)
    data size via `PRAGMA page_count`/`freelist_count` instead, and
    `VACUUM` runs at most once, after pruning finishes.
  - **Fixed a sync watermark bug that could silently and permanently lose
    events.** If a single day's System Log volume exceeded what one sync
    chunk could page through, the chunk's results were used (and the
    watermark advanced) exactly as if that day were fully synced —
    Okta's System Log has no way to re-fetch an aged-out window later,
    so anything past the page cap was gone for good. An incomplete chunk
    now stops the sync immediately, leaves the watermark at the end of
    the previous (complete) day, and records the failure so the next run
    retries that exact day instead of skipping past the gap.
  - **Fixed a frontend polling deadlock** in the Access Explorer
    bootstrap job: polling could stop before the final result had
    actually been fetched, in which case the UI never left its "loading"
    state. Several `useMemo`-wrapped array derivations (Resources tab,
    Compliance Report detail, Users tab's user picker) also now have
    stable array references across re-renders, fixing an issue where
    their fuzzy-search index was being needlessly rebuilt on every
    keystroke on a large tenant.
  - **Fixed CSV/formula injection in exported CSVs.** A cell value
    starting with `=`, `+`, `-`, `@`, a tab, or a carriage return is
    interpreted as an executable formula by Excel/Sheets/LibreOffice when
    the exported file is opened — any exported field that ultimately
    traces back to Okta System Log data (actor/resource display names)
    could carry such a value. These are now prefixed with a leading
    apostrophe before export, the standard neutralization.
  - **Fixed several minor correctness bugs found during this pass:** a
    malformed or negative `Content-Length` header could crash a request
    handler (or, for a negative value, hang the handling thread entirely)
    instead of returning a clean 400; several `/api/environments/{name}/...`
    routes never URL-decoded the name segment, breaking on environments
    with spaces or special characters in their name; admin deletion of an
    environment now also clears the environment's real owner's active
    pointer, not just the deleting admin's own, if it pointed at the
    deleted environment.
- **5.23.2**:
  - **New: scheduled sync audit trail.** `sync.scheduled_start` /
    `_completed` / `_failed` / `_skipped` entries now exist — previously
    only a manual "Sync now" click was logged at all; a scheduled run had
    zero audit trail regardless of outcome. A catch-up run (the server
    was down past the scheduled time) gets an explicit `minutes_late`
    field once it's more than one poll cycle late, distinguishing "the
    scheduler correctly caught up" from "the scheduler is broken." An
    unexpected exception in the scheduler loop itself is now also logged
    as `sync.scheduler_error`, not just printed to a log that's easy to
    miss.
  - **New: local-time equivalent on the sync schedule's Run Time field.**
    The field was already labeled "(UTC)," but that was easy to miss on a
    native time picker — confirmed live when a 2:00 PM UTC schedule was
    entered assuming local time. Now shows e.g. "= 7:00 AM in your local
    time (America/Los_Angeles)" directly under the input, updating live
    as you type.
  - **Fixed: step-up MFA corroboration could miss a real, existing Okta
    event.** Confirmed live: a single immediate System Log query right at
    step-up completion missed an event that Okta had published only ~2
    seconds earlier — the event existed, but Okta's own indexing hadn't
    caught up yet. Now retries a few times with a short delay before
    giving up (still fails open — a miss never blocks the save).
  - **New: Audit Log's Refresh also backfills missing MFA corroboration.**
    Clicking Refresh now also re-queries Okta for any older
    `access_control.update` entry whose `okta_mfa_log_event` is still
    `null`, closing the gap for entries that missed corroboration at save
    time. Requires the new optional `INTERNAL_API_SHARED_SECRET` env var
    (see "Register an OIDC application," step 4) — safely a no-op without
    it. A toast reports how many entries were found and backfilled, if
    any.
- **5.23.1**:
  - **Fixed: Audit Log's Refresh button failed silently.** `useQuery`'s
    `isError`/`error` were never checked, so a failed fetch (expired
    session, transient network error) just left the last-successful data
    on screen with zero indication anything went wrong. Now shows both a
    toast and a persistent inline error card (matching the pattern
    `SecretsAccessDashboard` already uses), with a note that what's shown
    may be stale.
  - **New: Okta System Log corroboration on step-up MFA audit entries.**
    `access_control.update` entries now carry an `okta_mfa_log_event`
    field — Okta's own `user.authentication.auth_via_mfa` System Log
    record for that exact challenge (published time, outcome, display
    message), looked up by `auth_gate.py` at the moment step-up completes
    and carried through to the audit write via a new `X-Auth-Mfa-Log-
    Event` header. Correlated by actor + tight timing proximity, since
    Okta's own step-up sequence has no shared transaction/request ID to
    join on (confirmed live against a real tenant — see
    `api_event_type_reference.md`). A `null` value means Okta hadn't
    indexed the event yet (or the lookup failed transiently) — it does
    NOT mean the MFA challenge didn't happen; the save was already gated
    by a verified step-up cookie before this lookup ever runs, so a miss
    here never blocks or invalidates a save.
- **5.23.0**:
  - **New: User Group + "Restrict login to these groups."** Previously,
    `OKTA_ADMIN_GROUP_ID` only gated admin *rights* — any authenticated
    Okta user in the org could log in and get non-admin access, with no
    way to restrict that. A new User Group ID, combined with a
    restrict-login toggle (off by default, so a fresh deployment never
    locks anyone out), lets an admin require membership in either group
    just to log in at all. See "Admin access" for the full setup.
  - **New: Access Control panel (sidebar, admin-only)** — both group IDs,
    and the restrict-login toggle, are now editable from the dashboard
    itself instead of only via `/etc/opa-compliance-wizard.env` +
    `systemctl restart opa-auth-gate` (no restart needed at all now — a
    saved change is read fresh on the very next login).
    `OKTA_ADMIN_GROUP_ID` becomes a first-boot bootstrap default only.
  - **New: step-up MFA required to save Access Control changes.**
    Clicking Save redirects through Okta again (Identity Engine's
    `max_age=0` + `acr_values=urn:okta:loa:2fa:any`) to prove a fresh
    second factor was just completed, before the save is accepted — a
    genuinely new interaction pattern for this app (previously every
    "dangerous action" was a plain inline confirm, never a re-auth step).
    Depends on the OIDC app's own Authentication Policy actually
    permitting/requiring MFA; see "Admin access" for the caveat. Every
    save is logged with a `step_up_verified: true` marker alongside the
    usual `admin_override` convention.
- **5.22.1**:
  - **Fixed: Compliance Reports card grid broke below tablet width.**
    `grid-cols-2` was unconditional, so each card had too little room for
    its icon+description+count row — the event count overlapped the
    description on a phone-width viewport. Now stacks to one column below
    `md`, matching every other multi-column layout from the 5.22.0 mobile
    pass. Checked every other grid in the app (`KeyValueGrid`, the Sync
    Settings run-time/retention/max-size row) — both hold up fine at
    390px as-is, no change needed there.
  - **Fixed: sidebar showed both the icon rail and the labeled panel at
    once on desktop**, widening it instead of collapsing — a real
    regression from 5.22.0's mobile pass. Replaced with one column that
    toggles between an icon-only rail and the full labeled panel via a
    new collapse/expand button; the choice persists across reloads
    (desktop-only — the mobile drawer is unaffected and always shows the
    full labeled panel when open).
- **5.22.0**:
  - **New: Relationships tab (Access Explorer).** Browse every
    relationship → its assignments → the policies that use them, in one
    dedicated drill-down (previously this data was only visible indirectly,
    folded into ordinary policy rules with no way to inspect the
    relationship/assignment config itself). Shows each assignment's real
    principal(s) and resolved resource(s) by name, not raw IDs.
  - **New: "via {relationship} → {assignment}" annotation on relationship-
    derived grants**, wherever they render — Projects, Resource Groups,
    Policies, Users, and Groups tabs all pick this up automatically
    through the shared `PolicyRuleCard`, with zero per-tab changes needed.
  - **Mobile-friendlier UI.** Sidebar collapses to a hamburger-triggered
    overlay drawer below tablet width (unchanged above it); every dialog
    (Environments, Sync settings, Assign Access, Banner, About, delete
    confirmations) now caps to the viewport width instead of overflowing;
    two-column tabs (Policies, Relationships) stack vertically on narrow
    screens; the footer wraps instead of clipping. Not a full redesign —
    dense tables still scroll horizontally, as before.
  - **Fixed: footer's "Sync now" showed only a spinner**, no indication of
    how far along a sync actually was. Now shows the same real (date-
    window-derived, not animated) progress bar the Sync Settings dialog
    already had — extracted into a shared helper so both stay in sync.
- **5.21.0**:
  - **Split into its own standalone repo.** No longer nested inside the
    `ItsGambit/Okta` monorepo — now `github.com/ItsGambit/opa-compliance-wizard`,
    full history preserved. `server/deploy.sh` now clones from the repo
    root instead of a monorepo subdirectory. (Left the footer's
    README/Changelog links pointing at the old monorepo path when this
    happened — fixed in this same release, see below.)
  - **New: tenant-wide resource inventory (Access Explorer → Resources).**
    Every resource kind OPA manages, live-verified against a real tenant:
    Windows/Linux/Gateway servers, Okta and SaaS service accounts, Active
    Directory accounts, database accounts, workload roles/connections,
    gateways, and the database/SaaS-app/AD "connections" (integration
    configs) each account family is discovered through — 13 kinds total,
    several via undocumented API paths found live rather than in any
    published spec.
  - **New: per-resource compliance-report history.** Click any resource in
    the Resources tab to see its full compliance-report history — every
    report row where that resource was involved, not just one report at a
    time. Backed by new indexed `resource_id`/`resource_alternate_id` and
    a normalized `event_targets` table on the compliance archive (so "was
    this resource ANY target on this event" is a fast indexed lookup, not
    a full-table scan), plus an exact-display-name fallback match for
    database accounts and individual Active Directory accounts, which
    (confirmed live) have no discoverable log-side id at all — Okta's
    System Log references a different, internal id for those two kinds
    with no API lookup back to the account object.
  - **New: relationship-based policy grants resolve correctly.** A small
    number of real security policies specify their principal and resource
    target through OPA's newer "relationships/assignments" feature instead
    of the ordinary principals/resource-selector fields — previously
    invisible to every tab (a policy like this showed no real
    principal or resource at all). Now resolved into the exact same shape
    every other policy already renders, including the case where one
    relationship is shared across multiple assignments with different
    principals and different granted resources.
  - **New: Active Directory discovery-rules panel.** Click an Active
    Directory Connection in the Resources tab to see exactly which
    discovery rules and matching criteria caused a given AD account to be
    found and matched to an Okta identity in the first place (e.g. "matches
    by username, partial match: starts with 'a1'") — previously no way to
    answer "why does this AD account exist as a managed resource at all."
  - **New: fuzzy, typo-tolerant search everywhere.** Every dropdown picker
    and every report/resource filter now does typo-tolerant matching with
    highlighted match text showing why a result matched, instead of plain
    exact-substring filtering.
  - **New: one global "Sync now," not a Refresh button per screen.**
    Every report and resource-history view reads the same shared
    compliance archive, so pulling fresh data from live Okta is now one
    action (in the footer, next to a new "Last Okta import" timestamp)
    that updates every open view at once — replacing several previous
    per-view Refresh buttons that, on inspection, only ever re-queried the
    already-archived data and never actually talked to Okta.
  - **New: Audit Log is a full page, not a pop-up**, with real per-field
    rendering (was a raw JSON dump) and the same fuzzy search as everywhere
    else. Also now captures client IP and user agent on every logged
    action (Okta's own System Log always has; this log never did) — older
    entries predate this and show as "—", not backfilled.
  - **Fixed: gateway servers misclassified as Linux servers.** Every
    OPA-managed server carries `"broker"` in its services list (the
    always-present connectivity agent), which an earlier version of the
    gateway-detection logic wrongly treated as gateway-specific — every
    real Linux server was showing up as a gateway instead. Now matched by
    hostname against the real Gateway resource list instead.
  - **Fixed: Okta/SaaS service accounts showed a raw ID instead of a
    name.** The resource list read a field that doesn't exist on the real
    account object; now reads the real name/username fields.
  - **Fixed: broken README/Changelog links in the footer** after the
    standalone-repo split above left them pointing at the old monorepo
    path.
  - Nav restructure: Compliance Reports is now the default landing tab
    (was Folder Builder); Secrets Access Dashboard moved under Compliance
    Reports as a sub-item instead of its own top-level tab; Folder Builder
    moved to last.
- **5.20.0**:
  - **Renamed the project** from "OPA Secrets Wizard" to **"OPA
    Compliance Wizard"** throughout (page title, sidebar, About dialog,
    footer, launcher filenames, CLI/server startup messages) — the
    compliance reporting feature set (5.19.0) is now this tool's
    primary purpose, not an add-on to a secrets-folder manager.
    Internal implementation details that would be riskier to rename —
    the OS keychain credential-storage prefix, the live server's
    systemd service names — were deliberately left unchanged for this
    release to avoid a credential-migration/downtime risk; see the
    project's own internal notes if you're tracking that follow-up.
  - **New: Okta-group-based admin roles.** Members of a designated Okta
    group (`OKTA_ADMIN_GROUP_ID`, see "Admin access" in
    [Hosting on a server](#hosting-on-a-server-optional)) can see and
    manage every environment on a hosted, multi-user deployment, not
    just their own or explicitly shared ones — checked once at login
    via a direct Okta API call, carried through the session the same
    way identity already was, and forwarded to the app via a new
    `X-Auth-Is-Admin` header (same pattern as the existing
    `X-Auth-Sub`/`X-Auth-User` headers). Every admin override action is
    logged with an `admin_override: true` marker.
  - **New: admin-only Audit Log viewer.** The `audit_log.jsonl` write
    path and its `GET /api/audit_log` read endpoint already existed
    (every mutating action has always been logged) but had no UI until
    now — a new sidebar panel, visible only to admins, lists every
    entry most-recent-first with load-more pagination.
  - **New: Shared / Private indicator on every environment.** Found
    while debugging a sync that looked "stuck" — the real cause was an
    Okta API token added to the wrong owner-scoped copy of an
    environment, with no way to see from the UI that separate
    owner-scoped copies even existed. The environment manager now shows
    a clickable Shared/Private badge and disables Edit/Delete for
    environments you don't own (unless you're an admin).
  - **Fixed: sync errors were silently swallowed.** The sync settings
    dialog only ever rendered `sync_state.last_sync_error`, which is
    `null` on a first-ever failed sync (nothing had been written yet to
    produce a `sync_state` row) — so a real, immediately-returned error
    like "No Okta URL/API token configured for this environment" looked
    like the Sync button had simply done nothing. The real error was
    already present in the job's live status the whole time; it just
    was never displayed. Fixed, plus a compact progress bar (with a
    real percentage, computed from how far the backfill's date window
    has actually advanced) replaced what was previously a raw, unbounded
    scrolling list of one line per day-chunk.
  - **Fixed a deploy gap that let nginx silently run a stale config.**
    `server/deploy.sh` syncs the app directory and restarts the app
    service, but nginx's config is a plain file copy on the server, not
    something this script ever touched — so a real nginx change (like
    the new `X-Auth-Is-Admin` header-forwarding rule this release needs)
    could sit committed and "deployed" for a while with nginx quietly
    still serving the old config underneath it, no error anywhere.
    `deploy.sh` now diffs its own nginx config against what's actually
    loaded and warns loudly (it can't safely auto-apply this itself, no
    sudo access to nginx by design) if they've drifted. **Superseded in
    5.24.0** — `deploy.sh` now actually applies/validates/reloads it
    (and also restarts `opa-auth-gate`) given a widened, still-narrowly-
    scoped sudoers rule; see that release's note and the "Hosting on a
    server" setup steps.
- **5.19.0**:
  - **New: Compliance Reports Dashboard.** A new top-level tab
    generates 14 audit-ready reports (grouped by SOC 2 CC6/CC7/CC8,
    plus a Privileged Access/PAM group) from a local, indefinitely-
    retained archive of Okta System Log + OPA PAM events — closing the
    gap between Okta's 90-day log retention and the 12-month-plus
    windows most audits actually cover. See
    [Compliance Reports Dashboard](#compliance-reports-dashboard) for
    the full feature description.
  - **New archive engine (`audit_store.py`).** SQLite-backed (see
    [Hosting on a server](#hosting-on-a-server-optional) for why SQLite
    over a client-server database), with an admin-configurable
    **ingestion scope** (curated ~20 event types vs. everything) that
    governs what's written at ingest time, and a separately-configurable
    **retention** policy (time window and/or size cap) layered on top —
    curated events are never auto-pruned regardless of retention
    settings. Supports both live-API delta sync (chunked day-by-day to
    stay well under Okta's pagination safety cap on high-volume
    tenants) and direct import from an already-exported System Log CSV.
  - **New restart-safe background scheduler.** A daemon thread in
    `server/serve.py`, started once at boot, polls every saved
    environment's persisted sync schedule/state rather than keeping an
    in-memory timer — survives `systemd` restarts and redeploys with no
    missed or duplicate runs (see the timezone bug below for how this
    was verified).
  - **First-run choice.** Enabling sync for an environment for the
    first time offers three paths: backfill the last 90 days live,
    import a CSV, or start fresh with no backfill.
  - **Secrets Access Dashboard merged into the same archive.** A new
    `build_project_secrets_report_from_archive` function serves this
    report from the compliance archive once an environment has synced
    at least once, removing the old 90-day/5-reveal caps entirely; any
    environment that hasn't opted in falls back to the exact original
    live-Okta-query behavior, unchanged. Verified byte-identical output
    between old and new for the same real project before switching the
    route over.
  - **CSV export everywhere.** Every report supports CSV export from
    its detail view, from its card on the picker (hover to reveal), and
    in bulk via a single "Export all reports" action — reusing the
    existing export utilities used throughout the rest of the app.
  - **Corrected several eventType names inherited from an external
    audit-requirements guide** that don't match real Okta System Log
    data — see finding #16 in
    ["Confirmed tenant behavior"](#confirmed-tenant-behavior-found-via-live-testing-not-docs)
    for the specifics (`app.oauth2.authorize.code`, not `.success`;
    `access.request.resolve`, not `.resolved`; `pam.security_policy.*`,
    not `pam.policy.*`; several guide-listed events confirmed genuinely
    absent from two real tenants). Every one of the 14 reports' event
    types was individually verified against live tenant data before
    being wired into a report definition.
  - **Two real bugs found and fixed via live testing, not caught by
    typecheck/build alone:**
    1. A timezone mismatch between the archive's UTC-stored sync
       timestamps and the scheduler's original local-time due-check
       could cause a duplicate same-day sync to queue right after a
       real one completed, once local time and UTC crossed a calendar-
       day boundary at different moments. Fixed by making the entire
       due-check UTC end-to-end; the sync schedule's run-time field is
       now explicitly labeled "(UTC)" in the UI.
    2. A bare date string from an HTML date picker (e.g.
       `"2026-09-29"`) compared directly against a full ISO timestamp
       column via plain string comparison silently excluded every
       event on that day from a report's date-range filter. Fixed by
       normalizing a bare date to end-of-day before comparing.
  - Preceded by a standalone HTML mockup, reviewed and iterated on
    (ingestion-scope choice, CSV-import option) before any real
    backend code was written — same process used for the 5.18.0 UI
    redesign.
  - Live-verified end-to-end: a full regression pass across all 5
    build phases together against fresh data, including deliberately
    deleting the archive's last 24 hours and re-syncing to confirm
    delta-sync correctly re-fetches exactly what was removed with no
    data loss.
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
