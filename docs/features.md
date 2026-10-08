# Features

Full feature documentation for the OPA Compliance Wizard dashboard. See
the main [README](../README.md) for installation and a quick overview;
this doc covers what each part of the dashboard actually does.

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
**Navigation and the browser's back button.** Every view (tab, sub-tab,
an opened compliance report) is a URL hash route such as
`#/reports/browse/mfa_enforcement`, so Back/Forward, reload and a pasted
link all land on the same view -- Back from a report returns to the
Compliance Reports home (v5.40.1).

The server binds `127.0.0.1` only. If the port is already taken by
another running instance, it fails fast with a clear message instead
of silently double-serving (see the [Changelog](../CHANGELOG.md)).

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
see [Hosting on a server](hosting.md#hosting-on-a-server-optional) for why that
choice, not a bigger database, is the right one here), then serving
16 pre-built reports on top of that archive.

**The 16 reports, grouped by SOC 2 Trust Services Criteria** (each maps
to a specific, live-verified set of real Okta/OPA event types — nothing
here is a guess or a report card that will silently always read zero):

- **CC6 — Access Controls:** MFA Enforcement, Provisioning &
  De-provisioning, Role/Group Changes, Admin Privilege Grants, JIT
  Access Requests, PAM Secrets, PAM JIT Access (Checkout/Checkin), PAM
  Credential Reveals, Client Enrollment, Device Management
- **CC7 — System Operations:** Session Activity, Threat Detection, PAM
  Sessions, Active Directory Sync Activity
- **CC8 — Change Management:** API Token Lifecycle, Policy
  Modifications, PAM Policy Modifications, Credential Rotation

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
  - *Curated only* — store just the ~20 event types the 16 reports
    above actually use. Smallest footprint; the right default for most
    deployments, especially larger tenants with high daily event
    volume.
  - *Everything* — store every System Log event type, for teams who
    want the full tenant history available for ad-hoc investigation
    beyond these 16 reports. Bigger archive, same reports.
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
  deployment; see [Hosting on a server](hosting.md#hosting-on-a-server-optional).
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
[Hosting on a server](hosting.md#hosting-on-a-server-optional)), every saved
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
`OKTA_ADMIN_GROUP_ID` in [Hosting on a server](hosting.md#hosting-on-a-server-optional)
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

**Preserving history past Okta's 90-day retention.** Enable compliance
sync (previous section) — once an environment completes its first sync,
every report for it is sourced from `audit_store.py`'s own SQLite
archive instead of a live, 90-day-bounded Okta System Log query, with no
retention cap beyond that archive's own (configurable)
`retention_days`/`retention_max_size_mb` settings. An earlier,
lighter-weight per-project local cache (`secrets_log_cache.json`,
Fernet-encrypted) existed before compliance sync did, but was retired in
v5.34.0 once the archive became a strict superset of what it ever
captured.

### Service Accounts Dashboard

The SaaS / Okta counterpart of the Secrets Access Dashboard (v5.40.0):
every **SaaS app service account** and **Okta Universal Directory
service account** across the whole tenant — including ones since
deleted — with who created, updated, assigned and deleted each one, who
revealed its password or checked it out, and its password-rotation
history (totals by outcome, first/last, and the most recent rotations),
all from the compliance archive.

Two sources merged, same as Secrets: the live roster (the same
per-project SaaS / Okta account lists the Access Explorer's Resources
tab shows, walked across every resource group and project) for what
exists right now, plus the archive's `pam.service_account.create /
.update / .delete / .assign / .password.reveal /
.password_rotation.end` and `pam.resource.checkout` history — see
[confirmed tenant behavior #17](api-notes.md#confirmed-tenant-behavior-found-via-live-testing-not-docs)
for what was actually verified. The same honesty rule applies: an
account absent from the live roster is only ever **deleted** when the
archive holds a successful delete event for it; otherwise it's
**unknown**, never guessed. Every history entry carries the event's real
outcome, because a service-account create or rotation genuinely ends
`DEFERRED` or `FAILURE` on real tenants.

**Why it's tenant-wide rather than per-project.** Secrets events carry
the project as a co-target; service-account events don't. A deleted
account's project is therefore not knowable from the archive, so a
per-project page could never say "deleted" honestly. Instead the
dashboard loads everything and filters client-side by **type** (SaaS
app / Okta), **status**, **resource group** and **project**, with a
fuzzy search over name, username, app, project and resource group —
and tells you how many no-longer-live accounts a resource group /
project filter is hiding. Summary tiles (accounts, SaaS, Okta, active,
deleted, unknown) always agree with the filtered table.

**What's deliberately left out.** Database and Active Directory
accounts share the exact same event types and the same "Service
Account" target type; they are classified out (and counted in a note
under the tiles) rather than mixed in or silently dropped. An account
id with no recognisable family marker is likewise excluded and counted,
never guessed into a type. `sync_status` and the last password change
are shown as **informational** text under the account, not as a
finding — a freshly registered SaaS account can legitimately sit
`NOT_SYNCED` (see [api-notes.md](api-notes.md)).

Clicking an account opens the same per-resource **history panel** the
Resources tab uses — every archived event where that account is a
target, with the date range, fuzzy filters, truncation notice and
export the generic reports have. **Export CSV / MD** covers the
currently filtered rows (with a Type column, so a SaaS-only or Okta-only
file is one filter away), and **Refresh** re-walks the live roster.

Requires a completed compliance sync for the active environment — this
report is sourced from the archive only (no live, 90-day Okta fallback
like the Secrets report's pre-sync path); until then the tab says so
and points at **Sync now**. It needs the OPA credentials for the roster
walk, not an Okta API token.

**Cost and freshness.** Loading the tab walks every resource group and
project (one call per project per account type) and then reads the
archive, so a tenant with hundreds of projects will take a while — the
tab says so while loading. The result is kept until you press
**Refresh** or a global sync completes; switching environments loads
that environment's own report. First start after upgrading to v5.40.0
builds two new archive indexes (a one-off few seconds on a large
archive) that keep the per-account rotation reads fast.

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

