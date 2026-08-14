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
you create one yourself; nothing in this tool writes one anymore), (3)
the dashboard's encrypted environment store — whichever environment is
active there. This means the CLI automatically follows whatever
environment you last activated in the dashboard, with zero plaintext
involved.

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

## Idempotency

Existing folders are detected by recursively walking the full folder
tree (`fetch_all_folders`, one API call per folder — see constraint #2
above) and matching by name (safe given constraint #1). Re-running the
CLI/dashboard with the same CSV is safe at every depth — anything that
already exists is skipped, not duplicated.

## Version

5.7.0 — first public testing release. The launcher now checks (and can
guide you through installing/upgrading) Python, Node.js, and this
project's own dependencies before building/starting anything; the
dashboard has an ⓘ "about / no warranty" dialog next to the gear icon;
and the repo itself is packaged for GitHub (MIT license, cleaned-up
`.gitignore`, no test artifacts).

### Changelog
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
