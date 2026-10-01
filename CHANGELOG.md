# Changelog

Full version history for the OPA Compliance Wizard. Each entry below pairs a one-paragraph summary with the detailed per-item breakdown.

5.27.0 — **First automated test suite (pytest, backend), plus an explicit
`DEPLOYMENT_MODE=local|hosted` startup guard.** First two items from the
fast-follow architecture plan's own suggested sequencing — regression
protection and deployment-safety hardening, both deliberately shipped
before any bigger migration work (environment UUIDs, SQLite) begins.
- **New: `DEPLOYMENT_MODE` environment variable** (`server/serve.py`,
  optional, defaults to `local`). `NGINX_PROXY_SECRET` being optional was
  the right call for not breaking standalone usage, but it meant the SAME
  binary, with ONE missing environment variable, could silently run in a
  dramatically weaker trust mode with no error, no startup warning,
  nothing — an easy misconfiguration to make exactly once, on exactly the
  deploy that matters, and never notice. In `hosted` mode, `serve.py` now
  refuses to start at all unless `NGINX_PROXY_SECRET` is also set — fails
  loudly at boot, matching this project's existing `_require_env` pattern
  in `server/auth_gate.py`, instead of failing silently at the first
  spoofed request. An unrecognized value (anything other than `local`/
  `hosted`) also fails fast rather than silently falling back to `local`.
  `local` (the default) is byte-for-byte unchanged behavior for every
  existing standalone/CLI run. See `docs/hosting.md` for setup.
- **New: first pytest suite in this repo** (`tests/`, `conftest.py`,
  `pyproject.toml`, `requirements-dev.txt`). Covers the functions with the
  most direct history of silent breakage this quarter:
  `_resolve_admin_target`/`environment_storage_name` (admin same-name
  disambiguation), `_is_admin_from_headers`/`_request_is_from_nginx` (the
  P0 header-spoofing fix — a regression test that fails loudly if anyone
  ever reverts it), `sync_okta_events`'s incomplete-chunk watermark
  behavior, `_atomic_write_json`'s crash-mid-write safety, and the new
  `DEPLOYMENT_MODE` guard above. Also adds a two-owner collision
  integration test (`test_two_owner_collision.py`) — two environments
  both named `"dev"` under different owners, exercised through the real
  admin HTTP routes — the single test that would have caught the
  cross-tenant F1/F2/F3 bugs (fixed by hand, external review, 2026-09-30)
  automatically instead of needing a human review to surface them.
  Written against today's `environment_storage_name`/`storage_name`
  scheme deliberately, asserting against the stable public contract
  (explicit `environment_id`, `_environment_visible_to`, the HTTP routes'
  `id` round-trip) rather than `environments.json`'s on-disk shape — so it
  keeps passing unchanged once a future UUID/SQLite migration lands.
  `CONTRIBUTING.md`'s "no automated test suite" note updated to match.

5.26.0 — **README/About wording fix (overselling what the Compliance
Reports Dashboard produces), plus two new live-verified resource kinds:
enrolled OPA Clients and Okta-managed Devices, now visible in Access
Explorer's Resources tab and reflected in two new compliance reports.**
- **Wording:** the README, About dialog, and header subtitle previously
  implied this tool generates a finished SOC 2/SOX/ISO 27001 report. It
  generates the underlying audit *evidence* those frameworks ask for —
  closer to "gets a PAM admin most of the way to what their auditor
  needs," not a certified report in itself. Reworded in all three places;
  the "About" dialog's description is now framework-agnostic ("SOC 2,
  SOX, ISO 27001, and similar frameworks") rather than naming exactly
  three as if they were the only ones supported.
- **New: Enrolled Clients.** `OpaClient.list_clients` (confirmed live
  against the real `opa-minimal.yaml` OpenAPI spec AND a real tenant, 10
  real clients returned) surfaces every end-user OPA client (laptop/
  workstation running the desktop app or `sft`) enrolled for the team —
  distinct from a managed server/gateway resource; this is what a HUMAN
  enrolls to make SSH/RDP connections at all. New compliance report
  "Client Enrollment" (CC6) backed by the real `pam.client.enroll`
  eventType.
- **New: Okta-Managed Devices.** `OktaClient.list_devices` (confirmed
  live, `GET /api/v1/devices`) surfaces Okta's own org-wide device
  inventory — genuinely separate from an OPA Client (a person can have
  one without the other; confirmed by comparing both tenant's real lists,
  which only partially overlap). Each device additionally carries its
  real `authenticator_enrollments` (confirmed live after the org enabled
  the underlying Okta feature mid-session; empty, not an error, on orgs
  without it — same for `GET .../os-accounts`, also now feature-gated on
  rather than always 401ing). New compliance report "Device Management"
  (CC6) backed by three live-confirmed eventTypes
  (`device.enrollment.create`, `device.lifecycle.activate`,
  `device.user.add`) — deliberately NOT also claiming
  suspend/unsuspend/deactivate/delete, which Okta's own device-lifecycle
  docs describe but which never fired in this tenant's real activity
  within the probe window; add them once a real example exists, per this
  project's standing "never guess an eventType" rule.
- **MFA Enforcement report enrichment:** `user.authentication.auth_via_mfa`
  events previously had an always-blank `resource_type_detail` column
  (this eventType's `debugContext.debugData` has no `resourceType` field
  at all) — now surfaces the real authenticator/factor used instead
  (confirmed live across a 50-event sample: `SIGNED_NONCE`/`signed_nonce`
  → "Okta Verify (FastPass)", `OKTA_VERIFY_PUSH` → "Okta Verify (Push)",
  `PASSWORD_AS_FACTOR` → "Password"), the real information an auditor
  asking "which factor types are actually in use" needs.
- Report count references in the README/features doc bumped 14 → 16 to
  match (two new reports this release).

5.25.1 — **Fixed a real `systemctl restart` crash-loop, and a UI color
nit from 5.25.0.** `server/serve.py` now retries binding its port a few
times with a short backoff before giving up — on the hosted Linux
server, `systemctl restart` can start the new process before the OS has
actually released the old one's socket, which surfaced as a real,
reproducible crash-loop (confirmed via repeated clean restarts, no
concurrent interference) that only ever recovered via systemd's own
`RestartSec=3`. Also: `deploy.failed` entries in the Audit Log now use
the existing red/`text-loss` error color (same as every other failure
state in this app) instead of the same neutral accent color as a
successful deploy — a mismatch caught immediately after 5.25.0 shipped.

5.25.0 — **New: deploys now show up in the Audit Log.** `server/deploy.sh`
logs `deploy.started`/`deploy.completed`/`deploy.failed` entries directly
to the same audit trail every other write action already uses — visually
distinct (accent-colored, left-bordered) in the Audit Log page, since a
deploy has no logged-in human actor behind it and reads differently from
every other entry around it. Previously a deploy was only ever visible in
`deploy.sh`'s own terminal output, invisible to anyone looking at the
dashboard's own audit history.

5.24.4 — **Fixed a stale `gnome-keyring-daemon` process pile-up on the
hosted server.** `server/start-headless.sh` calls `gnome-keyring-daemon
--unlock --login` on every service start/restart, but `--login` is
specifically a PAM-style, one-time-at-login invocation that deliberately
never fully initializes (per `gnome-keyring-daemon(1)`) — nothing ever
tore down the previous invocation first, so repeated restarts (e.g.
back-to-back `deploy.sh` runs) accumulated multiple competing daemon
processes with none reaped, one observed still running from over a week
earlier. (A separate crash-loop pattern observed during this session's
deploys turned out to have a different root cause — a TCP port-rebind
race on `systemctl restart`, not this — but the daemon pile-up was a
real, independently-confirmed leak worth fixing regardless.) Fixed by
killing any stray `gnome-keyring-daemon` for this user before starting a
fresh one — safe on this box specifically because
it has no desktop/login session at all, so this script is the only thing
that ever starts one here.

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
- **5.25.1**:
  - **Fixed a real `systemctl restart` crash-loop.** On the hosted Linux
    server, a restart could start the new `serve.py` process before the
    OS released the previous one's socket on the same port — confirmed
    live via several clean (no concurrent manual interference) restarts
    failing 2-3 times each before settling, relying entirely on
    systemd's `RestartSec=3` to eventually succeed. `main()` now retries
    the bind itself (5 attempts, 1s apart) before falling back to the
    same clear "could not bind" error — `StrictBindHTTPServer`'s
    deliberate `allow_reuse_address=False` (what makes a genuine
    double-bind mistake fail loudly) is unchanged.
  - **Fixed `deploy.failed` using the wrong color.** 5.25.0's new Audit
    Log entries for a deploy used the same neutral accent color for
    started/completed/failed alike — a failed deploy now uses this
    app's existing red/`text-loss` error convention instead.
- **5.25.0**:
  - **New: deploys now show up in the Audit Log.** `server/deploy.sh`
    logs `deploy.started`/`deploy.completed`/`deploy.failed` via the same
    `log_audit_event` call every other write action already uses — no
    new audit mechanism, just a new caller. The Audit Log page renders
    these with an accent-colored left border and action text, and
    "deploy.sh (server)" in place of an actor, since these have no
    logged-in human behind them and would otherwise be confusingly
    indistinguishable from a real local/CLI action.
- **5.24.4**:
  - **Fixed `gnome-keyring-daemon` processes piling up across restarts
    on the hosted server.** `server/start-headless.sh` ran `--unlock
    --login` on every start/restart, but `--login` is a one-time
    PAM-style invocation that never fully initializes and has no
    corresponding teardown — confirmed live, a daemon from over a week
    prior was still running untouched, with more added on every
    subsequent restart. Now kills any stray daemon for this user first;
    safe since this box has no desktop session, so this script is the
    only thing that ever starts one.
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
