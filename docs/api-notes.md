# API notes and tenant behavior

Live-verified OPA/Okta API quirks found during development of this
project — things the official docs don't mention, or get wrong. Useful
reference if you're extending this project or debugging a surprising
API response. See [features.md](features.md) for how this project uses
these APIs day-to-day.

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
   [Access Explorer](features.md#access-explorer)).

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

17. **Service-account events (SaaS app / Okta UD / database / AD) all
    share one target type and the same reveal/rotation eventTypes —
    the account family is only in `debugContext.debugData`.** Confirmed
    2026-10-07 by a read-only probe of a real compliance archive
    (~130k rows across these families, two environments), which is what
    the Service Accounts Dashboard (v5.40.0) is built on:
    - `pam.service_account.create`, `.update`, `.delete`, `.assign`,
      `.password.reveal`, `.password_rotation.start` and
      `.password_rotation.end` all exist with real payloads. The account
      is `target[0]` with `type: "Service Account"`, a 36-character uuid
      `id` that equals its `alternateId` — and equals the account's own
      `id` from the project `saas_app_accounts` /
      `okta_universal_directory_accounts` lists (the
      `access_tracking_id` the Access Explorer already indexes). The
      Okta-side ids (`privileged_resource_id` / `okta_user_id`) are
      never logged as targets. There is **no project co-target** on any
      of them (secrets events do carry one), so a deleted account's
      project cannot be recovered from the log.
    - `debugData.serviceAccountType` names the family on every
      `pam.service_account.*` event: `APP_ACCOUNT` (SaaS app),
      `OKTA_USER_ACCOUNT` (Okta UD), `DATABASE_ACCOUNT`,
      `PAM_AD_ACCOUNT` — the same two strings the staged-accounts API
      uses for `account_type`. Seen empty (`""`) once, on an update
      event, so code must not require it.
    - `pam.resource.checkout` carries the same account id as
      `target[1]` (after the Team) but has **no** `serviceAccountType`;
      `debugData.resourceType` is the discriminator there —
      `MANAGED_SAAS_APP_SERVICE_ACCOUNT` (SaaS), `PAM_DATABASE_ACCOUNT`,
      `SERVER_ACCOUNT`. No Okta UD checkout has been observed, so its
      `resourceType` value is unconfirmed and deliberately not coded.
    - `password_rotation.end` is by far the highest-volume PAM event —
      ~115k rows in the probed archive, ~83k of them Active Directory
      accounts, up to ~17k for a single account — with outcomes
      `SUCCESS` / `FAILURE` / `DEFERRED` (FAILURE rows carry
      `outcome.reason`), `debugData["system Initiated"]` as the literal
      strings `"Yes"` / `"No"` (note the space in the key), and
      `versionId` on most rows. `.start` fires far less often than
      `.end` and carries no outcome. `create` can also end `DEFERRED`
      or `FAILURE` and be retried under the same account id, so "when
      was it created" must prefer the successful attempt.
    - After assigning a staged account to a project, an Okta UD account
      rotates immediately (`status_detail: ROTATED`, `sync_status:
      SYNCED`) but a SaaS account registered through a bare
      `POST /privileged-access/api/v1/service-accounts` stayed
      `UNMANAGED` / `NOT_SYNCED` on two separate runs, while other SaaS
      accounts in the same org showed `ROTATED` / `SYNCED`. Not
      root-caused — which is why the dashboard shows `sync_status` as
      informational context and never as a compliance finding.

## Idempotency

Existing folders are detected by recursively walking the full folder
tree (`fetch_all_folders`, one API call per folder — see constraint #2
above) and matching by name (safe given constraint #1). Re-running the
CLI/dashboard with the same CSV is safe at every depth — anything that
already exists is skipped, not duplicated.

