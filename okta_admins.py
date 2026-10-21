"""Okta Admins report, Okta lifecycle cross-check and the Overview counts (5.50.0).

Everything here is READ-ONLY against Okta and sits on top of the chained
configuration snapshots in audit_store (record_config_snapshot): a capture
reads Okta once, stores one snapshot (sealed into the evidence chain) and the
report is computed from the stored snapshot, never from a live call, so
"as of the audit date" is the same code path as "now".

Two snapshot kinds:
  okta_admins            who holds an Okta admin role (USER principals only; groups
                         and OAuth clients that hold roles come in a later release),
                         with role targets, time-bound grants, the custom roles and
                         resource sets that exist.
  opa_principal_status   the Okta status of every OPA principal and Okta-UD service
                         account (lifecycle cross-check C1).

Privacy rules, enforced at capture: a user object keeps id, status, login, email and
first/last name only -- `credentials` and every other profile attribute are never read
into a snapshot. Tokens never appear in a snapshot, a log line or a message here.

The Okta role the token needs is named in MISSING_ROLES_MESSAGE; when Okta refuses a
read (E0000006 / HTTP 403) the capture records the refusal as a snapshot of status
"refused" and the report says so plainly instead of showing an empty list."""
import json
import urllib.parse
from datetime import datetime, timedelta, timezone

import audit_store

KIND_ADMINS = "okta_admins"
KIND_PRINCIPAL_STATUS = "opa_principal_status"

MISSING_ROLES_MESSAGE = (
    "Your Okta token cannot read admin role assignments; this report needs a token whose admin can view roles and "
    "admin assignments (for example a custom admin role with that permission, or Super Administrator)."
)
MISSING_USERS_MESSAGE = (
    "Your Okta token cannot read users; the lifecycle cross-check needs a token whose admin can view users "
    "(for example Read-only Administrator, or a custom admin role with that permission)."
)

# A role label is a plain-English name; the Okta type is what the report keys on.
GROUP_SCOPED_ROLES = ("USER_ADMIN", "HELP_DESK_ADMIN", "GROUP_MEMBERSHIP_ADMIN")
APP_SCOPED_ROLES = ("APP_ADMIN",)
# Roles that can change who has access to everything else; informational ordering for the screen.
HIGHEST_ROLES = ("SUPER_ADMIN", "ORG_ADMIN")

MAX_ADMINS = 2000        # one capture reads at most this many admin users (the rest are counted, not read)
MAX_PRINCIPALS = 5000    # one cross-check reads at most this many OPA principals
GRANT_EVENT_TYPES = ("user.account.privilege.grant", "user.account.privilege.revoke")
PRIVILEGE_EVENTS_LIMIT = 5000
OPA_ADMIN_ROLE_NAMES = ("pam_admin", "resource_admin", "delegated_resource_admin")


def _now():
    return datetime.now(timezone.utc)


def _iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


# ---------------------------------------------------------------------------
# Okta error classification
# ---------------------------------------------------------------------------
def error_code(exc):
    """The Okta errorCode (E0000006 ...) in an OktaApiError body, or None."""
    body = getattr(exc, "body", None)
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except ValueError:
            return None
    if isinstance(body, dict):
        code = body.get("errorCode")
        return code if isinstance(code, str) and len(code) <= 32 else None
    return None


def is_refused(exc):
    """True when Okta refused the call for lack of permission (E0000006 /
    HTTP 403), as opposed to a transport failure or a bad token."""
    status = str(getattr(exc, "status", ""))
    if error_code(exc) == "E0000015":
        return False  # "feature not enabled" also arrives as a 403; it is not a permission problem
    return error_code(exc) == "E0000006" or status == "403"


def is_feature_off(exc):
    """E0000015: the org does not have the feature (governance) enabled."""
    return error_code(exc) == "E0000015"


def is_not_found(exc):
    return str(getattr(exc, "status", "")) == "404" or error_code(exc) == "E0000007"


def _classify(exc):
    if is_refused(exc):
        return "refused"
    if is_feature_off(exc):
        return "feature_off"
    if is_not_found(exc):
        return "not_found"
    return "error"


def _part_error(part, exc):
    return {"part": part, "state": _classify(exc), "error_code": error_code(exc), "status": str(getattr(exc, "status", ""))[:12]}


# ---------------------------------------------------------------------------
# Capture: Okta admins
# ---------------------------------------------------------------------------
def _clean_user(raw):
    """id, status, login, email, name -- nothing else. `credentials` and
    every other attribute of an Okta user object are dropped here."""
    if not isinstance(raw, dict):
        return {}
    profile = raw.get("profile") if isinstance(raw.get("profile"), dict) else {}

    def text(value):
        return value if isinstance(value, str) else None

    return {
        "id": text(raw.get("id")), "status": text(raw.get("status")),
        "login": text(profile.get("login")), "email": text(profile.get("email")),
        "first_name": text(profile.get("firstName")), "last_name": text(profile.get("lastName")),
    }


def _clean_role(raw):
    if not isinstance(raw, dict):
        return None
    out = {k: raw.get(k) if isinstance(raw.get(k), str) else None
           for k in ("id", "label", "type", "status", "assignmentType", "created", "lastUpdated")}
    if raw.get("type") == "CUSTOM":
        out["custom_role_id"] = raw.get("role") if isinstance(raw.get("role"), str) else None
        out["resource_set_id"] = raw.get("resource-set") if isinstance(raw.get("resource-set"), str) else None
    return out if out["id"] else None


def _clean_group_target(raw):
    if not isinstance(raw, dict):
        return None
    profile = raw.get("profile") if isinstance(raw.get("profile"), dict) else {}
    return {"id": raw.get("id") if isinstance(raw.get("id"), str) else None,
            "name": profile.get("name") if isinstance(profile.get("name"), str) else None}


def _clean_app_target(raw):
    if not isinstance(raw, dict):
        return None
    return {k: raw.get(k) if isinstance(raw.get(k), str) else None for k in ("id", "name", "displayName", "status")}


def _clean_governance(raw):
    grants = []
    for g in (raw.get("grants") if isinstance(raw, dict) and isinstance(raw.get("grants"), list) else []):
        if not isinstance(g, dict):
            continue
        expires = audit_store._canonical_published(str(g["expirationDate"]).replace(" ", "T")) if g.get("expirationDate") else None
        grants.append({
            "type": g.get("type") if isinstance(g.get("type"), str) else None,
            "grant_id": g.get("grantId") if isinstance(g.get("grantId"), str) else None,
            "bundle_id": g.get("bundleId") if isinstance(g.get("bundleId"), str) else None,
            "expires": expires,
        })
    return sorted(grants, key=lambda g: (g["grant_id"] or "", g["type"] or ""))


def capture_okta_admins(okta_client, max_admins=MAX_ADMINS):
    """Reads Okta and returns {"status", "items", "meta", "source_endpoint"}
    ready for audit_store.record_config_snapshot. status:
      ok       the admin list was read (parts that could not be read are in meta["unreadable"])
      refused  Okta refused the admin list itself (E0000006 / 403): nothing was read
      error    any other failure reading the admin list (network, invalid token, bad response)
    Never raises for an Okta/transport error; the caller records whatever this returns."""
    from create_secret_folders import OktaApiError
    meta = {"unreadable": [], "governance": "unknown", "admins_total": 0, "admins_read": 0}
    source = "/api/v1/iam/assignees/users"
    try:
        assignees = okta_client.list_users_with_role_assignments(limit_total=max_admins + 1)
    except OktaApiError as exc:
        state = _classify(exc)
        meta.update({"error_code": error_code(exc), "endpoint": source, "http_status": str(exc.status)[:12]})
        return {"status": "refused" if state == "refused" else "error", "items": [], "meta": meta, "source_endpoint": source}
    ids, seen = [], set()
    for entry in assignees:
        uid = entry.get("id") if isinstance(entry, dict) else None
        if isinstance(uid, str) and uid and uid not in seen:
            seen.add(uid)
            ids.append(uid)
    meta["admins_total"] = len(ids)
    if len(ids) > max_admins:
        meta["truncated"] = True
        ids = ids[:max_admins]
    items = []
    governance_state = "unknown"  # unknown -> enabled | not_enabled | refused (decided on the first assignment)
    from create_secret_folders import checkpoint
    for uid in ids:
        checkpoint()  # 5.51.0: between admins, so a Stop (or a deadline) is noticed within a call or two
        user = {"id": uid}
        try:
            user = _clean_user(okta_client.get_user(uid)) or {"id": uid}
            user["id"] = user.get("id") or uid
        except OktaApiError as exc:
            meta["unreadable"].append({**_part_error("user_profile", exc), "id": uid})
        roles = []
        try:
            raw_roles = okta_client.list_user_roles(uid)
        except OktaApiError as exc:
            meta["unreadable"].append({**_part_error("user_roles", exc), "id": uid})
            raw_roles = []
        for raw in raw_roles:
            role = _clean_role(raw)
            if role is None:
                continue
            try:
                if role["type"] in GROUP_SCOPED_ROLES:
                    role["targets"] = {"groups": sorted(
                        (t for t in map(_clean_group_target, okta_client.list_role_group_targets(uid, role["id"])) if t and t["id"]),
                        key=lambda t: t["id"])}
                elif role["type"] in APP_SCOPED_ROLES:
                    role["targets"] = {"apps": sorted(
                        (t for t in map(_clean_app_target, okta_client.list_role_app_targets(uid, role["id"])) if t),
                        key=lambda t: (t["name"] or "", t["id"] or ""))}
            except OktaApiError as exc:
                role["targets"] = None
                meta["unreadable"].append({**_part_error("role_targets", exc), "id": uid, "role_id": role["id"]})
            if governance_state in ("unknown", "enabled"):
                try:
                    role["grants"] = _clean_governance(okta_client.get_role_governance(uid, role["id"]))
                    governance_state = "enabled"
                except OktaApiError as exc:
                    kind = _classify(exc)
                    if kind == "feature_off" or kind == "not_found":
                        governance_state = "not_enabled"  # E0000015: the org does not use governance; stop asking
                    elif kind == "refused":
                        governance_state = "refused"
                    else:
                        meta["unreadable"].append({**_part_error("role_governance", exc), "id": uid, "role_id": role["id"]})
            roles.append(role)
        roles.sort(key=lambda r: (r["type"] or "", r["id"]))
        items.append((f"user:{uid}", {"kind": "user", **user, "roles": roles}))
    meta["governance"] = governance_state
    meta["admins_read"] = len(items)
    # Custom roles and the resource sets they are bound to (definitions, not assignments).
    try:
        for role in okta_client.list_custom_roles():
            rid = role.get("id") if isinstance(role, dict) else None
            if not isinstance(rid, str) or not rid:
                continue
            obj = {"kind": "custom_role", "id": rid, "label": role.get("label"), "description": role.get("description"),
                   "created": role.get("created"), "lastUpdated": role.get("lastUpdated"), "permissions": None}
            try:
                perms = okta_client.list_custom_role_permissions(rid)
                obj["permissions"] = sorted(p.get("label") for p in perms if isinstance(p, dict) and isinstance(p.get("label"), str))
            except OktaApiError as exc:
                meta["unreadable"].append({**_part_error("custom_role_permissions", exc), "id": rid})
            items.append((f"custom_role:{rid}", obj))
    except OktaApiError as exc:
        meta["unreadable"].append(_part_error("custom_roles", exc))
    try:
        for rs in okta_client.list_resource_sets():
            rid = rs.get("id") if isinstance(rs, dict) else None
            if isinstance(rid, str) and rid:
                items.append((f"resource_set:{rid}", {"kind": "resource_set", "id": rid, "label": rs.get("label"),
                                                      "description": rs.get("description"),
                                                      "created": rs.get("created"), "lastUpdated": rs.get("lastUpdated")}))
    except OktaApiError as exc:
        meta["unreadable"].append(_part_error("resource_sets", exc))
    # Everything stored is sorted for a stable diff; the list of problems is capped.
    meta["unreadable"] = meta["unreadable"][:200]
    return {"status": "ok", "items": items, "meta": meta, "source_endpoint": source}


def capture_and_store(environment_id, okta_client, kind=KIND_ADMINS, captured_at=None, **capture_args):
    """Capture + record. Returns the stored snapshot dict (see
    audit_store.record_config_snapshot)."""
    if kind != KIND_ADMINS:
        raise ValueError(f"unknown snapshot kind {kind!r}")
    result = capture_okta_admins(okta_client, **capture_args)
    return audit_store.record_config_snapshot(
        environment_id, kind, result["items"], status=result["status"], source_endpoint=result["source_endpoint"],
        meta=result["meta"], captured_at=captured_at,
    )


AUTO_CAPTURE_MIN_INTERVAL = timedelta(hours=6)
AUTO_CAPTURE_RETRY_AFTER_FAILURE = timedelta(hours=24)  # a token that cannot read roles is not asked again every six hours


def capture_if_due(environment_id, okta_client, now=None):
    """The automatic capture after a sync: skipped when a capture of any status
    (a refusal included) was recorded in the last AUTO_CAPTURE_MIN_INTERVAL, so
    a busy 'Sync now' button cannot hammer Okta's role endpoints. After a refused or
    failed attempt the wait is 24 hours (the first refusal is sealed as evidence; a
    token that cannot read roles would otherwise add a snapshot, a manifest and an
    audit row four times a day). A manual capture (capture_and_store) is never held
    back. Returns the snapshot or None."""
    stamped = _iso(now) if now is not None else None  # a caller-supplied clock stamps the capture too
    now = now or _now()
    last = audit_store.list_config_snapshots(environment_id, kind=KIND_ADMINS, limit=1)
    if last:
        taken = audit_store._canonical_published(last[0]["captured_at"])
        wait = AUTO_CAPTURE_MIN_INTERVAL if last[0]["status"] == "ok" else AUTO_CAPTURE_RETRY_AFTER_FAILURE
        if taken and taken > _iso(now - wait):
            return None
    return capture_and_store(environment_id, okta_client, captured_at=stamped)


# ---------------------------------------------------------------------------
# OPA side: who holds an OPA admin role (for separation of duties)
# ---------------------------------------------------------------------------
def _norm(value):
    return value.strip().lower() if isinstance(value, str) and value.strip() else None


def is_powerful_opa_role(role):
    """An OPA team role that can administer the vault or its policies: the
    three named admin roles, or any role whose name ends in `admin`."""
    r = (role or "").strip().lower()
    return r in OPA_ADMIN_ROLE_NAMES or r.endswith("admin")


def opa_role_index(model):
    """{"state": "ok"|"not_loaded"|"partial", "users": [{id, name, email, user_type, roles, powerful_roles, via_groups}]}
    from the access model: a user's OPA roles are the union of the `roles` of
    the groups they belong to, plus `delegated_resource_admin` for every
    resource group that names one of their groups as a delegated admin group."""
    if not isinstance(model, dict) or not isinstance(model.get("users"), list):
        return {"state": "not_loaded", "users": []}
    groups = {g.get("id"): g for g in model.get("groups") or [] if isinstance(g, dict)}
    delegated = {}
    for rg in model.get("resource_groups") or []:
        if isinstance(rg, dict):
            for g in rg.get("delegated_resource_admin_groups") or []:
                if isinstance(g, dict) and g.get("id"):
                    delegated.setdefault(g["id"], []).append(rg.get("name"))
    out, partial = [], False
    for user in model["users"]:
        if not isinstance(user, dict):
            continue
        roles, via = set(), {}
        for ref in user.get("groups") or []:
            gid = ref.get("id") if isinstance(ref, dict) else None
            group = groups.get(gid) or {}
            for role in group.get("roles") or []:
                if isinstance(role, str):
                    roles.add(role)
                    via.setdefault(role, []).append(group.get("name") or ref.get("name"))
            if gid in delegated:
                roles.add("delegated_resource_admin")
                via.setdefault("delegated_resource_admin", []).append(group.get("name") or ref.get("name"))
        if user.get("groups_error"):
            partial = True
        details = user.get("details") if isinstance(user.get("details"), dict) else {}
        out.append({
            "id": user.get("id"), "name": user.get("name"), "email": details.get("email"),
            "user_type": user.get("user_type"), "groups_error": bool(user.get("groups_error")),
            "roles": sorted(roles), "powerful_roles": sorted(r for r in roles if is_powerful_opa_role(r)),
            "via_groups": {r: sorted(set(g for g in v if g)) for r, v in via.items() if is_powerful_opa_role(r)},
        })
    return {"state": "partial" if partial else "ok", "users": out}


def separation_of_duties(okta_users, opa_index):
    """Okta admins who are also OPA principals with an OPA admin role. `okta_users`
    are the user items of an okta_admins snapshot. A match is login/email equality
    (case-insensitive) between the Okta user and the OPA user's name or e-mail --
    the only link the two products share; a candidate for review, not a finding."""
    if opa_index["state"] == "not_loaded":
        return {"state": "not_loaded", "overlaps": [], "checked": 0}
    by_key = {}
    for u in opa_index["users"]:
        for key in (_norm(u["name"]), _norm(u["email"])):
            if key:
                by_key.setdefault(key, u)
    overlaps = []
    for ou in okta_users:
        okta_roles = sorted({r["type"] for r in ou.get("roles") or [] if r.get("type")})
        if not okta_roles:
            continue
        match = None
        for key in (_norm(ou.get("login")), _norm(ou.get("email"))):
            if key and key in by_key:
                match = by_key[key]
                break
        if match and match["powerful_roles"]:
            overlaps.append({
                "okta_user_id": ou.get("id"), "login": ou.get("login"), "okta_roles": okta_roles,
                "opa_user_id": match["id"], "opa_user_name": match["name"],
                "opa_roles": match["powerful_roles"], "via_groups": match["via_groups"],
            })
    overlaps.sort(key=lambda o: (o["login"] or "", o["okta_user_id"] or ""))
    return {"state": opa_index["state"], "overlaps": overlaps, "checked": len(okta_users)}


# ---------------------------------------------------------------------------
# The report
# ---------------------------------------------------------------------------
def _privilege_overlay(environment_id, since=None, until=None):
    """{okta_user_id: [{type, published, role, by}]} newest first, from the
    archive's grant/revoke events, plus a coverage note."""
    rows = audit_store.query_events(environment_id, event_types=list(GRANT_EVENT_TYPES), since=since, until=until,
                                    limit=PRIVILEGE_EVENTS_LIMIT)
    out = {}
    for row in rows:
        raw = row["raw"] if isinstance(row.get("raw"), dict) else {}
        targets = [t for t in (raw.get("target") or []) if isinstance(t, dict)]
        user = next((t for t in targets if t.get("type") == "User"), None)
        role = next((t for t in targets if t.get("type") == "ROLE"), None)
        if not user or not isinstance(user.get("id"), str) or not user["id"]:
            continue
        actor = raw.get("actor") if isinstance(raw.get("actor"), dict) else {}
        out.setdefault(user["id"], []).append({
            "type": "grant" if row["event_type"].endswith(".grant") else "revoke",
            "published": row["published"], "role": (role or {}).get("displayName"),
            "by": actor.get("alternateId") or actor.get("displayName"),
        })
    return out, len(rows) >= PRIVILEGE_EVENTS_LIMIT


def _snapshot_summary(snap):
    return None if snap is None else {k: snap[k] for k in ("snapshot_id", "captured_at", "status", "item_count", "sha256")}


def build_okta_admins_report(environment_id, as_of=None, access_model=None, now=None):
    """The Okta Admins report as of a date (default: the newest snapshot).

    state:
      never_captured  no capture has been attempted for this environment
      refused         the newest attempt (and no earlier success) was refused by Okta -> `message`
      error           the newest attempt failed for another reason and there is no earlier success
      ok              there is a successful snapshot (`as_of_snapshot`); if a NEWER attempt was refused
                      or failed it is reported in `last_attempt` and `message` (the data shown is older)
    """
    now = now or _now()
    attempts = audit_store.list_config_snapshots(environment_id, kind=KIND_ADMINS, limit=1)
    snap = audit_store.latest_config_snapshot(environment_id, KIND_ADMINS, as_of=as_of)
    base = {"as_of": as_of, "generated_at": _iso(now), "admins": [], "rows": [], "custom_roles": [], "resource_sets": [],
            "summary": {}, "separation_of_duties": {"state": "not_loaded", "overlaps": [], "checked": 0}, "notes": []}
    last_attempt = None
    if attempts:
        a = attempts[0]
        last_attempt = {"snapshot_id": a["snapshot_id"], "captured_at": a["captured_at"], "status": a["status"],
                        "error_code": (a.get("meta") or {}).get("error_code")}
    if snap is None:
        if last_attempt is None:
            return {**base, "state": "never_captured", "message": "No capture of the Okta admin list has been taken for this environment yet.",
                    "last_attempt": None, "as_of_snapshot": None}
        if last_attempt["status"] == "refused":
            return {**base, "state": "refused", "message": MISSING_ROLES_MESSAGE, "last_attempt": last_attempt, "as_of_snapshot": None}
        if as_of and last_attempt["status"] == "ok":
            return {**base, "state": "no_snapshot_for_date", "last_attempt": last_attempt, "as_of_snapshot": None,
                    "message": "There is no snapshot taken on or before that date."}
        return {**base, "state": "error", "last_attempt": last_attempt, "as_of_snapshot": None,
                "message": "The last capture failed before the admin list could be read. Check the Okta token and try again."}

    items = snap["items"]
    users = [i["object"] for i in items if isinstance(i["object"], dict) and i["object"].get("kind") == "user"]
    custom_roles = [i["object"] for i in items if isinstance(i["object"], dict) and i["object"].get("kind") == "custom_role"]
    resource_sets = [i["object"] for i in items if isinstance(i["object"], dict) and i["object"].get("kind") == "resource_set"]
    meta = snap.get("meta") or {}
    previous = _previous_ok_snapshot(environment_id, snap)
    prev_users = {}
    if previous:
        prev_users = {i["key"]: i["object"] for i in previous["items"] if i["key"].startswith("user:") and isinstance(i["object"], dict)}
    overlay, overlay_truncated = _privilege_overlay(environment_id, until=snap["captured_at"])
    coverage = audit_store.archive_coverage(environment_id)
    oldest = coverage.get("oldest")
    cr_by_id = {c["id"]: c for c in custom_roles}
    rs_by_id = {r["id"]: r for r in resource_sets}

    rows = []
    for u in users:
        events = overlay.get(u.get("id"), [])
        for role in u.get("roles") or []:
            created = role.get("created")
            if events:
                evidence = "event"
            elif oldest and created and created < oldest:
                evidence = "predates_archive"
            else:
                evidence = "none_in_archive"
            grant_events = [e for e in events if e["type"] == "grant"]
            custom = cr_by_id.get(role.get("custom_role_id")) if role.get("type") == "CUSTOM" else None
            rset = rs_by_id.get(role.get("resource_set_id")) if role.get("type") == "CUSTOM" else None
            targets = role.get("targets") or {}
            grants = role.get("grants") or []
            expiring = [g["expires"] for g in grants if g.get("expires")]
            rows.append({
                "okta_user_id": u.get("id"), "login": u.get("login"), "email": u.get("email"),
                "name": " ".join(p for p in (u.get("first_name"), u.get("last_name")) if p) or None,
                "user_status": u.get("status"),
                "role_assignment_id": role.get("id"), "role_type": role.get("type"), "role_label": role.get("label"),
                "assignment_type": role.get("assignmentType"), "role_status": role.get("status"),
                "assigned_at": created,
                "custom_role": (custom or {}).get("label") if custom else None,
                "custom_role_permissions": (custom or {}).get("permissions") if custom else None,
                "resource_set": (rset or {}).get("label") if rset else None,
                "target_groups": [t.get("name") or t.get("id") for t in targets.get("groups") or []],
                "target_apps": [t.get("displayName") or t.get("name") or t.get("id") for t in targets.get("apps") or []],
                "scope": ("groups" if "groups" in targets else "apps" if "apps" in targets else "org-wide"
                          if role.get("type") in HIGHEST_ROLES else "unscoped"),
                "time_bound": bool(expiring), "expires": min(expiring) if expiring else None,
                "granted_evidence": evidence,
                "last_grant_event": grant_events[0] if grant_events else None,
                "status": "active",
            })
    # removed: present in the previous snapshot, absent now
    now_ids = {u.get("id") for u in users}
    for key, pu in prev_users.items():
        if pu.get("id") not in now_ids:
            for role in pu.get("roles") or [{}]:
                events = overlay.get(pu.get("id"), [])
                revokes = [e for e in events if e["type"] == "revoke"]
                rows.append({
                    "okta_user_id": pu.get("id"), "login": pu.get("login"), "email": pu.get("email"),
                    "name": " ".join(p for p in (pu.get("first_name"), pu.get("last_name")) if p) or None,
                    "user_status": pu.get("status"), "role_assignment_id": role.get("id"), "role_type": role.get("type"),
                    "role_label": role.get("label"), "assignment_type": role.get("assignmentType"), "role_status": role.get("status"),
                    "assigned_at": role.get("created"), "custom_role": None, "custom_role_permissions": None, "resource_set": None,
                    "target_groups": [], "target_apps": [], "scope": None, "time_bound": False, "expires": None,
                    "granted_evidence": "event" if events else "none_in_archive", "last_grant_event": None,
                    "last_revoke_event": revokes[0] if revokes else None,
                    "status": "removed", "removed_between": [previous["captured_at"], snap["captured_at"]],
                })
    # unknown: privilege events name a user who is in no snapshot at all
    known_ever = set(now_ids) | {pu.get("id") for pu in prev_users.values()}
    for uid, events in overlay.items():
        if uid in known_ever:
            continue
        latest = events[0]
        rows.append({
            "okta_user_id": uid, "login": None, "email": None, "name": None, "user_status": None,
            "role_assignment_id": None, "role_type": None, "role_label": latest.get("role"),
            "assignment_type": None, "role_status": None, "assigned_at": None, "custom_role": None,
            "custom_role_permissions": None, "resource_set": None, "target_groups": [], "target_apps": [], "scope": None,
            "time_bound": False, "expires": None, "granted_evidence": "event",
            "last_grant_event": latest if latest["type"] == "grant" else None,
            "last_revoke_event": latest if latest["type"] == "revoke" else None,
            "status": "unknown",
        })
    rows.sort(key=lambda r: ({"active": 0, "removed": 1, "unknown": 2}[r["status"]], (r["login"] or r["okta_user_id"] or "").lower(), r["role_type"] or ""))
    role_counts = {}
    for r in rows:
        if r["status"] == "active":
            role_counts[r["role_type"]] = role_counts.get(r["role_type"], 0) + 1
    index = opa_role_index(access_model)
    sod = separation_of_duties(users, index)
    state_message = None
    if last_attempt and last_attempt["snapshot_id"] != snap["snapshot_id"] and last_attempt["status"] != "ok" \
            and (not as_of or last_attempt["captured_at"] <= (audit_store.normalize_window(None, as_of)[1] or "")):
        state_message = MISSING_ROLES_MESSAGE if last_attempt["status"] == "refused" else \
            "The most recent capture failed; this report shows the last successful snapshot."
    notes = []
    for problem in (meta.get("unreadable") or []):
        part = problem.get("part")
        if problem.get("state") == "refused" and part not in ("user_roles", "user_profile"):
            notes.append(f"{part.replace('_', ' ')} could not be read with this token ({problem.get('error_code') or 'refused'}).")
    if meta.get("truncated"):
        notes.append(f"More than {MAX_ADMINS} users hold roles; only the first {MAX_ADMINS} were read.")
    if meta.get("governance") == "not_enabled":
        notes.append("Time-bound (governance) admin access is not enabled in this org, so every assignment is standing.")
    elif meta.get("governance") == "refused":
        notes.append("This token cannot read governance grants, so time-bound access is not shown.")
    if overlay_truncated:
        notes.append(f"Only the newest {PRIVILEGE_EVENTS_LIMIT} privilege events were used for the overlay.")
    if sod["state"] == "not_loaded":
        notes.append("The OPA roster has not been loaded, so separation of duties is unknown. Open the Access Explorer once, then reload this report.")
    elif sod["state"] == "partial":
        notes.append("Some OPA users' group lists could not be read, so separation of duties may be incomplete.")
    notes.append("Admins who hold a role only through a group, and OAuth service apps with roles, are not listed yet "
                 "(this report covers users with a direct role assignment).")
    return {
        **base, "state": "ok", "message": state_message, "as_of_snapshot": _snapshot_summary(snap),
        "previous_snapshot": _snapshot_summary(previous), "last_attempt": last_attempt,
        "admins": [{"okta_user_id": u.get("id"), "login": u.get("login"), "email": u.get("email"), "user_status": u.get("status"),
                    "role_types": sorted({r["type"] for r in u.get("roles") or [] if r.get("type")})} for u in users],
        "rows": rows, "custom_roles": custom_roles, "resource_sets": resource_sets,
        "summary": {"admins": len(users), "assignments": sum(len(u.get("roles") or []) for u in users),
                    "removed": sum(1 for r in rows if r["status"] == "removed"),
                    "unknown": sum(1 for r in rows if r["status"] == "unknown"),
                    "time_bound": sum(1 for r in rows if r["time_bound"]), "by_role": role_counts,
                    "sod_overlaps": len(sod["overlaps"])},
        "separation_of_duties": sod, "notes": notes,
        "archive": {"oldest_event": oldest, "scope": coverage.get("ingestion_scope")},
    }


def _previous_ok_snapshot(environment_id, snap):
    older = [s for s in audit_store.list_config_snapshots(environment_id, kind=KIND_ADMINS, limit=200)
             if s["status"] == "ok" and (s["captured_at"], s["snapshot_id"]) < (snap["captured_at"], snap["snapshot_id"])]
    return audit_store.get_config_snapshot(environment_id, older[0]["snapshot_id"]) if older else None


# ---------------------------------------------------------------------------
# Lifecycle cross-check C1: the Okta status of every OPA principal
# ---------------------------------------------------------------------------
def opa_principals(model, limit=MAX_PRINCIPALS):
    """The OPA people and Okta-UD service accounts to look up in Okta:
    [{key, source, name, lookup}] -- humans by login/e-mail, Okta-UD accounts by
    their Okta user id. OPA-native service users have no Okta identity and are
    left out (counted in the return as `skipped_service_users`)."""
    principals, skipped = [], 0
    if not isinstance(model, dict):
        return principals, skipped
    for u in model.get("users") or []:
        if not isinstance(u, dict):
            continue
        if u.get("user_type") == "service":
            skipped += 1
            continue
        details = u.get("details") if isinstance(u.get("details"), dict) else {}
        # GET /api/v1/users/{x} matches Okta's profile.login (or an id), not the e-mail. An Okta-provisioned OPA user's name is
        # the Okta login, so the login is tried first and the e-mail only when the login finds nothing.
        keys = []
        for kind, value in (("login", u.get("name")), ("email", details.get("email"))):
            if isinstance(value, str) and value.strip() and value.strip() not in [k["value"] for k in keys]:
                keys.append({"kind": kind, "value": value.strip()})
        if keys:
            principals.append({"key": f"opa_user:{u.get('id')}", "source": "opa_user", "opa_id": u.get("id"),
                               "name": u.get("name"), "email": details.get("email"), "lookup": keys[0]["value"], "lookup_keys": keys})
    for a in model.get("okta_accounts") or []:
        if isinstance(a, dict) and isinstance(a.get("okta_user_id"), str) and a["okta_user_id"]:
            principals.append({"key": f"okta_ud_account:{a.get('id')}", "source": "okta_ud_account", "opa_id": a.get("id"),
                               "name": a.get("name") or a.get("username"), "email": None, "lookup": a["okta_user_id"], "okta_lookup_id": a["okta_user_id"],
                               "lookup_keys": [{"kind": "id", "value": a["okta_user_id"]}],
                               "project": a.get("project_name")})
    return principals[:limit], skipped


def capture_principal_status(okta_client, model, limit=MAX_PRINCIPALS):
    """Looks every principal up in Okta (GET /api/v1/users/{id|login}) and
    returns {"status","items","meta","source_endpoint"} for record_config_snapshot.
    Item state: the Okta `status` string, "ABSENT" (404), or "UNREADABLE". A token
    that cannot read users at all records status "refused" and no items."""
    from create_secret_folders import OktaApiError
    principals, skipped = opa_principals(model, limit)
    meta = {"principals": len(principals), "skipped_service_users": skipped, "unreadable": 0, "truncated": False}
    items = []
    from create_secret_folders import checkpoint
    for p in principals:
        checkpoint()  # 5.51.0: between principals
        entry = {k: p.get(k) for k in ("source", "opa_id", "name", "email", "project", "okta_lookup_id")}
        tried, found, failure = [], None, None
        for key in p.get("lookup_keys") or [{"kind": "login", "value": p["lookup"]}]:
            tried.append(key)
            try:
                found = okta_client.get_user(key["value"])
                break
            except OktaApiError as exc:
                kind = _classify(exc)
                if kind == "not_found":
                    continue  # try the next key (the e-mail after the login)
                failure = (kind, exc)
                break
        entry["lookup_keys"] = tried
        if found is not None:
            user = _clean_user(found)
            changed = found.get("statusChanged") if isinstance(found, dict) and isinstance(found.get("statusChanged"), str) else None
            entry.update({"okta_state": user.get("status") or "UNREADABLE", "okta_id": user.get("id"), "okta_login": user.get("login"),
                          "okta_status_changed": changed})
        elif failure is None:
            entry.update({"okta_state": "ABSENT", "okta_id": None, "okta_login": None})
        else:
            kind, exc = failure
            if kind == "refused" and not items:
                meta.update({"error_code": error_code(exc)})
                return {"status": "refused", "items": [], "meta": meta, "source_endpoint": "/api/v1/users/{id}"}
            meta["unreadable"] += 1
            entry.update({"okta_state": "UNREADABLE", "okta_id": None, "okta_login": None})
        items.append((p["key"], entry))
    return {"status": "ok", "items": items, "meta": meta, "source_endpoint": "/api/v1/users/{id}"}


# Okta user statuses that mean "this person cannot sign in to Okta now".
INACTIVE_OKTA_STATES = ("DEPROVISIONED", "SUSPENDED")
SIGNIN_CAPABLE = ("ACTIVE", "PROVISIONED", "RECOVERY", "PASSWORD_EXPIRED", "LOCKED_OUT", "STAGED")


def effective_access(model):
    """What OPA access still resolves, for cross-check C1: ({opa_user_id: {"groups", "policies", "resources"}},
    {okta_user_id: {"policies"}}) from the access model, or None when it is not loaded. A user has effective access
    when an ACTIVE policy names one of their groups and has at least one rule that resolves to a specific resource;
    an Okta service account when an active policy resolves to it."""
    if not isinstance(model, dict) or not isinstance(model.get("policies"), list):
        return None
    pols = []
    for p in model["policies"]:
        if not isinstance(p, dict) or not p.get("active"):
            continue
        principals = p.get("principals") if isinstance(p.get("principals"), dict) else {}
        gids = {g.get("id") for g in principals.get("user_groups") or [] if isinstance(g, dict) and g.get("id")}
        resolved = [res for r in (p.get("rules") if isinstance(p.get("rules"), list) else []) if isinstance(r, dict)
                    for res in (r.get("resolutions") if isinstance(r.get("resolutions"), list) else [])
                    if isinstance(res, dict) and res.get("kind") == "resolved"]
        if gids and resolved:
            pols.append((gids, resolved))
    users = {}
    for u in model.get("users") or []:
        if not isinstance(u, dict) or not u.get("id"):
            continue
        mine = {g.get("id") for g in u.get("groups") or [] if isinstance(g, dict)}
        hit = [(g, res) for g, res in pols if g & mine]
        if hit:
            users[u["id"]] = {"groups": len(mine & set().union(*(g for g, _ in hit))), "policies": len(hit), "resources": sum(len(res) for _, res in hit)}
    ud = {}
    for a in model.get("okta_accounts") or []:
        if isinstance(a, dict) and isinstance(a.get("okta_user_id"), str):
            n = sum(1 for _g, res in pols if any(r.get("id") in (a["okta_user_id"], a.get("id")) for r in res))
            if n:
                ud[a["okta_user_id"]] = {"policies": n}
    return users, ud


def absent_text(entry):
    """'no Okta user with login X or e-mail Y': the keys the lookup tried."""
    keys = entry.get("lookup_keys") or []
    parts = [f"{'login' if k.get('kind') == 'login' else 'e-mail' if k.get('kind') == 'email' else 'id'} {k.get('value')}" for k in keys if isinstance(k, dict)]
    return "no Okta user with " + " or ".join(parts) if parts else "no Okta user found"


def build_cross_checks(environment_id, access_model=None, now=None):
    """Cross-check cards. C1 'Okta lifecycle vs OPA principals':
    candidates = OPA principals whose Okta user is DEPROVISIONED or SUSPENDED, or
    absent from Okta. Candidates for review, never verdicts: an unknown (not read)
    is its own count. The inputs' timestamps are returned so a stale side says so."""
    now = now or _now()
    attempts = audit_store.list_config_snapshots(environment_id, kind=KIND_PRINCIPAL_STATUS, limit=1)
    snap = audit_store.latest_config_snapshot(environment_id, KIND_PRINCIPAL_STATUS)
    index = opa_role_index(access_model)
    opa_by_id = {u["id"]: u for u in index["users"]}
    card = {"id": "C1", "title": "Okta lifecycle vs OPA principals",
            "statement": ("People and Okta service accounts that are still OPA principals although their Okta user is "
                          "deprovisioned or suspended, or no longer exists in Okta. Candidates for review."),
            "state": "never_run", "message": None, "inputs": {"okta_snapshot": None, "opa_roster_loaded": index["state"] != "not_loaded"},
            "counts": {}, "rows": []}
    if snap is None:
        if attempts and attempts[0]["status"] == "refused":
            card.update({"state": "refused", "message": MISSING_USERS_MESSAGE})
        elif attempts:
            card.update({"state": "error", "message": "The last lookup of OPA principals in Okta failed. Check the Okta token and try again."})
        else:
            card["message"] = "Run the lookup to compare each OPA principal with its Okta user."
        return card
    effective = effective_access(access_model)
    rows, counts = [], {"checked": 0, "inactive_in_okta": 0, "absent_in_okta": 0, "unreadable": 0, "active": 0, "effective": 0, "effective_people": 0, "effective_accounts": 0}
    for item in snap["items"]:
        e = item["object"] if isinstance(item["object"], dict) else {}
        counts["checked"] += 1
        state = e.get("okta_state")
        if state in INACTIVE_OKTA_STATES:
            counts["inactive_in_okta"] += 1
            flag = "inactive"
        elif state == "ABSENT":
            counts["absent_in_okta"] += 1
            flag = "absent"
        elif state == "UNREADABLE" or state is None:
            counts["unreadable"] += 1
            flag = "unknown"
        else:
            counts["active"] += 1
            flag = None
        if flag:
            opa = opa_by_id.get(e.get("opa_id")) if e.get("source") == "opa_user" else None
            footprint = None
            if effective is not None:
                if e.get("source") == "opa_user":
                    footprint = effective[0].get(e.get("opa_id"))
                else:
                    footprint = effective[1].get(e.get("okta_lookup_id") or e.get("okta_id") or "")
            if flag in ("inactive", "absent") and effective is not None and footprint:
                counts["effective"] += 1
                counts["effective_people" if e.get("source") == "opa_user" else "effective_accounts"] += 1
            rows.append({**e, "absent_text": absent_text(e) if flag == "absent" else None, "flag": flag, "opa_roles": (opa or {}).get("roles", []),
                         "opa_powerful_roles": (opa or {}).get("powerful_roles", []),
                         "access_effective": None if effective is None else bool(footprint), "footprint": footprint})
    rows.sort(key=lambda r: ({"inactive": 0, "absent": 1, "unknown": 2}[r["flag"]], (r.get("name") or "").lower()))
    stale = snap["captured_at"] < _iso(now - timedelta(days=7))
    card.update({"state": "ok", "counts": counts, "rows": rows,
                 "inputs": {"okta_snapshot": _snapshot_summary(snap), "opa_roster_loaded": index["state"] != "not_loaded",
                            "okta_snapshot_stale": stale,
                            "skipped_service_users": (snap.get("meta") or {}).get("skipped_service_users", 0)},
                 "message": ("The Okta lookup is more than 7 days old; run it again for a current answer." if stale else None)})
    return card


def user_flags(environment_id):
    """{opa_user_id: {"okta_state", "flag"}} for the Access Explorer Users view,
    from the newest principal-status snapshot (empty when there is none)."""
    snap = audit_store.latest_config_snapshot(environment_id, KIND_PRINCIPAL_STATUS)
    if snap is None:
        return {"snapshot": None, "users": {}}
    users = {}
    for item in snap["items"]:
        e = item["object"] if isinstance(item["object"], dict) else {}
        if e.get("source") != "opa_user" or not e.get("opa_id"):
            continue
        state = e.get("okta_state")
        flag = "inactive" if state in INACTIVE_OKTA_STATES else "absent" if state == "ABSENT" else "unknown" if state in (None, "UNREADABLE") else None
        users[e["opa_id"]] = {"okta_state": state, "flag": flag}
    return {"snapshot": _snapshot_summary(snap), "users": users}


# ---------------------------------------------------------------------------
# Overview: counts only
# ---------------------------------------------------------------------------
def _c1_result(card):
    c = card["counts"]
    if card["state"] != "ok":
        return {"state": card["state"], "people": None, "accounts": None}
    return {"state": "ok", "people": c.get("effective_people"), "accounts": c.get("effective_accounts"),
            "unreadable": c.get("unreadable"), "checked": c.get("checked")}


def _c5_card(admins, index):
    sod = admins["separation_of_duties"]
    state = admins["state"] if admins["state"] != "ok" else ("not_loaded" if sod["state"] == "not_loaded" else "ok")
    return {
        "id": "C5", "title": "Okta admin who is also an OPA admin (separation of duties)",
        "statement": ("An Okta Super, Organization or Application Administrator who also holds pam_admin, resource_admin or delegated_resource_admin "
                      "in OPA. Since-dates come from the privilege-grant events and the snapshot history."),
        "state": state, "message": admins.get("message") if state == "refused" else None,
        "inputs": {"okta_snapshot": admins.get("as_of_snapshot"), "opa_roster_loaded": index["state"] != "not_loaded"},
        "counts": {"people": len(sod["overlaps"]) if state == "ok" else None},
        "result": {"state": state, "people": len(sod["overlaps"]) if state == "ok" else None},
    }


def privileged_identity_sets(environment_id, access_model=None, as_of=None):
    """(okta_user_ids, logins, sources): the people counted as privileged for the sign-in / MFA cohort --
    Okta admin role holders in the as-of snapshot (by Okta user id) and OPA users with an OPA admin role
    (by login / e-mail, which is how the System Log names them). `sources` maps each to why."""
    snap = audit_store.latest_config_snapshot(environment_id, KIND_ADMINS, as_of=as_of)
    ids, logins, sources = set(), set(), {}
    if snap:
        for item in snap["items"]:
            obj = item["object"] if isinstance(item["object"], dict) else {}
            if obj.get("kind") == "user" and obj.get("id") and obj.get("roles"):
                ids.add(obj["id"])
                if obj.get("login"):
                    logins.add(obj["login"].lower())
                sources.setdefault(obj["id"], set()).add("okta_admin")
    index = opa_role_index(access_model)
    for u in index["users"]:
        if u["powerful_roles"]:
            for key in (u.get("email"), u.get("name")):
                if isinstance(key, str) and key.strip():
                    logins.add(key.strip().lower())
                    sources.setdefault("login:" + key.strip().lower(), set()).add("opa_admin")
    return ids, logins, sources


def build_overview(environment_id, as_of=None, access_model=None, service_accounts_total=None, now=None, integrity=None, weeks=26, model_time=None, okta_host=None):
    """Counts for the executive dashboard, one cheap aggregate. Every Okta-derived
    block carries its own state ("ok" | "refused" | "never_captured" | "error" |
    "not_loaded") so a block whose Okta read was refused says so instead of
    showing zero. No names, no rows."""
    now = now or _now()
    admins = build_okta_admins_report(environment_id, as_of=as_of, access_model=access_model, now=now)
    index = opa_role_index(access_model)
    cross = build_cross_checks(environment_id, access_model=access_model, now=now)
    coverage = audit_store.archive_coverage(environment_id)
    sync = audit_store.get_sync_state(environment_id) or {}
    snapshots = audit_store.list_config_snapshots(environment_id, kind=KIND_ADMINS, limit=200)
    week_ago = _iso(now - timedelta(days=7))
    weekly = {"grants": 0, "revokes": 0, "since": week_ago, "revokes_archived": coverage.get("ingestion_scope") == "all"}
    for row in audit_store.query_events(environment_id, event_types=list(GRANT_EVENT_TYPES), since=week_ago, limit=PRIVILEGE_EVENTS_LIMIT):
        weekly["grants" if row["event_type"].endswith(".grant") else "revokes"] += 1
    oldest = coverage.get("oldest")
    coverage_days = None
    if oldest:
        parsed = audit_store._canonical_published(oldest)
        if parsed:
            coverage_days = max(0, (now - datetime.fromisoformat(parsed.replace("Z", "+00:00"))).days)
    admin_block = {"state": admins["state"], "message": admins.get("message"), "count": admins["summary"].get("admins"),
                   "by_role": admins["summary"].get("by_role", {}), "time_bound": admins["summary"].get("time_bound"),
                   "snapshot": admins.get("as_of_snapshot")}
    import inventory_counts
    import signin_mfa
    end = now
    if as_of:
        bound = audit_store.normalize_window(None, as_of)[1]
        parsed = audit_store._canonical_published(bound)
        if parsed:
            end = min(now, datetime.fromisoformat(parsed.replace("Z", "+00:00")))
    mfa_state = signin_mfa.built(environment_id)
    if mfa_state is None:
        signins_mfa = {"state": "not_built", "message": "The sign-in and MFA figures have not been built from the archive yet.", "weeks": []}
    else:
        pids, plogins, _src = privileged_identity_sets(environment_id, access_model, as_of)
        everyone = signin_mfa.weekly(environment_id, weeks, end)
        privileged = signin_mfa.weekly(environment_id, weeks, end, actor_ids=pids, actor_alts=plogins) if (pids or plogins) else []
        counts = signin_mfa.people_counts(environment_id, max(weeks, 13), end, pids, plogins) if (pids or plogins) else signin_mfa.people_counts(environment_id, max(weeks, 13), end)
        # people = distinct logins (an Okta admin's login is in the set too); an admin without a login still counts once
        counts["privileged_total"] = max(len(plogins), len(pids)) if (pids or plogins) else None
        signins_mfa = {
            "people": counts,
            "state": "ok", "built_at": mfa_state["built_at"], "updated_at": mfa_state["updated_at"], "events_used": mfa_state["events_used"],
            "weeks": [w["week"] for w in everyone], "everyone": everyone, "privileged": privileged,
            "privileged_cohort": {"okta_admins": len(pids), "opa_admin_logins": len(plogins)} if (pids or plogins) else None,
            "scope": coverage.get("ingestion_scope"),
            "notes": [
                "Sign-in volume is successful user.session.start events in the archive; MFA figures are successful and failed "
                "user.authentication.auth_via_mfa events, classified by the factor the event names. Password-only is derived "
                "(sign-ins minus multi-factor sign-ins in the same week) and is not observed.",
                "The privileged group is today's Okta admin role holders and OPA users with an OPA admin role, applied to the whole history.",
            ],
        }
        if privileged == [] and not (pids or plogins):
            signins_mfa["privileged_message"] = "No privileged people are known yet (capture the Okta admins and load the OPA roster)."
    import overview_extras as ox
    inv_summary = inventory_counts.series_summary(environment_id, as_of=as_of, now=now)
    snap_for_tiles = audit_store.latest_config_snapshot(environment_id, KIND_ADMINS, as_of=as_of)
    admin_users = [i["object"] for i in (snap_for_tiles["items"] if snap_for_tiles else []) if isinstance(i["object"], dict) and i["object"].get("kind") == "user" and i["object"].get("roles")]
    eff = effective_access(access_model)
    c5_card = _c5_card(admins, index)
    src = ox.sources(environment_id, end, as_of, admins, model_time, (len(eff[0]) + len(eff[1])) if eff else None, inv_summary, integrity)
    tl = ox.tiles(admin_users, index, cross, admins["separation_of_duties"], access_model, inv_summary, src["archive"]["days_held"])
    weekly_priv = ox.weekly_event_counts(environment_id, list(GRANT_EVENT_TYPES), end)
    req_types = ["access.request.create", "access.request.resolve", "access.request.expire"]
    weekly_req = ox.weekly_event_counts(environment_id, req_types, end, success_only=False)
    thirty = audit_store._iso_ms(end - timedelta(days=30))
    req30 = {"created": 0, "resolved": 0, "expired": 0}
    for r in audit_store.query_events(environment_id, event_types=req_types, since=thirty, until=audit_store._iso_ms(end), limit=5000):
        k = {"access.request.create": "created", "access.request.resolve": "resolved", "access.request.expire": "expired"}[r["event_type"]]
        req30[k] += 1
    opa_pts = next((x["points"] for x in inv_summary["series"] if x["key"] == "opa.privileged_users"), [])
    attention = ox.attention(src)
    para = ox.paragraph({"tiles": tl, "okta_state": admins["state"], "okta_host": okta_host, "archive": src["archive"], "chain": integrity,
                         "requests30": req30, "attention_sync": next((a["text"] for a in attention if a["kind"] == "sync"), None)})
    return {
        "environment_id": environment_id, "as_of": as_of, "generated_at": _iso(now),
        "sources": src, "attention": attention, "tiles": tl, "paragraph": para, "viewing_as_of": as_of if as_of and (admins.get("as_of_snapshot") or {}).get("snapshot_id") != (admins.get("last_attempt") or {}).get("snapshot_id") else None,
        "trends": {
            "admin_holders": {"okta": ox.admin_holder_points(environment_id, as_of), "opa": opa_pts},
            "privilege_events": [{"week": w, "granted": weekly_priv[w].get("user.account.privilege.grant", 0), "revoked": weekly_priv[w].get("user.account.privilege.revoke", 0)} for w in weekly_priv],
            "revokes_archived": coverage.get("ingestion_scope") == "all",
            "access_requests": [{"week": w, "created": weekly_req[w].get("access.request.create", 0), "resolved": weekly_req[w].get("access.request.resolve", 0),
                                 "expired": weekly_req[w].get("access.request.expire", 0)} for w in weekly_req],
        },
        "cross_checks": [{**{k: cross[k] for k in ("id", "title", "statement", "state", "message", "inputs", "counts")}, "result": _c1_result(cross)}, c5_card],
        "evidence_readiness": ox.evidence_readiness(end, src["archive"], (admins.get("as_of_snapshot") or {}).get("captured_at")),
        "inventory": inv_summary,
        "signins_mfa": signins_mfa,
        "okta_admins": admin_block,
        "opa_privileged_users": {"state": index["state"], "count": sum(1 for u in index["users"] if u["powerful_roles"]) if index["state"] != "not_loaded" else None,
                                 "users_total": len(index["users"]) if index["state"] != "not_loaded" else None},
        "sod_overlaps": {"state": admins["separation_of_duties"]["state"] if admins["state"] == "ok" else admins["state"],
                         "count": len(admins["separation_of_duties"]["overlaps"]) if admins["state"] == "ok" and admins["separation_of_duties"]["state"] != "not_loaded" else None},
        "lifecycle_c1": {"state": cross["state"], "message": cross.get("message"),
                         "inactive_in_okta": cross["counts"].get("inactive_in_okta"), "absent_in_okta": cross["counts"].get("absent_in_okta"),
                         "unreadable": cross["counts"].get("unreadable"), "checked": cross["counts"].get("checked"),
                         "snapshot": cross["inputs"].get("okta_snapshot")},
        "opa_service_accounts": {"state": "ok" if service_accounts_total is not None else "not_loaded", "count": service_accounts_total},
        "archive": {"has_archive": coverage.get("has_archive"), "coverage_days": coverage_days, "oldest_event": oldest,
                    "last_sync_completed_at": sync.get("last_sync_completed_at"), "last_sync_status": sync.get("last_sync_status"),
                    "ingestion_scope": coverage.get("ingestion_scope"), "chain": integrity},
        "weekly_privilege_events": weekly,
        "snapshot_dates": [{"snapshot_id": s["snapshot_id"], "captured_at": s["captured_at"], "status": s["status"]} for s in snapshots],
    }


def privileged_people_report(environment_id, access_model=None, as_of=None, weeks=26, now=None):
    """The people behind the privileged cohort of the Overview's sign-in / MFA figures (names), with each
    person's own figures over the window. Okta admin role holders (as-of snapshot) and OPA users with an
    OPA admin role, merged by login. Served only by the audited, admin-only endpoint."""
    import signin_mfa
    now = now or _now()
    snap = audit_store.latest_config_snapshot(environment_id, KIND_ADMINS, as_of=as_of)
    people = {}  # lower login or id -> person

    def person(key):
        return people.setdefault(key, {"login": None, "name": None, "okta_user_id": None, "okta_roles": [], "okta_status": None, "opa_roles": []})

    if snap:
        for item in snap["items"]:
            o = item["object"] if isinstance(item["object"], dict) else {}
            if o.get("kind") == "user" and o.get("id") and o.get("roles"):
                p = person((o.get("login") or o["id"]).lower())
                p.update(login=o.get("login"), okta_user_id=o["id"], okta_status=o.get("status"),
                         name=" ".join(x for x in (o.get("first_name"), o.get("last_name")) if x) or None,
                         okta_roles=sorted({r["type"] for r in o["roles"] if r.get("type")}))
    for u in opa_role_index(access_model)["users"]:
        if u["powerful_roles"]:
            key = next((k.strip().lower() for k in (u.get("email"), u.get("name")) if isinstance(k, str) and k.strip()), None)
            if key:
                p = people.get(key) or person(key)
                p["login"] = p["login"] or key
                p["opa_roles"] = u["powerful_roles"]
    ids = {p["okta_user_id"] for p in people.values() if p["okta_user_id"]}
    logins = {p["login"].lower() for p in people.values() if p["login"]}
    figures = signin_mfa.privileged_people(environment_id, ids, logins, weeks, now)
    by_id = {f["actor_id"]: f for f in figures}
    by_login = {(f["login"] or "").lower(): f for f in figures if f["login"]}
    out = []
    for key, p in people.items():
        f = by_id.get(p["okta_user_id"]) or by_login.get((p["login"] or "").lower())
        out.append({**p, "figures": {k: f[k] for k in ("signins", "mfa_success", "phishing_resistant_share", "sms_voice", "mfa_failed", "by_class")} if f else None})
    out.sort(key=lambda x: ((x["login"] or "").lower(), x["okta_user_id"] or ""))
    return {"weeks": weeks, "people": out, "generated_at": _iso(now),
            "note": "Each person's figures are their own sign-ins and multi-factor events in the archive over the window."}


PEOPLE_LISTS = ("c1", "c5", "mfa_nonpr", "mfa_smsvoice")


def people_list(environment_id, which, access_model=None, as_of=None):
    """The named list behind an Overview count (admin-only, audited endpoint): 'c1' the OPA principals whose Okta
    user is gone and whose OPA access still resolves, 'c5' the Okta admins who also hold an OPA admin role."""
    if which not in PEOPLE_LISTS:
        raise ValueError("list must be one of " + ", ".join(PEOPLE_LISTS))
    if which in ("mfa_nonpr", "mfa_smsvoice"):
        import signin_mfa
        pids, plogins, _ = privileged_identity_sets(environment_id, access_model, as_of)
        end = None
        if as_of:
            parsed = audit_store._canonical_published(audit_store.normalize_window(None, as_of)[1])
            end = min(_now(), datetime.fromisoformat(parsed.replace("Z", "+00:00"))) if parsed else None
        people = signin_mfa.non_pr_people(environment_id, pids, plogins, 13, end, "nonpr" if which == "mfa_nonpr" else "smsvoice")
        return {"list": which, "state": "ok", "message": None, "snapshot": None, "people": people,
                "note": "Privileged people with at least one successful multi-factor sign-in by that kind of factor in the period. An estimate: the factor comes from debugData.factor."}
    if which == "c5":
        report = build_okta_admins_report(environment_id, as_of=as_of, access_model=access_model)
        return {"list": "c5", "state": report["state"] if report["state"] != "ok" else report["separation_of_duties"]["state"],
                "message": report.get("message"), "snapshot": report.get("as_of_snapshot"), "people": report["separation_of_duties"]["overlaps"]}
    card = build_cross_checks(environment_id, access_model=access_model)
    rows = [r for r in card["rows"] if r["flag"] in ("inactive", "absent") and r.get("access_effective")]
    snap = card["inputs"].get("okta_snapshot")
    return {"list": "c1", "state": card["state"], "message": card["message"], "snapshot": snap, "people": rows,
            "note": ("'OPA access still effective' means at least one active OPA security policy resolves to this principal today. "
                     "This tool does not change it.")}
