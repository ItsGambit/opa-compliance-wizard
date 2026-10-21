"""Daily inventory COUNTS of the OPA side and the Okta side, as a chained snapshot (5.50.0).

Counts only: a snapshot item is {"series", "side", "label", "count"} -- never a name, an id or an
account. One item per series; a series whose read was refused is simply absent from that day's
snapshot and listed in the snapshot's meta, so the time series shows a gap, never a fake zero.

The OPA side is counted from the Access Explorer model (create_secret_folders.build_access_model),
reused from memory when it is loaded and built fresh otherwise. The Okta side pages Okta's list
endpoints read-only. Kubernetes clusters are not part of the product's model, so there is no series
for them."""
from datetime import datetime, timedelta, timezone

import audit_store

KIND_INVENTORY = "inventory_counts"
OKTA_POLICY_TYPES = ("OKTA_SIGN_ON", "PASSWORD", "MFA_ENROLL", "ACCESS_POLICY", "PROFILE_ENROLLMENT")
MAX_POINTS = 800  # points returned per series (a daily series of two years fits)

# (key, label) of every OPA series, in display order.
OPA_SERIES = (
    ("opa.resource_groups", "Resource groups"), ("opa.projects", "Projects"), ("opa.servers", "Servers"),
    ("opa.secret_folders", "Secret folders"), ("opa.secrets", "Secrets"),
    ("opa.saas_accounts", "SaaS app accounts"), ("opa.okta_ud_accounts", "Okta service accounts"),
    ("opa.ad_accounts", "Active Directory accounts"), ("opa.database_accounts", "Database accounts"),
    ("opa.users_human", "Users"), ("opa.users_service", "Service users"), ("opa.groups", "Groups"),
    ("opa.policies", "Security policies"), ("opa.policies_active", "Active security policies"),
    ("opa.relationships", "Relationships"), ("opa.assignments", "Assignments"),
    ("opa.group_memberships", "Group memberships"), ("opa.group_role_assignments", "Group role assignments"),
    ("opa.delegated_admin_group_assignments", "Delegated admin group assignments"),
    ("opa.policy_resource_grants", "Policy-to-resource grants"),
    ("opa.gateways", "Gateways"), ("opa.clients", "Enrolled clients"), ("opa.workload_roles", "Workload roles"),
    ("opa.workload_connections", "Workload connections"), ("opa.database_connections", "Database connections"),
    ("opa.saas_connections", "SaaS app connections"), ("opa.ad_connections", "Active Directory connections"),
)
OKTA_SERIES = (
    ("okta.users", "Users"), ("okta.groups", "Groups"), ("okta.apps", "Apps"),
    *((f"okta.policies.{t.lower()}", f"Policies: {t.replace('_', ' ').title()}") for t in OKTA_POLICY_TYPES),
    ("okta.admin_role_holders", "Users holding an admin role"), ("okta.devices", "Devices"),
)
LABELS = dict(OPA_SERIES + OKTA_SERIES)


def _lst(model, key):
    value = model.get(key)
    return value if isinstance(value, list) else []


def _len(model, key):
    value = model.get(key)
    return len(value) if isinstance(value, list) else None


def opa_counts(model):
    """{series_key: count} from an access model; a section the model could not read
    (it lists those in model["warnings"]) is left out, never counted as zero."""
    if not isinstance(model, dict):
        return {}
    unreadable = " ".join(w.get("section", "") for w in _lst(model, "warnings") if isinstance(w, dict))
    out = {}

    def put(key, value, skip_if=None):
        if value is not None and not (skip_if and skip_if in unreadable):
            out[key] = value

    put("opa.resource_groups", _len(model, "resource_groups"))
    put("opa.projects", _len(model, "projects"))
    put("opa.servers", _len(model, "servers"), "servers in project")
    totals = model.get("inventory_totals") if isinstance(model.get("inventory_totals"), dict) else {}
    for key, name in (("opa.secret_folders", "secret_folders"), ("opa.secrets", "secrets")):
        if isinstance(totals.get(name), int):
            out[key] = totals[name]
    put("opa.saas_accounts", _len(model, "saas_accounts"), "SaaS app accounts in project")
    put("opa.okta_ud_accounts", _len(model, "okta_accounts"), "Okta Universal Directory accounts in project")
    put("opa.ad_accounts", _len(model, "active_directory_accounts"), "Active Directory accounts in project")
    put("opa.database_accounts", _len(model, "database_accounts"), "database accounts in project")
    users = [u for u in _lst(model, "users") if isinstance(u, dict)]
    if isinstance(model.get("users"), list):
        out["opa.users_service"] = sum(1 for u in users if u.get("user_type") == "service")
        out["opa.users_human"] = len(users) - out["opa.users_service"]
        if not any(u.get("groups_error") for u in users):
            out["opa.group_memberships"] = sum(len(u["groups"]) if isinstance(u.get("groups"), list) else 0 for u in users)
    groups = [g for g in _lst(model, "groups") if isinstance(g, dict)]
    if isinstance(model.get("groups"), list):
        out["opa.groups"] = len(groups)
        out["opa.group_role_assignments"] = sum(len(g["roles"]) if isinstance(g.get("roles"), list) else 0 for g in groups)
    if isinstance(model.get("resource_groups"), list):
        out["opa.delegated_admin_group_assignments"] = sum(
            len(rg["delegated_resource_admin_groups"]) if isinstance(rg.get("delegated_resource_admin_groups"), list) else 0
            for rg in model["resource_groups"] if isinstance(rg, dict))
    policies = [p for p in _lst(model, "policies") if isinstance(p, dict)]
    if isinstance(model.get("policies"), list):
        out["opa.policies"] = len(policies)
        out["opa.policies_active"] = sum(1 for p in policies if p.get("active"))
        out["opa.policy_resource_grants"] = sum(
            1 for p in policies for r in (p.get("rules") if isinstance(p.get("rules"), list) else []) if isinstance(r, dict)
            for res in (r.get("resolutions") if isinstance(r.get("resolutions"), list) else []) if isinstance(res, dict) and res.get("kind") == "resolved")
    put("opa.relationships", _len(model, "relationships"), "relationships")
    put("opa.assignments", _len(model, "assignments"), "assignments")
    put("opa.gateways", _len(model, "gateways"), "gateways")
    put("opa.clients", _len(model, "clients"), "enrolled clients")
    put("opa.workload_roles", _len(model, "workload_roles"), "workload roles")
    put("opa.workload_connections", _len(model, "workload_connections"), "workload connections")
    put("opa.database_connections", _len(model, "database_connections"), "database connections")
    put("opa.saas_connections", _len(model, "saas_app_connections"), "SaaS app connections")
    put("opa.ad_connections", _len(model, "active_directory_connections"), "Active Directory connections")
    return out


def okta_counts(okta_client, admin_role_holders=None, device_count=None):
    """({series_key: count}, [problems]) -- read-only list walks, each capped; a refused
    or failed read is a problem entry, not a zero."""
    from create_secret_folders import OktaApiError
    out, problems = {}, []

    def one(key, kind, policy_type=None):
        try:
            count, capped = okta_client.count_okta_objects(kind, policy_type)
            out[key] = count
            if capped:
                problems.append({"series": key, "state": "capped"})
        except OktaApiError as exc:
            import okta_admins
            problems.append({"series": key, "state": okta_admins._classify(exc), "error_code": okta_admins.error_code(exc)})

    one("okta.users", "users")
    one("okta.groups", "groups")
    one("okta.apps", "apps")
    for t in OKTA_POLICY_TYPES:
        one(f"okta.policies.{t.lower()}", "policies", t)
    if isinstance(admin_role_holders, int):
        out["okta.admin_role_holders"] = admin_role_holders
    if isinstance(device_count, int):
        out["okta.devices"] = device_count
    return out, problems


def _latest_admin_holders(environment_id, now, max_age=timedelta(hours=36)):
    import okta_admins
    snap = audit_store.latest_config_snapshot(environment_id, okta_admins.KIND_ADMINS, with_items=False)
    if not snap:
        return None
    taken = audit_store._canonical_published(snap["captured_at"])
    if not taken or taken < audit_store._iso_ms(now - max_age):
        return None
    conn = audit_store._get_connection()
    return conn.execute("SELECT COUNT(*) FROM config_snapshot_items WHERE snapshot_id = ? AND item_key LIKE 'user:%'",
                        (snap["snapshot_id"],)).fetchone()[0]


def capture_inventory(environment_id, okta_client=None, opa_client=None, model=None, now=None, captured_at=None):
    """Counts the OPA and Okta sides and stores one sealed snapshot of kind inventory_counts.
    `model` (a loaded Access Explorer model) is reused; otherwise it is built from `opa_client`.
    Returns the stored snapshot. Raises only when NO series could be counted at all."""
    import create_secret_folders as engine
    now = now or datetime.now(timezone.utc)
    problems = []
    counts = {}
    if model is None and opa_client is not None:
        try:
            model = engine.build_access_model(opa_client, okta_client)
        except Exception as exc:  # the OPA side is unavailable today: say so, still count Okta
            problems.append({"series": "opa", "state": "error", "detail": type(exc).__name__})
    if isinstance(model, dict):
        counts.update(opa_counts(model))
        for w in _lst(model, "warnings"):
            if isinstance(w, dict) and isinstance(w.get("section"), str):
                problems.append({"series": "opa", "state": "not_readable", "section": w["section"][:80]})
    if okta_client is not None:
        device_count = len(model["devices"]) if isinstance(model, dict) and isinstance(model.get("devices"), list) and model["devices"] else None
        okta, okta_problems = okta_counts(okta_client, _latest_admin_holders(environment_id, now), device_count)
        counts.update(okta)
        problems.extend(okta_problems)
    if not counts:
        raise ValueError("Nothing could be counted: neither the OPA roster nor Okta was readable.")
    items = [(key, {"series": key, "side": key.split(".", 1)[0], "label": LABELS.get(key, key), "count": int(value)})
             for key, value in sorted(counts.items())]
    return audit_store.record_config_snapshot(
        environment_id, KIND_INVENTORY, items, status="ok", source_endpoint="inventory",
        meta={"problems": problems[:100], "series": len(items)}, captured_at=captured_at)


def series_summary(environment_id, as_of=None, now=None):
    """The inventory time series for the overview: per series key its label, side, first-seen date,
    latest count and the change over 7 and 30 days (None when there is no snapshot that old), plus the
    points. state: ok | never_captured."""
    rows = audit_store.config_series(environment_id, KIND_INVENTORY, as_of=as_of, limit_snapshots=1000)
    if not rows["snapshots"]:
        return {"state": "never_captured", "series": [], "snapshots": 0, "latest": None, "problems": []}
    out = []
    latest_at = rows["snapshots"][-1]["captured_at"]
    for key, points in sorted(rows["series"].items(), key=lambda kv: _order(kv[0])):
        pts = [(t, c) for t, c in points if isinstance(c, int)]
        if not pts:
            continue
        latest_t, latest_c = pts[-1]
        out.append({
            "key": key, "label": LABELS.get(key, key), "side": key.split(".", 1)[0],
            "first_seen": pts[0][0], "latest": latest_c, "latest_at": latest_t,
            "delta_7d": _delta(pts, latest_t, latest_c, 7), "delta_30d": _delta(pts, latest_t, latest_c, 30),
            "points": [{"t": t, "count": c} for t, c in _thin(pts)],
        })
    return {"state": "ok", "series": out, "snapshots": len(rows["snapshots"]), "latest": latest_at,
            "problems": (rows["snapshots"][-1].get("meta") or {}).get("problems", [])}


def _order(key):
    keys = [k for k, _ in OPA_SERIES + OKTA_SERIES]
    return (keys.index(key) if key in keys else len(keys), key)


def _delta(points, latest_t, latest_c, days):
    """Latest minus the count at the newest snapshot at or before latest_t - days; None if the
    series (or the archive of snapshots) is not that old -- never inferred."""
    cutoff = audit_store._iso_ms(datetime.fromisoformat(latest_t.replace("Z", "+00:00")) - timedelta(days=days))
    base = None
    for t, c in points:
        if t <= cutoff:
            base = c
        else:
            break
    return None if base is None else latest_c - base


def _thin(points):
    if len(points) <= MAX_POINTS:
        return points
    step = len(points) / MAX_POINTS
    picked = [points[int(i * step)] for i in range(MAX_POINTS - 1)]
    return picked + [points[-1]]


MIN_INTERVAL = timedelta(hours=20)


def capture_if_due(environment_id, okta_client=None, opa_client=None, model=None, now=None):
    """The automatic daily capture after a sync: skipped when an inventory snapshot was recorded in the
    last 20 hours. Returns the snapshot or None."""
    now = now or datetime.now(timezone.utc)
    last = audit_store.list_config_snapshots(environment_id, kind=KIND_INVENTORY, limit=1)
    if last:
        taken = audit_store._canonical_published(last[0]["captured_at"])
        if taken and taken > audit_store._iso_ms(now - MIN_INTERVAL):
            return None
    return capture_inventory(environment_id, okta_client=okta_client, opa_client=opa_client, model=model, now=now)
