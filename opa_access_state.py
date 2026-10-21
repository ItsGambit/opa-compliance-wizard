"""The daily sealed OPA access state (5.51.0): who could reach what on a date, as a chained snapshot.

One snapshot a day (20 hours apart at the most) per environment, built from the OPA scan the refresh just read: no extra OPA or Okta
call. Items are small and keyed, so snapshots compare and export like every other kind:

    user:<id>     id, name, user_type, status, email, group_ids, groups_error, effective
    group:<id>    id, name, roles, member_count
    policy:<id>   id, name, active, principal_group_ids, rules (per rule: the privileges it grants, the projects and resource ids it
                  resolves to; ids only, never a resource name), relationship_ids
    summary:counts   the same series as inventory_counts.opa_counts, plus the sections the key could not read

The names and e-mails are in the items on purpose (evidence of who held access); resource names, secret values, keys and tokens are
not. A scan that could not read a section says so in `summary:counts` and in the snapshot's meta, so a gap is never a zero. A failed
scan writes nothing (its failure is audited as access_scan.failed). Never pruned; purged with the environment's archive."""
from datetime import datetime, timedelta, timezone

import audit_store

KIND = "opa_access_state"
GATE_HOURS = 20
SOURCE_ENDPOINT = "opa scan (stored)"


def _lst(value):
    return value if isinstance(value, list) else []


def _dicts(value):
    return [x for x in _lst(value) if isinstance(x, dict)]


def _ids(refs):
    return sorted({r.get("id") for r in _lst(refs) if isinstance(r, dict) and isinstance(r.get("id"), str)})


def _rule_item(rule):
    resolved = [r for r in _dicts(rule.get("resolutions")) if r.get("kind") == "resolved"]
    resource_ids = sorted({r["id"] for r in resolved if isinstance(r.get("id"), str)})
    flags = sorted({f for p in _dicts(rule.get("privileges")) for f in _lst(p.get("flags")) if isinstance(f, str)})
    return {
        "resource_type": rule.get("resource_type") if isinstance(rule.get("resource_type"), str) else None,
        "resource_kinds": sorted({r["resource_kind"] for r in resolved if isinstance(r.get("resource_kind"), str)}),
        "privilege_flags": flags,
        "resolved_project_ids": sorted({r["project_id"] for r in resolved if isinstance(r.get("project_id"), str)}),
        "resolved_resource_ids": resource_ids,
    }


def _policy_item(policy):
    principals = policy.get("principals") if isinstance(policy.get("principals"), dict) else {}
    item = {
        "id": policy.get("id"), "name": policy.get("name"), "active": bool(policy.get("active")),
        "principal_group_ids": _ids(principals.get("user_groups")),
        "rules": [_rule_item(r) for r in _dicts(policy.get("rules"))],
        "relationship_ids": sorted(x for x in _lst(policy.get("relationship_ids")) if isinstance(x, str)),
    }
    if len(audit_store._canonical_json(item).encode("utf-8")) > audit_store.SNAPSHOT_MAX_ITEM_BYTES:
        # A rule that resolves to tens of thousands of resources: keep the counts, drop the id lists, and say so.
        for rule in item["rules"]:
            rule["resolved_resource_count"] = len(rule["resolved_resource_ids"])
            rule["resolved_resource_ids"] = []
        item["truncated"] = True
    return item


def build_items(model):
    """([(key, object)], meta) for the model. Raises ValueError when there is nothing to record (no users, groups or policies read)."""
    if not isinstance(model, dict):
        raise ValueError("no OPA scan to record")
    import inventory_counts
    import okta_admins
    users, groups, policies = _dicts(model.get("users")), _dicts(model.get("groups")), _dicts(model.get("policies"))
    effective = okta_admins.effective_access(model)
    effective_users = effective[0] if effective else {}
    members = {}
    for u in users:
        for gid in _ids(u.get("groups")):
            members[gid] = members.get(gid, 0) + 1
    groups_known = not any(u.get("groups_error") for u in users)
    items = []
    for u in users:
        if not isinstance(u.get("id"), str):
            continue
        details = u.get("details") if isinstance(u.get("details"), dict) else {}
        items.append((f"user:{u['id']}", {
            "id": u["id"], "name": u.get("name"), "user_type": u.get("user_type"), "status": u.get("status"),
            "email": details.get("email") if isinstance(details.get("email"), str) else None,
            "group_ids": _ids(u.get("groups")), "groups_error": bool(u.get("groups_error")), "effective": u["id"] in effective_users,
        }))
    for g in groups:
        if isinstance(g.get("id"), str):
            items.append((f"group:{g['id']}", {
                "id": g["id"], "name": g.get("name"), "roles": sorted(r for r in _lst(g.get("roles")) if isinstance(r, str)),
                "member_count": members.get(g["id"], 0) if groups_known else None,
            }))
    truncated = 0
    for p in policies:
        if isinstance(p.get("id"), str):
            item = _policy_item(p)
            truncated += 1 if item.get("truncated") else 0
            items.append((f"policy:{p['id']}", item))
    unreadable = [w.get("section") for w in _dicts(model.get("warnings")) if isinstance(w.get("section"), str)]
    items.append(("summary:counts", {"counts": inventory_counts.opa_counts(model), "unreadable_sections": sorted(unreadable)}))
    if not (users or groups or policies):
        raise ValueError("the OPA scan holds no users, groups or policies to record")
    meta = {"unreadable_sections": sorted(unreadable), "truncated_policies": truncated, "users": len(users), "groups": len(groups), "policies": len(policies)}
    return items, meta


def due(environment_id, now=None):
    """True when no access state was sealed in the last GATE_HOURS (one evidence point a day is the design)."""
    now = now or datetime.now(timezone.utc)
    last = audit_store.list_config_snapshots(environment_id, kind=KIND, limit=1)
    if not last:
        return True
    parsed = audit_store._canonical_published(last[0]["captured_at"])
    if not parsed:
        return True
    return now - datetime.fromisoformat(parsed.replace("Z", "+00:00")) >= timedelta(hours=GATE_HOURS)


def capture_if_due(environment_id, model, built_at=None, now=None):
    """Seals today's access state from `model` unless one was sealed in the last 20 hours. Returns the snapshot dict, or None when not due.
    Raises on a model with nothing to record or a snapshot the store refuses (the caller reports it; the scan itself stays good)."""
    if not due(environment_id, now):
        return None
    items, meta = build_items(model)
    meta["scan_built_at"] = built_at
    return audit_store.record_config_snapshot(environment_id, KIND, items, status="ok", source_endpoint=SOURCE_ENDPOINT, meta=meta)
