"""The remaining Overview blocks (5.50.0): the sources strip, the tiles, the trend series, the evidence readiness table,
the attention list and the 'State of privileged access' paragraph. Counts only; every block says when its source is not
readable. Used by okta_admins.build_overview and by the people lists."""
from datetime import datetime, timedelta, timezone

import audit_store

PRIV_WEEKS = 13


def _iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _days_between(a_iso, b):
    parsed = audit_store._canonical_published(a_iso)
    if not parsed:
        return None
    return (b - datetime.fromisoformat(parsed.replace("Z", "+00:00"))).days


def week_labels(now, count=PRIV_WEEKS):
    import signin_mfa
    monday = datetime.strptime(signin_mfa.week_start(now.strftime("%Y-%m-%d")), "%Y-%m-%d")
    return [(monday - timedelta(weeks=i)).strftime("%Y-%m-%d") for i in range(count - 1, -1, -1)]


def weekly_event_counts(environment_id, event_types, now, weeks=PRIV_WEEKS, success_only=True):
    """{week: {event_type: n}} for the last `weeks` weeks from the archive (published week)."""
    import signin_mfa
    labels = week_labels(now, weeks)
    out = {w: {} for w in labels}
    conn = audit_store._get_connection()
    marks = ",".join("?" for _ in event_types)
    sql = f"SELECT event_type, published, outcome_result FROM events WHERE environment_id = ? AND event_type IN ({marks}) AND published >= ? AND published <= ?"
    for r in conn.execute(sql, (environment_id, *event_types, labels[0] + "T00:00:00.000Z", _iso(now))):
        if success_only and r["outcome_result"] not in (None, "", "SUCCESS"):
            continue
        w = signin_mfa.week_start(r["published"])
        if w in out:
            out[w][r["event_type"]] = out[w].get(r["event_type"], 0) + 1
    return out


def admin_holder_points(environment_id, as_of=None):
    """Okta admin role holders per successful okta_admins snapshot: [{t, count}] oldest first."""
    conn = audit_store._get_connection()
    sql = ("SELECT s.captured_at AS t, (SELECT COUNT(*) FROM config_snapshot_items i WHERE i.snapshot_id = s.snapshot_id AND i.item_key LIKE 'user:%') AS n "
           "FROM config_snapshots s WHERE s.environment_id = ? AND s.kind = 'okta_admins' AND s.status = 'ok'")
    params = [environment_id]
    if as_of:
        sql += " AND s.captured_at <= ?"
        params.append(audit_store.normalize_window(None, as_of)[1])
    sql += " ORDER BY s.captured_at"
    return [{"t": r["t"], "count": r["n"]} for r in conn.execute(sql, params)]


def _refresh_view(sync, schedule):
    """What the Overview says about the daily refresh: the schedule and what the last scheduled and the last other refresh
    did to each part (state only; the messages stay in the job record)."""
    stored = sync.get("last_refresh") if isinstance(sync.get("last_refresh"), dict) else {}

    def one(record):
        if not isinstance(record, dict):
            return None
        return {"finished_at": record.get("finished_at"), "trigger": record.get("trigger"),
                "parts": {p: {"state": (d or {}).get("state"), "message": (d or {}).get("message")} for p, d in (record.get("parts") or {}).items()}}
    schedule = schedule or {}
    return {"schedule": {"enabled": bool(schedule.get("enabled")), "run_time": schedule.get("run_time") or "02:00"},
            "last_scheduled": one(stored.get("scheduled")), "last_manual": one(stored.get("manual"))}


def _opa_model_block(model_time, effective_principals, scan, refresh):
    """sources.opa_model (5.51.0): when the stored scan was read, where it came from, how old it is. The old keys stay."""
    out = {"loaded": model_time is not None or effective_principals is not None, "refreshed_at": model_time,
           "principals_effective": effective_principals, "built_at": None, "age_seconds": None, "source": "none", "stale": False,
           "very_stale": False, "counts": {}, "warnings_count": 0, "modified_at": None, "last_scan_outcome": None}
    if scan:
        out.update({k: scan.get(k) for k in ("built_at", "age_seconds", "source", "stale", "very_stale", "counts", "warnings_count", "modified_at")})
    last = [r for r in (refresh.get("last_scheduled"), refresh.get("last_manual")) if r and (r.get("parts") or {}).get("opa")]
    if last:
        newest = max(last, key=lambda r: r.get("finished_at") or "")
        out["last_scan_outcome"] = newest["parts"]["opa"]["state"]
    return out


def sources(environment_id, now, as_of, admins_report, model_time, effective_principals, inventory_series, integrity, scan=None, schedule=None, okta_host=None):
    snaps = audit_store.list_config_snapshots(environment_id, kind="okta_admins", limit=1000)
    ok = [s for s in snaps if s["status"] == "ok"]
    ok.sort(key=lambda s: s["captured_at"])
    chosen = (admins_report.get("as_of_snapshot") or {}).get("snapshot_id")
    index = next((i + 1 for i, s in enumerate(ok) if s["snapshot_id"] == chosen), None)
    coverage = audit_store.archive_coverage(environment_id)
    sync = audit_store.get_sync_state(environment_id) or {}
    newest_snapshot = snaps[0] if snaps else None
    users_series = next((x for x in (inventory_series or {}).get("series", []) if x["key"] == "okta.users"), None)
    refresh = _refresh_view(sync, schedule)
    return {
        "okta_snapshot": {
            "captured_at": (admins_report.get("as_of_snapshot") or {}).get("captured_at"), "index": index, "snapshots_total": len(ok),
            "first_at": ok[0]["captured_at"] if ok else None, "state": admins_report.get("state"),
            "newest_attempt_status": newest_snapshot["status"] if newest_snapshot else None,
            "newest_attempt_at": newest_snapshot["captured_at"] if newest_snapshot else None,
            "newest_attempt_error_code": ((newest_snapshot.get("meta") or {}).get("error_code") if newest_snapshot and newest_snapshot["status"] != "ok" else None),
            "days_old": _days_between((admins_report.get("as_of_snapshot") or {}).get("captured_at"), now) if admins_report.get("as_of_snapshot") else None,
        },
        "archive": {
            "has_archive": coverage.get("has_archive"), "oldest": coverage.get("oldest"), "newest": coverage.get("newest"),
            "days_held": _days_between(coverage["oldest"], now) if coverage.get("oldest") else None,
            "events": (audit_store.get_sync_state(environment_id) or {}).get("total_events_ingested"),
            "last_sync_completed_at": sync.get("last_sync_completed_at"), "last_sync_status": sync.get("last_sync_status"),
            "last_sync_error": sync.get("last_sync_error"), "last_sync_attempt_at": sync.get("last_sync_attempt_at"),
            "sync_mode": sync.get("sync_mode"), "scope": coverage.get("ingestion_scope"),
            "days_since_sync": _days_between(sync["last_sync_completed_at"], now) if sync.get("last_sync_completed_at") else None,
        },
        "chain": integrity,
        "opa_model": _opa_model_block(model_time, effective_principals, scan, refresh),
        "refresh": refresh,
        "okta_org": {"users": users_series["latest"] if users_series else None, "host": okta_host},
    }


OKTA_LOG_WINDOW_DAYS = 90  # Okta keeps System Log events for 90 days (the same window the sync's first backfill uses)
OKTA_WINDOW_WARN_DAYS = 80  # from here the message says the oldest unfetched events are about to leave the window


def _day_label(iso):
    parsed = audit_store._canonical_published(iso) if iso else None
    if not parsed:
        return None
    dt = datetime.fromisoformat(parsed.replace("Z", "+00:00"))
    return f"{dt.day} {dt.strftime('%b %Y')}"


def _sync_attention_text(archive, now):
    """The banner sentence for a sync that has not succeeded: what happened, what is at stake (it depends on how long ago the
    last success was, because Okta only keeps 90 days), and what to do."""
    days = archive.get("days_since_sync")
    if days is None:
        return "The archive has not synced yet. Select Refresh to read the System Log now, or check the sync settings (Overview, Schedule)."
    error = f" ({archive['last_sync_error']})" if archive.get("last_sync_error") else ""
    since = _day_label(archive.get("last_sync_completed_at"))
    if days >= OKTA_LOG_WINDOW_DAYS:
        gap_end = _day_label(_iso(now - timedelta(days=OKTA_LOG_WINDOW_DAYS)))
        return (f"Archive sync has not succeeded for {days} days{error}. Events from {since} to {gap_end} are no longer available from Okta; "
                "the archive has a gap there. Select Refresh to fetch what Okta still holds.")
    if days >= OKTA_WINDOW_WARN_DAYS:
        left = OKTA_LOG_WINDOW_DAYS - days
        return (f"Archive sync has not succeeded for {days} days{error}. Events from {since} leave Okta's 90-day window in {left} day{'s' if left != 1 else ''}. "
                "Select Refresh soon, or check the sync settings (Overview, Schedule).")
    lead = f"Archive sync has not succeeded for {days} day{'s' if days != 1 else ''}{error}." if days else f"The last archive sync failed{error}."
    return (lead + " Events since then are still inside Okta's 90-day window and will be fetched by the next successful run. "
            "Select Refresh now, or check the sync settings (Overview, Schedule).")


def attention(src, now=None):
    """Plain sentences for the banner: what is stale or failing, in the order a reader needs them."""
    out = []
    now = now or datetime.now(timezone.utc)
    a, o = src["archive"], src["okta_snapshot"]
    if a.get("last_sync_status") == "error" or (a.get("days_since_sync") or 0) >= 2:
        days = a.get("days_since_sync")
        short = (f"Archive sync has not succeeded for {days} day(s)" + (f" ({a['last_sync_error']})" if a.get("last_sync_error") else "") + "."
                 if days is not None else "Archive sync has not completed yet.")  # the one-pager's wording: no button names
        out.append({"kind": "sync", "text": _sync_attention_text(a, now), "short": short})
    if o.get("newest_attempt_status") in ("refused", "error") and o.get("newest_attempt_at"):
        out.append({"kind": "snapshot", "text": "The newest Okta configuration capture " + ("was refused by Okta." if o["newest_attempt_status"] == "refused" else "failed.")})
    elif (o.get("days_old") or 0) >= 2:
        out.append({"kind": "snapshot", "text": f"The Okta configuration snapshot is {o['days_old']} days old."})
    if src.get("chain") and src["chain"].get("valid") is False:
        out.append({"kind": "chain", "text": "The evidence chain check found a break: " + str(src["chain"].get("reason"))})
    scheduled = (src.get("refresh") or {}).get("last_scheduled")
    opa_part = ((scheduled or {}).get("parts") or {}).get("opa") or {}
    if opa_part.get("state") and opa_part["state"] != "ok":
        out.append({"kind": "scheduled_opa", "text": "The last scheduled refresh did not read OPA" + (f": {opa_part['message']}" if opa_part.get("message") else ".")})
    return out


def tiles(admin_users, opa_index, c1_card, sod, model, inventory_series, archive_days):
    """Counts for the six tiles. Each is None when its source is not available."""
    okta_roles = {}
    for u in admin_users:
        for t in {r.get("type") for r in u.get("roles") or [] if r.get("type")}:
            okta_roles[t] = okta_roles.get(t, 0) + 1
    opa_roles = {}
    privileged = 0
    for u in opa_index["users"]:
        if u["powerful_roles"]:
            privileged += 1
            for r in u["powerful_roles"]:
                opa_roles[r] = opa_roles.get(r, 0) + 1
    saas = len(model.get("saas_accounts") or []) if model else None
    ud = len(model.get("okta_accounts") or []) if model else None
    service_users = sum(1 for u in (model or {}).get("users") or [] if isinstance(u, dict) and u.get("user_type") == "service") if model else None
    return {
        "okta_people": len(admin_users), "okta_by_role": okta_roles,
        "opa_privileged": privileged if opa_index["state"] != "not_loaded" else None, "opa_by_role": opa_roles,
        "both": len(sod["overlaps"]) if sod["state"] != "not_loaded" else None,
        "left_okta": {"people": c1_card["counts"].get("effective_people"), "accounts": c1_card["counts"].get("effective_accounts"),
                      "state": c1_card["state"], "effective_known": bool(c1_card["inputs"].get("opa_roster_loaded"))},
        "service": {"saas": saas, "okta_ud": ud, "service_users": service_users, "total": (saas + ud) if saas is not None else None},
        "archive_days": archive_days,
    }


def paragraph(ctx):
    """'State of privileged access': one sentence per block, a sentence dropped (and said so) when its source is unavailable."""
    parts = []
    t, host = ctx["tiles"], ctx.get("okta_host") or "Okta"
    if ctx["okta_state"] == "ok":
        sup = t["okta_by_role"].get("SUPER_ADMIN", 0)
        s = f"{t['okta_people']} {'person holds' if t['okta_people'] == 1 else 'people hold'} an Okta admin role in {host} ({sup} of them Super Administrator)"
    elif ctx["okta_state"] == "refused":
        s = "The Okta token cannot read admin role assignments, so Okta admin roles are not reported"
    else:
        s = "Okta admin roles have not been captured yet"
    if t["opa_privileged"] is not None:
        s += (f" and {t['opa_privileged']} {'holds' if t['opa_privileged'] == 1 else 'hold'} a privileged OPA role (pam_admin, resource_admin or delegated_resource_admin)")
        parts.append(s + ".")
    else:
        parts.append(s + ". No OPA scan is stored yet, so privileged OPA roles are not reported.")
    if t["both"] is not None and ctx["okta_state"] == "ok":
        parts.append("Nobody holds both an Okta admin role and a privileged OPA role." if t["both"] == 0 else
                     f"{t['both']} {'person holds' if t['both'] == 1 else 'people hold'} both and {'is' if t['both'] == 1 else 'are'} listed for separation-of-duties review.")
    left = t["left_okta"]
    if left["state"] == "ok" and left["effective_known"]:
        p, a = left["people"] or 0, left["accounts"] or 0
        if p == 0 and a == 0:
            parts.append("Nobody who has left Okta (deprovisioned or suspended) still holds effective OPA access.")
        else:
            bits = []
            if p:
                bits.append(f"{p} {'person' if p == 1 else 'people'}")
            if a:
                bits.append(f"{a} Okta Universal Directory service {'account' if a == 1 else 'accounts'}")
            parts.append(" and ".join(bits) + " ha" + ("s" if (p + a) == 1 else "ve") + " left Okta but still " + ("holds" if (p + a) == 1 else "hold") + " effective OPA access and " + ("is" if (p + a) == 1 else "are") + " listed for review.")
    elif left["state"] == "never_run":
        parts.append("The Okta status of OPA principals has not been looked up yet.")
    elif left["state"] == "refused":
        parts.append("The Okta token cannot read users, so people who left Okta are not checked.")
    sv = t["service"]
    if sv["total"] is not None:
        parts.append(f"OPA has {sv['total']} service accounts ({sv['saas']} SaaS, {sv['okta_ud']} Okta Universal Directory) and {sv['service_users']} service users with API keys.")
    req = ctx.get("requests30")
    if req and req["created"]:
        parts.append(f"In the 30 days to the last sync OPA recorded {req['created']} access requests: {req['resolved']} resolved, {req['expired']} expired.")
    arch = ctx["archive"]
    if arch.get("days_held"):
        s = f"The evidence archive holds {arch['days_held']} days of System Log events (Okta itself keeps 90)"
        if arch.get("days_since_sync") is not None:
            s += f", was last synced {arch['days_since_sync']} day(s) ago" if arch["days_since_sync"] >= 1 else ", was synced today"
        chain = ctx.get("chain")
        if chain and chain.get("valid") is True:
            s += f", and its evidence chain was verified intact ({chain.get('manifest_count')} manifests, 0 breaks)"
        elif chain and chain.get("valid") is False:
            s += ", and its evidence chain check found a break"
        parts.append(s + ".")
    if ctx.get("attention_sync"):
        parts.append(ctx["attention_sync"])
    return " ".join(parts)


def evidence_readiness(now, archive, okta_snapshot_at):
    groups = {}
    for key, meta in audit_store.COMPLIANCE_REPORTS.items():
        groups.setdefault(meta["control"], []).append(meta["label"])
    names = {"CC6": "Access controls", "CC7": "System operations", "CC8": "Change management"}
    rows = [{"group": f"{c} {names.get(c, '')}".strip(), "reports": labels, "built_from": "Archive", "current_through": archive.get("newest")}
            for c, labels in sorted(groups.items())]
    rows.append({"group": "Okta Admins", "reports": ["User principals, targets, custom roles, SoD against OPA roles, grant events overlaid"],
                 "built_from": "Snapshot + archive", "current_through": okta_snapshot_at})
    rows.append({"group": "Service Accounts and Secrets Access", "reports": ["Live roster merged with archive history"], "built_from": "Live + archive",
                 "current_through": archive.get("newest")})
    return rows
