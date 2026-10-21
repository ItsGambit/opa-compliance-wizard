"""Okta sign-ins and MFA by week, from the System Log archive (5.50.0).

Aggregated incrementally into small tables (audit_store migration 10: mfa_week_totals for everyone,
mfa_week_user per person) so the Overview never rescans the archive: a refresh reads only archived
events that arrived since the last one (rowid watermark in mfa_agg_state). Derived data: a rebuild
from the archive gives the same numbers (events are bucketed by their `published` week, so a
late-arriving event lands in the right week).

What is counted, per ISO week (Monday, UTC):
  signin            successful user.session.start events (sign-in volume)
  mfa_<class>       successful user.authentication.auth_via_mfa events by factor class
  mfa_unclassified  successful multi-factor events whose factor the event does not name
  mfa_fail          failed multi-factor attempts (FAILURE, ABANDONED, UNANSWERED, DENY); never the reason
The factor classification is the FastPass deployment tool's (activity/model.rs, classify_factor):
debugContext.debugData.factor, else authenticationContext.credentialType for SMS and EMAIL. A password
counted as a factor is left out, because it always pairs with a real factor.
"Password only" is DERIVED, not observed: sign-ins minus multi-factor sign-ins in the same week, never
below zero. It is labelled as such wherever it is shown.
Phishing-resistant means FastPass, passkey / security key (FIDO2 WebAuthn) and smart card (PIV), Okta's
own classification (the tool's Factor::phishing_resistant)."""
import json
from datetime import datetime, timedelta, timezone

import audit_store

EVENT_MFA = "user.authentication.auth_via_mfa"
EVENT_SESSION = "user.session.start"
FACTOR_CLASSES = (
    ("fastpass", "Okta FastPass"), ("passkey", "Passkey or security key (FIDO2 / WebAuthn)"), ("smart_card", "Smart card (PIV)"),
    ("okta_verify_push", "Okta Verify push"), ("okta_verify_code", "Okta Verify one-time code"), ("sms", "SMS text message"),
    ("voice", "Voice call"), ("email", "Email code or link"), ("other_code", "Other one-time code or token"),
    ("security_question", "Security question"), ("other", "Other (not recognised)"),
)
PHISHING_RESISTANT = ("fastpass", "passkey", "smart_card")
FAILED_OUTCOMES = ("FAILURE", "ABANDONED", "UNANSWERED", "DENY")
BATCH = 5000


def classify_factor(factor, credential_type=None):
    """Port of the FastPass tool's classify_factor. Returns a class key, "" (the password counted as a
    factor: leave the event out) or None (no factor named: unclassified)."""
    raw = factor.strip() if isinstance(factor, str) else ""
    if not raw:
        c = credential_type.strip().upper() if isinstance(credential_type, str) else ""
        return {"SMS": "sms", "EMAIL": "email"}.get(c)
    up = raw.upper()
    if up in ("PASSWORD_AS_FACTOR", "PASSWORD"):
        return ""
    direct = {
        "SIGNED_NONCE": "fastpass", "FIDO_WEBAUTHN": "passkey", "WEBAUTHN": "passkey",
        "OKTA_VERIFY_PUSH": "okta_verify_push", "OKTA_PUSH": "okta_verify_push", "PUSH": "okta_verify_push",
        "OKTA_SOFT_TOKEN": "okta_verify_code", "OKTA_VERIFY_TOTP": "okta_verify_code", "OKTA_VERIFY_CODE": "okta_verify_code",
        "SECURITY_QUESTION": "security_question",
    }
    if up in direct:
        return direct[up]
    if any(n in up for n in ("SMART_CARD", "PIV", "CERTIFICATE")):
        return "smart_card"
    if "SMS" in up:
        return "sms"
    if "CALL" in up or "VOICE" in up:
        return "voice"
    if "EMAIL" in up:
        return "email"
    if any(n in up for n in ("TOTP", "OTP", "TOKEN", "GOOGLE", "YUBIKEY")):
        return "other_code"
    return "other"


def week_start(published):
    """The Monday (YYYY-MM-DD, UTC) of the ISO week of a canonical published timestamp, or None."""
    try:
        dt = datetime.strptime(published[:10], "%Y-%m-%d")
    except (ValueError, TypeError):
        return None
    return (dt - timedelta(days=dt.weekday())).strftime("%Y-%m-%d")


def _observation(event_type, published, raw):
    """(week, actor_id, actor_alt, key) for one archived event, or None when it is not counted."""
    if not isinstance(raw, dict):
        return None
    week = week_start(published)
    if week is None:
        return None
    outcome = raw.get("outcome") if isinstance(raw.get("outcome"), dict) else {}
    result = str(outcome.get("result") or "").upper()
    failed = result in FAILED_OUTCOMES
    ok = result in ("SUCCESS", "") or result == "UNKNOWN"
    actor = raw.get("actor") if isinstance(raw.get("actor"), dict) else {}
    actor_id = actor.get("id") if isinstance(actor.get("id"), str) and actor.get("id") else None
    alt = actor.get("alternateId") if isinstance(actor.get("alternateId"), str) else None
    if event_type == EVENT_SESSION:
        return (week, actor_id, alt, "signin") if ok else None
    if event_type != EVENT_MFA:
        return None
    debug = (raw.get("debugContext") or {}).get("debugData") if isinstance(raw.get("debugContext"), dict) else None
    debug = debug if isinstance(debug, dict) else {}
    context = raw.get("authenticationContext") if isinstance(raw.get("authenticationContext"), dict) else {}
    cls = classify_factor(debug.get("factor"), context.get("credentialType"))
    if cls == "":
        return None
    if failed:
        return (week, actor_id, alt, "mfa_fail")
    if not ok:
        return None
    return (week, actor_id, alt, f"mfa_{cls}" if cls else "mfa_unclassified")


def refresh(environment_id, max_batches=None):
    """Folds archived events newer than the stored watermark into the aggregate tables and returns
    {"events_scanned", "events_counted", "rowid"}. Idempotent per event (the rowid watermark moves only
    with the commit of its batch), resumable, and bounded by `max_batches` when given."""
    conn = audit_store._get_connection()
    state = conn.execute("SELECT last_rowid, events_used FROM mfa_agg_state WHERE environment_id = ?", (environment_id,)).fetchone()
    last, used = (state["last_rowid"], state["events_used"]) if state else (0, 0)
    scanned = counted = batches = 0
    while max_batches is None or batches < max_batches:
        rows = conn.execute(
            "SELECT rowid AS rid, event_type, published, raw_json FROM events WHERE environment_id = ? "
            "AND event_type IN (?, ?) AND rowid > ? ORDER BY rowid LIMIT ?",
            (environment_id, EVENT_MFA, EVENT_SESSION, last, BATCH),
        ).fetchall()
        if not rows:
            break
        totals, users = {}, {}
        for r in rows:
            try:
                obs = _observation(r["event_type"], r["published"], json.loads(r["raw_json"]))
            except ValueError:
                obs = None
            if obs is None:
                continue
            week, actor_id, alt, key = obs
            totals[(week, key)] = totals.get((week, key), 0) + 1
            if actor_id:
                u = users.setdefault((week, actor_id, key), [alt and alt.lower(), 0])
                u[1] += 1
            counted += 1
        last = rows[-1]["rid"]
        scanned += len(rows)
        used += len(rows)
        batches += 1
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        with audit_store._db_lock:
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.executemany(
                    "INSERT INTO mfa_week_totals (environment_id, week, key, count) VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(environment_id, week, key) DO UPDATE SET count = count + excluded.count",
                    [(environment_id, w, k, c) for (w, k), c in totals.items()])
                conn.executemany(
                    "INSERT INTO mfa_week_user (environment_id, week, actor_id, actor_alt, key, count) VALUES (?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(environment_id, week, actor_id, key) DO UPDATE SET count = count + excluded.count, "
                    "actor_alt = COALESCE(excluded.actor_alt, actor_alt)",
                    [(environment_id, w, a, v[0], k, v[1]) for (w, a, k), v in users.items()])
                conn.execute(
                    "INSERT INTO mfa_agg_state (environment_id, last_rowid, events_used, built_at, updated_at) VALUES (?, ?, ?, ?, ?) "
                    "ON CONFLICT(environment_id) DO UPDATE SET last_rowid = excluded.last_rowid, events_used = excluded.events_used, "
                    "built_at = COALESCE(built_at, excluded.built_at), updated_at = excluded.updated_at",
                    (environment_id, last, used, now, now))
                conn.commit()
            except Exception:
                conn.rollback()
                raise
        if len(rows) < BATCH:
            break
    return {"events_scanned": scanned, "events_counted": counted, "rowid": last}


def rebuild(environment_id):
    """Drops this environment's aggregates and folds the whole archive again."""
    conn = audit_store._get_connection()
    with audit_store._db_lock:
        for t in ("mfa_week_user", "mfa_week_totals", "mfa_agg_state"):
            conn.execute(f"DELETE FROM {t} WHERE environment_id = ?", (environment_id,))
        conn.commit()
    return refresh(environment_id)


def built(environment_id):
    row = audit_store._get_connection().execute(
        "SELECT built_at, updated_at, events_used FROM mfa_agg_state WHERE environment_id = ?", (environment_id,)).fetchone()
    return dict(row) if row else None


def _weeks(now, count):
    monday = datetime.strptime(week_start(now.strftime("%Y-%m-%d")), "%Y-%m-%d")
    return [(monday - timedelta(weeks=i)).strftime("%Y-%m-%d") for i in range(count - 1, -1, -1)]


def _row_figures(week, counts):
    """The derived figures of one week from its raw counts."""
    classes = {k: counts.get(f"mfa_{k}", 0) for k, _ in FACTOR_CLASSES}
    unclassified = counts.get("mfa_unclassified", 0)
    mfa_ok = sum(classes.values()) + unclassified
    fail = counts.get("mfa_fail", 0)
    signins = counts.get("signin", 0)
    pr = sum(classes[k] for k in PHISHING_RESISTANT)
    classified = mfa_ok - unclassified
    return {
        "week": week, "signins": signins, "mfa_success": mfa_ok, "by_class": classes, "unclassified": unclassified,
        "phishing_resistant": pr, "phishing_resistant_share": round(pr / classified, 4) if classified else None,
        "sms_voice": classes["sms"] + classes["voice"],
        "password_only_derived": max(0, signins - mfa_ok) if signins else 0,
        "mfa_failed": fail, "mfa_failure_rate": round(fail / (fail + mfa_ok), 4) if (fail + mfa_ok) else None,
    }


def weekly(environment_id, weeks=26, now=None, actor_ids=None, actor_alts=None):
    """Weekly figures for the last `weeks` weeks, oldest first. With actor_ids / actor_alts the cohort is
    those people (an actor matches by Okta user id or by lower-cased login); without, everyone."""
    now = now or datetime.now(timezone.utc)
    weeks = max(1, min(int(weeks), 156))
    labels = _weeks(now, weeks)
    conn = audit_store._get_connection()
    per_week = {w: {} for w in labels}
    if actor_ids is None and actor_alts is None:
        for r in conn.execute("SELECT week, key, count FROM mfa_week_totals WHERE environment_id = ? AND week >= ? AND week <= ?",
                              (environment_id, labels[0], labels[-1])):
            per_week[r["week"]][r["key"]] = r["count"]
    else:
        ids, alts = sorted(set(actor_ids or ())), sorted({a.lower() for a in (actor_alts or ()) if a})
        seen = set()
        for column, values in (("actor_id", ids), ("actor_alt", alts)):
            for i in range(0, len(values), 400):
                chunk = values[i:i + 400]
                marks = ",".join("?" for _ in chunk)
                for r in conn.execute(
                        f"SELECT week, actor_id, key, count FROM mfa_week_user WHERE environment_id = ? AND week >= ? AND week <= ? "
                        f"AND {column} IN ({marks})", (environment_id, labels[0], labels[-1], *chunk)):
                    if (r["week"], r["actor_id"], r["key"]) in seen:
                        continue  # matched by both id and login: count once
                    seen.add((r["week"], r["actor_id"], r["key"]))
                    per_week[r["week"]][r["key"]] = per_week[r["week"]].get(r["key"], 0) + r["count"]
    return [_row_figures(w, per_week[w]) for w in labels]


def privileged_people(environment_id, actor_ids, actor_alts, weeks=26, now=None):
    """Per person (Okta id and/or login) figures over the window, for the audited privileged-people endpoint.
    Returns [{actor_id, login, signins, mfa_success, phishing_resistant_share, sms_voice, mfa_failed, by_class}]."""
    now = now or datetime.now(timezone.utc)
    labels = _weeks(now, max(1, min(int(weeks), 156)))
    conn = audit_store._get_connection()
    ids, alts = sorted(set(actor_ids or ())), sorted({a.lower() for a in (actor_alts or ()) if a})
    people = {}
    for column, values in (("actor_id", ids), ("actor_alt", alts)):
        for i in range(0, len(values), 400):
            chunk = values[i:i + 400]
            marks = ",".join("?" for _ in chunk)
            for r in conn.execute(
                    f"SELECT week, actor_id, actor_alt, key, count FROM mfa_week_user WHERE environment_id = ? AND week >= ? AND week <= ? "
                    f"AND {column} IN ({marks})", (environment_id, labels[0], labels[-1], *chunk)):
                p = people.setdefault(r["actor_id"], {"login": r["actor_alt"], "counts": {}, "seen": set()})
                if (r["week"], r["key"]) in p["seen"]:
                    continue
                p["seen"].add((r["week"], r["key"]))
                p["counts"][r["key"]] = p["counts"].get(r["key"], 0) + r["count"]
    out = []
    for actor_id, p in people.items():
        f = _row_figures("window", p["counts"])
        out.append({"actor_id": actor_id, "login": p["login"], **{k: f[k] for k in (
            "signins", "mfa_success", "phishing_resistant_share", "sms_voice", "mfa_failed", "by_class")}})
    out.sort(key=lambda x: (x["login"] or x["actor_id"]))
    return out


NON_PHISHING_RESISTANT = tuple(k for k, _ in FACTOR_CLASSES if k not in PHISHING_RESISTANT)


def people_counts(environment_id, weeks=13, now=None, actor_ids=None, actor_alts=None):
    """Distinct-people counts (no names): {"everyone_sms_voice_30d", "privileged_sms_voice_30d", "privileged_non_pr", "privileged_by_class",
    "privileged_total"}. 'sms_voice_30d' covers the blocks of seven days that overlap the last 30 days (the last five weeks). The privileged
    figures are for the cohort given by actor_ids / actor_alts (None when there is none)."""
    now = now or datetime.now(timezone.utc)
    labels = _weeks(now, max(1, min(int(weeks), 156)))
    last5 = labels[-5:]
    conn = audit_store._get_connection()
    out = {"everyone_sms_voice_30d": 0, "privileged_sms_voice_30d": None, "privileged_non_pr": None, "privileged_by_class": None, "privileged_total": None}
    out["everyone_sms_voice_30d"] = conn.execute(
        "SELECT COUNT(DISTINCT actor_id) FROM mfa_week_user WHERE environment_id = ? AND week >= ? AND week <= ? AND key IN ('mfa_sms', 'mfa_voice')",
        (environment_id, last5[0], last5[-1])).fetchone()[0]
    ids, alts = sorted(set(actor_ids or ())), sorted({a.lower() for a in (actor_alts or ()) if a})
    if not ids and not alts:
        return out
    by_class, nonpr, smsvoice, seen = {k: set() for k, _ in FACTOR_CLASSES}, set(), set(), set()
    for column, values in (("actor_id", ids), ("actor_alt", alts)):
        for i in range(0, len(values), 400):
            chunk = values[i:i + 400]
            marks = ",".join("?" for _ in chunk)
            for r in conn.execute(
                    f"SELECT week, actor_id, key FROM mfa_week_user WHERE environment_id = ? AND week >= ? AND week <= ? AND {column} IN ({marks}) AND key LIKE 'mfa_%'",
                    (environment_id, labels[0], labels[-1], *chunk)):
                cls = r["key"][4:]
                if cls in by_class:
                    by_class[cls].add(r["actor_id"])
                    if cls in NON_PHISHING_RESISTANT:
                        nonpr.add(r["actor_id"])
                    if cls in ("sms", "voice") and r["week"] in last5:
                        smsvoice.add(r["actor_id"])
    out.update({"privileged_non_pr": len(nonpr), "privileged_sms_voice_30d": len(smsvoice),
                "privileged_by_class": {k: len(v) for k, v in by_class.items()}})
    return out


def non_pr_people(environment_id, actor_ids, actor_alts, weeks=13, now=None, which="nonpr"):
    """Privileged people (figures per person) who used a non-phishing-resistant factor ('nonpr') or SMS / voice in the last five weeks
    ('smsvoice'), for the audited people list."""
    people = privileged_people(environment_id, actor_ids, actor_alts, weeks, now)
    keys = NON_PHISHING_RESISTANT if which == "nonpr" else ("sms", "voice")
    return [p for p in people if any(p["by_class"].get(k, 0) > 0 for k in keys)]
