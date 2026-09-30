"""SQLite-backed compliance audit archive -- the persistent store behind
the Compliance Reports dashboard (see the "OPA + Okta Compliance
Reporting Dashboard" plan). Imported by both the CLI and server/serve.py,
same "engine has zero duplication between CLI and dashboard" convention
as create_secret_folders.py.

Why SQLite and not another flat JSON file (like secrets_log_cache.json):
ingesting the FULL Okta System Log daily, retained for a year+, is a
fundamentally different scale than the existing per-project OPA-only
cache -- real 90-day exports from this project's own test tenants run
15k-56k rows. A flat JSON file has no indexing and requires a whole-file
read+rewrite on every merge; SQLite gives real date/event-type indexing
and scales to years of data while still being a single file with zero
new runtime dependency (stdlib sqlite3).

Two independent settings, confirmed with the user before building this:
- `ingestion_scope` ("curated" or "all") controls what gets WRITTEN on
  ingest. "curated" only inserts rows matching COMPLIANCE_EVENT_TYPES;
  "all" inserts everything Okta returns. This is chosen at ingest time,
  not applied as a later filter -- a customer who picks "curated" should
  see a correspondingly smaller table, not "everything, mostly hidden."
- Retention (retention_days / max_size_mb) is a SEPARATE pruning policy
  layered on top of whichever ingestion_scope was chosen. Curated events
  never auto-prune regardless of ingestion_scope -- even a "curated only"
  archive can still have its own (typically longer) retention cap.
"""
import csv
import json
import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# Verified compliance event-type mapping (Phase 1 of the plan -- every
# entry here was confirmed to actually exist via live probing against
# real tenants (dev + patlabs), not assumed from the audit-requirements
# guide, which got many exact event names wrong (see plan for the full
# guide-vs-reality comparison). Curated/allow-listed events are the ones
# that (a) never get pruned regardless of retention settings, and (b)
# are what an "ingestion_scope=curated" sync actually writes.
# ---------------------------------------------------------------------------
COMPLIANCE_EVENT_TYPES = {
    # CC6 -- Access Controls
    "user.authentication.auth_via_mfa": "mfa_enforcement",
    "policy.evaluate_sign_on": "mfa_enforcement",
    "user.session.start": "session_activity",
    "pam.auth_token.issue": "session_activity",  # confirmed live 2026-09-30: "Issue an authentication token for a web session"
    "user.lifecycle.create": "provisioning",
    "user.lifecycle.deactivate": "provisioning",
    "group.user_membership.add": "role_group_changes",
    "group.user_membership.remove": "role_group_changes",
    "user.account.privilege.grant": "admin_privilege_grants",
    "access.request.create": "jit_access_requests",
    "access.request.update": "jit_access_requests",
    "access.request.resolve": "jit_access_requests",
    "access.request.expire": "jit_access_requests",
    # CC7 -- System Operations
    "security.request.blocked": "threat_detection",
    "security.protected_action.attempt": "threat_detection",
    # CC8 -- Change Management
    "system.api_token.create": "api_token_lifecycle",
    "system.api_token.revoke": "api_token_lifecycle",
    "policy.rule.add": "policy_modifications",
    "policy.rule.update": "policy_modifications",
    "policy.mapping.create": "policy_modifications",
    "policy.lifecycle.create": "policy_modifications",
    # OPA / PAM
    "pam.secret.create": "pam_secrets",
    "pam.secret.update": "pam_secrets",
    "pam.secret.delete": "pam_secrets",
    "pam.secret.reveal": "pam_secrets",
    "pam.secret_folder.create": "pam_secrets",
    "pam.secret_folder.update": "pam_secrets",
    "pam.secret_folder.delete": "pam_secrets",
    "pam.resource.checkout": "pam_jit_access",
    "pam.resource.checkin.start": "pam_jit_access",
    "pam.resource.checkin.end": "pam_jit_access",
    "pam.user_creds.issue": "pam_sessions",
    "pam.gateway_creds.issue": "pam_sessions",
    "pam.server.ssh_login": "pam_sessions",
    "pam.service_account.password.reveal": "pam_credential_reveals",
    # confirmed live 2026-09-30: "reveal password for a vaulted server
    # account to an end-user" -- same conceptual bucket as the
    # service-account reveal above, just for a server-local account.
    "pam.server_account.password.reveal": "pam_credential_reveals",
    # confirmed live 2026-09-30: actor is the Server itself reporting a
    # local-account password change result -- a credential-lifecycle
    # event, same bucket as secret create/update/delete/reveal.
    "pam.server_account.password_change.update": "pam_secrets",
    # confirmed live 2026-09-30: SystemPrincipal-initiated, target is the
    # Active Directory Connection itself -- recurring automated AD sync,
    # a real CC7 system-operations signal, not previously covered by any
    # report.
    "pam.active_directory.account_discovery.complete": "ad_sync_activity",
    # confirmed live 2026-09-30: real, high-volume (55 combined events/90d
    # on patlabs) service-account credential rotation lifecycle, not
    # previously covered by any report.
    "pam.service_account.password_rotation.start": "credential_rotation",
    "pam.service_account.password_rotation.end": "credential_rotation",
    "pam.security_policy.create": "pam_policy_modifications",
    "pam.security_policy.update": "pam_policy_modifications",
}

INGESTION_SCOPES = ("curated", "all")

# ---------------------------------------------------------------------------
# Report definitions (Phase 4) -- one entry per report_key value that
# appears in COMPLIANCE_EVENT_TYPES above. `event_types` for each report
# is derived from COMPLIANCE_EVENT_TYPES automatically (see
# _event_types_for_report below) rather than duplicated here, so the two
# structures can never drift out of sync with each other.
# ---------------------------------------------------------------------------
COMPLIANCE_REPORTS = {
    "mfa_enforcement": {
        "label": "MFA Enforcement",
        "control": "CC6",
        "description": "Every MFA challenge (success and abandoned) plus the sign-on policy evaluation that gates it.",
    },
    "session_activity": {
        "label": "Session Activity",
        "control": "CC7",
        "description": "Successful sign-ins to Okta across all apps.",
    },
    "provisioning": {
        "label": "Provisioning & De-provisioning",
        "control": "CC6",
        "description": "User lifecycle create/deactivate events.",
    },
    "role_group_changes": {
        "label": "Role/Group Changes",
        "control": "CC6",
        "description": "Group membership add/remove — RBAC drift over time.",
    },
    "admin_privilege_grants": {
        "label": "Admin Privilege Grants",
        "control": "CC6",
        "description": "Super-admin / role assignment changes.",
    },
    "jit_access_requests": {
        "label": "JIT Access Requests",
        "control": "CC6",
        "description": (
            "Access-request lifecycle (create/update/resolve/expire) -- proves an access request was "
            "made and resolved. Known limitation, confirmed live 2026-09-30 against a real denied "
            "request: Okta's own System Log does not capture the actual approve/deny DECISION anywhere "
            "on the resolve event (debugContext.debugData.decisions is always the literal string \"[]\", "
            "and outcome.result is always SUCCESS regardless of the decision -- this is a real gap in "
            "Okta's own audit trail, not something this tool can surface by picking a different field)."
        ),
    },
    "threat_detection": {
        "label": "Threat Detection",
        "control": "CC7",
        "description": "Blocked requests and protected-action attempts flagged by Okta's own security controls.",
    },
    "api_token_lifecycle": {
        "label": "API Token Lifecycle",
        "control": "CC8",
        "description": "Service-account API token create/revoke.",
    },
    "policy_modifications": {
        "label": "Policy Modifications",
        "control": "CC8",
        "description": "Global Okta sign-on/security policy rule and mapping changes.",
    },
    "pam_secrets": {
        "label": "PAM Secrets",
        "control": "CC6",
        "description": "Vaulted secret and secret-folder create/update/delete/reveal.",
    },
    "pam_jit_access": {
        "label": "PAM JIT Access (Checkout/Checkin)",
        "control": "CC6",
        "description": "Zero Standing Privileges evidence — resource checkout and checkin.",
    },
    "pam_sessions": {
        "label": "PAM Sessions",
        "control": "CC7",
        "description": "Credential issuance and SSH logins to privileged servers. Note: SSH login actor is the OS-level username, not the Okta identity — correlate with a nearby credential-issuance row to attribute a session to a real person.",
    },
    "pam_credential_reveals": {
        "label": "PAM Credential Reveals",
        "control": "CC6",
        "description": "Service-account/shared-credential password reveals.",
    },
    "pam_policy_modifications": {
        "label": "PAM Policy Modifications",
        "control": "CC8",
        "description": "OPA security policy create/update.",
    },
    "ad_sync_activity": {
        "label": "Active Directory Sync Activity",
        "control": "CC7",
        "description": "Recurring, automated Active Directory account discovery -- evidence that AD-vaulted accounts stay in sync with the domain.",
    },
    "credential_rotation": {
        "label": "Credential Rotation",
        "control": "CC8",
        "description": "Service-account password rotation lifecycle (scheduled and manual).",
    },
}


def _event_types_for_report(report_key):
    return [et for et, key in COMPLIANCE_EVENT_TYPES.items() if key == report_key]


def list_reports():
    """Returns every report definition plus its derived event_types list --
    the frontend's report picker renders directly from this, grouped by
    `control`."""
    return [
        {"key": key, "event_types": _event_types_for_report(key), **meta}
        for key, meta in COMPLIANCE_REPORTS.items()
    ]


def _audit_db_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "audit_store.db")


_db_lock = threading.Lock()
_connections = {}  # thread-id -> sqlite3.Connection, since sqlite3 connections
                    # aren't safe to share across threads without care


def _get_connection():
    """One connection per thread (sqlite3's own recommendation), all
    pointing at the same on-disk file -- WAL mode lets a background sync
    write while a dashboard request reads concurrently without either
    blocking the other, which is a real requirement here (unlike
    secrets_log_cache.json's whole-file read+rewrite, which had no
    locking story at all for exactly this concurrent-access case)."""
    tid = threading.get_ident()
    conn = _connections.get(tid)
    if conn is None:
        conn = sqlite3.connect(_audit_db_path(), timeout=30)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.row_factory = sqlite3.Row
        _connections[tid] = conn
    return conn


def init_db():
    conn = _get_connection()
    with _db_lock:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                uuid TEXT NOT NULL,
                environment TEXT NOT NULL,
                event_type TEXT NOT NULL,
                published TEXT NOT NULL,
                actor_id TEXT,
                actor_display_name TEXT,
                actor_alternate_id TEXT,
                outcome_result TEXT,
                is_curated INTEGER NOT NULL DEFAULT 0,
                raw_json TEXT NOT NULL,
                PRIMARY KEY (environment, uuid)
            );
            CREATE INDEX IF NOT EXISTS idx_events_env_published
                ON events (environment, published);
            CREATE INDEX IF NOT EXISTS idx_events_env_type
                ON events (environment, event_type);
            CREATE INDEX IF NOT EXISTS idx_events_env_curated_published
                ON events (environment, is_curated, published);

            CREATE TABLE IF NOT EXISTS sync_state (
                environment TEXT PRIMARY KEY,
                last_synced_at TEXT,
                last_sync_completed_at TEXT,
                last_sync_status TEXT,
                last_sync_error TEXT,
                total_events_ingested INTEGER NOT NULL DEFAULT 0,
                ingestion_scope TEXT NOT NULL DEFAULT 'curated'
            );
        """)
        conn.commit()

    # Added 2026-09-30 for the Resources tab's per-resource history drill-
    # down -- resource_id/resource_alternate_id/resource_type_detail used
    # to be computed at READ time in _four_field_row() from raw_json only
    # (never stored, never indexed), so "show me every report row about
    # THIS server/account" would have meant scanning + JSON-parsing the
    # whole table in Python on every click. Storing them as real, indexed
    # columns instead makes that lookup fast forever after. SQLite has no
    # "ADD COLUMN IF NOT EXISTS" -- ALTER TABLE is run unconditionally and
    # the "duplicate column" error it raises on every run after the first
    # is caught and ignored, matching this file's existing convention of
    # never crashing on a safe re-run.
    with _db_lock:
        for column in ("resource_id", "resource_alternate_id", "resource_type_detail"):
            try:
                conn.execute(f"ALTER TABLE events ADD COLUMN {column} TEXT")
            except sqlite3.OperationalError as exc:
                if "duplicate column" not in str(exc).lower():
                    raise
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_env_resource_id ON events (environment, resource_id)"
        )
        conn.commit()

    backfill_resource_columns()


# ---------------------------------------------------------------------------
# Event shape normalization -- live API (nested JSON) and CSV export
# (flattened target0-3.* columns) have DIFFERENT shapes and need separate
# parsers, both converging on the same normalized row tuple so ingestion
# (dedup-by-uuid, is_curated flagging, INSERT OR REPLACE) is identical
# either way.
# ---------------------------------------------------------------------------
def _normalize_live_event(event):
    """Shapes one raw Okta System Log API event (nested JSON, `target`
    is a list of dicts) into the normalized row tuple. resource_id/
    resource_alternate_id/resource_type_detail are computed here (via the
    same _resource_fields helper _four_field_row uses at read time) so
    they land in the DB as real, indexed columns -- see resource_history."""
    actor = event.get("actor") or {}
    outcome = event.get("outcome") or {}
    resource_id, resource_alt_id, resource_type_detail = _resource_fields(event.get("eventType"), event)
    return (
        event.get("uuid"),
        event.get("eventType"),
        event.get("published"),
        actor.get("id"),
        actor.get("displayName"),
        actor.get("alternateId"),
        outcome.get("result"),
        json.dumps(event, separators=(",", ":")),
        resource_id,
        resource_alt_id,
        resource_type_detail,
    )


def _normalize_csv_row(row):
    """Shapes one row from a System Log CSV export (flattened
    target0-3.* columns, dotted header names) into the same normalized
    row tuple as _normalize_live_event, PLUS reconstructs a `target`
    list so raw_json's shape matches a live event closely enough for
    report/drill-down code to treat both sources identically."""
    targets = []
    for i in range(4):
        t_id = row.get(f"target{i}.id", "")
        t_type = row.get(f"target{i}.type", "")
        if not t_id and not t_type:
            continue
        targets.append({
            "id": t_id,
            "type": t_type,
            "alternateId": row.get(f"target{i}.alternate_id", ""),
            "displayName": row.get(f"target{i}.display_name", ""),
        })
    raw = {
        "uuid": row.get("uuid"),
        "eventType": row.get("event_type"),
        "published": row.get("timestamp"),
        "displayMessage": row.get("display_message"),
        "severity": row.get("severity"),
        "actor": {
            "id": row.get("actor.id"),
            "type": row.get("actor.type"),
            "displayName": row.get("actor.display_name"),
            "alternateId": row.get("actor.alternate_id"),
        },
        "outcome": {"result": row.get("outcome.result"), "reason": row.get("outcome.reason")},
        "client": {"ipAddress": row.get("client.ip_address")},
        "target": targets,
        "_source": "csv_import",
    }
    resource_id, resource_alt_id, resource_type_detail = _resource_fields(row.get("event_type"), raw)
    return (
        row.get("uuid"),
        row.get("event_type"),
        row.get("timestamp"),
        row.get("actor.id"),
        row.get("actor.display_name"),
        row.get("actor.alternate_id"),
        row.get("outcome.result"),
        json.dumps(raw, separators=(",", ":")),
        resource_id,
        resource_alt_id,
        resource_type_detail,
    )


def _insert_rows(conn, environment, rows, ingestion_scope):
    """rows: list of normalized tuples from either normalizer above.
    Filters by ingestion_scope BEFORE inserting (see module docstring --
    scope governs what's written, not a later filter), dedupes by
    (environment, uuid). Uses INSERT OR IGNORE, not OR REPLACE -- a raw
    Okta System Log event is immutable once published (matches the
    guide's own "Immutable Audit Trails" requirement), so a genuine
    re-ingest of an already-stored uuid should be a true no-op, not a
    silent rewrite. This also makes `inserted_count` mean what it says:
    real new rows only, via cur.rowcount (0 = already existed, 1 = new)
    -- an OR REPLACE would report every row as "inserted" every time,
    even a pure re-run of the same data (caught live: re-importing the
    same CSV a second time reported 3149 "inserted" again instead of 0,
    and doubled total_events_ingested -- fixed by switching to OR IGNORE
    + checking rowcount instead of a blind per-row counter).
    Returns (new_row_count, max_published_seen_across_ALL_rows_scanned)
    -- max_published still reflects every row this call looked at
    (including ones that turned out to be duplicates), since the
    watermark must advance based on what was FETCHED, not just what was
    newly inserted, or a delta sync could re-scan the same already-seen
    day forever."""
    max_published = None
    inserted = 0
    with _db_lock:
        for (uuid, event_type, published, actor_id, actor_name, actor_alt, outcome, raw_json,
             resource_id, resource_alt_id, resource_type_detail) in rows:
            if not uuid or not event_type or not published:
                continue  # malformed row (e.g. a CSV export's trailing blank line) -- skip, don't crash
            is_curated = 1 if event_type in COMPLIANCE_EVENT_TYPES else 0
            if ingestion_scope == "curated" and not is_curated:
                continue
            cur = conn.execute(
                """INSERT OR IGNORE INTO events
                   (uuid, environment, event_type, published, actor_id,
                    actor_display_name, actor_alternate_id, outcome_result,
                    is_curated, raw_json, resource_id, resource_alternate_id,
                    resource_type_detail)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (uuid, environment, event_type, published, actor_id,
                 actor_name, actor_alt, outcome, is_curated, raw_json,
                 resource_id, resource_alt_id, resource_type_detail),
            )
            inserted += cur.rowcount
            if max_published is None or published > max_published:
                max_published = published
        conn.commit()
    return inserted, max_published


def is_first_sync(environment):
    conn = _get_connection()
    row = conn.execute(
        "SELECT 1 FROM sync_state WHERE environment = ?", (environment,)
    ).fetchone()
    return row is None


def get_sync_state(environment):
    """`total_events_ingested` is always recomputed live via COUNT(*),
    overriding whatever the stored column says -- caught live during
    Phase 3 testing: the stored running-counter approach silently drifted
    to a wrong value (reset to 0) after a `sync_state` row got deleted
    without also deleting the environment's `events` rows (an entirely
    plausible real scenario, not just a test artifact -- e.g. an admin
    resetting sync configuration without wanting to lose the archive).
    A derived COUNT(*) can never drift from the data it's describing, so
    the stored column is effectively vestigial now; kept in the schema
    only so existing rows don't need a migration."""
    conn = _get_connection()
    row = conn.execute(
        "SELECT * FROM sync_state WHERE environment = ?", (environment,)
    ).fetchone()
    if row is None:
        return None
    result = dict(row)
    result["total_events_ingested"] = conn.execute(
        "SELECT COUNT(*) FROM events WHERE environment = ?", (environment,)
    ).fetchone()[0]
    return result


def _upsert_sync_state(conn, environment, **fields):
    existing = conn.execute(
        "SELECT * FROM sync_state WHERE environment = ?", (environment,)
    ).fetchone()
    merged = dict(existing) if existing else {
        "environment": environment, "last_synced_at": None,
        "last_sync_completed_at": None, "last_sync_status": None,
        "last_sync_error": None, "total_events_ingested": 0,
        "ingestion_scope": "curated",
    }
    merged.update(fields)
    conn.execute(
        """INSERT OR REPLACE INTO sync_state
           (environment, last_synced_at, last_sync_completed_at, last_sync_status,
            last_sync_error, total_events_ingested, ingestion_scope)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (merged["environment"], merged["last_synced_at"], merged["last_sync_completed_at"],
         merged["last_sync_status"], merged["last_sync_error"], merged["total_events_ingested"],
         merged["ingestion_scope"]),
    )
    conn.commit()


CHUNK_DAYS = 1  # window size for the day-by-day walk below


def sync_okta_events(okta_client, environment, ingestion_scope, since=None, on_progress=None):
    """Pulls System Log events from the real Okta API via the EXISTING
    OktaClient.get_system_log (pagination + rate-limit handling already
    built in, shared with every other Okta call in this project) and
    ingests them. `since` defaults to 90 days ago if this is the first
    sync for `environment`, else resumes from the last watermark.

    Walks the window one day at a time (via get_system_log's `until`)
    rather than one unbounded call -- confirmed live 2026-09-29: a
    genuinely busy tenant's automatic OPA credential-rotation traffic
    alone produces >1,100 raw events/day, so a 90-day backfill can
    exceed max_pages=200 (200k events) within a SINGLE unbounded call,
    silently truncating the sync short of "now" even though every
    individual API call succeeded. Chunking bounds each day's page count
    well under that cap, and -- just as importantly -- advances and
    persists the watermark after EVERY chunk (not just at the very end),
    so a mid-run crash/restart resumes from the last completed day
    instead of re-fetching the whole window or silently losing progress.

    Returns {"inserted": int, "scanned": int, "since": str, "chunks": int}."""
    if ingestion_scope not in INGESTION_SCOPES:
        raise ValueError(f"ingestion_scope must be one of {INGESTION_SCOPES}")
    conn = _get_connection()

    if since is None:
        state = get_sync_state(environment)
        if state and state.get("last_synced_at"):
            since = state["last_synced_at"]
        else:
            since = (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    original_since = since
    now_dt = datetime.now(timezone.utc)
    cursor = datetime.fromisoformat(since.replace("Z", "+00:00"))
    total_inserted = 0
    total_scanned = 0
    chunks = 0

    while cursor < now_dt:
        chunk_until_dt = min(cursor + timedelta(days=CHUNK_DAYS), now_dt)
        chunk_since = cursor.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        chunk_until = chunk_until_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        if on_progress:
            on_progress("fetch", "progress", f"{chunk_since} .. {chunk_until}")
        events = okta_client.get_system_log(
            since=chunk_since, until=chunk_until, limit=1000, sort_order="ASCENDING", max_pages=200
        )
        total_scanned += len(events)

        rows = [_normalize_live_event(e) for e in events]
        inserted, max_published = _insert_rows(conn, environment, rows, ingestion_scope)
        total_inserted += inserted
        chunks += 1

        # Persist progress after EVERY chunk, not just at the end -- a
        # restart mid-backfill resumes from here instead of from scratch.
        watermark = max_published or chunk_until
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        _upsert_sync_state(
            conn, environment,
            last_synced_at=watermark,
            last_sync_completed_at=now_iso,
            last_sync_status="running",
            last_sync_error=None,
            total_events_ingested=(get_sync_state(environment) or {}).get("total_events_ingested", 0) + inserted,
            ingestion_scope=ingestion_scope,
        )
        cursor = chunk_until_dt

    _upsert_sync_state(conn, environment, last_sync_status="success")
    if on_progress:
        on_progress("ingest", "done", f"{total_inserted} new row(s) inserted across {chunks} day-chunk(s)")
    return {"inserted": total_inserted, "scanned": total_scanned, "since": original_since, "chunks": chunks}


def import_from_csv(csv_path, environment, ingestion_scope, on_progress=None):
    """Ingests a System Log CSV export (the FLATTENED column shape --
    event_type, timestamp, actor.*, target0-3.*, etc. -- confirmed
    against a real 90-day export this session, distinct from the live
    API's nested JSON shape, hence the separate _normalize_csv_row).
    Reuses the exact same ingestion_scope-filtered, dedup-by-uuid insert
    path as sync_okta_events, so a CSV backfill and a later live delta
    sync merge into one consistent store with no duplicate rows."""
    if ingestion_scope not in INGESTION_SCOPES:
        raise ValueError(f"ingestion_scope must be one of {INGESTION_SCOPES}")
    conn = _get_connection()

    if on_progress:
        on_progress("read_csv", "start", csv_path)
    rows = []
    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for csv_row in reader:
            rows.append(_normalize_csv_row(csv_row))
    if on_progress:
        on_progress("read_csv", "done", f"{len(rows)} row(s) read")

    inserted, max_published = _insert_rows(conn, environment, rows, ingestion_scope)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    existing_state = get_sync_state(environment)
    # A CSV import advances the watermark too, IF it's newer than what's
    # already recorded -- e.g. importing a 90-day export shouldn't roll
    # last_synced_at BACKWARD if a live sync already ran more recently.
    prior_watermark = (existing_state or {}).get("last_synced_at")
    new_watermark = max_published if (not prior_watermark or (max_published and max_published > prior_watermark)) else prior_watermark
    _upsert_sync_state(
        conn, environment,
        last_synced_at=new_watermark,
        last_sync_completed_at=now,
        last_sync_status="success",
        last_sync_error=None,
        total_events_ingested=(existing_state or {}).get("total_events_ingested", 0) + inserted,
        ingestion_scope=ingestion_scope,
    )
    if on_progress:
        on_progress("ingest", "done", f"{inserted} new row(s) inserted")
    return {"inserted": inserted, "scanned": len(rows)}


def prune_events(environment, retention_days=None, max_size_mb=None):
    """Deletes non-curated rows older than retention_days. Curated rows
    (is_curated=1) are NEVER auto-pruned regardless of ingestion_scope --
    even a "curated only" archive can have its own separate, longer
    retention. If max_size_mb is also set and the DB file is still over
    that size after the time-based prune, walks the cutoff back one day
    at a time (oldest non-curated first) until under the cap, or until
    every non-curated row is gone (curated rows are never sacrificed to
    satisfy a size cap).

    Returns {"pruned": int, "cutoff": str|None}."""
    conn = _get_connection()
    pruned_total = 0
    cutoff = None

    if retention_days is not None:
        cutoff_dt = datetime.now(timezone.utc) - timedelta(days=retention_days)
        cutoff = cutoff_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        with _db_lock:
            cur = conn.execute(
                "DELETE FROM events WHERE environment = ? AND is_curated = 0 AND published < ?",
                (environment, cutoff),
            )
            pruned_total += cur.rowcount
            conn.commit()

    if max_size_mb is not None:
        conn.execute("VACUUM")  # reclaim space from the deletes above before measuring
        max_bytes = max_size_mb * 1024 * 1024
        step_days = 1
        # Walk the cutoff back further, oldest non-curated first, until under the cap
        # or nothing non-curated is left to prune.
        for _ in range(3650):  # hard safety cap -- never loop forever
            size = os.path.getsize(_audit_db_path())
            if size <= max_bytes:
                break
            remaining = conn.execute(
                "SELECT COUNT(*) FROM events WHERE environment = ? AND is_curated = 0",
                (environment,),
            ).fetchone()[0]
            if remaining == 0:
                break
            oldest = conn.execute(
                "SELECT MIN(published) FROM events WHERE environment = ? AND is_curated = 0",
                (environment,),
            ).fetchone()[0]
            if not oldest:
                break
            step_cutoff = (
                datetime.fromisoformat(oldest.replace("Z", "+00:00")) + timedelta(days=step_days)
            ).strftime("%Y-%m-%dT%H:%M:%S.000Z")
            with _db_lock:
                cur = conn.execute(
                    "DELETE FROM events WHERE environment = ? AND is_curated = 0 AND published < ?",
                    (environment, step_cutoff),
                )
                pruned_total += cur.rowcount
                conn.commit()
            conn.execute("VACUUM")

    return {"pruned": pruned_total, "cutoff": cutoff}


def _normalize_until(until):
    """A bare date like "2026-09-29" (what an HTML <input type="date">
    naturally sends) must NOT be compared directly against a full ISO
    timestamp column via a plain string `<=` -- "2026-09-29T10:00:00.000Z"
    sorts AFTER the bare string "2026-09-29" lexicographically, so a
    naive `published <= until` would silently exclude every event on
    that day, not include it as a user picking "to: Sep 29" would
    expect. Caught before shipping, by directly testing the string
    comparison Python would actually perform. Bumps a bare 10-character
    date up to end-of-day (23:59:59.999) so the comparison includes the
    whole day; a value that's already a full timestamp passes through
    unchanged."""
    if until and len(until) == 10:  # "YYYY-MM-DD" exactly, no time component
        return until + "T23:59:59.999Z"
    return until


def query_events(environment, event_types=None, since=None, until=None, actor_id=None, resource_id=None, limit=1000):
    """Generic report query -- used by every COMPLIANCE_REPORTS preset in
    Phase 4, and by resource_history below. Returns raw rows (dicts with
    the full parsed raw_json under "raw"), shaping to the four-field
    standard is left to the caller since different reports want different
    extra columns from the same underlying rows.

    resource_id, when given, matches against EITHER the stored
    resource_id OR resource_alternate_id column (both are populated from
    the same real target id -- see _resource_fields -- and for most
    resource kinds confirmed live to just be the same value twice, but
    matching both covers any kind where they'd genuinely differ) and uses
    idx_events_env_resource_id, so this stays fast even on a large archive."""
    conn = _get_connection()
    until = _normalize_until(until)
    clauses = ["environment = ?"]
    params = [environment]
    if event_types:
        placeholders = ",".join("?" for _ in event_types)
        clauses.append(f"event_type IN ({placeholders})")
        params.extend(event_types)
    if since:
        clauses.append("published >= ?")
        params.append(since)
    if until:
        clauses.append("published <= ?")
        params.append(until)
    if actor_id:
        clauses.append("actor_id = ?")
        params.append(actor_id)
    if resource_id:
        clauses.append("(resource_id = ? OR resource_alternate_id = ?)")
        params.extend([resource_id, resource_id])
    sql = (
        "SELECT uuid, event_type, published, actor_id, actor_display_name, "
        "actor_alternate_id, outcome_result, resource_id, resource_alternate_id, "
        "resource_type_detail, raw_json FROM events WHERE "
        + " AND ".join(clauses)
        + " ORDER BY published DESC LIMIT ?"
    )
    params.append(limit)
    out = []
    for row in conn.execute(sql, params):
        d = dict(row)
        d["raw"] = json.loads(d.pop("raw_json"))
        out.append(d)
    return out


def count_events(environment, event_types=None, since=None, until=None):
    """Cheap count-only query (no raw_json parsing) -- used by the report
    picker's per-card event counts, where fetching every row's full
    payload just to discard it would be wasteful."""
    conn = _get_connection()
    until = _normalize_until(until)
    clauses = ["environment = ?"]
    params = [environment]
    if event_types:
        placeholders = ",".join("?" for _ in event_types)
        clauses.append(f"event_type IN ({placeholders})")
        params.extend(event_types)
    if since:
        clauses.append("published >= ?")
        params.append(since)
    if until:
        clauses.append("published <= ?")
        params.append(until)
    sql = "SELECT COUNT(*) FROM events WHERE " + " AND ".join(clauses)
    return conn.execute(sql, params).fetchone()[0]


# Full per-event-type audit, 2026-09-30, against two real 90-day System
# Log CSV exports from patlabs (55,857 + 56,478 rows -- far higher sample
# size than a live API pull for every event type at once). "Skip a
# leading Team" was the ORIGINAL fix, but a full audit of every mapped
# event type's real target-type ordering found it's genuinely
# event-type-specific, not just "skip Team" -- several events have a
# non-Team target ahead of the real resource too:
#   pam.server_account.password_change.update: Team, Server, SERVER
#     ACCOUNT, Resource Group -- skip-Team picked Server (the host), but
#     Server Account (index 2) is the actual credential that changed.
#   pam.user_creds.issue: Project, Team, USER -- skip-Team picked Project
#     (context), but User (index 2) is who the credential was issued to.
#   pam.gateway_creds.issue: Client, GATEWAY, Team -- skip-Team picked
#     Client (the requesting device), but Gateway (index 1) is the real
#     resource being accessed.
#   user.account.privilege.grant: User, ROLE_ASSIGNED, ROLE -- the User
#     (index 0) is who RECEIVED the grant (useful, but not "the
#     resource" for a Trust Services report), the ROLE (index 2, e.g.
#     "Super Organization Administrator") is what was actually granted.
#   user.session.start: AuthenticatorEnrollment, APPINSTANCE -- the MFA
#     method (index 0) was being shown as "the resource," when the real
#     point of a session-activity report is which app was accessed
#     (index 1).
# Every other mapped event type's target[0] (after skipping a leading
# Team, still the common case) was CONFIRMED correct in this same audit
# -- see the plan file's own audit table for the full per-event-type
# breakdown, not just these five corrected cases.
_PRIMARY_TARGET_TYPE_BY_EVENT = {
    "pam.server_account.password_change.update": "Server Account",
    "pam.user_creds.issue": "User",
    "pam.gateway_creds.issue": "Gateway",
    "user.account.privilege.grant": "ROLE",
    "user.session.start": "AppInstance",
}


def _primary_target(event_type, targets):
    """Picks the target entry that's actually "the affected resource" for
    this specific event type -- see _PRIMARY_TARGET_TYPE_BY_EVENT above
    for the handful of event types where that ISN'T simply "the first
    non-Team target" (the general-case fallback below, still correct for
    every other mapped event type per the same audit)."""
    wanted_type = _PRIMARY_TARGET_TYPE_BY_EVENT.get(event_type)
    if wanted_type:
        for t in targets:
            if t.get("type") == wanted_type:
                return t
        # Real event existed but didn't have the expected target shape
        # (e.g. an older/differently-shaped event) -- fall through to the
        # general case rather than returning nothing.
    for t in targets:
        if t.get("type") != "Team":
            return t
    return targets[0] if targets else None


def _resource_fields(event_type, raw):
    """Computes (resource_id, resource_alternate_id, resource_type_detail)
    for one raw event -- shared by _four_field_row (read-time display) AND
    the ingest normalizers (_normalize_live_event/_normalize_csv_row, which
    persist these as real, indexed DB columns for the Resources tab's
    per-resource history drill-down -- see resource_history). Keeping ONE
    implementation means the stored columns and the read-time display can
    never drift out of sync with each other.

    resource_id/resource_alternate_id (real Okta user id / email, confirmed
    live 2026-09-30 on e.g. user.lifecycle.create's target) matter for the
    same reason actor_id/actor_alternate_id already did for the "User"
    column -- displayName alone is not a unique identifier (a real tenant
    can have two people who share a display name but have distinct Okta
    user ids/emails) -- AND, as of this drill-down feature, this same id is
    the join key back to a resource's own `id` in the Access Explorer
    resource inventory (AccessServer/AccessGateway/etc. -- confirmed live
    2026-09-30 by comparing a real Gateway/Server Account/Database Account
    target's id directly against the matching AccessModel entry's id).

    resource_type_detail is a SEPARATE thing from the target's own generic
    `type` field (e.g. "Service Account") -- it surfaces
    debugContext.debugData.resourceType when present (confirmed live
    2026-09-30: real values include PAM_DATABASE_ACCOUNT, SERVER_ACCOUNT on
    pam.resource.checkout/checkin.* events), which is what actually
    distinguishes checking out a database account from checking out a
    server account -- the target's own generic type alone can't tell those
    apart."""
    targets = raw.get("target") or []
    primary = _primary_target(event_type, targets)
    resource_id = primary.get("id") if primary else None
    resource_alternate_id = primary.get("alternateId") if primary else None
    resource_type_detail = ((raw.get("debugContext") or {}).get("debugData") or {}).get("resourceType")
    return resource_id or None, resource_alternate_id or None, resource_type_detail or None


def backfill_resource_columns():
    """One-time (per environment's worth of pre-existing rows) migration,
    called from init_db() right after the ALTER TABLEs above -- populates
    resource_id/resource_alternate_id/resource_type_detail for every row
    that predates those columns existing. Idempotent and cheap to call on
    every boot: only rows where ALL THREE columns are still NULL are
    touched (a real row can legitimately have resource_type_detail NULL
    while resource_id is set, e.g. any non-PAM-checkout event -- so "any
    one of the three is set" is treated as "already backfilled", not
    "still needs it", to avoid ever recomputing rows that were already
    correctly populated at ingest time going forward).

    Batches UPDATEs (500 rows per transaction) rather than one giant
    transaction, since a real archive was seen this session at 56k+ rows
    for a single 90-day window -- holding the write lock for one huge
    transaction would block concurrent report reads for longer than
    necessary."""
    conn = _get_connection()
    BATCH_SIZE = 500
    with _db_lock:
        rows = conn.execute(
            """SELECT environment, uuid, event_type, raw_json FROM events
               WHERE resource_id IS NULL AND resource_alternate_id IS NULL
                     AND resource_type_detail IS NULL"""
        ).fetchall()
    if not rows:
        return 0
    updated = 0
    batch = []
    for row in rows:
        raw = json.loads(row["raw_json"])
        resource_id, resource_alt_id, resource_type_detail = _resource_fields(row["event_type"], raw)
        batch.append((resource_id, resource_alt_id, resource_type_detail, row["environment"], row["uuid"]))
        if len(batch) >= BATCH_SIZE:
            with _db_lock:
                conn.executemany(
                    """UPDATE events SET resource_id = ?, resource_alternate_id = ?,
                       resource_type_detail = ? WHERE environment = ? AND uuid = ?""",
                    batch,
                )
                conn.commit()
            updated += len(batch)
            batch = []
    if batch:
        with _db_lock:
            conn.executemany(
                """UPDATE events SET resource_id = ?, resource_alternate_id = ?,
                   resource_type_detail = ? WHERE environment = ? AND uuid = ?""",
                batch,
            )
            conn.commit()
        updated += len(batch)
    return updated


def _four_field_row(event_row):
    """Shapes one query_events() row to the "four-field standard" the
    audit-requirements guide calls for on every exported report row:
    User, Action, Timestamp, Affected Resource -- plus Outcome and the
    real event_type, which every report needs regardless of its specific
    focus. `raw.target` is Okta's own target list (or, for a CSV-imported
    row, the reconstructed list built by _normalize_csv_row) -- see
    _primary_target for which entry is picked as "the resource".

    resource_id/resource_alternate_id/resource_type_detail are read
    straight from the row's own stored columns (populated at ingest time
    by _resource_fields -- see there for what each one means) rather than
    recomputed from raw_json here, so a query_events() caller that already
    filtered/joined on those columns (e.g. resource_history) doesn't pay
    to recompute values it already has. resource_type (the target's own
    generic `type`, e.g. "Service Account") is display-only and NOT one of
    the stored/indexed columns, so it's still derived here."""
    raw = event_row["raw"]
    targets = raw.get("target") or []
    primary = _primary_target(event_row["event_type"], targets)
    resource = primary.get("displayName") if primary else None
    resource_type = primary.get("type") if primary else None
    return {
        "uuid": event_row["uuid"],
        "user": event_row["actor_display_name"] or event_row["actor_alternate_id"] or event_row["actor_id"] or "unknown",
        "actor_alternate_id": event_row["actor_alternate_id"],
        "action": raw.get("displayMessage") or event_row["event_type"],
        "event_type": event_row["event_type"],
        "timestamp": event_row["published"],
        "resource": resource or "",
        "resource_type": resource_type or "",
        "resource_type_detail": event_row.get("resource_type_detail") or "",
        "resource_id": event_row.get("resource_id") or "",
        "resource_alternate_id": event_row.get("resource_alternate_id") or "",
        "outcome": event_row["outcome_result"] or "",
        "targets": targets,  # full target list -- some reports need target1/2 too, e.g. PAM's Team/Server
    }


def run_report(report_key, environment, since=None, until=None, limit=1000):
    """Runs one named COMPLIANCE_REPORTS preset and returns rows shaped to
    the four-field standard. Raises KeyError if report_key isn't a real
    report."""
    if report_key not in COMPLIANCE_REPORTS:
        raise KeyError(f"Unknown report: {report_key!r}")
    event_types = _event_types_for_report(report_key)
    rows = query_events(environment, event_types=event_types, since=since, until=until, limit=limit)
    return [_four_field_row(r) for r in rows]


def resource_history(environment, resource_id, since=None, until=None, limit=1000):
    """Every report row across EVERY event type (not scoped to one
    COMPLIANCE_REPORTS preset) whose resource_id/resource_alternate_id
    matches this one real resource's own id -- the Resources tab's
    per-resource drill-down (click a server/AD account/DB account/etc.,
    see its full compliance history). The join key was confirmed live
    2026-09-30 by comparing real target ids on archived patlabs events
    directly against the matching AccessModel entries' own ids (a
    Gateway target's id IS that gateway's AccessGateway.id, etc. -- see
    the plan file for the exact sampled events). No resource_id given
    means "nothing to look up" -- returns [] rather than every event ever,
    since an empty/falsy id is never a real resource's id."""
    if not resource_id:
        return []
    rows = query_events(environment, since=since, until=until, resource_id=resource_id, limit=limit)
    return [_four_field_row(r) for r in rows]
