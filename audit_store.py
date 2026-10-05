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
import hashlib
import json
import os
import secrets
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# Verified compliance event-type mapping (Phase 1 of the plan -- every
# entry here was confirmed to actually exist via live probing against
# real tenants (dev + a real production tenant), not assumed from the audit-requirements
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
    # confirmed live 2026-09-30: real, high-volume service-account
    # credential rotation lifecycle on a real tenant, not previously
    # covered by any report.
    "pam.service_account.password_rotation.start": "credential_rotation",
    "pam.service_account.password_rotation.end": "credential_rotation",
    "pam.security_policy.create": "pam_policy_modifications",
    "pam.security_policy.update": "pam_policy_modifications",
    # confirmed real (90-day CSV export, a real tenant): a human's local OPA
    # client (laptop/workstation running the desktop app or `sft`)
    # enrolling to be able to make SSH/RDP connections at all -- a CC6
    # access-control signal distinct from pam_sessions (which is "did they
    # connect" after this already happened), not previously covered by
    # any report.
    "pam.client.enroll": "pam_client_enrollment",
    # confirmed real (live System Log scan, a real tenant, 2026-10-01): Okta's
    # own org-wide DEVICE lifecycle, separate from pam.client.enroll above
    # (an OPA client is the PAM connection agent; an Okta Device is the
    # underlying managed/unmanaged hardware MFA'd against) -- a CC6
    # device-trust signal, not previously covered by any report. ONLY
    # these three are live-confirmed with a real example this session --
    # Okta's own device-lifecycle docs describe five states (Created,
    # Active, Suspended, Deactivated, Deleted) and five transitions
    # (activate, suspend, unsuspend, deactivate, delete), so
    # device.lifecycle.suspend/.unsuspend/.deactivate/.delete almost
    # certainly also exist, but none fired in this tenant's real activity
    # within the probe window -- deliberately NOT guessed into this dict
    # per this project's standing rule (every entry here must be
    # live-confirmed, not inferred). Add them once a real example exists.
    "device.enrollment.create": "device_management",
    "device.lifecycle.activate": "device_management",
    "device.user.add": "device_management",
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
    "pam_client_enrollment": {
        "label": "Client Enrollment",
        "control": "CC6",
        "description": "A user's local OPA client (laptop/workstation) enrolling to connect to privileged resources. See also the Access Explorer's Resources tab for the current live roster of enrolled clients.",
    },
    "device_management": {
        "label": "Device Management",
        "control": "CC6",
        "description": "Okta-managed device enrollment and user association -- device-trust evidence, separate from OPA client enrollment above. Known gap: only enrollment/activation/user-add are covered; suspend/unsuspend/deactivate/delete exist per Okta's own device-lifecycle docs but have no live-confirmed eventType yet (see COMPLIANCE_EVENT_TYPES comment). See also the Access Explorer's Resources tab for the current live device inventory.",
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
_thread_local = threading.local()  # holds .conn -- one sqlite3.Connection per thread


def _get_connection():
    """One connection per thread (sqlite3's own recommendation), all
    pointing at the same on-disk file -- WAL mode lets a background sync
    write while a dashboard request reads concurrently without either
    blocking the other, which is a real requirement here (unlike
    secrets_log_cache.json's whole-file read+rewrite, which had no
    locking story at all for exactly this concurrent-access case).

    FIX (confirmed real leak, external review 2026-09-30): this used to
    key connections in a plain module-level dict by threading.get_ident().
    server/serve.py uses ThreadingHTTPServer, which spawns a brand-new OS
    thread per incoming HTTP request -- every request that ever touched
    this module opened one more sqlite3.Connection (and its OS file
    descriptor) that NOTHING ever removed from that dict, even after the
    thread itself exited. Unbounded memory + FD growth on a long-running
    server. threading.local() ties the connection's lifetime to the
    Thread object itself instead of a dict entry keyed by a recycled OS
    thread id -- once the (short-lived, one-per-request) thread object is
    garbage collected, its .conn attribute goes with it, with no manual
    bookkeeping and no way to leak."""
    conn = getattr(_thread_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(_audit_db_path(), timeout=30)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.row_factory = sqlite3.Row
        _thread_local.conn = conn
    return conn


def _schema_version(conn):
    """Returns the highest-applied migration version, or 0 if
    schema_migrations doesn't exist yet (a fresh database, or one that
    predates this mechanism -- see migration 1, which creates the table
    itself as its own first act)."""
    try:
        row = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
        return row[0] or 0
    except sqlite3.OperationalError:
        return 0


def _table_columns(conn, table):
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def _migration_001_unified_schema(conn):
    """The Phase 2 migration: creates every table this app now stores in
    SQLite (environment metadata, active-environment pointers, sync
    schedules, the banner) alongside the archive tables
    (events/sync_state/event_targets).

    Two real starting shapes handled here, confirmed by direct inspection
    rather than assumed:
    1. **Fresh database** (no `events` table at all) -- the CREATE TABLE
       statements below create every table with its final shape
       (`environment_id`, not `environment`) directly.
    2. **Existing pre-Phase-2 database** (real `events`/`sync_state`/
       `event_targets` tables already populated, keyed by bare display
       name in a column literally named `environment`) -- renamed IN
       PLACE via `ALTER TABLE ... RENAME COLUMN`, empirically confirmed
       (against both this app's installed SQLite versions, 3.46.1 and
       3.49.1) to correctly carry the primary key, foreign key clause,
       and every index referencing that column along with it -- no manual
       index/FK rebuild needed. Real data is PRESERVED, not recreated;
       only the column's name changes here. The column's real VALUES
       (today's bare display names) are re-pointed to real
       `environment_id`s by `create_secret_folders.migrate_legacy_
       environments_json` immediately after this schema migration runs,
       since resolving the real collision-tiebreak logic (which
       `environment_id` a bare name should map to, when more than one
       shares that name) needs keyring access this module doesn't have.

    `environment_id` was deliberately chosen as the real
    `app_environments` foreign key everywhere, instead of continuing to
    key the archive by bare display name -- the whole point of this
    migration. `active_environments.environment_id REFERENCES
    app_environments(environment_id) ON DELETE CASCADE` is a REAL fix
    over the old environments.json design (confirmed via code history: a
    deleted environment used to leave a dangling active-pointer unless
    delete_environment remembered to clean it up by hand) -- SQLite
    enforces this at the schema level now, for free."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS app_environments (
            environment_id TEXT PRIMARY KEY,
            owner_id TEXT,
            display_name TEXT NOT NULL,
            base_domain TEXT NOT NULL,
            team_name TEXT NOT NULL,
            key_id TEXT NOT NULL,
            okta_url TEXT,
            shared INTEGER NOT NULL DEFAULT 0,
            preserve_logs_locally INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(owner_id, display_name)
        );

        CREATE TABLE IF NOT EXISTS active_environments (
            owner_key TEXT PRIMARY KEY,
            environment_id TEXT NOT NULL REFERENCES app_environments(environment_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS sync_schedules (
            environment_id TEXT PRIMARY KEY REFERENCES app_environments(environment_id) ON DELETE CASCADE,
            enabled INTEGER NOT NULL DEFAULT 0,
            run_time TEXT NOT NULL DEFAULT '02:00',
            ingestion_scope TEXT NOT NULL DEFAULT 'curated',
            retention_days INTEGER,
            retention_max_size_mb INTEGER
        );

        CREATE TABLE IF NOT EXISTS banner_config (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            enabled INTEGER NOT NULL DEFAULT 0,
            message TEXT NOT NULL DEFAULT '',
            variant TEXT NOT NULL DEFAULT 'warning',
            dismissible INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS events (
            uuid TEXT NOT NULL,
            environment_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            published TEXT NOT NULL,
            actor_id TEXT,
            actor_display_name TEXT,
            actor_alternate_id TEXT,
            outcome_result TEXT,
            is_curated INTEGER NOT NULL DEFAULT 0,
            raw_json TEXT NOT NULL,
            resource_id TEXT,
            resource_alternate_id TEXT,
            resource_type_detail TEXT,
            PRIMARY KEY (environment_id, uuid)
        );

        CREATE TABLE IF NOT EXISTS sync_state (
            environment_id TEXT PRIMARY KEY,
            last_synced_at TEXT,
            last_sync_completed_at TEXT,
            last_sync_status TEXT,
            last_sync_error TEXT,
            total_events_ingested INTEGER NOT NULL DEFAULT 0,
            ingestion_scope TEXT NOT NULL DEFAULT 'curated'
        );

        CREATE TABLE IF NOT EXISTS event_targets (
            environment_id TEXT NOT NULL,
            uuid TEXT NOT NULL,
            target_id TEXT,
            target_alternate_id TEXT,
            target_display_name TEXT,
            FOREIGN KEY (environment_id, uuid) REFERENCES events(environment_id, uuid)
        );
    """)

    # The three CREATE TABLE IF NOT EXISTS above are no-ops when the
    # table already exists under the OLD column name ("environment") --
    # detect and rename in place, preserving real data, rather than ever
    # dropping/recreating. Order matters: events before event_targets
    # (its FOREIGN KEY clause references events' own column), though
    # SQLite's RENAME COLUMN updates both sides regardless of order --
    # confirmed empirically, this ordering is just for readability.
    for table in ("events", "sync_state", "event_targets"):
        columns = _table_columns(conn, table)
        if "environment" in columns and "environment_id" not in columns:
            conn.execute(f"ALTER TABLE {table} RENAME COLUMN environment TO environment_id")

    conn.executescript("""
        CREATE INDEX IF NOT EXISTS idx_events_env_published
            ON events (environment_id, published);
        CREATE INDEX IF NOT EXISTS idx_events_env_type
            ON events (environment_id, event_type);
        CREATE INDEX IF NOT EXISTS idx_events_env_curated_published
            ON events (environment_id, is_curated, published);
        CREATE INDEX IF NOT EXISTS idx_events_env_resource_id
            ON events (environment_id, resource_id);
        CREATE INDEX IF NOT EXISTS idx_event_targets_id
            ON event_targets (environment_id, target_id);
        CREATE INDEX IF NOT EXISTS idx_event_targets_alt_id
            ON event_targets (environment_id, target_alternate_id);
        CREATE INDEX IF NOT EXISTS idx_event_targets_name
            ON event_targets (environment_id, target_display_name);
        CREATE INDEX IF NOT EXISTS idx_event_targets_env_uuid
            ON event_targets (environment_id, uuid);
    """)


def _migration_002_ingestion_manifests(conn):
    """Phase 6: a hash-chained ingestion batch manifest, one row per
    sync_okta_events()/import_from_csv() call -- see
    _record_ingestion_manifest/verify_ingestion_chain below. Pure
    CREATE TABLE/INDEX IF NOT EXISTS -- a brand-new table, not a reshape
    of an existing one, so (unlike migration 1) there's no column
    rename/backfill step.

    Deliberately NO FOREIGN KEY to app_environments, unlike
    active_environments/sync_schedules -- this table is COMPLIANCE
    EVIDENCE, same category as events/sync_state/event_targets (none of
    which reference app_environments either), not an administrative
    pointer. delete_environment() only ever touches app_environments
    (confirmed: it never deletes from events/sync_state/event_targets --
    an environment CONFIGURATION being removed must not destroy years of
    archived audit history for that tenant). An FK with ON DELETE
    CASCADE here would silently erase the integrity chain the moment
    someone deleted and re-added an environment -- exactly the kind of
    accidental, hard-to-notice evidence loss this phase exists to make
    detectable, not cause."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS ingestion_manifests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            environment_id TEXT NOT NULL,
            source TEXT NOT NULL,
            since TEXT,
            until TEXT,
            row_count INTEGER NOT NULL,
            batch_hash TEXT NOT NULL,
            prev_manifest_hash TEXT,
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_ingestion_manifests_env_created
            ON ingestion_manifests (environment_id, created_at);
    """)


def _migration_003_pending_admin_actions(conn):
    """Phase 3: a server-held pending-action record binding a step-up MFA
    approval to the EXACT payload that was reviewed, closing the gap
    where a step-up cookie (valid for any payload submitted within its
    TTL) could be used to apply a DIFFERENT access_control.json change
    than the one the admin actually looked at -- see
    create_pending_admin_action/consume_pending_admin_action below.

    Deliberately NO FOREIGN KEY -- actor_sub is an Okta subject
    identifier, not a row in any table this app owns (same reasoning as
    ingestion_manifests' own just-shipped precedent: don't borrow
    app_environments' ON DELETE CASCADE convention for a table that
    isn't an environment-scoped administrative pointer).

    actor_sub is nullable, NOT NOT NULL -- confirmed live (2026-10-01)
    that a local/direct run (no login gate in front at all) legitimately
    has actor_sub=None (see server/serve.py's own
    `actor_sub = None if owner_key == LOCAL_OWNER_KEY_HEADER else
    owner_key`, and its save route's existing comment: "A direct/local
    run... is exempt" from the admin check, same exemption this project
    already applies elsewhere). consume_pending_admin_action's `row[
    "actor_sub"] != actor_sub` comparison already handles None == None
    correctly; only the schema's own NOT NULL was too strict."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS pending_admin_actions (
            action_id TEXT PRIMARY KEY,
            actor_sub TEXT,
            action_type TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            payload_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            consumed_at TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_pending_admin_actions_expires
            ON pending_admin_actions (expires_at);
    """)


def _migration_004_drop_preserve_logs_locally(conn):
    """Phase 5 of docs/fast-follow-redesign.md: retires the
    preserve_logs_locally toggle (and the secrets_log_cache.json/Fernet
    machinery it controlled -- see create_secret_folders.py's
    build_secrets_access_report) now that any environment with even one
    completed sync gets its full, unretention-limited history from this
    database's own archive instead. Confirmed safe to drop: not part of
    app_environments' UNIQUE(owner_id, display_name) constraint or any
    index, and DROP COLUMN support (SQLite 3.35.0+) is well below both
    real installs' confirmed SQLite versions (3.46.1/3.49.1)."""
    conn.execute("ALTER TABLE app_environments DROP COLUMN preserve_logs_locally")


MIGRATIONS = {
    1: _migration_001_unified_schema,
    2: _migration_002_ingestion_manifests,
    3: _migration_003_pending_admin_actions,
    4: _migration_004_drop_preserve_logs_locally,
}


def run_migrations():
    """Applies every migration in MIGRATIONS whose version is greater
    than what's already recorded in schema_migrations, in order, each in
    its own transaction. Replaces the old ad hoc `ALTER TABLE ... except
    sqlite3.OperationalError` pattern (and its two always-re-run backfill
    functions) that was this file's only schema-growth mechanism before
    Phase 2 -- every future schema change should add a new numbered
    function to MIGRATIONS, not another one-off patch.

    Idempotent: calling this on an already-fully-migrated database is a
    cheap no-op (one SELECT MAX(version), no transactions opened)."""
    conn = _get_connection()
    current_version = _schema_version(conn)
    for version in sorted(v for v in MIGRATIONS if v > current_version):
        with _db_lock:
            try:
                MIGRATIONS[version](conn)
                conn.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                    (version, datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")),
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise


def init_db():
    run_migrations()
    import create_secret_folders
    create_secret_folders.migrate_legacy_environments_json()
    backfill_resource_columns()
    backfill_event_targets()
    _cleanup_expired_pending_admin_actions()
    _cleanup_retired_secrets_log_cache()


def _cleanup_retired_secrets_log_cache():
    """One-shot Phase 5 cleanup, mirroring Phase 1's own
    _legacy_environment_storage_name precedent: deletes
    secrets_log_cache.json (fully superseded by this database's archive
    for any synced environment, and never load-bearing for one that
    hasn't synced -- see build_secrets_access_report) and its dedicated
    Fernet key from the keyring, if either still exists from before this
    phase. Safe to call on every init_db() -- both checks are already
    no-ops once cleaned up once."""
    import create_secret_folders
    path = os.path.join(os.path.dirname(os.path.abspath(create_secret_folders.__file__)), "secrets_log_cache.json")
    if os.path.isfile(path):
        os.remove(path)
        create_secret_folders.log("INFO", f"Removed retired {path} -- its data is fully superseded by this database's own archive.")
    create_secret_folders.keyring_delete("_shared", "secrets_log_cache_key")


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
    they land in the DB as real, indexed columns -- see resource_history.

    The trailing `targets` list (Okta's own raw target dicts) is carried
    through separately from resource_id/etc above -- _insert_rows fans it
    out into one event_targets row per real target, for
    resource_history's "was this resource ANY target on this event, not
    just the ONE primary one" query. Real bug found 2026-09-30: a genuine
    Server target (e.g. usp-srv1) can coexist on an event alongside a
    Server Account target that _primary_target prefers as "the" resource
    -- resource_id alone silently drops the Server's own id, so clicking
    it in the Resources tab found zero history even though real activity
    against it existed."""
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
        event.get("target") or [],
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
        targets,
    )


def _insert_rows(conn, environment_id, rows, ingestion_scope):
    """rows: list of normalized tuples from either normalizer above.
    Filters by ingestion_scope BEFORE inserting (see module docstring --
    scope governs what's written, not a later filter), dedupes by
    (environment_id, uuid). Uses INSERT OR IGNORE, not OR REPLACE -- a raw
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
    Returns (new_row_count, max_published_seen_across_ALL_rows_scanned,
    new_uuids) -- max_published still reflects every row this call
    looked at (including ones that turned out to be duplicates), since
    the watermark must advance based on what was FETCHED, not just what
    was newly inserted, or a delta sync could re-scan the same
    already-seen day forever. new_uuids (Phase 6) is only the uuids of
    rows that were genuinely new this call (cur.rowcount == 1) -- fed to
    _record_ingestion_manifest by the caller to hash exactly what this
    batch actually added, not every row merely scanned."""
    max_published = None
    inserted = 0
    new_uuids = []
    with _db_lock:
        for (uuid, event_type, published, actor_id, actor_name, actor_alt, outcome, raw_json,
             resource_id, resource_alt_id, resource_type_detail, targets) in rows:
            if not uuid or not event_type or not published:
                continue  # malformed row (e.g. a CSV export's trailing blank line) -- skip, don't crash
            is_curated = 1 if event_type in COMPLIANCE_EVENT_TYPES else 0
            if ingestion_scope == "curated" and not is_curated:
                continue
            cur = conn.execute(
                """INSERT OR IGNORE INTO events
                   (uuid, environment_id, event_type, published, actor_id,
                    actor_display_name, actor_alternate_id, outcome_result,
                    is_curated, raw_json, resource_id, resource_alternate_id,
                    resource_type_detail)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (uuid, environment_id, event_type, published, actor_id,
                 actor_name, actor_alt, outcome, is_curated, raw_json,
                 resource_id, resource_alt_id, resource_type_detail),
            )
            inserted += cur.rowcount
            if max_published is None or published > max_published:
                max_published = published
            # Only fan out into event_targets on a genuine new insert
            # (cur.rowcount == 1) -- INSERT OR IGNORE is a no-op on a
            # duplicate uuid, and re-inserting the same event's targets
            # every re-run would duplicate rows with nothing to dedupe on.
            if cur.rowcount:
                new_uuids.append(uuid)
                if targets:
                    conn.executemany(
                        """INSERT INTO event_targets
                           (environment_id, uuid, target_id, target_alternate_id, target_display_name)
                           VALUES (?, ?, ?, ?, ?)""",
                        [
                            (environment_id, uuid, t.get("id"), t.get("alternateId"), t.get("displayName"))
                            for t in targets
                        ],
                    )
        conn.commit()
    return inserted, max_published, new_uuids


def _record_ingestion_manifest(conn, environment_id, source, since, until, new_uuids):
    """Phase 6: writes one hash-chained manifest row for a completed
    ingestion call (one per sync_okta_events()/import_from_csv()
    invocation, NOT per internal day-chunk -- see this phase's design
    notes). batch_hash is a sha256 of the sorted new_uuids list -- an
    identifier hash, not a content hash, computed once at ingestion time
    so verify_ingestion_chain never needs to re-read `events` later (and
    is therefore unaffected by prune_events deleting old non-curated
    rows afterward). A batch with zero new rows still gets a row here
    (hash of an empty list) -- "nothing new happened" is itself a
    chained, verifiable fact, not a silent skip that would leave a gap.

    Chains to the immediately preceding manifest row for this SAME
    environment_id (by insertion order) -- not a separate mutable
    "chain head" column, since this one-row lookup is cheap and avoids
    a second piece of state that could drift out of sync with the table
    it's describing. Caller must hold conn (same connection as the
    row-insert transaction it's covering); this function commits on its
    own since both of this phase's callers write their manifest row in
    a separate locked section after their chunking loop, not inside
    _insert_rows' own per-chunk lock (see sync_okta_events)."""
    batch_hash = hashlib.sha256("\n".join(sorted(new_uuids)).encode()).hexdigest()
    with _db_lock:
        prev = conn.execute(
            "SELECT batch_hash FROM ingestion_manifests WHERE environment_id = ? ORDER BY id DESC LIMIT 1",
            (environment_id,),
        ).fetchone()
        conn.execute(
            """INSERT INTO ingestion_manifests
               (environment_id, source, since, until, row_count, batch_hash, prev_manifest_hash, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (environment_id, source, since, until, len(new_uuids), batch_hash,
             prev["batch_hash"] if prev else None,
             datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")),
        )
        conn.commit()
    return batch_hash


def verify_ingestion_chain(environment_id):
    """Walks this environment's ingestion_manifests in insertion order
    and confirms each row's prev_manifest_hash matches the preceding
    row's batch_hash (and the first row's prev_manifest_hash is NULL) --
    a cheap, mechanical "has this chain been tampered with" check that
    never touches `events` (the stored hashes are the source of truth,
    not something recomputed from live data -- see
    _record_ingestion_manifest), so it stays fast regardless of archive
    size. Returns {"valid": bool, "manifest_count": int, "broken_at":
    id|None} -- broken_at is the id of the first row whose
    prev_manifest_hash doesn't match, or None if the chain is intact (or
    empty -- zero manifests is a valid, intact chain of nothing)."""
    conn = _get_connection()
    rows = conn.execute(
        "SELECT id, batch_hash, prev_manifest_hash FROM ingestion_manifests WHERE environment_id = ? ORDER BY id ASC",
        (environment_id,),
    ).fetchall()
    expected_prev = None
    for row in rows:
        if row["prev_manifest_hash"] != expected_prev:
            return {"valid": False, "manifest_count": len(rows), "broken_at": row["id"]}
        expected_prev = row["batch_hash"]
    return {"valid": True, "manifest_count": len(rows), "broken_at": None}


class PendingActionError(Exception):
    """Phase 3: raised by consume_pending_admin_action with a specific,
    HTTP-layer-actionable `reason` -- "not_found", "expired",
    "already_consumed", or "actor_mismatch" -- so a caller can return a
    precise error (e.g. "your session expired, try again" vs. a generic
    403) instead of collapsing every failure into one bare status code."""

    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def create_pending_admin_action(actor_sub, action_type, payload, ttl_seconds):
    """Mints an unguessable action_id (secrets.token_urlsafe, server-side
    only -- never client-supplied) and stores `payload` -- the EXACT
    settings an admin reviewed before triggering a step-up MFA
    transaction -- server-side, keyed by that id. This is the mechanism
    that closes the real gap confirmed in this app's step-up flow: a
    step-up cookie, once issued, previously authorized ANY payload
    submitted within its TTL by that sub, not specifically the one shown
    on screen when step-up was triggered. The browser now only ever
    carries this opaque action_id through the Okta redirect (see
    auth_gate.py's FLOW_COOKIE/STEPUP_COOKIE), never the actual settings.

    payload_hash (sha256 of the canonical, sorted-keys JSON encoding) is
    stored as defense-in-depth alongside the action_id lookup itself --
    not currently re-verified by consume_pending_admin_action (the
    action_id -> payload_json binding is already exact), but gives any
    future auditor/caller a cheap way to confirm a stored payload wasn't
    altered after the fact without needing to trust the row's own
    plaintext column."""
    conn = _get_connection()
    action_id = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    payload_json = json.dumps(payload, separators=(",", ":"))
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    payload_hash = hashlib.sha256(canonical.encode()).hexdigest()
    with _db_lock:
        conn.execute(
            """INSERT INTO pending_admin_actions
               (action_id, actor_sub, action_type, payload_json, payload_hash, created_at, expires_at, consumed_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, NULL)""",
            (action_id, actor_sub, action_type, payload_json, payload_hash,
             now.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
             (now + timedelta(seconds=ttl_seconds)).strftime("%Y-%m-%dT%H:%M:%S.000Z")),
        )
        conn.commit()
    return action_id


def consume_pending_admin_action(action_id, actor_sub):
    """Looks up `action_id`, verifies it belongs to `actor_sub`, hasn't
    expired, and hasn't already been consumed -- if all three hold,
    marks it consumed and returns the stored payload (parsed from JSON).
    Raises PendingActionError otherwise, with a specific `reason`.

    Single-use is enforced via one UPDATE ... WHERE consumed_at IS NULL
    followed by checking cur.rowcount, inside the SAME _db_lock-held
    transaction as the lookup -- mirrors _insert_rows' own
    INSERT-OR-IGNORE-then-check-rowcount dedup discipline, so two
    concurrent consume attempts for the same action_id can't both
    observe consumed_at IS NULL and both succeed."""
    conn = _get_connection()
    with _db_lock:
        row = conn.execute(
            "SELECT * FROM pending_admin_actions WHERE action_id = ?", (action_id,)
        ).fetchone()
        if row is None:
            raise PendingActionError("not_found")
        if row["actor_sub"] != actor_sub:
            raise PendingActionError("actor_mismatch")
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        if row["expires_at"] < now_iso:
            raise PendingActionError("expired")
        cur = conn.execute(
            "UPDATE pending_admin_actions SET consumed_at = ? WHERE action_id = ? AND consumed_at IS NULL",
            (now_iso, action_id),
        )
        conn.commit()
        if cur.rowcount == 0:
            raise PendingActionError("already_consumed")
    return json.loads(row["payload_json"])


def _cleanup_expired_pending_admin_actions():
    """Bounded, cheap sweep -- deletes expired-and-never-consumed rows.
    Called once from init_db() (same place backfill_resource_columns/
    backfill_event_targets already run on boot), not on a scheduler --
    prevents indefinite accumulation of abandoned actions (an admin who
    starts a step-up flow and never completes it) without needing new
    scheduling infrastructure for what is, at this app's scale, a tiny
    table."""
    conn = _get_connection()
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    with _db_lock:
        conn.execute(
            "DELETE FROM pending_admin_actions WHERE expires_at < ? AND consumed_at IS NULL",
            (now_iso,),
        )
        conn.commit()


def is_first_sync(environment_id):
    conn = _get_connection()
    row = conn.execute(
        "SELECT 1 FROM sync_state WHERE environment_id = ?", (environment_id,)
    ).fetchone()
    return row is None


def get_sync_state(environment_id):
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
        "SELECT * FROM sync_state WHERE environment_id = ?", (environment_id,)
    ).fetchone()
    if row is None:
        return None
    result = dict(row)
    result["total_events_ingested"] = conn.execute(
        "SELECT COUNT(*) FROM events WHERE environment_id = ?", (environment_id,)
    ).fetchone()[0]
    return result


def _upsert_sync_state(conn, environment_id, **fields):
    existing = conn.execute(
        "SELECT * FROM sync_state WHERE environment_id = ?", (environment_id,)
    ).fetchone()
    merged = dict(existing) if existing else {
        "environment_id": environment_id, "last_synced_at": None,
        "last_sync_completed_at": None, "last_sync_status": None,
        "last_sync_error": None, "total_events_ingested": 0,
        "ingestion_scope": "curated",
    }
    merged.update(fields)
    conn.execute(
        """INSERT OR REPLACE INTO sync_state
           (environment_id, last_synced_at, last_sync_completed_at, last_sync_status,
            last_sync_error, total_events_ingested, ingestion_scope)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (merged["environment_id"], merged["last_synced_at"], merged["last_sync_completed_at"],
         merged["last_sync_status"], merged["last_sync_error"], merged["total_events_ingested"],
         merged["ingestion_scope"]),
    )
    conn.commit()


CHUNK_DAYS = 1  # window size for the day-by-day walk below

# BUG FIX (external review, 2026-10-05, DATA-02): the System Log is
# eventually consistent -- an event can become queryable moments AFTER a
# sync already ran past its `published` time. The old code let the final
# chunk's `until` reach the literal wall-clock "now" and set the watermark
# from whatever was actually returned, so an event indexed a few seconds
# late, with a `published` time just behind the watermark, was never
# fetched again -- permanently, since Okta's own 90-day retention makes
# the gap unrecoverable later. For a tool whose entire purpose is complete
# audit evidence, silent omission is the worst failure mode.
#
# Two independent guards, both from the review's own recommendation:
# - SAFETY_LAG: a sync's chunking never asks Okta for events newer than
#   "now minus this", so a run never advances the watermark into a window
#   Okta might still be indexing.
# - WATERMARK_OVERLAP: resuming from a STORED watermark (since=None) starts
#   a bit before it, not exactly at it, re-scanning a window that was
#   already fully synced -- INSERT OR IGNORE's existing dedup-by-uuid
#   makes this free of duplicates, so overlap costs nothing but a few
#   re-scanned rows per run.
# Neither applies to an explicitly-passed `since` (a caller -- e.g. a
# manual CSV backfill comparison, or a test -- asked for a specific start
# point on purpose; only the automatic resume-from-watermark path needs
# the safety margin).
SAFETY_LAG_SECONDS = 5 * 60
WATERMARK_OVERLAP_SECONDS = 60 * 60


def sync_okta_events(okta_client, environment_id, ingestion_scope, since=None, on_progress=None):
    """Pulls System Log events from the real Okta API via the EXISTING
    OktaClient.get_system_log (pagination + rate-limit handling already
    built in, shared with every other Okta call in this project) and
    ingests them. `since` defaults to 90 days ago if this is the first
    sync for `environment_id`, else resumes from just before the last
    watermark (see WATERMARK_OVERLAP_SECONDS above).

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
    The walk never reaches literal "now" -- see SAFETY_LAG_SECONDS above.

    Returns {"inserted": int, "scanned": int, "since": str, "chunks": int,
    "complete": bool} -- "complete" is False if a day-chunk hit
    get_system_log's max_pages cap (see that method's docstring); in that
    case the sync stops early with last_sync_status="error" and the
    watermark deliberately NOT advanced past the incomplete chunk, so the
    next sync run retries it rather than silently skipping lost events."""
    if ingestion_scope not in INGESTION_SCOPES:
        raise ValueError(f"ingestion_scope must be one of {INGESTION_SCOPES}")
    conn = _get_connection()

    if since is None:
        state = get_sync_state(environment_id)
        if state and state.get("last_synced_at"):
            watermark_dt = datetime.fromisoformat(state["last_synced_at"].replace("Z", "+00:00"))
            since = (watermark_dt - timedelta(seconds=WATERMARK_OVERLAP_SECONDS)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        else:
            since = (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    original_since = since
    safe_now_dt = datetime.now(timezone.utc) - timedelta(seconds=SAFETY_LAG_SECONDS)
    cursor = datetime.fromisoformat(since.replace("Z", "+00:00"))
    total_inserted = 0
    total_scanned = 0
    chunks = 0
    all_new_uuids = []  # Phase 6: accumulated across every day-chunk, hashed into ONE manifest row for this whole call

    while cursor < safe_now_dt:
        chunk_until_dt = min(cursor + timedelta(days=CHUNK_DAYS), safe_now_dt)
        chunk_since = cursor.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        chunk_until = chunk_until_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        if on_progress:
            on_progress("fetch", "progress", f"{chunk_since} .. {chunk_until}")
        events, complete = okta_client.get_system_log(
            since=chunk_since, until=chunk_until, limit=1000, sort_order="ASCENDING", max_pages=200
        )
        total_scanned += len(events)

        rows = [_normalize_live_event(e) for e in events]
        inserted, max_published, new_uuids = _insert_rows(conn, environment_id, rows, ingestion_scope)
        total_inserted += inserted
        all_new_uuids.extend(new_uuids)
        chunks += 1

        # FIX (external review, 2026-09-30, "1.5"): get_system_log logs a
        # WARN when it hits max_pages with more pages still remaining, but
        # previously returned the truncated results exactly like a
        # complete fetch -- this loop would advance the watermark past
        # chunk_until as if the whole day was fully ingested, silently
        # and PERMANENTLY losing whatever events existed on the remaining
        # page(s) (Okta's System Log has no way to re-fetch an aged-out
        # window later). If this chunk came back incomplete, stop the
        # whole sync here with the watermark left at the END of the
        # PREVIOUS chunk (not this one) -- the next sync run will retry
        # this exact chunk from scratch rather than skip past the gap.
        if not complete:
            error_message = (
                f"Hit max_pages for {chunk_since}..{chunk_until} -- more events exist on this "
                f"day than could be fetched in one sync run. Watermark NOT advanced past this "
                f"day; the next sync will retry it. If this persists, the day's event volume may "
                f"exceed what a single day-chunk can safely page through."
            )
            _upsert_sync_state(
                conn, environment_id,
                last_sync_completed_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                last_sync_status="error",
                last_sync_error=error_message,
                total_events_ingested=(get_sync_state(environment_id) or {}).get("total_events_ingested", 0) + inserted,
                ingestion_scope=ingestion_scope,
            )
            if on_progress:
                on_progress("ingest", "error", f"Incomplete fetch for {chunk_since}..{chunk_until}; stopping sync.")
            # Phase 6: an interrupted sync still produced real inserted
            # rows (across however many chunks completed before the
            # failing one) -- those need to be in the chain too, same
            # "nothing new is silently invisible" reasoning as a
            # zero-new-rows batch below.
            _record_ingestion_manifest(conn, environment_id, "sync", original_since, chunk_until, all_new_uuids)
            return {
                "inserted": total_inserted, "scanned": total_scanned, "since": original_since,
                "chunks": chunks, "complete": False, "error": error_message,
            }

        # Persist progress after EVERY chunk, not just at the end -- a
        # restart mid-backfill resumes from here instead of from scratch.
        watermark = max_published or chunk_until
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        _upsert_sync_state(
            conn, environment_id,
            last_synced_at=watermark,
            last_sync_completed_at=now_iso,
            last_sync_status="running",
            last_sync_error=None,
            total_events_ingested=(get_sync_state(environment_id) or {}).get("total_events_ingested", 0) + inserted,
            ingestion_scope=ingestion_scope,
        )
        cursor = chunk_until_dt

    _upsert_sync_state(conn, environment_id, last_sync_status="success")
    _record_ingestion_manifest(conn, environment_id, "sync", original_since, safe_now_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z"), all_new_uuids)
    if on_progress:
        on_progress("ingest", "done", f"{total_inserted} new row(s) inserted across {chunks} day-chunk(s)")
    return {"inserted": total_inserted, "scanned": total_scanned, "since": original_since, "chunks": chunks, "complete": True}


def import_from_csv(csv_path, environment_id, ingestion_scope, on_progress=None):
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

    inserted, max_published, new_uuids = _insert_rows(conn, environment_id, rows, ingestion_scope)
    _record_ingestion_manifest(conn, environment_id, "csv_import", None, None, new_uuids)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    existing_state = get_sync_state(environment_id)
    # A CSV import advances the watermark too, IF it's newer than what's
    # already recorded -- e.g. importing a 90-day export shouldn't roll
    # last_synced_at BACKWARD if a live sync already ran more recently.
    prior_watermark = (existing_state or {}).get("last_synced_at")
    new_watermark = max_published if (not prior_watermark or (max_published and max_published > prior_watermark)) else prior_watermark
    _upsert_sync_state(
        conn, environment_id,
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


def _delete_pruned_targets(conn, environment_id, events_where_sql, events_where_params):
    """Deletes every event_targets row whose (environment_id, uuid) is
    about to be pruned from events by the SAME where-clause -- must run
    BEFORE the events DELETE in the same transaction, since event_targets'
    FOREIGN KEY (environment_id, uuid) REFERENCES events(environment_id,
    uuid) raises IntegrityError on an events delete that still has
    children (DATA-01). Caller already holds _db_lock."""
    conn.execute(
        f"""DELETE FROM event_targets WHERE environment_id = ? AND uuid IN (
                SELECT uuid FROM events WHERE environment_id = ? {events_where_sql}
            )""",
        (environment_id, environment_id, *events_where_params),
    )


def prune_events(environment_id, retention_days=None, max_size_mb=None):
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
            # BUG FIX (external review, 2026-10-05, DATA-01): event_targets
            # has a FOREIGN KEY on (environment_id, uuid) -> events, and
            # _insert_rows writes a target row for nearly every real Okta
            # event -- so the very first prune that matched a row with a
            # target used to raise sqlite3.IntegrityError, which meant
            # retention pruning NEVER actually deleted anything on a fresh
            # install, the DB grew without bound, and _run_sync_job logged
            # a perfectly successful sync as a failure every single day.
            # Children deleted first, in the SAME transaction as the
            # parent delete, same as any other cascade-by-hand.
            _delete_pruned_targets(conn, environment_id, "AND is_curated = 0 AND published < ?", (cutoff,))
            cur = conn.execute(
                "DELETE FROM events WHERE environment_id = ? AND is_curated = 0 AND published < ?",
                (environment_id, cutoff),
            )
            pruned_total += cur.rowcount
            conn.commit()

    if max_size_mb is not None:
        max_bytes = max_size_mb * 1024 * 1024
        step_days = 1
        pruned_any_by_size = False

        def _live_data_bytes():
            # PERFORMANCE FIX (external review, 2026-09-30): the loop
            # below used to call VACUUM after every single day's delete to
            # make os.path.getsize(...) reflect the shrink -- confirmed
            # real: up to 3650 full-database rebuilds in the worst case
            # (VACUUM rewrites the ENTIRE file, not just the freed pages),
            # causing severe disk I/O thrashing and blocking every
            # concurrent HTTP read for the whole rebuild each time.
            #
            # The fix is NOT simply "stop calling VACUUM" -- SQLite's
            # DELETE never shrinks the on-disk file by itself (freed pages
            # go to an internal freelist, the file stays the same size
            # until something vacuums it), so removing VACUUM without
            # also changing what this loop measures would make
            # os.path.getsize(...) never decrease, and the loop would
            # never detect "under the cap now" -- it would delete
            # everything instead of stopping early once enough is freed,
            # a functional regression, not a fix.
            #
            # Real fix: estimate LIVE (used, non-freed) data size directly
            # from SQLite's own page accounting -- (page_count -
            # freelist_count) * page_size -- which drops immediately after
            # a DELETE + COMMIT, with NO vacuum needed to observe it. This
            # is exactly as accurate for "should we keep pruning" as the
            # physical file size was (the file size only ever matters
            # because it's a proxy for how much space this data actually
            # occupies -- this measures that directly), and costs three
            # cheap PRAGMA reads instead of a full file rewrite.
            page_count = conn.execute("PRAGMA page_count").fetchone()[0]
            freelist_count = conn.execute("PRAGMA freelist_count").fetchone()[0]
            page_size = conn.execute("PRAGMA page_size").fetchone()[0]
            return (page_count - freelist_count) * page_size

        # Walk the cutoff back further, oldest non-curated first, until under the cap
        # or nothing non-curated is left to prune.
        for _ in range(3650):  # hard safety cap -- never loop forever
            if _live_data_bytes() <= max_bytes:
                break
            remaining = conn.execute(
                "SELECT COUNT(*) FROM events WHERE environment_id = ? AND is_curated = 0",
                (environment_id,),
            ).fetchone()[0]
            if remaining == 0:
                break
            oldest = conn.execute(
                "SELECT MIN(published) FROM events WHERE environment_id = ? AND is_curated = 0",
                (environment_id,),
            ).fetchone()[0]
            if not oldest:
                break
            step_cutoff = (
                datetime.fromisoformat(oldest.replace("Z", "+00:00")) + timedelta(days=step_days)
            ).strftime("%Y-%m-%dT%H:%M:%S.000Z")
            with _db_lock:
                # DATA-01, same reasoning as the retention_days branch above.
                _delete_pruned_targets(conn, environment_id, "AND is_curated = 0 AND published < ?", (step_cutoff,))
                cur = conn.execute(
                    "DELETE FROM events WHERE environment_id = ? AND is_curated = 0 AND published < ?",
                    (environment_id, step_cutoff),
                )
                pruned_total += cur.rowcount
                conn.commit()
            pruned_any_by_size = True

        # Reclaim the actual disk space exactly ONCE, after every delete
        # this call is going to do -- not per-iteration.
        if pruned_any_by_size:
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


def _require_positive_limit(limit):
    """BUG FIX (external review, 2026-10-05, DATA-06): SQLite's `LIMIT`
    with a NEGATIVE value means "no limit at all" (confirmed: `LIMIT -5`
    on a 10-row table returns all 10), not "zero" or an error -- so a
    negative `limit` silently removed the row cap this function exists to
    enforce, rather than rejecting the request. `limit=0` is also
    nonsensical for these callers (every one wants at least the newest
    row) and is rejected the same way, matching UI-03/DATA-07's
    recommendation. Raises ValueError; callers map that to an HTTP 400."""
    if not isinstance(limit, int) or limit < 1:
        raise ValueError(f"limit must be a positive integer, got {limit!r}")


def query_events(environment_id, event_types=None, since=None, until=None, actor_id=None, resource_id=None, limit=1000):
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
    _require_positive_limit(limit)
    conn = _get_connection()
    until = _normalize_until(until)
    clauses = ["environment_id = ?"]
    params = [environment_id]
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


def count_events(environment_id, event_types=None, since=None, until=None):
    """Cheap count-only query (no raw_json parsing) -- used by the report
    picker's per-card event counts, where fetching every row's full
    payload just to discard it would be wasteful."""
    conn = _get_connection()
    until = _normalize_until(until)
    clauses = ["environment_id = ?"]
    params = [environment_id]
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
# Log CSV exports from a real tenant (55,857 + 56,478 rows -- far higher
# sample size than a live API pull for every event type at once). "Skip a
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
    debug_data = (raw.get("debugContext") or {}).get("debugData") or {}
    resource_type_detail = debug_data.get("resourceType")
    if not resource_type_detail and event_type == "user.authentication.auth_via_mfa":
        # confirmed live 2026-09-30 against a real tenant: this eventType's
        # debugData has no `resourceType` field at all, but DOES carry the
        # real authenticator/factor used (e.g. OKTA_VERIFY_PUSH,
        # SIGNED_NONCE/FastPass, GOOGLE_AUTHENTICATOR) in `factor` --
        # without this, the MFA Enforcement report's resource_type_detail
        # column was always blank and fell back to the target's generic
        # "AuthenticatorEnrollment" type for every row, which can't
        # distinguish a push challenge from a TOTP code or a FastPass
        # phishing-resistant verification -- real information an auditor
        # asking "which factor types are actually in use" needs.
        resource_type_detail = debug_data.get("factor")
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
            """SELECT environment_id, uuid, event_type, raw_json FROM events
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
        batch.append((resource_id, resource_alt_id, resource_type_detail, row["environment_id"], row["uuid"]))
        if len(batch) >= BATCH_SIZE:
            with _db_lock:
                conn.executemany(
                    """UPDATE events SET resource_id = ?, resource_alternate_id = ?,
                       resource_type_detail = ? WHERE environment_id = ? AND uuid = ?""",
                    batch,
                )
                conn.commit()
            updated += len(batch)
            batch = []
    if batch:
        with _db_lock:
            conn.executemany(
                """UPDATE events SET resource_id = ?, resource_alternate_id = ?,
                   resource_type_detail = ? WHERE environment_id = ? AND uuid = ?""",
                batch,
            )
            conn.commit()
        updated += len(batch)
    return updated


def backfill_event_targets():
    """One-time (per environment's worth of pre-existing rows) migration,
    called from init_db() right after backfill_resource_columns() above --
    populates event_targets for every row that predates that table
    existing. Idempotent: an event already present in event_targets is
    skipped (checked via NOT EXISTS, since target_id can legitimately be
    NULL for a real target with no id -- a plain NULL-column check like
    backfill_resource_columns uses doesn't work here). A real event with
    genuinely zero targets (raw.target == [], confirmed real -- 547 of a
    ~20k sample) never gets an event_targets row and so gets re-scanned on
    every boot; harmless (a cheap re-check, not a re-insert) but not
    perfectly idempotent for that slice -- acceptable given how small it
    is relative to a full backfill's one-time cost.

    Same batched-executemany pattern as backfill_resource_columns (500
    rows per transaction) for the same reason: don't hold the write lock
    for one giant transaction on a 56k+ row archive."""
    conn = _get_connection()
    BATCH_SIZE = 500
    with _db_lock:
        rows = conn.execute(
            """SELECT e.environment_id, e.uuid, e.raw_json FROM events e
               WHERE NOT EXISTS (
                   SELECT 1 FROM event_targets t
                   WHERE t.environment_id = e.environment_id AND t.uuid = e.uuid
               )"""
        ).fetchall()
    if not rows:
        return 0
    updated = 0
    batch = []
    for row in rows:
        raw = json.loads(row["raw_json"])
        for t in raw.get("target") or []:
            batch.append((row["environment_id"], row["uuid"], t.get("id"), t.get("alternateId"), t.get("displayName")))
        if len(batch) >= BATCH_SIZE:
            with _db_lock:
                conn.executemany(
                    """INSERT INTO event_targets
                       (environment_id, uuid, target_id, target_alternate_id, target_display_name)
                       VALUES (?, ?, ?, ?, ?)""",
                    batch,
                )
                conn.commit()
            updated += len(batch)
            batch = []
    if batch:
        with _db_lock:
            conn.executemany(
                """INSERT INTO event_targets
                   (environment_id, uuid, target_id, target_alternate_id, target_display_name)
                   VALUES (?, ?, ?, ?, ?)""",
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
    the stored/indexed columns, so it's still derived here.

    request_id/outcome_reason/client_ip/client_geo are all read straight
    from `raw` -- the full original Okta event is already persisted in
    raw_json for every row (see events table schema), so none of these
    needed a new ingestion/migration step, just reading what's already
    there. Confirmed live against this project's own real archive data
    (2026-10-02): outcome.reason is None on success, a real string on a
    real non-success result (e.g. "Authenticator method unanswered" on a
    real UNANSWERED MFA event); client.ipAddress/geographicalContext are
    populated exactly as expected on every sampled auth-flow row.

    accessRequestSubject gets a narrow, event-type-scoped override of
    `resource` for the jit_access_requests report specifically: Okta's own
    target displayName degrades to a near-useless "Task with id X was
    resolved" on access.request.update/.resolve (confirmed live), while
    debugContext.debugData.accessRequestSubject stays the same meaningful
    "{user} is requesting {access} to {resource}" text across the whole
    create->update->resolve lifecycle for one request. Scoped to this one
    event-type family only, not a change to the generic resource-picking
    logic every other report also uses."""
    import create_secret_folders
    raw = event_row["raw"]
    targets = raw.get("target") or []
    primary = _primary_target(event_row["event_type"], targets)
    resource = primary.get("displayName") if primary else None
    resource_type = primary.get("type") if primary else None
    event_type = event_row["event_type"] or ""
    if event_type.startswith("access.request."):
        subject = (raw.get("debugContext") or {}).get("debugData", {}).get("accessRequestSubject")
        resource = subject or resource
    outcome = raw.get("outcome") or {}
    client = raw.get("client") or {}
    geo = client.get("geographicalContext") or {}
    client_geo = ", ".join(part for part in (geo.get("city"), geo.get("state"), geo.get("country")) if part)
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
        "outcome_reason": outcome.get("reason") or "",
        "client_ip": client.get("ipAddress") or "",
        "client_geo": client_geo,
        "request_id": create_secret_folders._extract_request_id(raw),
        "targets": targets,  # full target list -- some reports need target1/2 too, e.g. PAM's Team/Server
    }


def run_report(report_key, environment_id, since=None, until=None, limit=1000):
    """Runs one named COMPLIANCE_REPORTS preset and returns
    {"rows": [...], "total": int, "truncated": bool} shaped to the
    four-field standard. Raises KeyError if report_key isn't a real
    report, ValueError if limit isn't a positive integer.

    UI-03/DATA-07 (external review, 2026-10-05): report rows were
    silently capped at `limit` (1000 by default) with nothing in the
    response saying so -- a report card's own count (count_events, no
    cap) could read e.g. 4,812 while the detail view and every export
    built from it silently held only the newest 1,000, dropping the
    OLDEST part of a 90-day evidence window without warning. `total`
    (the real, uncapped count for the same filters) and `truncated` let
    the frontend show "Showing newest N of M" instead of presenting a
    partial result as complete."""
    if report_key not in COMPLIANCE_REPORTS:
        raise KeyError(f"Unknown report: {report_key!r}")
    _require_positive_limit(limit)
    event_types = _event_types_for_report(report_key)
    rows = query_events(environment_id, event_types=event_types, since=since, until=until, limit=limit)
    total = count_events(environment_id, event_types=event_types, since=since, until=until)
    return {"rows": [_four_field_row(r) for r in rows], "total": total, "truncated": total > len(rows)}


def resource_history(environment_id, resource_id=None, resource_name=None, since=None, until=None, limit=1000):
    """Every report row across EVERY event type (not scoped to one
    COMPLIANCE_REPORTS preset) where this one real resource appears as
    ANY target on the event -- the Resources tab's per-resource drill-down
    (click a server/AD account/DB account/etc., see its full compliance
    history).

    Deliberately NOT the same query as query_events(resource_id=...) --
    that matches only the ONE target _primary_target() picked as "the"
    resource for the event's four-field-standard row, which is correct
    for an ordinary report row but wrong here: a real bug found
    2026-09-30 live against a real tenant is that a genuine Server target
    (e.g. a server named srv1) can coexist on an event alongside a Server Account target
    _primary_target prefers, so resource_id alone silently drops the
    Server's own id and a click on it found zero history despite real
    activity existing. This instead JOINs event_targets (one row per REAL
    target per event, populated at ingest time -- see _insert_rows) so
    ANY target match surfaces the event, not just the primary pick.

    resource_id matches target_id OR target_alternate_id. resource_name
    (an exact display-name match against target_display_name) is a
    SEPARATE fallback needed for two resource kinds confirmed live
    2026-09-30 to have NO discoverable log-side id at all: database
    accounts and individual Active Directory accounts. Their own `id`
    field (fetched from the ordinary list/detail API) never appears
    anywhere in the System Log -- the log instead references a completely
    different "Service Account" target id with no API lookup, confirmed
    STABLE across a real, fresh rotation triggered live to verify (so a
    genuine persistent identity, just not one this codebase can resolve
    to an object). Exact-displayName matching is the only way to link
    those two kinds back to their real history; confirmed no real name
    collisions exist within either kind on this tenant (5 distinct
    database account names, 11 distinct AD account names). SaaS/Okta
    accounts do NOT need this fallback -- their own id (privileged_
    resource_id/okta_user_id) IS the real log target id, confirmed live
    against a real Salesforce account and two Okta service accounts.

    At least one of resource_id/resource_name must be given (both empty
    means "nothing to look up" -- returns the empty-result shape rather
    than every event ever).

    Returns {"rows": [...], "total": int, "truncated": bool} -- see
    run_report's docstring for why (UI-03/DATA-07, external review,
    2026-10-05). Raises ValueError if limit isn't a positive integer."""
    _require_positive_limit(limit)
    if not resource_id and not resource_name:
        return {"rows": [], "total": 0, "truncated": False}
    conn = _get_connection()
    until_norm = _normalize_until(until)
    match_clauses = []
    match_params = []
    if resource_id:
        match_clauses.append("(t.target_id = ? OR t.target_alternate_id = ?)")
        match_params.extend([resource_id, resource_id])
    if resource_name:
        match_clauses.append("t.target_display_name = ?")
        match_params.append(resource_name)
    clauses = ["e.environment_id = ?", "(" + " OR ".join(match_clauses) + ")"]
    params = [environment_id, *match_params]
    if since:
        clauses.append("e.published >= ?")
        params.append(since)
    if until_norm:
        clauses.append("e.published <= ?")
        params.append(until_norm)
    where_sql = " AND ".join(clauses)
    join_sql = (
        "FROM events e JOIN event_targets t "
        "ON e.environment_id = t.environment_id AND e.uuid = t.uuid WHERE " + where_sql
    )
    total = conn.execute(f"SELECT COUNT(DISTINCT e.uuid) {join_sql}", params).fetchone()[0]
    sql = (
        "SELECT DISTINCT e.uuid, e.event_type, e.published, e.actor_id, e.actor_display_name, "
        "e.actor_alternate_id, e.outcome_result, e.resource_id, e.resource_alternate_id, "
        f"e.resource_type_detail, e.raw_json {join_sql}"
        " ORDER BY e.published DESC LIMIT ?"
    )
    out = []
    for row in conn.execute(sql, params + [limit]):
        d = dict(row)
        d["raw"] = json.loads(d.pop("raw_json"))
        out.append(d)
    rows = [_four_field_row(r) for r in out]
    return {"rows": rows, "total": total, "truncated": total > len(rows)}
