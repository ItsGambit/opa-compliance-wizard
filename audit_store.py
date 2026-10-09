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
import re
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
        "description": "Service-account/shared-credential password reveals. The resource column names the account family (SaaS app, Okta, Database, Active Directory, Server). For a per-account roster with status and full history of SaaS/Okta service accounts, see the Service Accounts dashboard.",
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
        "description": "Service-account password rotation lifecycle (scheduled and manual). The resource column names the account family (SaaS app, Okta, Database, Active Directory); the outcome column is the real result (SUCCESS / FAILURE / DEFERRED). For per-account rotation totals on SaaS/Okta service accounts, see the Service Accounts dashboard.",
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
    """DATA-14 (external review, 2026-10-05): OPA_AUDIT_DB_PATH lets an
    operator keep the archive outside the code checkout (so a deploy's
    rsync and the evidence store never share a directory). Default is
    unchanged: next to this file."""
    override = os.environ.get("OPA_AUDIT_DB_PATH")
    if override:
        return override
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "audit_store.db")


# DATA-14: the archive holds names, e-mails, client IPs and pending admin
# action payloads. Hosted mode already runs under systemd's UMask=0077; a
# local/desktop run used the process umask (typically 022), creating a
# world-readable audit_store.db. The first connect now creates the file
# (and SQLite's -wal/-shm sidecars) owner-only, and re-tightens an
# existing file so an archive created by an older version is fixed on the
# next start. POSIX only -- os.chmod is a no-op on Windows for these bits.
_DB_FILE_MODE = 0o600


def _restrict_db_file_modes(path):
    for candidate in (path, path + "-wal", path + "-shm"):
        try:
            if os.path.exists(candidate):
                os.chmod(candidate, _DB_FILE_MODE)
        except OSError:
            pass  # read-only media / unsupported filesystem -- never block startup over a chmod


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
        path = _audit_db_path()
        # DATA-14: pre-create the file owner-only. Done with O_CREAT|0600
        # rather than os.umask(): umask is process-wide, and two request
        # threads opening their first connection together could leave the
        # whole process's umask changed. SQLite gives -wal/-shm the main
        # file's mode; _restrict_db_file_modes re-tightens an archive
        # created by an older version. A missing parent directory (e.g. an
        # OPA_AUDIT_DB_PATH nobody created) fails here with a clear path.
        if path != ":memory:" and not os.path.exists(path):
            try:
                os.close(os.open(path, os.O_CREAT | os.O_WRONLY, _DB_FILE_MODE))
            except FileNotFoundError:
                raise RuntimeError(f"The archive directory for {path!r} does not exist; create it (owned by the app user) first.")
        conn = sqlite3.connect(path, timeout=30)
        conn.execute("PRAGMA journal_mode=WAL")
        _restrict_db_file_modes(path)
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
    real installs' confirmed SQLite versions (3.46.1/3.49.1).

    DATA-08 (external review, 2026-10-05): idempotent -- a process that
    died between this DROP and the schema_migrations INSERT used to leave
    a database that raised "no such column" on every later start, with
    no way to repair it short of hand-editing. Now a missing column means
    "already done". The SQLite floor itself is enforced once, in
    run_migrations, with a readable message instead of a raw syntax error."""
    if "preserve_logs_locally" in _table_columns(conn, "app_environments"):
        conn.execute("ALTER TABLE app_environments DROP COLUMN preserve_logs_locally")


def _migration_005_service_account_report_indexes(conn):
    """v5.40.0 (Service Accounts report). Two query plans were measured
    against the real schema with EXPLAIN QUERY PLAN during that
    feature's review and both ignored idx_events_env_resource_id:
      * per-resource newest-N reads (query_events with resource_id and
        an event_type filter, ORDER BY published DESC LIMIT n) walked the
        whole environment newest-first via idx_events_env_published --
        ~100ms per account on a 175k-row environment, paid once per
        service account;
      * the per-resource GROUP BY behind count_events_by_resource
        scanned every row of the environment that has a resource_id, not
        just the event types asked for -- 0.5s on a 515k-row environment,
        growing with the whole archive rather than with the family being
        counted.
    The first index makes a (environment, resource, type) read
    index-ordered by published; the second is a covering index for the
    GROUP BY (0.014s on the same data). Both are plain CREATE INDEX on
    existing columns -- no data migration, idempotent, and a one-off cost
    of a few seconds on a large archive at first start after upgrade."""
    conn.execute(
        """CREATE INDEX IF NOT EXISTS idx_events_env_resource_type_published
           ON events (environment_id, resource_id, event_type, published)"""
    )
    conn.execute(
        """CREATE INDEX IF NOT EXISTS idx_events_env_type_resource_outcome
           ON events (environment_id, event_type, resource_id, outcome_result, resource_type_detail, published)"""
    )


def _migration_006_evidence_chain_v2_and_sync_attempts(conn):
    """2026-10-05 external review, DATA-04 / DATA-05 / DATA-03 / DATA-10.
    Three ALTER TABLE ADD COLUMNs plus one index, every one guarded by a
    column/index-exists check so a half-applied run is simply resumed:

    - ingestion_manifests.content_hash / entry_hash / entries_json: the
      "chain v2" fields -- see _record_ingestion_manifest. Rows written
      before this migration keep only batch_hash and are verified by the
      v1 rule (prev == previous batch_hash); the first v2 row chains to
      the last v1 row's batch_hash, so the boundary is explicit, not a
      re-seal of history nobody can vouch for.
    - sync_state.last_sync_attempt_at: when a sync last STARTED, separate
      from last_sync_completed_at, which now only ever means "finished
      successfully" (DATA-05). The scheduler keys its retry back-off off
      the attempt and its "already ran today" off the completion.
    - sync_state.last_import_at: when a CSV import last ran. A CSV import
      no longer touches the live-sync watermark at all (DATA-03).
    - idx_events_env_type_published: makes the report picker's 18
      per-card COUNT(*) queries index-only (DATA-10)."""
    manifest_cols = _table_columns(conn, "ingestion_manifests")
    for column in ("content_hash TEXT", "entry_hash TEXT", "entries_json TEXT"):
        if column.split()[0] not in manifest_cols:
            conn.execute(f"ALTER TABLE ingestion_manifests ADD COLUMN {column}")
    state_cols = _table_columns(conn, "sync_state")
    for column in ("last_sync_attempt_at TEXT", "last_import_at TEXT"):
        if column.split()[0] not in state_cols:
            conn.execute(f"ALTER TABLE sync_state ADD COLUMN {column}")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_env_type_published ON events (environment_id, event_type, published)"
    )
    # Its prefix now covers everything idx_events_env_type served; keeping
    # both would only add write cost per insert.
    conn.execute("DROP INDEX IF EXISTS idx_events_env_type")


def _migration_007_manifest_entries_and_chain_heads(conn):
    """5.40.4, evidence chain v2 goes live (DATA-04 follow-up from that
    release's own review). Two tables, both IF NOT EXISTS:

    - manifest_entries: one row per curated event a v2 manifest sealed
      (environment_id, manifest_id, uuid, sha256 of raw_json). 5.40.2's
      dormant design kept these as a single entries_json cell, which a
      90-day first backfill of a mid-size tenant (~1M curated rows) would
      have made a ~95 MB value built and parsed in one piece; rows can be
      written with executemany and re-read with a cursor instead.
    - chain_heads: the newest link per environment, written in the same
      transaction as each manifest (and backfilled here from each existing
      chain's last row), so removing manifests from the END of the chain
      (which leaves nothing behind to disagree) no longer verifies as
      valid, and the next sync links to the recorded head rather than the
      surviving row, so it cannot paper over the gap. Like the chain itself this is unkeyed: it
      catches an edit that doesn't also rewrite this row, not a writer
      who recomputes everything (see verify_ingestion_chain)."""
    conn.execute(
        """CREATE TABLE IF NOT EXISTS manifest_entries (
               environment_id TEXT NOT NULL,
               manifest_id INTEGER NOT NULL,
               uuid TEXT NOT NULL,
               sha TEXT NOT NULL,
               PRIMARY KEY (manifest_id, uuid)
           )"""
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_manifest_entries_env ON manifest_entries (environment_id)")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS chain_heads (
               environment_id TEXT PRIMARY KEY,
               manifest_id INTEGER NOT NULL,
               head_hash TEXT NOT NULL,
               updated_at TEXT NOT NULL
           )"""
    )
    # Record today's head for every existing chain, so an upgraded archive
    # (all v1, or v2 rows from a hand-enabled 5.40.2/5.40.3) is checked
    # for a cut-short tail from the upgrade onward instead of reporting
    # "head missing". INSERT OR IGNORE keeps a re-run harmless.
    conn.execute(
        """INSERT OR IGNORE INTO chain_heads (environment_id, manifest_id, head_hash, updated_at)
           SELECT m.environment_id, m.id, COALESCE(m.entry_hash, m.batch_hash), m.created_at
           FROM ingestion_manifests m
           JOIN (SELECT MAX(id) AS id FROM ingestion_manifests GROUP BY environment_id) last ON last.id = m.id"""
    )


def _migration_008_shared_environment_permissions(conn):
    """5.42.0: admin-configurable permissions for shared environments --
    what a user may do with an environment another user owns and has
    shared (see create_secret_folders.SHARED_CAPABILITIES). Two new tables,
    both IF NOT EXISTS; nothing existing is altered, and no evidence-chain
    table (ingestion_manifests, manifest_entries, chain_heads, events) is
    touched. Both start empty: no row means "inherit", so every capability
    resolves to its built-in default -- exactly what a shared user could do
    before this release -- until an admin changes something.

    - shared_permission_defaults: the global default per capability.
    - shared_permission_overrides: per-environment overrides, removed with
      their environment (ON DELETE CASCADE, same convention as
      sync_schedules).

    A rollback to older code leaves both tables unused and harmless."""
    conn.execute(
        """CREATE TABLE IF NOT EXISTS shared_permission_defaults (
               capability TEXT PRIMARY KEY,
               value TEXT NOT NULL CHECK (value IN ('allow', 'deny')),
               updated_at TEXT NOT NULL,
               updated_by TEXT
           )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS shared_permission_overrides (
               environment_id TEXT NOT NULL REFERENCES app_environments(environment_id) ON DELETE CASCADE,
               capability TEXT NOT NULL,
               value TEXT NOT NULL CHECK (value IN ('allow', 'deny')),
               updated_at TEXT NOT NULL,
               updated_by TEXT,
               PRIMARY KEY (environment_id, capability)
           )"""
    )


MIGRATIONS = {
    1: _migration_001_unified_schema,
    2: _migration_002_ingestion_manifests,
    3: _migration_003_pending_admin_actions,
    4: _migration_004_drop_preserve_logs_locally,
    5: _migration_005_service_account_report_indexes,
    6: _migration_006_evidence_chain_v2_and_sync_attempts,
    7: _migration_007_manifest_entries_and_chain_heads,
    8: _migration_008_shared_environment_permissions,
}

# DATA-08: migration 4 needs ALTER TABLE ... DROP COLUMN (SQLite 3.35.0,
# 2021-03). launch.py's Python floor alone admits interpreters bundled with
# an older SQLite (e.g. Debian 11's 3.34), which used to fail at boot with a
# raw `near "DROP": syntax error`.
MIN_SQLITE_VERSION = (3, 35, 0)


def run_migrations():
    """Applies every migration in MIGRATIONS whose version is greater
    than what's already recorded in schema_migrations, in order, each in
    its own transaction. Replaces the old ad hoc `ALTER TABLE ... except
    sqlite3.OperationalError` pattern (and its two always-re-run backfill
    functions) that was this file's only schema-growth mechanism before
    Phase 2 -- every future schema change should add a new numbered
    function to MIGRATIONS, not another one-off patch.

    DATA-08 (external review, 2026-10-05): each migration now runs under
    an explicit BEGIN IMMEDIATE, which (a) takes SQLite's write lock up
    front so two processes starting together (server + CLI) serialise
    instead of both passing the version check and racing the same DDL,
    and (b) makes the DDL + the schema_migrations INSERT one atomic unit
    -- under Python's default (legacy) transaction control no transaction
    was open yet when the DDL ran (only DML auto-begins), so the rollback
    below undid nothing. The version is re-read AFTER the lock is held
    for the same reason. Migrations 1-3 use executescript, whose implicit
    COMMIT ends the BEGIN IMMEDIATE early; every statement they run is IF
    NOT EXISTS and the version row is INSERT OR IGNORE, so two processes
    racing a fresh database both finish without a duplicate-key crash.

    Idempotent: calling this on an already-fully-migrated database is a
    cheap no-op (one SELECT MAX(version), no transactions opened)."""
    if sqlite3.sqlite_version_info < MIN_SQLITE_VERSION:
        raise RuntimeError(
            f"SQLite {sqlite3.sqlite_version} is too old: this application needs SQLite "
            f"{'.'.join(map(str, MIN_SQLITE_VERSION))} or newer (ALTER TABLE ... DROP COLUMN). "
            "Use a Python build linked against a newer SQLite."
        )
    conn = _get_connection()
    current_version = _schema_version(conn)
    for version in sorted(v for v in MIGRATIONS if v > current_version):
        with _db_lock:
            try:
                conn.execute("BEGIN IMMEDIATE")
                if _schema_version(conn) >= version:
                    conn.rollback()  # another process applied it while we waited for the write lock
                    continue
                MIGRATIONS[version](conn)
                conn.execute(
                    "INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?, ?)",
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
    canonicalize_stored_timestamps()
    reflag_curated_rows()
    _cleanup_expired_pending_admin_actions()
    _cleanup_retired_secrets_log_cache()


def reflag_curated_rows():
    """DATA-13 (external review, 2026-10-05): is_curated is computed once
    at ingest, so an event type added to COMPLIANCE_EVENT_TYPES later
    left every already-stored row of that type prunable (is_curated=0)
    even though it now backs a report card. Re-flags them from the
    CURRENT mapping at every start -- index-served (environment_id,
    event_type) and a no-op once done. Never clears a flag: a type
    removed from the mapping keeps the rows that were curated when they
    were ingested (nothing the archive already promised to keep is
    silently demoted to prunable). Runs per environment so the
    (environment_id, event_type) index serves every statement instead of
    a whole-table scan. Returns the number of rows re-flagged."""
    conn = _get_connection()
    types = sorted(COMPLIANCE_EVENT_TYPES)
    if not types:
        return 0
    placeholders = ",".join("?" for _ in types)
    environment_ids = [r[0] for r in conn.execute("SELECT DISTINCT environment_id FROM events")]
    total = 0
    with _db_lock:
        try:
            for environment_id in environment_ids:
                cur = conn.execute(
                    f"UPDATE events SET is_curated = 1 WHERE environment_id = ? AND is_curated = 0 "
                    f"AND event_type IN ({placeholders})",
                    (environment_id, *types),
                )
                total += cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    return total


def canonicalize_stored_timestamps():
    """DATA-03 / DATA-13 boot backfill: rows ingested before 5.40.2 from a
    CSV export kept the file's own timestamp shape (e.g. a space instead
    of `T`, no milliseconds, an offset), which sorts and filters wrongly
    against the canonical `YYYY-MM-DDTHH:MM:SS.mmmZ` form every other row
    has -- and INSERT OR IGNORE's dedup means a later live fetch of the
    same event never corrects it. Rewrites `published` (and the copy
    inside raw_json) through _canonical_published for every row whose
    stored value is not already canonical; a row that cannot be parsed
    is left alone and counted. Index-served (the LIKE excludes canonical
    rows by shape, so a healthy archive scans nothing it keeps).
    Returns (rewritten, unparseable)."""
    conn = _get_connection()
    rows = conn.execute(
        """SELECT environment_id, uuid, published, raw_json FROM events
           WHERE published IS NULL OR LENGTH(published) != 24 OR published NOT LIKE '____-__-__T__:__:__.___Z'"""
    ).fetchall()
    if not rows:
        return 0, 0
    rewritten = unparseable = 0
    with _db_lock:
        try:
            for row in rows:
                canonical = _canonical_published(row["published"])
                if canonical is None:
                    unparseable += 1
                    continue
                raw_json = row["raw_json"]
                try:
                    raw = json.loads(raw_json)
                    raw["published"] = canonical
                    raw_json = json.dumps(raw, separators=(",", ":"))
                except (ValueError, TypeError):
                    pass  # unreadable raw_json: fix the column, leave the blob
                conn.execute(
                    "UPDATE events SET published = ?, raw_json = ? WHERE environment_id = ? AND uuid = ?",
                    (canonical, raw_json, row["environment_id"], row["uuid"]),
                )
                rewritten += 1
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    return rewritten, unparseable


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
        _canonical_published(event.get("published")),
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


_ISO_TIMESTAMP_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})[T ](?P<time>\d{2}:\d{2}:\d{2})(?:\.(?P<frac>\d{1,9}))?"
    r"(?P<tz>Z|z|[+-]\d{2}:?\d{2})?$",
    re.ASCII,  # \d must mean 0-9, not every Unicode digit
)


def _iso_ms(dt):
    """The archive's canonical form for an aware datetime: millisecond
    precision, UTC, trailing Z -- what every stored `published` and
    every sync cursor/watermark uses, so string comparisons between them
    are exact (a second-precision cursor against a millisecond watermark
    is what made a no-progress check unreliable, review item DATA-09)."""
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _canonical_published(value):
    """DATA-03 / DATA-13 (external review, 2026-10-05): every comparison
    on `published` in this module is a plain string comparison, which is
    only correct when every stored value has the exact same shape --
    `YYYY-MM-DDTHH:MM:SS.mmmZ` (what the live API emits). CSV exports
    used to be stored verbatim, so a differently-shaped timestamp sorted
    and filtered wrongly, and a bad or future one could poison the sync
    watermark. Returns that canonical UTC form for any ISO-8601-ish
    input (space or T separator, 0-9 fractional digits, Z or an offset,
    or no zone -- treated as UTC, which is what Okta's own export uses),
    or None for anything that doesn't parse, which _insert_rows treats
    as a malformed row and skips."""
    if value is None:
        return None
    try:
        if isinstance(value, datetime):
            return _iso_ms(value if value.tzinfo else value.replace(tzinfo=timezone.utc))
        text = str(value).strip()
        m = _ISO_TIMESTAMP_RE.match(text)
        if not m:
            return None
        frac = (m.group("frac") or "0")[:6].ljust(6, "0")
        tz = m.group("tz")
        if not tz or tz in ("Z", "z"):
            tzinfo = timezone.utc
        else:
            sign = 1 if tz[0] == "+" else -1
            digits = tz[1:].replace(":", "")
            tzinfo = timezone(sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:])))  # +24:00 raises -> None
        dt = datetime.strptime(f"{m.group('date')}T{m.group('time')}.{frac}", "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=tzinfo)
        return _iso_ms(dt)  # a year-0001/9999 value near the UTC boundary overflows -> None
    except (ValueError, OverflowError):
        return None  # shape matched, value didn't (month 13, offset +24:00, out-of-range year)


def _normalize_csv_row(row):
    """Shapes one row from a System Log CSV export (flattened
    target0-3.* columns, dotted header names) into the same normalized
    row tuple as _normalize_live_event, PLUS reconstructs a `target`
    list so raw_json's shape matches a live event closely enough for
    report/drill-down code to treat both sources identically. The
    timestamp is canonicalised (DATA-03/DATA-13, see _canonical_published)
    both in the stored column and inside raw_json, so a CSV row and a
    live row of the same event compare identically everywhere."""
    published = _canonical_published(row.get("timestamp"))
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
        "published": published,
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
        published,
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
    new_entries) -- max_published reflects every well-formed row this
    call looked at: duplicates AND rows the ingestion scope filtered out
    (it is computed before the curated-scope check), since the watermark
    must advance based on what was FETCHED, not just what was stored, or
    a delta sync could re-scan the same already-seen day forever -- and,
    in curated scope, a capped chunk with no curated rows after the
    cursor would otherwise look like "no progress" (review DATA-09).
    new_entries (Phase 6, extended for the v2
    chain -- DATA-04) is one (uuid, is_curated, sha256(raw_json)) per
    row that was genuinely new this call (cur.rowcount == 1) -- fed to
    _record_ingestion_manifest by the caller to hash exactly what this
    batch actually added, content included, not every row merely
    scanned.

    DATA-11 (external review, 2026-10-05): the whole batch is one
    transaction that is rolled back if any row raises mid-way -- before,
    a bad row left this thread's write transaction open after the lock
    was released, blocking every other writer until the thread died."""
    max_published = None
    inserted = 0
    new_entries = []
    with _db_lock:
        try:
            for (uuid, event_type, published, actor_id, actor_name, actor_alt, outcome, raw_json,
                 resource_id, resource_alt_id, resource_type_detail, targets) in rows:
                if not uuid or not event_type or not published:
                    continue  # malformed row (e.g. a CSV export's trailing blank line) -- skip, don't crash
                if max_published is None or published > max_published:
                    max_published = published  # before the scope filter -- see the docstring
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
                # Only fan out into event_targets on a genuine new insert
                # (cur.rowcount == 1) -- INSERT OR IGNORE is a no-op on a
                # duplicate uuid, and re-inserting the same event's targets
                # every re-run would duplicate rows with nothing to dedupe on.
                if cur.rowcount:
                    new_entries.append((uuid, is_curated, _content_sha256(raw_json)))
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
        except Exception:
            conn.rollback()
            raise
    return inserted, max_published, new_entries


def _content_sha256(raw_json):
    return hashlib.sha256(raw_json.encode("utf-8")).hexdigest()


def _manifest_entry_hash(prev_hash, environment_id, source, since, until, row_count, created_at, batch_hash, content_hash):
    """DATA-04: the v2 link. Every field an auditor would rely on is
    inside the hash, and so is the previous link, so editing any manifest
    field, deleting a manifest, or re-ordering them changes every hash
    after it. Field separator is a newline, which none of these values
    can contain (ids/hashes/ISO timestamps/ints)."""
    parts = [prev_hash or "", environment_id, source, since or "", until or "", str(row_count), created_at, batch_hash, content_hash]
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


def _recorded_head_is_stale(conn, environment_id, recorded):
    """True when the recorded head's own manifest is still there, with the
    same link hash, and rows were appended after it -- what code older
    than 5.40.4 (which never updates chain_heads) leaves behind if it ran
    a sync after 5.40.4 had started once. Those rows are checked by the
    chain walk like any others, so linking past them weakens nothing.
    A tail that was REMOVED takes the recorded row with it (or leaves the
    head pointing past the last row), so it is never mistaken for this."""
    row = conn.execute(
        "SELECT batch_hash, entry_hash FROM ingestion_manifests WHERE id = ? AND environment_id = ?",
        (recorded["manifest_id"], environment_id),
    ).fetchone()
    if row is None or (row["entry_hash"] or row["batch_hash"]) != recorded["head_hash"]:
        return False
    return conn.execute(
        "SELECT 1 FROM ingestion_manifests WHERE environment_id = ? AND id > ? LIMIT 1",
        (environment_id, recorded["manifest_id"]),
    ).fetchone() is not None


def _sha256_of_lines(lines):
    """sha256 of "\n".join(lines), fed line by line so a 1M-line batch
    never materialises the joined string."""
    h = hashlib.sha256()
    for i, line in enumerate(lines):
        if i:
            h.update(b"\n")
        h.update(line.encode("utf-8"))
    return h.hexdigest()


def _manifest_content_hash(entries):
    """sha256 over `uuid:sha256(raw_json)` for every CURATED row in the
    batch, sorted by uuid. Curated rows are the ones the archive promises
    never to prune (see prune_events), so they are the only ones a later
    deep verification can be expected to re-read; a non-curated row that
    retention has legitimately removed must not make the chain look
    tampered with."""
    return _sha256_of_lines(sorted(f"{uuid}:{sha}" for uuid, is_curated, sha in entries if is_curated))


def _record_ingestion_manifest(conn, environment_id, source, since, until, new_entries):
    """Phase 6: writes one hash-chained manifest row for a completed
    ingestion call (one per sync_okta_events()/import_from_csv()
    invocation, NOT per internal day-chunk -- see this phase's design
    notes). A batch with zero new rows still gets a row here -- "nothing
    new happened" is itself a chained, verifiable fact, not a silent skip
    that would leave a gap.

    Chain v2 (DATA-04, external review, 2026-10-05). The v1 chain only
    linked each row's prev_manifest_hash to the previous row's
    batch_hash, where batch_hash was a hash of the new uuids alone -- so
    editing any event, editing any manifest field, truncating the tail,
    or deleting any manifest from a run of empty batches (all with the
    identical empty-list hash, i.e. every quiet day) all still verified
    as valid. A v2 row stores three more things:
      - content_hash: sha256 over `uuid:sha256(raw_json)` of every CURATED
        row in the batch (the rows the archive never prunes), so the
        content of the evidence is sealed, not just its identifiers;
      - entry_hash: sha256 over the previous link AND every field of this
        row (source, since, until, row_count, created_at, batch_hash,
        content_hash) -- the real link. prev_manifest_hash now carries
        the previous row's entry_hash (or its batch_hash for a pre-v2
        row), so the v1->v2 boundary is explicit rather than a re-seal;
      - its sealed entries: (uuid, sha) for the CURATED rows only (the
        ones content_hash covers and a deep verify re-reads), one
        manifest_entries row each (migration 007; 5.40.2's dormant
        format put them in a single entries_json cell, which the verifier
        still reads if present). Non-curated rows are counted in
        row_count but not listed.
    Every manifest (v1 or v2) also updates chain_heads in the same
    transaction, so a chain cut short at the end is detectable (see
    verify_ingestion_chain).
    batch_hash (sorted-uuids hash, every row) is kept so pre-v2 rows and
    tools that read it keep working.

    Returns the new head hash (entry_hash, or batch_hash while the v2
    flag is off). Every manifest -- success, failure or import -- is also
    anchored OUTSIDE the database as an `evidence_chain.sealed` entry in
    audit_log.jsonl (environment_id, source, row_count, head), so a
    head written by someone who also rewrote chain_heads can still be
    compared against the last logged one; the anchor must never be able
    to break an ingestion, so a logging failure is swallowed.

    The new row links to the RECORDED head (chain_heads) when there is
    one, not to whatever row happens to be last: otherwise the first sync
    after manifests were removed from the end would chain onto the
    surviving row, overwrite the head, and make the gap verify as valid
    again. The read and the write are one BEGIN IMMEDIATE transaction, so
    two processes cannot fork the chain either. Caller must hold conn;
    commits on its own, after the row-insert transaction it covers."""
    entries = [tuple(e) for e in new_entries]
    batch_hash = _sha256_of_lines(sorted(uuid for uuid, _c, _s in entries))
    content_hash = _manifest_content_hash(entries)
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    with _db_lock:
        try:
            if not conn.in_transaction:
                conn.execute("BEGIN IMMEDIATE")
            recorded = conn.execute(
                "SELECT manifest_id, head_hash FROM chain_heads WHERE environment_id = ?", (environment_id,)
            ).fetchone()
            prev = conn.execute(
                "SELECT batch_hash, entry_hash FROM ingestion_manifests WHERE environment_id = ? ORDER BY id DESC LIMIT 1",
                (environment_id,),
            ).fetchone()
            last_hash = (prev["entry_hash"] or prev["batch_hash"]) if prev else None
            if recorded is None or _recorded_head_is_stale(conn, environment_id, recorded):
                prev_hash = last_hash
            else:
                prev_hash = recorded["head_hash"]
            if EVIDENCE_CHAIN_V2:
                entry_hash = _manifest_entry_hash(
                    prev_hash, environment_id, source, since, until, len(entries), created_at, batch_hash, content_hash
                )
                v2_fields = (content_hash, entry_hash, None)  # entries go to manifest_entries (migration 007)
            else:
                entry_hash = batch_hash  # v1 head: the next row chains to batch_hash, exactly as before
                v2_fields = (None, None, None)
            cur = conn.execute(
                """INSERT INTO ingestion_manifests
                   (environment_id, source, since, until, row_count, batch_hash, prev_manifest_hash, created_at,
                    content_hash, entry_hash, entries_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (environment_id, source, since, until, len(entries), batch_hash, prev_hash, created_at, *v2_fields),
            )
            manifest_id = cur.lastrowid
            if EVIDENCE_CHAIN_V2:
                conn.executemany(
                    "INSERT INTO manifest_entries (environment_id, manifest_id, uuid, sha) VALUES (?, ?, ?, ?)",
                    ((environment_id, manifest_id, u, s) for u, c, s in entries if c),
                )
            # The head is recorded in both modes, so a v1 row written with
            # the flag off still keeps chain_heads current (the chain is
            # reported as downgraded either way; it must not ALSO look cut short).
            conn.execute(
                """INSERT INTO chain_heads (environment_id, manifest_id, head_hash, updated_at) VALUES (?, ?, ?, ?)
                   ON CONFLICT(environment_id) DO UPDATE SET
                       manifest_id = excluded.manifest_id, head_hash = excluded.head_hash, updated_at = excluded.updated_at""",
                (environment_id, manifest_id, entry_hash, created_at),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    try:
        import create_secret_folders
        create_secret_folders.log_audit_event(
            None, None, "evidence_chain.sealed",
            {"environment_id": environment_id, "source": source, "row_count": len(entries), "chain_head": entry_hash},
        )
    except Exception:
        pass
    return entry_hash


# DATA-04: new manifests are written in the v2 format (enabled 5.40.4,
# maintainer decision 2026-10-08). Each v2 row seals the content of every
# curated event it ingested plus every manifest field, so the chain is
# tamper evidence from the first v2 row onward. Rows written before then
# stay v1 (a uuid-only continuity check) and are never re-sealed: the
# first v2 row chains to the last v1 row's batch_hash, and
# verify_ingestion_chain reports how many legacy rows precede it. Setting
# this back to False is a downgrade the verifier flags as a broken chain.
EVIDENCE_CHAIN_V2 = True


def verify_ingestion_chain(environment_id, deep=False):
    """Walks this environment's ingestion_manifests in insertion order
    and verifies the chain (DATA-04, see _record_ingestion_manifest):
    every row's prev_manifest_hash must equal the previous row's head
    (entry_hash, or batch_hash for a pre-v2 row); every v2 row's
    entry_hash must recompute from its stored fields; and with
    deep=True every v2 row's curated events are re-read from `events`,
    re-hashed and compared against its sealed entries (manifest_entries)
    and content_hash -- so a
    deleted or edited curated event, an edited manifest field, a deleted
    manifest, or a re-ordered chain all surface here. A non-curated row
    missing from `events` is NOT a failure (retention pruning is
    legitimate) -- it is counted in `unverifiable_rows`.

    Once a v2 row has been seen, a later row WITHOUT v2 fields breaks the
    chain ("downgrade"): otherwise anyone with write access could null
    the v2 columns of the tail and relink it by batch_hash, turning the
    content seal back off silently.

    Returns {"valid", "manifest_count", "broken_at", "reason",
    "head_hash", "legacy_manifests", "deep", "deep_applicable",
    "verified_rows", "unverifiable_rows"}. deep_applicable is False when
    no manifest carries v2 fields (nothing content-sealed to re-read --
    an archive whose manifests all predate 5.40.4), so a caller never
    mistakes "verified 0 rows" for "all rows verified". broken_at is the
    id of the first bad row, or None (or the recorded head's manifest id
    when the chain was cut short). Zero manifests with no recorded head
    is a valid, intact chain of nothing.

    The END of the chain is checked against chain_heads (migration 007),
    written with every manifest since 5.40.4 and backfilled at upgrade:
    if manifests were removed from the
    tail -- including every v2 manifest, which would otherwise make the
    archive look like an all-legacy pre-5.40.4 one -- the computed head
    no longer matches the recorded one; the writer links new rows to the
    recorded head, so a later sync leaves the gap visible as a
    prev_manifest_hash mismatch instead of healing it. All reads happen
    in one read transaction, so a sync committing mid-check cannot make
    the head look "removed". Rows that older code appended after the
    recorded head (a code-only rollback; it never updates chain_heads)
    are walked and checked like any others and reported as
    `head_stale: true`, not as tampering.

    Threat model, stated plainly: the hashes are unkeyed, so this detects
    edits made by someone who does not also recompute the chain (and
    chain_heads) after them -- a careless or partial edit, a restore of
    the wrong backup, a tool that rewrote rows. Someone with write access
    who recomputes every hash can forge a valid chain; the out-of-band
    check for that is comparing head_hash with the last
    `evidence_chain.sealed` entry in audit_log.jsonl. Rewriting or
    deleting the chain_heads row needs no hashing at all, so the tail
    check is only as strong as that row. Event content is only re-read
    with deep=True, and only for curated events."""
    conn = _get_connection()  # this thread's own connection: no _db_lock, so a long deep check never blocks a sync
    own_txn = not conn.in_transaction
    if own_txn:
        conn.execute("BEGIN")  # one WAL read snapshot for every read below
    try:
        return _verify_ingestion_chain_snapshot(conn, environment_id, deep)
    finally:
        if own_txn:
            conn.rollback()


def _verify_ingestion_chain_snapshot(conn, environment_id, deep):
    rows = conn.execute(
        """SELECT id, environment_id, source, since, until, row_count, batch_hash, prev_manifest_hash,
                  created_at, content_hash, entry_hash
           FROM ingestion_manifests WHERE environment_id = ? ORDER BY id ASC""",
        (environment_id,),
    ).fetchall()
    recorded_head = conn.execute(
        "SELECT manifest_id, head_hash FROM chain_heads WHERE environment_id = ?", (environment_id,)
    ).fetchone()
    result = {
        "valid": True, "manifest_count": len(rows), "broken_at": None, "reason": None, "head_hash": None,
        "legacy_manifests": 0, "deep": bool(deep), "deep_applicable": False, "verified_rows": 0, "unverifiable_rows": 0,
    }

    def _broken(row, reason):
        result.update({"valid": False, "broken_at": row["id"], "reason": reason})
        return result

    expected_prev = None
    seen_v2 = False
    for row in rows:
        if row["prev_manifest_hash"] != expected_prev:
            return _broken(row, "prev_manifest_hash does not match the previous manifest")
        if not row["entry_hash"]:
            if seen_v2:
                return _broken(row, "a manifest without v2 fields follows a sealed (v2) manifest -- chain downgraded")
            result["legacy_manifests"] += 1
            expected_prev = row["batch_hash"]
            continue
        seen_v2 = True
        result["deep_applicable"] = True
        recomputed = _manifest_entry_hash(
            row["prev_manifest_hash"], row["environment_id"], row["source"], row["since"], row["until"],
            row["row_count"], row["created_at"], row["batch_hash"], row["content_hash"],
        )
        if recomputed != row["entry_hash"]:
            return _broken(row, "entry_hash does not match the manifest's stored fields")
        if deep:
            legacy_json = conn.execute(
                "SELECT entries_json FROM ingestion_manifests WHERE id = ?", (row["id"],)
            ).fetchone()["entries_json"]
            if legacy_json is not None:  # 5.40.2-format v2 row (flag forced on by hand before 5.40.4)
                try:
                    pairs = [tuple(e) for e in json.loads(legacy_json)]
                except (ValueError, TypeError):
                    return _broken(row, "entries_json is unreadable")
                sealed = sorted(
                    (f"{u}:{sha}", u, sha, _stored_raw(conn, environment_id, u)) for u, sha in pairs
                )
            else:
                # Streamed in the content hash's own order: SQLite's default
                # BINARY collation compares UTF-8 bytes, which orders the
                # same as Python's code-point sort of the same strings.
                sealed = (
                    (r["line"], r["uuid"], r["sha"], r["raw_json"]) for r in conn.execute(
                        """SELECT me.uuid || ':' || me.sha AS line, me.uuid, me.sha, e.raw_json
                           FROM manifest_entries me
                           LEFT JOIN events e ON e.environment_id = me.environment_id AND e.uuid = me.uuid
                           WHERE me.manifest_id = ? ORDER BY line""",
                        (row["id"],),
                    )
                )
            h = hashlib.sha256()
            count = 0
            first_event_problem = None
            for line, uuid, sha, raw_json in sealed:
                if count:
                    h.update(b"\n")
                h.update(line.encode("utf-8"))
                count += 1
                if first_event_problem is None:
                    if raw_json is None:
                        first_event_problem = f"curated event {uuid} is missing from the archive"
                    elif _content_sha256(raw_json) != sha:
                        first_event_problem = f"event {uuid} content does not match its sealed hash"
            if count > row["row_count"]:
                return _broken(row, "the manifest lists more sealed rows than row_count")
            # The sealed entries are the curated rows only, so the content
            # hash recomputes from them directly; non-curated rows are the
            # difference between row_count and the sealed count and were
            # never content-sealed (retention may legitimately prune them).
            if h.hexdigest() != row["content_hash"]:
                return _broken(row, "content_hash does not match the manifest's sealed entries")
            if first_event_problem:
                return _broken(row, first_event_problem)
            result["unverifiable_rows"] += row["row_count"] - count
            result["verified_rows"] += count
        expected_prev = row["entry_hash"]
    result["head_hash"] = expected_prev
    result["head_stale"] = False
    if (recorded_head is not None and recorded_head["head_hash"] != expected_prev
            and _recorded_head_is_stale(conn, environment_id, recorded_head)):
        # Rows appended after the recorded head by older code (a code-only
        # rollback) -- the walk above already validated them. Not tampering;
        # the next sync refreshes the head.
        result["head_stale"] = True
    elif recorded_head is not None and recorded_head["head_hash"] != expected_prev:
        result.update({
            "valid": False, "broken_at": recorded_head["manifest_id"],
            "reason": "the chain ends before the recorded head -- manifests were removed from the end",
        })
    elif recorded_head is None and seen_v2:
        result.update({
            "valid": False, "broken_at": rows[-1]["id"],
            "reason": "sealed (v2) manifests exist but the recorded chain head is missing",
        })
    return result


def _stored_raw(conn, environment_id, uuid):
    found = conn.execute(
        "SELECT raw_json FROM events WHERE environment_id = ? AND uuid = ?", (environment_id, uuid)
    ).fetchone()
    return found["raw_json"] if found else None


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
    now_iso = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    # Rows are swept an hour AFTER they expire, so an admin returning late
    # from the step-up redirect still gets the accurate "expired", not
    # "not_found".
    sweep_before = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    with _db_lock:
        try:
            # SRV-05 (external review, 2026-10-05): the expired-and-abandoned
            # sweep used to run only at process start, so between restarts
            # every prepare added a row with no runtime bound. Swept here,
            # in the same transaction (index-served by
            # idx_pending_admin_actions_expires), so the table only ever
            # holds actions that are still claimable or already consumed.
            conn.execute(
                "DELETE FROM pending_admin_actions WHERE expires_at < ? AND consumed_at IS NULL",
                (sweep_before,),
            )
            conn.execute(
                """INSERT INTO pending_admin_actions
                   (action_id, actor_sub, action_type, payload_json, payload_hash, created_at, expires_at, consumed_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, NULL)""",
                (action_id, actor_sub, action_type, payload_json, payload_hash, now_iso,
                 (now + timedelta(seconds=ttl_seconds)).strftime("%Y-%m-%dT%H:%M:%S.000Z")),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    return action_id


def consume_pending_admin_action(action_id, actor_sub, action_types=None, return_action_type=False):
    """Looks up `action_id`, verifies it belongs to `actor_sub`, hasn't
    expired, and hasn't already been consumed -- if all three hold,
    marks it consumed and returns the stored payload (parsed from JSON).
    Raises PendingActionError otherwise, with a specific `reason`.

    `action_types` (5.42.0, optional): the action types this caller
    applies. A pending action of any other type is refused with
    "action_type_mismatch" and left untouched -- a step-up approval for an
    Environments change can't be spent on (or burned by) the Access
    Control save, nor the other way round. None keeps the old behaviour.
    return_action_type=True returns (payload, action_type) instead, so a
    caller can check the stored payload against the row's own type.

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
        if action_types is not None and row["action_type"] not in action_types:
            raise PendingActionError("action_type_mismatch")
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
    payload = json.loads(row["payload_json"])
    return (payload, row["action_type"]) if return_action_type else payload


def count_open_pending_admin_actions(actor_sub, action_types):
    """How many of these types `actor_sub` has prepared and not yet applied
    (unexpired) -- 5.42.0, bounds what one user can leave pending."""
    conn = _get_connection()
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    marks = ",".join("?" * len(action_types))
    row = conn.execute(
        f"""SELECT COUNT(*) FROM pending_admin_actions
            WHERE actor_sub IS ? AND consumed_at IS NULL AND expires_at >= ? AND action_type IN ({marks})""",
        (actor_sub, now_iso, *action_types),
    ).fetchone()
    return row[0]


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


_SYNC_STATE_FIELDS = (
    "last_synced_at", "last_sync_completed_at", "last_sync_status", "last_sync_error",
    "total_events_ingested", "ingestion_scope", "last_sync_attempt_at", "last_import_at",
)


def _upsert_sync_state(conn, environment_id, **fields):
    """Writes ONLY the supplied fields (DATA-11, external review,
    2026-10-05): the old read-merge-write outside the lock let a CSV
    import racing a background sync write back a stale copy of the whole
    row -- moving the watermark backwards or overwriting the status.
    One statement under _db_lock, so there is nothing stale to merge."""
    unknown = set(fields) - set(_SYNC_STATE_FIELDS)
    if unknown:
        raise ValueError(f"unknown sync_state field(s): {sorted(unknown)}")
    columns = ["environment_id", *fields]
    placeholders = ",".join("?" for _ in columns)
    updates = ", ".join(f"{col}=excluded.{col}" for col in fields) or "environment_id=environment_id"
    with _db_lock:
        try:
            conn.execute(
                f"INSERT INTO sync_state ({', '.join(columns)}) VALUES ({placeholders}) "
                f"ON CONFLICT(environment_id) DO UPDATE SET {updates}",
                (environment_id, *fields.values()),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise


def reset_sync_watermark(environment_id):
    """DATA-03 remedy: clears last_synced_at so the next sync backfills
    the full 90-day window from scratch (INSERT OR IGNORE dedupes every
    row it has already). The only supported way out of an unusable
    watermark (a poisoned pre-5.40.2 CSV import, a clock that jumped) --
    nothing else is touched. Returns the watermark that was cleared."""
    conn = _get_connection()
    state = get_sync_state(environment_id)
    previous = (state or {}).get("last_synced_at")
    _upsert_sync_state(conn, environment_id, last_synced_at=None, last_sync_status=None, last_sync_error=None)
    return previous


def environment_has_archive(environment_id):
    """True once this environment has anything to report from -- a
    completed live sync OR a CSV import (DATA-03 moved imports off the
    sync watermark, so "has it synced" alone would wrongly say no for an
    import-only environment). Used by the archive-only report routes."""
    state = get_sync_state(environment_id)
    return bool(state and (state.get("last_sync_completed_at") or state.get("last_import_at")))


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
    "complete": bool, "incomplete_chunks": int, "chain_head": str}.

    Incomplete chunks (DATA-09, external review, 2026-10-05): when a
    day-chunk hits get_system_log's max_pages cap, the fetch is ASCENDING,
    so everything up to the newest `published` actually returned is known
    complete. The sync now persists the watermark at exactly that
    timestamp and carries on from there (re-reading that one inclusive
    instant, which INSERT OR IGNORE dedupes) instead of stopping -- the
    old "stop and retry the same day tomorrow" could never get past a day
    busier than the cap and let everything after it age out of Okta's
    90-day window. Only a chunk that returns NO progress at all (every
    page carried the same instant) stops the run with last_sync_status
    "error", since re-reading it would loop forever.

    Failure (DATA-05): a chunk's rows commit as they land, so an exception
    on a later chunk used to leave rows that no manifest covered and a
    sync_state stuck at "running" with no error. Any exception now
    records the manifest for every row already inserted, writes
    last_sync_status="error" + last_sync_error, and re-raises. Exactly
    one manifest is written per call (5.40.6): a failure after this
    call's manifest committed (e.g. the final sync_state write) marks the
    sync "error" but never seals the same rows a second time.
    last_sync_completed_at is written ONLY by a successful completion;
    last_sync_attempt_at records every start (the scheduler keys its
    retry back-off off the attempt, not the completion)."""
    if ingestion_scope not in INGESTION_SCOPES:
        raise ValueError(f"ingestion_scope must be one of {INGESTION_SCOPES}")
    conn = _get_connection()

    # Every start is an attempt (DATA-05), recorded BEFORE anything can
    # fail -- including the watermark check just below -- so the
    # scheduler's back-off sees it.
    _upsert_sync_state(
        conn, environment_id,
        last_sync_attempt_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        last_sync_status="running", last_sync_error=None, ingestion_scope=ingestion_scope,
    )

    if since is None:
        state = get_sync_state(environment_id)
        stored = (state or {}).get("last_synced_at")
        if stored:
            canonical = _canonical_published(stored)
            if canonical is None or canonical > datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"):
                # DATA-03: a watermark that doesn't parse, or sits in the
                # future, would make every later sync a silent no-op (or
                # a crash) -- say so instead of pretending to sync. The
                # remedy is reset_sync_watermark (route: POST
                # /api/environments/<name>/sync/reset_watermark).
                message = (
                    f"Stored sync watermark {stored!r} is unusable (unparseable or in the future). "
                    "Reset the watermark (Compliance sync settings -> Reset watermark) and sync again; "
                    "the next sync will backfill the full 90-day window."
                )
                _upsert_sync_state(conn, environment_id, last_sync_status="error", last_sync_error=message)
                raise ValueError(message)
            watermark_dt = datetime.fromisoformat(canonical.replace("Z", "+00:00"))
            since = (watermark_dt - timedelta(seconds=WATERMARK_OVERLAP_SECONDS)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        else:
            since = (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    original_since = since
    safe_now_dt = datetime.now(timezone.utc) - timedelta(seconds=SAFETY_LAG_SECONDS)
    cursor = datetime.fromisoformat(since.replace("Z", "+00:00"))
    total_inserted = 0
    total_scanned = 0  # rows fetched, INCLUDING any re-read after a page-cap resume (see DATA-09 above)
    chunks = 0
    incomplete_chunks = 0
    all_new_entries = []  # Phase 6: accumulated across every day-chunk, sealed into ONE manifest row for this whole call
    # Exactly one manifest per call (5.40.6): once this call's rows are
    # sealed, nothing may seal them again. Before this, a failure AFTER the
    # success manifest committed (the final _upsert_sync_state) fell into
    # the except below, whose _fail wrote a second manifest for the same
    # rows -- the chain stayed valid but row_count was counted twice.
    sealed = {"head": None, "done": False}

    def _seal(until):
        if not sealed["done"]:
            sealed["head"] = _record_ingestion_manifest(
                conn, environment_id, "sync", original_since, until, all_new_entries
            )
            sealed["done"] = True  # only after the commit: a seal that raised rolled back and may be retried
        return sealed["head"]

    def _fail(error_message, until):
        try:
            _upsert_sync_state(conn, environment_id, last_sync_status="error", last_sync_error=error_message)
            if on_progress:
                on_progress("ingest", "error", error_message)
        except Exception:
            _seal(until)  # the rows still get sealed when the status write (or the callback) fails
            raise
        # An interrupted sync still produced real inserted rows (across
        # however many chunks completed) -- those must be in the chain
        # too, same "nothing new is silently invisible" reasoning as a
        # zero-new-rows batch. A no-op if this call already sealed them.
        return _seal(until)

    try:
        while cursor < safe_now_dt:
            chunk_until_dt = min(cursor + timedelta(days=CHUNK_DAYS), safe_now_dt)
            chunk_since = _iso_ms(cursor)  # millisecond-exact, so "no progress" below compares like with like
            chunk_until = _iso_ms(chunk_until_dt)

            if on_progress:
                on_progress("fetch", "progress", f"{chunk_since} .. {chunk_until}")
            events, complete = okta_client.get_system_log(
                since=chunk_since, until=chunk_until, limit=1000, sort_order="ASCENDING", max_pages=200
            )
            total_scanned += len(events)

            rows = [_normalize_live_event(e) for e in events]
            inserted, max_published, new_entries = _insert_rows(conn, environment_id, rows, ingestion_scope)
            total_inserted += inserted
            all_new_entries.extend(new_entries)
            chunks += 1

            if not complete:
                incomplete_chunks += 1
                if not max_published or max_published <= chunk_since:
                    error_message = (
                        f"Hit max_pages for {chunk_since}..{chunk_until} without making progress -- more "
                        f"events share the instant {chunk_since} than one sync run can page through. "
                        f"Watermark left at {chunk_since}; the next sync will retry it."
                    )
                    chain_head = _fail(error_message, chunk_until)
                    return {
                        "inserted": total_inserted, "scanned": total_scanned, "since": original_since,
                        "chunks": chunks, "complete": False, "incomplete_chunks": incomplete_chunks,
                        "error": error_message, "chain_head": chain_head,
                    }
                # Everything up to max_published is complete (ascending
                # fetch); resume from exactly there, same day.
                if on_progress:
                    on_progress("fetch", "progress", f"{chunk_since} .. {chunk_until} hit the page cap at {max_published}; resuming from there")
                _upsert_sync_state(conn, environment_id, last_synced_at=max_published, last_sync_status="running")
                cursor = datetime.fromisoformat(max_published.replace("Z", "+00:00"))
                continue

            # Persist progress after EVERY chunk, not just at the end -- a
            # restart mid-backfill resumes from here instead of from scratch.
            watermark = max_published or chunk_until
            _upsert_sync_state(conn, environment_id, last_synced_at=watermark, last_sync_status="running")
            cursor = chunk_until_dt

        # Still inside the try: a failure sealing the manifest or writing
        # the final state must also end as "error", never a silent "running".
        chain_head = _seal(_iso_ms(safe_now_dt))
        _upsert_sync_state(
            conn, environment_id,
            last_sync_completed_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            last_sync_status="success", last_sync_error=None,
        )
    except Exception as exc:
        try:
            _fail(f"{type(exc).__name__}: {exc}", _iso_ms(cursor))
        except Exception:
            pass  # the original exception is the one worth surfacing
        raise

    if on_progress:
        on_progress("ingest", "done", f"{total_inserted} new row(s) inserted across {chunks} day-chunk(s)")
    return {
        "inserted": total_inserted, "scanned": total_scanned, "since": original_since, "chunks": chunks,
        "complete": True, "incomplete_chunks": incomplete_chunks, "chain_head": chain_head,
    }


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
    skipped_unparseable = 0
    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for csv_row in reader:
            normalized = _normalize_csv_row(csv_row)
            if normalized[2] is None and (normalized[0] or normalized[1]):
                skipped_unparseable += 1  # a real row whose timestamp didn't parse (DATA-03) -- never stored
            rows.append(normalized)
    if on_progress:
        on_progress("read_csv", "done", f"{len(rows)} row(s) read")

    inserted, _max_published, new_entries = _insert_rows(conn, environment_id, rows, ingestion_scope)
    chain_head = _record_ingestion_manifest(conn, environment_id, "csv_import", None, None, new_entries)

    # DATA-03 (external review, 2026-10-05): a CSV import no longer
    # touches last_synced_at at all. The live-sync watermark describes
    # what the LIVE sync has covered; letting a file's newest timestamp
    # set it meant (a) a future/garbage timestamp silently disabled every
    # later sync, (b) a filtered or partial export skipped everything the
    # file didn't contain, and (c) an import on a new environment skipped
    # the first live sync's 90-day backfill. The import is recorded in
    # its own column; the next live sync still backfills from scratch and
    # the dedup-by-uuid insert keeps the overlap free of duplicates.
    _upsert_sync_state(
        conn, environment_id,
        last_import_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        ingestion_scope=ingestion_scope,
    )
    if on_progress:
        on_progress("ingest", "done", f"{inserted} new row(s) inserted")
    return {"inserted": inserted, "scanned": len(rows), "skipped_unparseable": skipped_unparseable, "chain_head": chain_head}


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
    retention. If max_size_mb is also set and this environment's own
    archived payload (the bytes of its stored events -- NOT the database
    file, see DATA-12 below) is still over that size after the
    time-based prune, walks the cutoff back one day at a time (oldest
    non-curated first) until under the cap, or until every non-curated
    row is gone (curated rows are never sacrificed to satisfy a size cap).

    Returns {"pruned": int, "cutoff": str|None}."""
    conn = _get_connection()
    pruned_total = 0
    cutoff = None

    if retention_days is not None:
        cutoff_dt = datetime.now(timezone.utc) - timedelta(days=retention_days)
        cutoff = cutoff_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        with _db_lock:
            try:
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
            except Exception:
                conn.rollback()  # DATA-11
                raise

    if max_size_mb is not None:
        max_bytes = max_size_mb * 1024 * 1024
        step_days = 1
        pruned_any_by_size = False

        # DATA-12 (external review, 2026-10-05): the cap is measured
        # against THIS environment's own stored payload (the UTF-8 BYTES of
        # its raw_json -- CAST AS BLOB, since LENGTH() on TEXT counts
        # characters), not the whole database file. Measuring the file
        # meant every other environment's rows -- and the orphaned archive
        # of any deleted environment (see list_orphaned_archives) --
        # counted against this environment's cap, so a live environment
        # lost its own non-curated history to make room for data nobody
        # could even see. This IS a change of meaning for an install with a
        # cap already configured: indexes, event_targets and row overhead
        # are no longer counted, so the file can exceed the configured
        # number -- the cap is a per-environment payload budget now, which
        # is what "max N MB for this environment" means (noted in the
        # 5.40.2 changelog and in the sync-settings dialog). Computed once,
        # then decremented by the bytes each step removes, so a long walk
        # back is not O(rows) per iteration.
        live_bytes = conn.execute(
            "SELECT COALESCE(SUM(LENGTH(CAST(raw_json AS BLOB))), 0) FROM events WHERE environment_id = ?", (environment_id,)
        ).fetchone()[0]

        # Walk the cutoff back further, oldest non-curated first, until under the cap
        # or nothing non-curated is left to prune.
        for _ in range(3650):  # hard safety cap -- never loop forever
            if live_bytes <= max_bytes:
                break
            oldest = conn.execute(
                "SELECT MIN(published) FROM events WHERE environment_id = ? AND is_curated = 0",
                (environment_id,),
            ).fetchone()[0]
            if not oldest:
                break  # nothing non-curated left -- curated rows are never sacrificed to a size cap
            step_cutoff = (
                datetime.fromisoformat(oldest.replace("Z", "+00:00")) + timedelta(days=step_days)
            ).strftime("%Y-%m-%dT%H:%M:%S.000Z")
            with _db_lock:
                try:
                    step_bytes = conn.execute(
                        "SELECT COALESCE(SUM(LENGTH(CAST(raw_json AS BLOB))), 0) FROM events "
                        "WHERE environment_id = ? AND is_curated = 0 AND published < ?",
                        (environment_id, step_cutoff),
                    ).fetchone()[0]
                    # DATA-01, same reasoning as the retention_days branch above.
                    _delete_pruned_targets(conn, environment_id, "AND is_curated = 0 AND published < ?", (step_cutoff,))
                    cur = conn.execute(
                        "DELETE FROM events WHERE environment_id = ? AND is_curated = 0 AND published < ?",
                        (environment_id, step_cutoff),
                    )
                    pruned_total += cur.rowcount
                    conn.commit()
                except Exception:
                    conn.rollback()
                    raise
            live_bytes -= step_bytes
            pruned_any_by_size = True

        # Reclaim the actual disk space exactly ONCE, after every delete
        # this call is going to do -- not per-iteration. Under the lock
        # (DATA-11): VACUUM rewrites the file and blocks every writer for
        # its duration, so no writer should be mid-transaction when it runs.
        if pruned_any_by_size:
            with _db_lock:
                conn.execute("VACUUM")

    return {"pruned": pruned_total, "cutoff": cutoff}


def list_orphaned_archives():
    """DATA-12: environment_ids that still have archive rows (events,
    sync_state, ingestion_manifests or their chain tables) but no app_environments row any
    more -- the data a deleted environment leaves behind, which no route
    could address, prune, export or purge before. Returns one dict per
    orphan with what an admin needs to decide: event_count, bytes (raw
    payload), oldest/newest published, manifest_count. Cost: the
    DISTINCT over events is an index scan of the whole table plus one
    aggregate per orphan -- fine for an admin-only, on-demand call, not
    something to poll."""
    conn = _get_connection()
    ids = {
        r[0] for r in conn.execute(
            """SELECT DISTINCT environment_id FROM events
               UNION SELECT environment_id FROM sync_state
               UNION SELECT environment_id FROM ingestion_manifests
               UNION SELECT environment_id FROM chain_heads
               UNION SELECT environment_id FROM manifest_entries"""
        )
    } - {r[0] for r in conn.execute("SELECT environment_id FROM app_environments")}
    out = []
    for environment_id in sorted(ids):
        stats = conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(LENGTH(CAST(raw_json AS BLOB))), 0), MIN(published), MAX(published) "
            "FROM events WHERE environment_id = ?",
            (environment_id,),
        ).fetchone()
        manifests = conn.execute(
            "SELECT COUNT(*) FROM ingestion_manifests WHERE environment_id = ?", (environment_id,)
        ).fetchone()[0]
        out.append({
            "environment_id": environment_id, "event_count": stats[0], "bytes": stats[1],
            "oldest_published": stats[2], "newest_published": stats[3], "manifest_count": manifests,
        })
    return out


# Every table holding one environment's archive, in purge order (children first).
ARCHIVE_TABLES = ("event_targets", "events", "sync_state", "manifest_entries", "chain_heads", "ingestion_manifests")


def archive_has_rows(environment_id):
    """True if any archive table holds a row for this environment id (the
    same tables purge_environment_archive empties)."""
    conn = _get_connection()
    return any(
        conn.execute(f"SELECT 1 FROM {table} WHERE environment_id = ? LIMIT 1", (environment_id,)).fetchone()
        for table in ARCHIVE_TABLES
    )


def purge_environment_archive(environment_id):
    """DATA-12: removes every archive row for an environment that no
    longer exists -- events, event_targets, sync_state, ingestion_manifests
    and their sealed entries / recorded head -- in one transaction. Refuses (ValueError) while
    an app_environments row still references the id: a live environment's
    evidence is deleted through delete_environment(purge_archive=True),
    never by addressing the archive directly. Returns the per-table
    counts so the caller can audit-log exactly what was destroyed."""
    conn = _get_connection()
    with _db_lock:
        try:
            conn.execute("BEGIN IMMEDIATE")  # the existence check and the deletes are one unit
            if conn.execute("SELECT 1 FROM app_environments WHERE environment_id = ?", (environment_id,)).fetchone():
                raise ValueError("That environment still exists; delete the environment itself to purge its archive.")
            counts = {}
            for table in ARCHIVE_TABLES:
                counts[table] = conn.execute(f"DELETE FROM {table} WHERE environment_id = ?", (environment_id,)).rowcount
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    return counts


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


_BARE_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def normalize_window(since, until):
    """DATA-13 (external review, 2026-10-05): the `from`/`to` query
    parameters used to be compared against `published` as raw strings,
    so "2026-09-29T10:00" (no seconds), a value with a +02:00 offset, or
    plain garbage gave a subtly wrong window with no error. Each bound is
    now parsed and re-emitted in the archive's canonical UTC form: a bare
    date (what the date pickers send) means that whole UTC day -- start
    of day for `since`, end of day for `until` (the _normalize_until
    rule); any other ISO-8601 value is converted to UTC; anything else
    raises ValueError (-> HTTP 400 via the shared handler). None passes
    through. Applied inside query_events/count_events so every caller --
    reports, resource history, the picker counts -- gets the same rule."""
    def _one(value, end_of_day):
        if value is None or value == "":
            return None
        text = str(value).strip()
        if _BARE_DATE_RE.match(text):
            try:
                datetime.strptime(text, "%Y-%m-%d")
            except ValueError:
                raise ValueError(f"invalid date {value!r}: expected YYYY-MM-DD")
            return text + ("T23:59:59.999Z" if end_of_day else "T00:00:00.000Z")
        canonical = _canonical_published(text)
        if canonical is None:
            raise ValueError(f"invalid timestamp {value!r}: expected YYYY-MM-DD or an ISO-8601 date-time")
        return canonical

    since_norm, until_norm = _one(since, False), _one(until, True)
    if since_norm and until_norm and since_norm > until_norm:
        raise ValueError("the 'from' bound is after the 'to' bound")
    return since_norm, until_norm


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


def iter_events_targeting(environment_id, target_id, event_types):
    """Yields every archived event of `event_types` that names `target_id`
    among its targets (any target, not only the primary resource),
    newest first, one row at a time: {"uuid", "published", "raw"}.

    ENG2-03 (external review, 2026-10-05): the archive-backed secrets
    report used query_events(limit=100000) over the WHOLE environment and
    filtered by project in Python -- the cap applied before the filter, so
    past 100k secret/folder events the oldest (the creates) silently fell
    off, and every request parsed up to 100k raw events. event_targets
    holds one row per target of every stored event (written on insert,
    backfilled at boot for older rows) and is indexed on (environment_id,
    target_id), so the project filter runs in SQL and nothing is capped.
    The caller still checks the target's type itself."""
    if not event_types:
        return
    conn = _get_connection()
    placeholders = ",".join("?" for _ in event_types)
    sql = (
        "SELECT uuid, published, raw_json FROM events WHERE environment_id = ? "
        f"AND event_type IN ({placeholders}) "
        "AND uuid IN (SELECT uuid FROM event_targets WHERE environment_id = ? AND target_id = ?) "
        "ORDER BY published DESC"
    )
    for row in conn.execute(sql, (environment_id, *event_types, environment_id, target_id)):
        yield {"uuid": row["uuid"], "published": row["published"], "raw": json.loads(row["raw_json"])}


def query_events(environment_id, event_types=None, since=None, until=None, actor_id=None, resource_id=None, limit=1000,
                 match_alternate_id=True):
    """Generic report query -- used by every COMPLIANCE_REPORTS preset in
    Phase 4, and by resource_history below. Returns raw rows (dicts with
    the full parsed raw_json under "raw"), shaping to the four-field
    standard is left to the caller since different reports want different
    extra columns from the same underlying rows.

    resource_id, when given, matches against EITHER the stored
    resource_id OR resource_alternate_id column (both are populated from
    the same real target id -- see _resource_fields -- and for most
    resource kinds confirmed live to just be the same value twice, but
    matching both covers any kind where they'd genuinely differ).

    match_alternate_id=False restricts that to resource_id alone. Measured
    with EXPLAIN QUERY PLAN during the v5.40.0 review: the OR form can't
    use any index on resource_id (resource_alternate_id is unindexed), so
    SQLite walks the environment newest-first via idx_events_env_published
    until `limit` rows match -- ~100ms per call on a 175k-row environment
    for a rarely-matching resource. With the OR dropped (and
    _migration_005's index) the same read is index-ordered. Callers that
    know alternateId == id for their event family (confirmed for every
    service-account event, see create_secret_folders.py) pass False."""
    _require_positive_limit(limit)
    conn = _get_connection()
    since, until = normalize_window(since, until)
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
    if resource_id and match_alternate_id:
        clauses.append("(resource_id = ? OR resource_alternate_id = ?)")
        params.extend([resource_id, resource_id])
    elif resource_id:
        clauses.append("resource_id = ?")
        params.append(resource_id)
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
    since, until = normalize_window(since, until)
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


def count_events_by_resource(environment_id, event_types):
    """Per-resource totals for the given event types, without parsing a
    single raw_json: {resource_id: {"total", "by_outcome": {outcome:
    count}, "type_details": {resource_type_detail: count}, "first_at",
    "last_at"}} for every resource that has any matching row. One GROUP
    BY over stored columns, served by _migration_005's covering index --
    added for the service-accounts report, where password_rotation.end
    alone was 115k rows in a real archive and loading those as raw
    events just to count them per account is not an option.

    type_details is what lets that report classify an account family
    (SaaS / Okta / database / AD) for ids it only ever sees in rotation
    rows WITHOUT reading any raw JSON: _resource_type_detail_fallback
    stores debugData.serviceAccountType in resource_type_detail at
    ingest, so every value a resource's rows ever carried is one bucket
    here. Rows ingested before that fallback existed have NULL there
    (not counted in type_details) -- the caller samples raw rows only for
    a resource whose type_details is empty. Rows whose resource_id is
    NULL have nothing to group by and are skipped."""
    if not event_types:
        return {}
    conn = _get_connection()
    placeholders = ",".join("?" for _ in event_types)
    sql = (
        "SELECT resource_id, outcome_result, resource_type_detail, COUNT(*) AS n, "
        "MIN(published) AS first_at, MAX(published) AS last_at FROM events "
        f"WHERE environment_id = ? AND event_type IN ({placeholders}) AND resource_id IS NOT NULL "
        "GROUP BY resource_id, outcome_result, resource_type_detail"
    )
    out = {}
    for row in conn.execute(sql, [environment_id, *event_types]):
        entry = out.setdefault(
            row["resource_id"], {"total": 0, "by_outcome": {}, "type_details": {}, "first_at": None, "last_at": None}
        )
        outcome = row["outcome_result"] or "UNKNOWN"
        entry["total"] += row["n"]
        entry["by_outcome"][outcome] = entry["by_outcome"].get(outcome, 0) + row["n"]
        detail = row["resource_type_detail"]
        if detail:
            entry["type_details"][detail] = entry["type_details"].get(detail, 0) + row["n"]
        if entry["first_at"] is None or (row["first_at"] and row["first_at"] < entry["first_at"]):
            entry["first_at"] = row["first_at"]
        if entry["last_at"] is None or (row["last_at"] and row["last_at"] > entry["last_at"]):
            entry["last_at"] = row["last_at"]
    return out


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
    resource_type_detail = debug_data.get("resourceType") or _resource_type_detail_fallback(event_type, debug_data)
    return resource_id or None, resource_alternate_id or None, resource_type_detail or None


def _resource_type_detail_fallback(event_type, debug_data):
    """What to show as resource_type_detail when an event has no
    debugData.resourceType at all -- shared by _resource_fields (ingest
    time, stored) and _four_field_row (read time, for rows ingested
    before a given fallback existed, so no backfill migration is needed
    when one is added). Every branch is live-confirmed:

    - user.authentication.auth_via_mfa (confirmed 2026-09-30): no
      `resourceType`, but the real authenticator/factor used (e.g.
      OKTA_VERIFY_PUSH, SIGNED_NONCE/FastPass, GOOGLE_AUTHENTICATOR) is in
      `factor` -- without it the MFA Enforcement report's detail column
      was always blank and fell back to the generic
      "AuthenticatorEnrollment" target type, which can't distinguish a
      push challenge from a TOTP code or a phishing-resistant FastPass
      verification -- real information an auditor asking "which factor
      types are actually in use" needs.
    - pam.service_account.* (confirmed 2026-10-07 across ~130k real rows):
      no `resourceType`, but `serviceAccountType` names the account
      family (APP_ACCOUNT = SaaS app, OKTA_USER_ACCOUNT = Okta Universal
      Directory, DATABASE_ACCOUNT, PAM_AD_ACCOUNT). Without it the
      Credential Reveals / Credential Rotation cards showed every row as
      a bare "Service Account", lumping four genuinely different account
      families together -- see create_secret_folders.py's
      SERVICE_ACCOUNT_TYPE_TO_KIND for the same strings on the report
      side. An empty string (seen once live, on an update event) is
      returned as None so the generic target type still shows."""
    event_type = event_type or ""
    if event_type == "user.authentication.auth_via_mfa":
        return debug_data.get("factor") or None
    if event_type.startswith("pam.service_account."):
        return debug_data.get("serviceAccountType") or None
    return None


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
    # Read-time fallback for rows ingested before a given
    # _resource_type_detail_fallback branch existed -- those rows already
    # have resource_id set, so backfill_resource_columns (which only
    # touches rows with all three columns NULL) will never revisit them.
    debug_data = (raw.get("debugContext") or {}).get("debugData") or {}
    resource_type_detail = event_row.get("resource_type_detail") or _resource_type_detail_fallback(event_type, debug_data)
    return {
        "uuid": event_row["uuid"],
        "user": event_row["actor_display_name"] or event_row["actor_alternate_id"] or event_row["actor_id"] or "unknown",
        "actor_alternate_id": event_row["actor_alternate_id"],
        "action": raw.get("displayMessage") or event_row["event_type"],
        "event_type": event_row["event_type"],
        "timestamp": event_row["published"],
        "resource": resource or "",
        "resource_type": resource_type or "",
        "resource_type_detail": resource_type_detail or "",
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
    accounts do NOT need this fallback -- but note WHICH id is the log
    target: it is the account's own OPA-internal `id` (the
    access_tracking_id the Access Explorer indexes), NOT the Okta-side
    privileged_resource_id / okta_user_id, which are never logged as
    targets at all (confirmed 2026-08-15 and again across ~130k real
    rows on 2026-10-07 -- see create_secret_folders.py's
    RESOURCE_ACCESS_EVENT_TYPES and SERVICE_ACCOUNT_REPORT_EVENT_TYPES).
    The Service Accounts Dashboard (v5.40.0) calls this with that id and
    NO resource_name on purpose: a service-account display name can
    repeat across apps or collide with a DB/AD account, and a
    compliance drill-down must not mix another account's events in.

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
