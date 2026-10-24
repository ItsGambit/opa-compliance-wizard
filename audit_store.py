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
import zlib
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
    # CC6 -- Access Controls (API tokens moved here from CC8 in 5.53.0; see server/control_catalogue.json)
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
        "description": "Every MFA challenge (success and abandoned) plus the sign-on policy evaluation that gates it.",
    },
    "session_activity": {
        "label": "Session Activity",
        "description": "Successful sign-ins to Okta across all apps.",
    },
    "provisioning": {
        "label": "Provisioning & De-provisioning",
        "description": "User lifecycle create/deactivate events.",
    },
    "role_group_changes": {
        "label": "Role/Group Changes",
        "description": "Group membership add/remove — RBAC drift over time.",
    },
    "admin_privilege_grants": {
        "label": "Admin Privilege Grants",
        "description": "Super-admin / role assignment changes.",
    },
    "jit_access_requests": {
        "label": "JIT Access Requests",
        "description": (
            "Access-request lifecycle (create/update/resolve/expire) -- shows an access request was "
            "made and resolved. Known limitation, confirmed live 2026-09-30 against a real denied "
            "request: Okta's own System Log does not capture the actual approve/deny DECISION anywhere "
            "on the resolve event (debugContext.debugData.decisions is always the literal string \"[]\", "
            "and outcome.result is always SUCCESS regardless of the decision -- this is a real gap in "
            "Okta's own audit trail, not something this tool can surface by picking a different field)."
        ),
    },
    "threat_detection": {
        "label": "Threat Detection",
        "description": "Blocked requests and protected-action attempts flagged by Okta's own security controls.",
    },
    "api_token_lifecycle": {
        "label": "API Token Lifecycle",
        "description": "Service-account API token create/revoke.",
    },
    "policy_modifications": {
        "label": "Policy Modifications",
        "description": "Global Okta sign-on/security policy rule and mapping changes.",
    },
    "pam_secrets": {
        "label": "PAM Secrets",
        "description": "Vaulted secret and secret-folder create/update/delete/reveal.",
    },
    "pam_jit_access": {
        "label": "PAM JIT Access (Checkout/Checkin)",
        "description": "Resource checkout and checkin.",
    },
    "pam_sessions": {
        "label": "PAM Sessions",
        "description": "Credential issuance and SSH logins to privileged servers. Note: SSH login actor is the OS-level username, not the Okta identity — correlate with a nearby credential-issuance row to attribute a session to a real person.",
    },
    "pam_credential_reveals": {
        "label": "PAM Credential Reveals",
        "description": "Service-account/shared-credential password reveals. The resource column names the account family (SaaS app, Okta, Database, Active Directory, Server). For a per-account roster with status and full history of SaaS/Okta service accounts, see the Service Accounts dashboard.",
    },
    "pam_policy_modifications": {
        "label": "PAM Policy Modifications",
        "description": "OPA security policy create/update.",
    },
    "pam_client_enrollment": {
        "label": "Client Enrollment",
        "description": "A user's local OPA client (laptop/workstation) enrolling to connect to privileged resources. See also the Access Explorer's Resources tab for the current live roster of enrolled clients.",
    },
    "device_management": {
        "label": "Device Management",
        "description": "Okta-managed device enrollment and user association -- device registration record, separate from OPA client enrollment above. Known gap: only enrollment/activation/user-add are covered; suspend/unsuspend/deactivate/delete exist per Okta's own device-lifecycle docs but have no live-confirmed eventType yet (see COMPLIANCE_EVENT_TYPES comment). See also the Access Explorer's Resources tab for the current live device inventory.",
    },
    "ad_sync_activity": {
        "label": "Active Directory Sync Activity",
        "description": "Recurring, automated Active Directory account discovery -- shows that discovery runs completed.",
    },
    "credential_rotation": {
        "label": "Credential Rotation",
        "description": "Service-account password rotation lifecycle (scheduled and manual). The resource column names the account family (SaaS app, Okta, Database, Active Directory); the outcome column is the real result (SUCCESS / FAILURE / DEFERRED). For per-account rotation totals on SaaS/Okta service accounts, see the Service Accounts dashboard.",
    },
}


def _event_types_for_report(report_key):
    return [et for et, key in COMPLIANCE_EVENT_TYPES.items() if key == report_key]


CONTROL_CATALOGUE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "server", "control_catalogue.json")
_CONTROL_CATALOGUE = None


def load_control_catalogue(path=None):
    """5.53.0: the control catalogue (framework mappings, methodology notes and known limits per report) is versioned data
    in server/control_catalogue.json, not code. Cached after the first read of the default file."""
    global _CONTROL_CATALOGUE
    if path is None and _CONTROL_CATALOGUE is not None:
        return _CONTROL_CATALOGUE
    with open(path or CONTROL_CATALOGUE_PATH, encoding="utf-8") as fh:
        data = json.load(fh)
    if path is None:
        _CONTROL_CATALOGUE = data
    return data


def report_catalogue_entry(report_key):
    return load_control_catalogue()["reports"][report_key]


def report_controls(report_key):
    """The report's mapped controls, in catalogue order ([{framework, id, status}, ...])."""
    return list(report_catalogue_entry(report_key)["controls"])


def report_control(report_key):
    """Coarse grouping ('CC6', 'CC7', 'CC8') derived from the first mapped control ('CC6.1' -> 'CC6')."""
    return report_controls(report_key)[0]["id"].split(".")[0]


def report_mapping_status(report_key):
    """'proposed' unless every mapped control is auditor-reviewed. Nothing is auditor-reviewed in 5.53.0."""
    statuses = {c["status"] for c in report_controls(report_key)}
    return "auditor-reviewed" if statuses == {"auditor-reviewed"} else "proposed"


def list_reports():
    """Returns every report definition plus its derived event_types list, its mapped controls and mapping status
    -- the frontend's report picker renders directly from this, grouped by `control` (derived from the first
    mapped control)."""
    return [
        {"key": key, "event_types": _event_types_for_report(key), **meta,
         "control": report_control(key), "controls": report_controls(key), "mapping_status": report_mapping_status(key),
         "methodology": report_catalogue_entry(key)["methodology"], "known_limits": list(report_catalogue_entry(key)["known_limits"])}
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
    data_dir = os.environ.get("OPA_DATA_DIR")  # 5.47.0: the /var/lib layout (see create_secret_folders._data_dir)
    return os.path.join(data_dir or os.path.dirname(os.path.abspath(__file__)), "audit_store.db")


def shared_location_notice(path=None, platform=None, environ=None):
    """5.51.0: on Windows os.chmod cannot make the archive owner-only; the file inherits its folder's permissions. If the data folder is
    one other users of the computer can read (C:\\Users\\Public, ProgramData, the root of a drive, a network share), say so in one line.
    None everywhere else, and for any other Windows folder (typically inside the user's own profile). The app never rewrites ACLs."""
    import ntpath
    if (platform or os.name) != "nt":
        return None
    env = os.environ if environ is None else environ
    folder = path or os.path.dirname(_audit_db_path())
    norm = ntpath.normpath(folder)
    low = ntpath.normcase(norm)
    drive, rest = ntpath.splitdrive(norm)
    shared = low.startswith("\\\\")  # a UNC path (a network share)
    shared = shared or rest in ("", "\\")  # the root of a drive
    for name, fallback in (("PUBLIC", "C:\\Users\\Public"), ("ProgramData", "C:\\ProgramData")):
        root = ntpath.normcase(ntpath.normpath(env.get(name) or fallback))
        shared = shared or low == root or low.startswith(root + "\\")
    if not shared:
        return None
    return (f"The archive is in a location other users of this computer may read: {norm}. "
            "Move it with OPA_DATA_DIR (the folder must be one only you can read).")


def _warn_if_shared_location():
    notice = shared_location_notice()
    if notice:
        import create_secret_folders as engine
        engine.log("WARN", notice)
    return notice


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



def _migration_009_shared_permission_grants_and_known_identities(conn):
    """5.43.0: per-user exceptions to the shared-environment permissions
    (migration 008), and the identities the login gates have vouched for.
    Two new tables, both IF NOT EXISTS; nothing existing is altered and no
    evidence-chain table is touched. A new migration rather than an edit to
    008: anyone who already ran 5.42.0 is at schema 8 and would never see
    an edited 008.

    - shared_permission_grants: one capability for one user on one
      environment (allow/deny), above that environment's override. The
      user is the pair (issuer, subject) -- the Okta issuer of the login
      gate that authenticated them and their `sub` there. A `sub` alone is
      only unique within one Okta org (OIDC Core 5.7: iss + sub together
      are the stable identifier), and two gates can front different orgs.
      Removed with their environment (ON DELETE CASCADE).
    - known_identities: (issuer, subject) -> the e-mail last seen and when,
      written when a gate-authenticated user first reaches the backend in a
      process, so an admin can pick a user for a grant by e-mail.

    A rollback to older code leaves both tables unused and harmless."""
    conn.execute(
        """CREATE TABLE IF NOT EXISTS shared_permission_grants (
               environment_id TEXT NOT NULL REFERENCES app_environments(environment_id) ON DELETE CASCADE,
               capability TEXT NOT NULL,
               issuer TEXT NOT NULL CHECK (issuer <> ''),
               subject TEXT NOT NULL CHECK (subject <> ''),
               value TEXT NOT NULL CHECK (value IN ('allow', 'deny')),
               updated_at TEXT NOT NULL,
               updated_by TEXT,
               PRIMARY KEY (environment_id, capability, issuer, subject)
           )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS known_identities (
               issuer TEXT NOT NULL,
               subject TEXT NOT NULL,
               email TEXT,
               first_seen_at TEXT NOT NULL,
               last_seen_at TEXT NOT NULL,
               PRIMARY KEY (issuer, subject)
           )"""
    )


def _migration_010_snapshots_polling_sync_and_correlation(conn):
    """5.50.0. Three additions, every statement guarded or IF NOT EXISTS:

    - config_snapshots / config_snapshot_items: chained configuration
      snapshots (see record_config_snapshot). A snapshot is sealed into
      ingestion_manifests (source "snapshot:<kind>") in the same
      transaction that stores it. Like the archive tables there is NO
      foreign key to app_environments: deleting an environment's
      configuration must not erase its evidence.
    - sync_state.poll_cursor / sync_mode: the System Log polling cursor
      (the `next` link of the last page read) and which sync mode the
      environment is in. An existing install has neither, so its next
      sync resumes from its stored watermark in polling mode (see
      sync_okta_events): no gap, and the 1-hour overlap is deduplicated
      by event uuid.
    - mfa_week_totals / mfa_week_user / mfa_agg_state: the weekly sign-in and
      MFA aggregates behind the Overview (see signin_mfa.py), refreshed
      incrementally from the archive; derived data, rebuildable from events.
    - events.transaction_id / root_session_id / api_token_id: the
      System Log correlation fields (transaction.id,
      authenticationContext.rootSessionId, transaction.detail.
      requestApiTokenId) as indexed columns. Existing rows are filled in
      by backfill_correlation_columns() at start-up.

    A rollback to older code ignores all of it; the one thing older code
    cannot do is deep-verify a snapshot manifest, which is why this
    migration is declared not rollback-safe."""
    conn.execute("CREATE INDEX IF NOT EXISTS idx_manifest_entries_uuid ON manifest_entries (environment_id, uuid)")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS config_snapshots (
            snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
            environment_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            status TEXT NOT NULL,
            captured_at TEXT NOT NULL,
            source_endpoint TEXT,
            item_count INTEGER NOT NULL DEFAULT 0,
            sha256 TEXT NOT NULL,
            meta_json TEXT,
            manifest_id INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_config_snapshots_env_kind
            ON config_snapshots (environment_id, kind, captured_at);
        CREATE TABLE IF NOT EXISTS config_snapshot_items (
            snapshot_id INTEGER NOT NULL,
            environment_id TEXT NOT NULL,
            item_key TEXT NOT NULL,
            sha TEXT NOT NULL,
            json TEXT NOT NULL,
            PRIMARY KEY (snapshot_id, item_key)
        );
        CREATE INDEX IF NOT EXISTS idx_config_snapshot_items_env
            ON config_snapshot_items (environment_id);
        CREATE TABLE IF NOT EXISTS mfa_week_totals (
            environment_id TEXT NOT NULL,
            week TEXT NOT NULL,
            key TEXT NOT NULL,
            count INTEGER NOT NULL,
            PRIMARY KEY (environment_id, week, key)
        );
        CREATE TABLE IF NOT EXISTS mfa_week_user (
            environment_id TEXT NOT NULL,
            week TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            actor_alt TEXT,
            key TEXT NOT NULL,
            count INTEGER NOT NULL,
            PRIMARY KEY (environment_id, week, actor_id, key)
        );
        CREATE INDEX IF NOT EXISTS idx_mfa_week_user_actor ON mfa_week_user (environment_id, actor_id);
        CREATE INDEX IF NOT EXISTS idx_mfa_week_user_alt ON mfa_week_user (environment_id, actor_alt);
        CREATE TABLE IF NOT EXISTS mfa_agg_state (
            environment_id TEXT PRIMARY KEY,
            last_rowid INTEGER NOT NULL DEFAULT 0,
            events_used INTEGER NOT NULL DEFAULT 0,
            built_at TEXT,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS backfill_markers (
            name TEXT PRIMARY KEY,
            completed_at TEXT NOT NULL
        );
    """)
    state_cols = _table_columns(conn, "sync_state")
    for column in ("poll_cursor TEXT", "sync_mode TEXT"):
        if column.split()[0] not in state_cols:
            conn.execute(f"ALTER TABLE sync_state ADD COLUMN {column}")
    event_cols = _table_columns(conn, "events")
    for column in ("transaction_id TEXT", "root_session_id TEXT", "api_token_id TEXT"):
        if column.split()[0] not in event_cols:
            conn.execute(f"ALTER TABLE events ADD COLUMN {column}")
    conn.executescript("""
        CREATE INDEX IF NOT EXISTS idx_events_env_transaction
            ON events (environment_id, transaction_id) WHERE transaction_id IS NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_events_env_root_session
            ON events (environment_id, root_session_id) WHERE root_session_id IS NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_events_env_api_token
            ON events (environment_id, api_token_id) WHERE api_token_id IS NOT NULL;
    """)


def _migration_011_opa_model_cache(conn):
    """5.51.0. The stored OPA scan: one replaceable row per environment holding the Access Explorer model (redacted,
    canonical JSON, zlib-compressed). Derived data, not evidence: it is overwritten by every successful scan and is not
    chained. Like the archive tables it has NO foreign key to app_environments (an environment's delete removes the row
    explicitly; a start-up sweep removes any left behind). A rollback to 5.50.x ignores the table, so this migration is
    rollback-safe."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS opa_model_cache (
            environment_id   TEXT PRIMARY KEY,
            built_at         TEXT NOT NULL,
            duration_seconds REAL,
            source_version   TEXT NOT NULL,
            sha256           TEXT NOT NULL,
            raw_bytes        INTEGER NOT NULL,
            model_zlib       BLOB NOT NULL,
            warnings_json    TEXT,
            counts_json      TEXT NOT NULL,
            modified_at      TEXT
        );
    """)
    # What the last refresh job did, per part (counts and state names only), so the Overview can say a scheduled run did not
    # read OPA even after a restart. Older code ignores the column.
    if "last_refresh_json" not in _table_columns(conn, "sync_state"):
        conn.execute("ALTER TABLE sync_state ADD COLUMN last_refresh_json TEXT")


def _migration_012_settings_unlocks(conn):
    """5.53.0: opening Settings and Updates needs a fresh MFA on a hosted server. One row per (user, gate, login session) records
    that the user passed it and until when. Additive and rollback-safe: older code never reads the table."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS settings_unlocks (
            actor_sub   TEXT NOT NULL,
            issuer      TEXT NOT NULL DEFAULT '',
            session_fp  TEXT NOT NULL,
            action_id   TEXT NOT NULL,
            unlocked_at TEXT NOT NULL,
            expires_at  TEXT NOT NULL,
            PRIMARY KEY (actor_sub, issuer, session_fp)
        );
        CREATE INDEX IF NOT EXISTS idx_settings_unlocks_expires ON settings_unlocks (expires_at);
    """)


def _migration_013_sync_runs_and_prune_history(conn):
    """5.53.0: the archive records each sync, import and prune, so an evidence package's coverage statements rest on
    records and not on inference. sync_runs: one row per sync or CSV import (started, finished, outcome, the window it
    read, rows stored). prune_history: one row per retention prune that deleted rows. Additive and rollback-safe: older
    code never reads either table. No foreign keys (evidence, like the other archive tables). Not pruned by anything yet."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS sync_runs (
            id INTEGER PRIMARY KEY,
            environment_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            outcome TEXT,
            window_since TEXT,
            window_until TEXT,
            rows INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_sync_runs_env_started ON sync_runs (environment_id, started_at);
        CREATE TABLE IF NOT EXISTS prune_history (
            id INTEGER PRIMARY KEY,
            environment_id TEXT NOT NULL,
            pruned_at TEXT NOT NULL,
            cutoff TEXT NOT NULL,
            rows_pruned INTEGER NOT NULL,
            scope TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_prune_history_env_pruned ON prune_history (environment_id, pruned_at);
    """)


def _now_iso():
    return _iso_ms(datetime.now(timezone.utc))


def _run_start(environment_id, kind):
    """Records the start of a sync or import; returns the row id, or None when it could not be written (recording
    must never stop an ingestion: the run then simply has no record and counts for nothing)."""
    try:
        conn = _get_connection()
        with _db_lock:
            cur = conn.execute("INSERT INTO sync_runs (environment_id, kind, started_at) VALUES (?, ?, ?)",
                               (environment_id, kind, _now_iso()))
            conn.commit()
            return cur.lastrowid
    except sqlite3.Error:
        return None


def _run_finish(run_id, outcome, window_since=None, window_until=None, rows=None):
    """outcome: ok | failed | stopped. A run that never reaches this (a killed process) keeps a NULL outcome and
    never counts as coverage."""
    if run_id is None:
        return
    try:
        conn = _get_connection()
        with _db_lock:
            conn.execute("UPDATE sync_runs SET finished_at = ?, outcome = ?, window_since = ?, window_until = ?, rows = ? WHERE id = ?",
                         (_now_iso(), outcome, window_since, window_until, rows, run_id))
            conn.commit()
    except sqlite3.Error:
        pass


def _record_prune(environment_id, cutoff, rows_pruned, scope):
    """Caller holds _db_lock and commits. Written in the same transaction as the delete when it can be."""
    if rows_pruned and cutoff:
        conn = _get_connection()
        conn.execute("INSERT INTO prune_history (environment_id, pruned_at, cutoff, rows_pruned, scope) VALUES (?, ?, ?, ?, ?)",
                     (environment_id, _now_iso(), cutoff, rows_pruned, scope))


MIGRATIONS = {
    1: _migration_001_unified_schema,
    2: _migration_002_ingestion_manifests,
    3: _migration_003_pending_admin_actions,
    4: _migration_004_drop_preserve_logs_locally,
    5: _migration_005_service_account_report_indexes,
    6: _migration_006_evidence_chain_v2_and_sync_attempts,
    7: _migration_007_manifest_entries_and_chain_heads,
    8: _migration_008_shared_environment_permissions,
    9: _migration_009_shared_permission_grants_and_known_identities,
    10: _migration_010_snapshots_polling_sync_and_correlation,
    11: _migration_011_opa_model_cache,
    12: _migration_012_settings_unlocks,
    13: _migration_013_sync_runs_and_prune_history,
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


def _ensure_manifest_entry_index():
    """An archive already at schema 10 (an early 5.50.0 build) lacks the (environment, uuid) index on manifest_entries that the
    unsealed-event check needs; creating it is idempotent."""
    conn = _get_connection()
    with _db_lock:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_manifest_entries_uuid ON manifest_entries (environment_id, uuid)")
        conn.commit()


def init_db():
    run_migrations()
    _ensure_manifest_entry_index()
    import create_secret_folders
    create_secret_folders.migrate_legacy_environments_json()
    backfill_resource_columns()
    backfill_event_targets()
    canonicalize_stored_timestamps()
    reflag_curated_rows()
    backfill_correlation_columns()
    _cleanup_expired_pending_admin_actions()
    _cleanup_expired_settings_unlocks()
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
                transaction_id, root_session_id, api_token_id = _correlation_fields_from_json(raw_json)
                cur = conn.execute(
                    """INSERT OR IGNORE INTO events
                       (uuid, environment_id, event_type, published, actor_id,
                        actor_display_name, actor_alternate_id, outcome_result,
                        is_curated, raw_json, resource_id, resource_alternate_id,
                        resource_type_detail, transaction_id, root_session_id, api_token_id)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (uuid, environment_id, event_type, published, actor_id,
                     actor_name, actor_alt, outcome, is_curated, raw_json,
                     resource_id, resource_alt_id, resource_type_detail,
                     transaction_id, root_session_id, api_token_id),
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


def _correlation_fields(raw):
    """(transaction.id, authenticationContext.rootSessionId,
    transaction.detail.requestApiTokenId) of one raw System Log event, each
    None unless it is a non-empty string (System Log query guide, "Event
    correlation" and "Correlating events based on API token")."""
    if not isinstance(raw, dict):
        return None, None, None

    def _text(value):
        return value if isinstance(value, str) and value and len(value) <= 256 else None

    transaction = raw.get("transaction") if isinstance(raw.get("transaction"), dict) else {}
    detail = transaction.get("detail") if isinstance(transaction.get("detail"), dict) else {}
    context = raw.get("authenticationContext") if isinstance(raw.get("authenticationContext"), dict) else {}
    return _text(transaction.get("id")), _text(context.get("rootSessionId")), _text(detail.get("requestApiTokenId"))


def _correlation_fields_from_json(raw_json):
    try:
        return _correlation_fields(json.loads(raw_json))
    except (ValueError, TypeError):
        return None, None, None


def backfill_correlation_columns(batch_size=2000):
    """Fills events.transaction_id / root_session_id / api_token_id for rows
    stored before migration 010, in rowid batches (never one giant
    transaction, never the whole table in memory), then records a marker so
    later starts skip the scan. Safe to interrupt and re-run. Returns the
    number of rows that received at least one value."""
    conn = _get_connection()
    if conn.execute("SELECT 1 FROM backfill_markers WHERE name = 'event_correlation_columns'").fetchone():
        return 0
    filled = 0
    last_rowid = 0
    while True:
        with _db_lock:
            rows = conn.execute(
                "SELECT rowid AS rid, raw_json FROM events WHERE rowid > ? ORDER BY rowid LIMIT ?",
                (last_rowid, batch_size),
            ).fetchall()
            if not rows:
                break
            updates = []
            for row in rows:
                fields = _correlation_fields_from_json(row["raw_json"])
                if any(fields):
                    updates.append((*fields, row["rid"]))
            if updates:
                conn.executemany(
                    "UPDATE events SET transaction_id = ?, root_session_id = ?, api_token_id = ? WHERE rowid = ?", updates
                )
                filled += len(updates)
            conn.commit()
            last_rowid = rows[-1]["rid"]
    with _db_lock:
        conn.execute(
            "INSERT OR REPLACE INTO backfill_markers (name, completed_at) VALUES ('event_correlation_columns', ?)",
            (datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),),
        )
        conn.commit()
    return filled


def events_by_correlation(environment_id, transaction_id=None, root_session_id=None, api_token_id=None, limit=500):
    """Events sharing one correlation value (exactly one of the three), newest
    first, as raw dicts -- the index-backed lookup behind "same session as"
    and "activity by this API token". Bounded by `limit`."""
    given = [(c, v) for c, v in (("transaction_id", transaction_id), ("root_session_id", root_session_id),
                                 ("api_token_id", api_token_id)) if v]
    if len(given) != 1:
        raise ValueError("pass exactly one correlation value")
    _require_positive_limit(limit)
    column, value = given[0]
    conn = _get_connection()
    rows = conn.execute(
        f"SELECT raw_json FROM events WHERE environment_id = ? AND {column} = ? ORDER BY published DESC LIMIT ?",
        (environment_id, value, limit),
    ).fetchall()
    return [json.loads(r["raw_json"]) for r in rows]


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
    with _db_lock:
        try:
            if not conn.in_transaction:
                conn.execute("BEGIN IMMEDIATE")
            entry_hash, _manifest_id = _write_manifest_row(conn, environment_id, source, since, until, entries)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    _anchor_chain_head(environment_id, source, len(entries), entry_hash)
    return entry_hash


def _anchor_chain_head(environment_id, source, row_count, entry_hash):
    """The out-of-database anchor of a freshly sealed manifest (see
    _record_ingestion_manifest). Never allowed to break an ingestion."""
    try:
        import create_secret_folders
        create_secret_folders.log_audit_event(
            None, None, "evidence_chain.sealed",
            {"environment_id": environment_id, "source": source, "row_count": row_count, "chain_head": entry_hash},
        )
    except Exception:
        pass


def _write_manifest_row(conn, environment_id, source, since, until, entries):
    """The chain write itself, for a caller that already holds _db_lock and an
    open write transaction on `conn` (it neither locks nor commits, so a
    snapshot can be stored and sealed in ONE transaction). Returns
    (entry_hash, manifest_id)."""
    batch_hash = _sha256_of_lines(sorted(uuid for uuid, _c, _s in entries))
    content_hash = _manifest_content_hash(entries)
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
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
            ((environment_id, manifest_id, u, sh) for u, c, sh in entries if c),
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
    return entry_hash, manifest_id


# DATA-04: new manifests are written in the v2 format (enabled 5.40.4,
# maintainer decision 2026-10-08). Each v2 row seals the content of every
# curated event it ingested plus every manifest field, so the chain is
# tamper evidence from the first v2 row onward. Rows written before then
# stay v1 (a uuid-only continuity check) and are never re-sealed: the
# first v2 row chains to the last v1 row's batch_hash, and
# verify_ingestion_chain reports how many legacy rows precede it. Setting
# this back to False is a downgrade the verifier flags as a broken chain.
EVIDENCE_CHAIN_V2 = True


def verify_ingestion_chain(environment_id, deep=False, sync_in_progress=False):
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
        return _verify_ingestion_chain_snapshot(conn, environment_id, deep, sync_in_progress)
    finally:
        if own_txn:
            conn.rollback()


def _verify_ingestion_chain_snapshot(conn, environment_id, deep, sync_in_progress=False):
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
                is_snapshot = (row["source"] or "").startswith(SNAPSHOT_SOURCE_PREFIX)
                if is_snapshot:
                    # 5.50.0: a snapshot's sealed objects live in config_snapshot_items (until = snapshot id).
                    problem = _snapshot_seal_problem(conn, environment_id, row)
                    if problem:
                        return _broken(row, problem)
                    sealed = (
                        (r["line"], r["uuid"], r["sha"], r["json"]) for r in conn.execute(
                            """SELECT me.uuid || ':' || me.sha AS line, me.uuid, me.sha, i.json
                               FROM manifest_entries me
                               LEFT JOIN config_snapshot_items i ON i.snapshot_id = CAST(? AS INTEGER)
                                    AND i.environment_id = me.environment_id AND i.item_key = me.uuid
                               WHERE me.manifest_id = ? ORDER BY line""",
                            (row["until"], row["id"]),
                        )
                    )
                else:
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
                        first_event_problem = (
                            f"snapshot object {uuid} is missing" if (row["source"] or "").startswith(SNAPSHOT_SOURCE_PREFIX)
                            else f"curated event {uuid} is missing from the archive")
                    elif _content_sha256(raw_json) != sha:
                        first_event_problem = (
                            f"snapshot object {uuid} content does not match its sealed hash"
                            if (row["source"] or "").startswith(SNAPSHOT_SOURCE_PREFIX)
                            else f"event {uuid} content does not match its sealed hash")
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
    if deep and result["valid"]:
        # 5.50.0: every curated event stored must be covered by a manifest. A sync killed between a page's commit and its
        # seal leaves rows no manifest names; they used to verify as valid. A sync running right now has rows it has not
        # sealed yet (it seals once, at its end): that is "pending", not a break.
        unsealed = _count_unsealed_curated(conn, environment_id, result["legacy_manifests"])
        result["unsealed_events"] = unsealed
        if unsealed and sync_in_progress:
            result["unsealed_pending"] = True
        elif unsealed:
            result.update({
                "valid": False, "broken_at": None,
                "reason": f"{unsealed} curated events are stored but not sealed into the evidence chain (a sync was interrupted, "
                          "or events were re-flagged as curated after an upgrade); "
                          "the next sync seals them in a recovery manifest",
            })
    return result


def _unsealed_boundary(conn, environment_id, legacy_manifests):
    """rowid above which an unsealed curated event counts. With no legacy (pre-5.40.4, content-unsealed) manifests every
    unsealed event counts (0). With legacy manifests, rows from before the first sealed event cannot be told from rows the
    legacy chain never sealed, so only rows after the first sealed one count; with none sealed at all, nothing counts (None)."""
    if not legacy_manifests:
        return 0
    row = conn.execute(
        """SELECT e.rowid FROM events e WHERE e.environment_id = ? AND e.is_curated = 1
           AND EXISTS (SELECT 1 FROM manifest_entries m WHERE m.environment_id = e.environment_id AND m.uuid = e.uuid)
           ORDER BY e.rowid LIMIT 1""", (environment_id,)).fetchone()
    return row[0] if row else None


_UNSEALED_SQL = """FROM events e WHERE e.environment_id = ? AND e.is_curated = 1 AND e.rowid > ?
                   AND NOT EXISTS (SELECT 1 FROM manifest_entries m WHERE m.environment_id = e.environment_id AND m.uuid = e.uuid)"""


def _entries_json_uuids(conn, environment_id):
    """uuids sealed through the 5.40.2-format entries_json cell (a hand-enabled v2 install), which manifest_entries does not hold."""
    out = set()
    for r in conn.execute("SELECT entries_json FROM ingestion_manifests WHERE environment_id = ? AND entries_json IS NOT NULL", (environment_id,)):
        try:
            out.update(str(pair[0]) for pair in json.loads(r[0]))
        except (ValueError, TypeError, IndexError):
            pass
    return out


def _count_unsealed_curated(conn, environment_id, legacy_manifests=None):
    if legacy_manifests is None:
        legacy_manifests = conn.execute(
            "SELECT COUNT(*) FROM ingestion_manifests WHERE environment_id = ? AND entry_hash IS NULL", (environment_id,)).fetchone()[0]
    boundary = _unsealed_boundary(conn, environment_id, legacy_manifests)
    if boundary is None:
        return 0
    extra = _entries_json_uuids(conn, environment_id)
    if not extra:
        return conn.execute("SELECT COUNT(*) " + _UNSEALED_SQL, (environment_id, boundary)).fetchone()[0]
    return sum(1 for r in conn.execute("SELECT e.uuid " + _UNSEALED_SQL, (environment_id, boundary)) if r["uuid"] not in extra)


RECOVERY_BATCH = 100000


def seal_unsealed_events(environment_id, limit=RECOVERY_BATCH):
    """Seals the curated events no manifest names -- what a sync that was killed mid-run leaves behind -- into ONE recovery
    manifest (source "sync_recovery", since/until the published range of the rows), so the chain says plainly that this is the
    recovery of an interrupted run and covers exactly those rows. The rows are sealed as they are stored now: the recovery
    proves them from this moment, not from their original sync. Returns {"sealed": n, "since", "until", "chain_head"} or
    {"sealed": 0}. Bounded by `limit` rows per call (the next sync continues)."""
    conn = _get_connection()
    legacy = conn.execute("SELECT COUNT(*) FROM ingestion_manifests WHERE environment_id = ? AND entry_hash IS NULL", (environment_id,)).fetchone()[0]
    boundary = _unsealed_boundary(conn, environment_id, legacy)
    if boundary is None:
        return {"sealed": 0}
    extra = _entries_json_uuids(conn, environment_id)
    rows = [r for r in conn.execute("SELECT e.uuid, e.published, e.raw_json " + _UNSEALED_SQL + " ORDER BY e.rowid LIMIT ?", (environment_id, boundary, limit))
            if r["uuid"] not in extra]
    if not rows:
        return {"sealed": 0}
    entries = [(r["uuid"], 1, _content_sha256(r["raw_json"])) for r in rows]
    since = min(r["published"] for r in rows)
    until = max(r["published"] for r in rows)
    head = _record_ingestion_manifest(conn, environment_id, "sync_recovery", since, until, entries)
    return {"sealed": len(entries), "since": since, "until": until, "chain_head": head}


# ---------------------------------------------------------------------------
# Chained configuration snapshots (5.50.0)
# ---------------------------------------------------------------------------
# A snapshot is the state of one kind of Okta configuration (e.g. who holds an
# admin role) at one moment, stored as one row per object and sealed into the
# same hash chain as the System Log archive: ONE ingestion_manifests row with
# source "snapshot:<kind>", whose sealed entries are the objects
# (manifest_entries.uuid = the object key, sha = sha256 of its canonical JSON).
# `until` of that manifest is the snapshot id, so deep verification can find
# the rows to re-hash. The snapshot and its seal are written in one
# transaction: a snapshot without a seal cannot exist.
#
# What the seal proves, stated plainly (same threat model as the event chain,
# see verify_ingestion_chain): editing, deleting or adding an object of a past
# snapshot, deleting a snapshot, or reordering them is detected by a deep
# integrity check; someone who also recomputes every hash and the recorded
# head is not.
SNAPSHOT_STATUSES = ("ok", "refused", "error")
SNAPSHOT_SOURCE_PREFIX = "snapshot:"
SNAPSHOT_MAX_ITEMS = 200000
SNAPSHOT_MAX_ITEM_BYTES = 256 * 1024
SNAPSHOT_MAX_KEY_CHARS = 512
_SNAPSHOT_KIND_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$", re.ASCII)


def _canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _snapshot_sha(item_shas):
    """sha256 over the sorted `key:sha` lines of a snapshot's objects."""
    return _sha256_of_lines(sorted(f"{key}:{sha}" for key, sha in item_shas))


def record_config_snapshot(environment_id, kind, items, status="ok", source_endpoint=None, meta=None, captured_at=None):
    """Stores one snapshot and seals it into the evidence chain. `items` is an
    iterable of (item_key, object) pairs (object: any JSON-able dict; the
    caller has already removed anything that must not be kept, e.g. user
    `credentials`). status "refused"/"error" records an attempt that read
    nothing (zero items) -- also sealed, so "the token could not read this on
    that date" is evidence too. Returns the snapshot dict (see
    get_config_snapshot, without items)."""
    if not _SNAPSHOT_KIND_RE.match(str(kind or "")):
        raise ValueError("snapshot kind must be lower-case letters, digits and underscores")
    if status not in SNAPSHOT_STATUSES:
        raise ValueError(f"snapshot status must be one of {SNAPSHOT_STATUSES}")
    prepared = {}
    for key, obj in items:
        if not isinstance(key, str) or not key or len(key) > SNAPSHOT_MAX_KEY_CHARS or "\n" in key:
            raise ValueError("a snapshot item needs a non-empty key of at most 512 characters")
        if key in prepared:
            raise ValueError(f"duplicate snapshot item key {key!r}")
        text = _canonical_json(obj)
        if len(text.encode("utf-8")) > SNAPSHOT_MAX_ITEM_BYTES:
            raise ValueError(f"snapshot item {key!r} is larger than {SNAPSHOT_MAX_ITEM_BYTES} bytes")
        prepared[key] = (text, _content_sha256(text))
        if len(prepared) > SNAPSHOT_MAX_ITEMS:
            raise ValueError(f"more than {SNAPSHOT_MAX_ITEMS} items in one snapshot")
    if status != "ok" and prepared:
        raise ValueError("a refused or failed snapshot holds no items")
    captured_at = _canonical_published(captured_at) if captured_at else datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    if captured_at is None:
        raise ValueError("captured_at is not a timestamp")
    snapshot_sha = _snapshot_sha((k, v[1]) for k, v in prepared.items())
    meta_json = _canonical_json(meta) if meta else None
    entries = [(k, 1, v[1]) for k, v in prepared.items()]
    conn = _get_connection()
    with _db_lock:
        try:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute(
                """INSERT INTO config_snapshots
                   (environment_id, kind, status, captured_at, source_endpoint, item_count, sha256, meta_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (environment_id, kind, status, captured_at, source_endpoint, len(prepared), snapshot_sha, meta_json),
            )
            snapshot_id = cur.lastrowid
            conn.executemany(
                "INSERT INTO config_snapshot_items (snapshot_id, environment_id, item_key, sha, json) VALUES (?, ?, ?, ?, ?)",
                ((snapshot_id, environment_id, k, v[1], v[0]) for k, v in prepared.items()),
            )
            chain_head, manifest_id = _write_manifest_row(
                conn, environment_id, SNAPSHOT_SOURCE_PREFIX + kind, captured_at, str(snapshot_id), entries
            )
            conn.execute("UPDATE config_snapshots SET manifest_id = ? WHERE snapshot_id = ?", (manifest_id, snapshot_id))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    _anchor_chain_head(environment_id, SNAPSHOT_SOURCE_PREFIX + kind, len(entries), chain_head)
    return {
        "snapshot_id": snapshot_id, "environment_id": environment_id, "kind": kind, "status": status,
        "captured_at": captured_at, "source_endpoint": source_endpoint, "item_count": len(prepared),
        "sha256": snapshot_sha, "meta": meta or None, "manifest_id": manifest_id, "chain_head": chain_head,
    }


def _snapshot_row(row):
    out = dict(row)
    meta = out.pop("meta_json", None)
    try:
        out["meta"] = json.loads(meta) if meta else None
    except ValueError:
        out["meta"] = None
    return out


def list_config_snapshots(environment_id, kind=None, limit=200):
    """Newest first, without items."""
    _require_positive_limit(limit)
    conn = _get_connection()
    sql = "SELECT * FROM config_snapshots WHERE environment_id = ?"
    params = [environment_id]
    if kind:
        sql += " AND kind = ?"
        params.append(kind)
    sql += " ORDER BY captured_at DESC, snapshot_id DESC LIMIT ?"
    params.append(min(int(limit), 1000))
    return [_snapshot_row(r) for r in conn.execute(sql, params)]


def config_series(environment_id, kind, as_of=None, limit_snapshots=1000):
    """Time series from the objects of successful snapshots of one kind whose objects each carry a
    numeric "count": {"snapshots": [{snapshot_id, captured_at, meta}], "series": {item_key: [(captured_at, count)]}},
    oldest first, at most the newest `limit_snapshots` snapshots up to `as_of`. One indexed read; the
    objects are tiny (counts only)."""
    _require_positive_limit(limit_snapshots)
    conn = _get_connection()
    sql = "SELECT snapshot_id, captured_at, meta_json FROM config_snapshots WHERE environment_id = ? AND kind = ? AND status = 'ok'"
    params = [environment_id, kind]
    if as_of:
        sql += " AND captured_at <= ?"
        params.append(normalize_window(None, as_of)[1])
    sql += " ORDER BY captured_at DESC, snapshot_id DESC LIMIT ?"
    params.append(min(int(limit_snapshots), 5000))
    snaps = list(reversed(conn.execute(sql, params).fetchall()))
    out = {"snapshots": [], "series": {}}
    for snap in snaps:
        meta = None
        try:
            meta = json.loads(snap["meta_json"]) if snap["meta_json"] else None
        except ValueError:
            pass
        out["snapshots"].append({"snapshot_id": snap["snapshot_id"], "captured_at": snap["captured_at"], "meta": meta})
        for r in conn.execute("SELECT item_key, json FROM config_snapshot_items WHERE snapshot_id = ? AND environment_id = ?",
                              (snap["snapshot_id"], environment_id)):
            try:
                obj = json.loads(r["json"])
            except ValueError:
                continue
            count = obj.get("count") if isinstance(obj, dict) else None
            if isinstance(count, int) and not isinstance(count, bool):
                out["series"].setdefault(r["item_key"], []).append((snap["captured_at"], count))
    return out


def get_config_snapshot(environment_id, snapshot_id, with_items=True):
    """The snapshot (scoped to this environment -- another environment's id
    answers None) with, by default, `items`: [{"key", "sha", "object"}]."""
    conn = _get_connection()
    try:
        snapshot_id = int(snapshot_id)
    except (TypeError, ValueError):
        return None
    row = conn.execute(
        "SELECT * FROM config_snapshots WHERE environment_id = ? AND snapshot_id = ?", (environment_id, snapshot_id)
    ).fetchone()
    if row is None:
        return None
    out = _snapshot_row(row)
    if with_items:
        items = []
        for r in conn.execute(
                "SELECT item_key, sha, json FROM config_snapshot_items WHERE snapshot_id = ? AND environment_id = ? ORDER BY item_key",
                (snapshot_id, environment_id)):
            try:
                obj = json.loads(r["json"])
            except ValueError:
                obj = None
            items.append({"key": r["item_key"], "sha": r["sha"], "object": obj})
        out["items"] = items
    return out


def latest_config_snapshot(environment_id, kind, as_of=None, with_items=True, only_ok=True):
    """The newest snapshot of `kind` captured at or before `as_of` (a date or
    timestamp; a bare date means the end of that day), or the newest of all.
    Only successful captures unless only_ok=False."""
    conn = _get_connection()
    sql = "SELECT snapshot_id FROM config_snapshots WHERE environment_id = ? AND kind = ?"
    params = [environment_id, kind]
    if only_ok:
        sql += " AND status = 'ok'"
    if as_of:
        bound = normalize_window(None, as_of)[1]  # a bad value raises ValueError (HTTP 400 at the route)
        sql += " AND captured_at <= ?"
        params.append(bound)
    sql += " ORDER BY captured_at DESC, snapshot_id DESC LIMIT 1"
    row = conn.execute(sql, params).fetchone()
    return get_config_snapshot(environment_id, row["snapshot_id"], with_items) if row else None


def diff_config_snapshots(environment_id, older_id, newer_id):
    """added / removed / changed objects between two snapshots of the same kind
    (and environment). `changed` lists the keys whose canonical JSON differs,
    with the field names that differ at the top level. Raises ValueError for an
    unknown snapshot or two different kinds."""
    a = get_config_snapshot(environment_id, older_id)
    b = get_config_snapshot(environment_id, newer_id)
    if a is None or b is None:
        raise ValueError("snapshot not found")
    if a["kind"] != b["kind"]:
        raise ValueError("the two snapshots are of different kinds")
    before = {i["key"]: i for i in a["items"]}
    after = {i["key"]: i for i in b["items"]}
    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    changed = []
    for key in sorted(set(before) & set(after)):
        if before[key]["sha"] != after[key]["sha"]:
            x, y = before[key]["object"] or {}, after[key]["object"] or {}
            fields = sorted(f for f in set(x) | set(y) if x.get(f) != y.get(f)) if isinstance(x, dict) and isinstance(y, dict) else []
            changed.append({"key": key, "fields": fields, "before": before[key]["object"], "after": after[key]["object"]})
    return {
        "kind": a["kind"], "older": {k: a[k] for k in ("snapshot_id", "captured_at", "status", "item_count")},
        "newer": {k: b[k] for k in ("snapshot_id", "captured_at", "status", "item_count")},
        "added": [{"key": k, "object": after[k]["object"]} for k in added],
        "removed": [{"key": k, "object": before[k]["object"]} for k in removed],
        "changed": changed,
        "unchanged": len(set(before) & set(after)) - len(changed),
    }


def export_config_snapshot(environment_id, snapshot_id):
    """Everything an auditor needs to re-check one snapshot offline: the
    snapshot, its objects with their sha256, the sha256 over the set, and the
    chain link that sealed it. None if it is not this environment's."""
    snap = get_config_snapshot(environment_id, snapshot_id)
    if snap is None:
        return None
    conn = _get_connection()
    manifest = conn.execute(
        "SELECT id, source, since, until, row_count, batch_hash, prev_manifest_hash, created_at, content_hash, entry_hash "
        "FROM ingestion_manifests WHERE id = ? AND environment_id = ?", (snap["manifest_id"], environment_id)
    ).fetchone()
    snap["manifest"] = dict(manifest) if manifest else None
    snap["format"] = "opa-compliance-wizard-config-snapshot/1"
    return snap


def verify_config_snapshot(environment_id, snapshot_id):
    """Re-hashes one snapshot's stored objects against their recorded sha256
    and the snapshot's own sha256/item_count. {"valid", "reason"}. (The chain
    seal over the same hashes is checked by verify_ingestion_chain(deep=True).)"""
    snap = get_config_snapshot(environment_id, snapshot_id)
    if snap is None:
        return {"valid": False, "reason": "snapshot not found"}
    conn = _get_connection()
    pairs = []
    for r in conn.execute("SELECT item_key, sha, json FROM config_snapshot_items WHERE snapshot_id = ? AND environment_id = ?",
                          (snap["snapshot_id"], environment_id)):
        if _content_sha256(r["json"]) != r["sha"]:
            return {"valid": False, "reason": f"object {r['item_key']} does not match its recorded hash"}
        pairs.append((r["item_key"], r["sha"]))
    if len(pairs) != snap["item_count"]:
        return {"valid": False, "reason": "the number of stored objects differs from the snapshot's item count"}
    if _snapshot_sha(pairs) != snap["sha256"]:
        return {"valid": False, "reason": "the objects do not match the snapshot's recorded hash"}
    return {"valid": True, "reason": None}


def _snapshot_seal_problem(conn, environment_id, manifest_row):
    """Deep-check helper: the snapshot a snapshot manifest sealed must still
    exist, point back at this manifest, and hold exactly the number of objects
    the manifest counted (an object ADDED after sealing is as much a change as
    one edited or removed). Returns a reason or None."""
    try:
        snapshot_id = int(manifest_row["until"])
    except (TypeError, ValueError):
        return "a snapshot manifest does not name its snapshot"
    snap = conn.execute(
        "SELECT manifest_id, item_count, kind FROM config_snapshots WHERE snapshot_id = ? AND environment_id = ?",
        (snapshot_id, environment_id),
    ).fetchone()
    if snap is None:
        return f"snapshot {snapshot_id} was removed after it was sealed"
    if snap["manifest_id"] != manifest_row["id"] or SNAPSHOT_SOURCE_PREFIX + snap["kind"] != manifest_row["source"]:
        return f"snapshot {snapshot_id} does not match the manifest that sealed it"
    stored = conn.execute(
        "SELECT COUNT(*) FROM config_snapshot_items WHERE snapshot_id = ? AND environment_id = ?", (snapshot_id, environment_id)
    ).fetchone()[0]
    if stored != manifest_row["row_count"] or stored != snap["item_count"]:
        return f"snapshot {snapshot_id} holds {stored} objects but {manifest_row['row_count']} were sealed"
    return None


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


# ---------------------------------------------------------------------------
# Settings unlock (5.53.0, migration 012). A row says: this user, signed in through this gate, in this login session,
# passed a fresh MFA and may read Settings and Updates until expires_at. All times are UTC ISO strings written here.
# ---------------------------------------------------------------------------

def _unlock_iso(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _unlock_key(actor_sub, issuer, session_fp):
    return (str(actor_sub or ""), str(issuer or ""), str(session_fp or ""))


def upsert_settings_unlock(actor_sub, issuer, session_fp, action_id, ttl_seconds, now=None):
    """Creates or replaces the unlock for this user, gate and session. Returns (unlocked_at, expires_at) as ISO strings.
    Refuses an empty subject or session fingerprint (fails closed)."""
    key = _unlock_key(actor_sub, issuer, session_fp)
    if not key[0] or not key[2]:
        raise ValueError("an unlock needs a subject and a session fingerprint")
    now = now or datetime.now(timezone.utc)
    unlocked_at, expires_at = _unlock_iso(now), _unlock_iso(now + timedelta(seconds=ttl_seconds))
    conn = _get_connection()
    with _db_lock:
        try:
            conn.execute("DELETE FROM settings_unlocks WHERE expires_at < ?", (unlocked_at,))
            conn.execute(
                """INSERT INTO settings_unlocks (actor_sub, issuer, session_fp, action_id, unlocked_at, expires_at)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT (actor_sub, issuer, session_fp) DO UPDATE SET
                     action_id = excluded.action_id, unlocked_at = excluded.unlocked_at, expires_at = excluded.expires_at""",
                (*key, str(action_id or ""), unlocked_at, expires_at),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    return unlocked_at, expires_at


def renew_settings_unlock(actor_sub, issuer, session_fp, action_id, ttl_seconds, now=None):
    """A completed write that passed its own fresh MFA restarts the window (an upsert, so a save after expiry opens it
    again). Same arguments and result as upsert_settings_unlock."""
    return upsert_settings_unlock(actor_sub, issuer, session_fp, action_id, ttl_seconds, now=now)


def settings_unlock_active(actor_sub, issuer, session_fp, now=None, delete_expired=True):
    """The unlock row as a dict if unlocked_at <= now < expires_at, else None. An expired row is deleted on the way out (unless
    `delete_expired` is False: the status poll must leave it for the first refused request to record the expiry); a row whose
    unlocked_at is in the future (the clock went back) is refused and left alone."""
    key = _unlock_key(actor_sub, issuer, session_fp)
    if not key[0] or not key[2]:
        return None
    now_iso = _unlock_iso(now or datetime.now(timezone.utc))
    conn = _get_connection()
    with _db_lock:
        row = conn.execute(
            "SELECT * FROM settings_unlocks WHERE actor_sub = ? AND issuer = ? AND session_fp = ?", key
        ).fetchone()
        if row is None:
            return None
        if row["expires_at"] <= now_iso:
            if delete_expired:
                conn.execute(
                    "DELETE FROM settings_unlocks WHERE actor_sub = ? AND issuer = ? AND session_fp = ?", key
                )
                conn.commit()
            return None
        if row["unlocked_at"] > now_iso:
            return None
        return dict(row)


def take_expired_settings_unlock(actor_sub, issuer, session_fp, now=None):
    """If this key's row has expired, deletes it and returns it (once: a second caller gets None), so the first refused request
    after expiry can record `settings.locked`. A live row is left alone."""
    key = _unlock_key(actor_sub, issuer, session_fp)
    now_iso = _unlock_iso(now or datetime.now(timezone.utc))
    conn = _get_connection()
    with _db_lock:
        row = conn.execute(
            "SELECT * FROM settings_unlocks WHERE actor_sub = ? AND issuer = ? AND session_fp = ?", key
        ).fetchone()
        if row is None or row["expires_at"] > now_iso:
            return None
        conn.execute("DELETE FROM settings_unlocks WHERE actor_sub = ? AND issuer = ? AND session_fp = ?", key)
        conn.commit()
    return dict(row)


def delete_settings_unlock(actor_sub, issuer, session_fp):
    """Ends the window now. Returns the deleted row as a dict, or None if there was none."""
    key = _unlock_key(actor_sub, issuer, session_fp)
    conn = _get_connection()
    with _db_lock:
        row = conn.execute(
            "SELECT * FROM settings_unlocks WHERE actor_sub = ? AND issuer = ? AND session_fp = ?", key
        ).fetchone()
        if row is None:
            return None
        conn.execute("DELETE FROM settings_unlocks WHERE actor_sub = ? AND issuer = ? AND session_fp = ?", key)
        conn.commit()
    return dict(row)


def list_settings_unlocks():
    """Every unlock row (expired ones included), for the operator's break-glass listing. Holds no secrets."""
    conn = _get_connection()
    with _db_lock:
        return [dict(r) for r in conn.execute("SELECT * FROM settings_unlocks ORDER BY unlocked_at").fetchall()]


def clear_settings_unlocks():
    """Deletes every unlock row. Returns how many there were."""
    conn = _get_connection()
    with _db_lock:
        n = conn.execute("DELETE FROM settings_unlocks").rowcount
        conn.commit()
    return n


def _cleanup_expired_settings_unlocks():
    conn = _get_connection()
    with _db_lock:
        conn.execute("DELETE FROM settings_unlocks WHERE expires_at < ?", (_unlock_iso(datetime.now(timezone.utc)),))
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
    result.pop("poll_cursor", None)  # an internal resume point (an Okta paging link), not something to show or export
    raw_refresh = result.pop("last_refresh_json", None)  # 5.51.0: parsed below as `last_refresh`
    try:
        result["last_refresh"] = json.loads(raw_refresh) if raw_refresh else None
    except ValueError:
        result["last_refresh"] = None
    result["total_events_ingested"] = conn.execute(
        "SELECT COUNT(*) FROM events WHERE environment_id = ?", (environment_id,)
    ).fetchone()[0]
    return result


_SYNC_STATE_FIELDS = (
    "last_synced_at", "last_sync_completed_at", "last_sync_status", "last_sync_error",
    "total_events_ingested", "ingestion_scope", "last_sync_attempt_at", "last_import_at",
    "poll_cursor", "sync_mode", "last_refresh_json",
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
    _upsert_sync_state(conn, environment_id, last_synced_at=None, last_sync_status=None, last_sync_error=None,
                       poll_cursor=None, sync_mode=None)
    return previous


def environment_has_archive(environment_id):
    """True once this environment has anything to report from -- a
    completed live sync OR a CSV import (DATA-03 moved imports off the
    sync watermark, so "has it synced" alone would wrongly say no for an
    import-only environment). Used by the archive-only report routes."""
    state = get_sync_state(environment_id)
    return bool(state and (state.get("last_sync_completed_at") or state.get("last_import_at")))


def archive_coverage(environment_id):
    """What this environment's archive can vouch for, for the Access
    Explorer's evidence layer: whether it has an archive at all, the stored
    ingestion scope, the sync watermark (`last_synced_at`) and the oldest and
    newest stored event times. Two cheap reads (no COUNT, no raw_json): the
    sync_state row and MIN/MAX over the (environment_id, published) index."""
    conn = _get_connection()
    state = conn.execute(
        "SELECT last_synced_at, last_sync_completed_at, last_import_at, ingestion_scope "
        "FROM sync_state WHERE environment_id = ?", (environment_id,)
    ).fetchone()
    state = dict(state) if state else {}
    span = conn.execute(
        "SELECT MIN(published) AS oldest, MAX(published) AS newest FROM events WHERE environment_id = ?",
        (environment_id,),
    ).fetchone()
    return {
        "has_archive": bool(state.get("last_sync_completed_at") or state.get("last_import_at")),
        "ingestion_scope": state.get("ingestion_scope"),
        "last_synced_at": state.get("last_synced_at"),
        "last_sync_completed_at": state.get("last_sync_completed_at"),
        "last_import_at": state.get("last_import_at"),
        "oldest": span["oldest"], "newest": span["newest"],
    }


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


MAX_TIMEOUTS_PER_RUN = 8  # Okta 30-second timeouts one run tolerates (each costs several retried requests) before it stops as partial
SYSTEM_LOG_PATH = "/api/v1/logs"  # equals create_secret_folders.SYSTEM_LOG_PATH (a test pins it)
SYSTEM_LOG_MAX_SINCE_DAYS = 180  # Okta: "The since parameter is over 180 days prior to the current day" (HTTP 400)
POLL_LIMIT = 1000
POLL_MIN_LIMIT = 50  # the page size a timed-out poll shrinks to before giving up
POLL_MAX_PAGES = 2000  # per run; a longer catch-up resumes from the saved cursor on the next run
POLL_CURSOR_MAX_CHARS = 4096


def clamp_system_log_since(since_iso, now=None):
    """(since, clamped). Okta refuses a `since` more than 180 days back with a
    400, and keeps only 90 days of events anyway, so an older `since` (a stale
    watermark, a hand-entered date) is moved to 179 days back instead of
    failing the sync. `clamped` tells the caller to say so."""
    now = now or datetime.now(timezone.utc)
    floor = _iso_ms(now - timedelta(days=SYSTEM_LOG_MAX_SINCE_DAYS - 1))
    canonical = _canonical_published(since_iso)
    if canonical is None or canonical < floor:
        return floor, True
    return canonical, False


def _is_timeout_error(exc):
    """Okta answers a System Log query that ran past its 30-second limit with
    HTTP 500 and error code E0000009. That is "ask for less", never "no
    events"."""
    return str(getattr(exc, "status", "")) == "500" and "E0000009" in str(getattr(exc, "body", ""))


def _poll_start_path(since_iso, limit=POLL_LIMIT):
    from urllib.parse import urlencode
    return f"{SYSTEM_LOG_PATH}?" + urlencode({"limit": str(limit), "sortOrder": "ASCENDING", "since": since_iso})


def _path_with_limit(path, limit):
    """`path` with its limit parameter replaced (every other parameter, the
    paging cursor included, untouched)."""
    from urllib.parse import parse_qsl, urlencode, urlsplit
    parts = urlsplit(path)
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != "limit"]
    query.insert(0, ("limit", str(limit)))
    return f"{parts.path}?{urlencode(query)}"


def _query_limit(path):
    from urllib.parse import parse_qs, urlsplit
    try:
        return int((parse_qs(urlsplit(path).query).get("limit") or [POLL_LIMIT])[0])
    except ValueError:
        return POLL_LIMIT


def _usable_poll_cursor(value):
    """A stored cursor is used only if it still looks like one of our own
    System Log paging links (a relative /api/v1/logs path with a bounded
    length): the archive file is data, and a cursor is a request path."""
    return (isinstance(value, str) and 0 < len(value) <= POLL_CURSOR_MAX_CHARS
            and value.startswith(SYSTEM_LOG_PATH + "?") and "\n" not in value and "\r" not in value)


def _read_poll_cursor(conn, environment_id):
    row = conn.execute("SELECT poll_cursor FROM sync_state WHERE environment_id = ?", (environment_id,)).fetchone()
    value = row["poll_cursor"] if row else None
    return value if _usable_poll_cursor(value) else None


def sync_okta_events(okta_client, environment_id, ingestion_scope, since=None, on_progress=None):
    """Pulls System Log events (see _sync_okta_events_impl) and records the run in sync_runs: started before anything
    can fail, finished with ok (complete), stopped (a Stop or deadline) or failed (anything else, including an
    exception, which is re-raised). The window recorded is the one asked of Okta: `since` as the manifest has it
    (None when the run resumed from its saved cursor) and the `until` the manifest names."""
    if ingestion_scope not in INGESTION_SCOPES:
        raise ValueError(f"ingestion_scope must be one of {INGESTION_SCOPES}")
    run_id = _run_start(environment_id, "sync")
    info = {}
    try:
        result = _sync_okta_events_impl(okta_client, environment_id, ingestion_scope, since=since, on_progress=on_progress, _info=info)
    except BaseException:
        _run_finish(run_id, "failed", info.get("since"), info.get("until"), info.get("rows"))
        raise
    outcome = "ok" if result.get("complete") else ("stopped" if result.get("cancelled") else "failed")
    _run_finish(run_id, outcome, result.get("since"), info.get("until"), result.get("inserted"))
    return result


def _sync_okta_events_impl(okta_client, environment_id, ingestion_scope, since=None, on_progress=None, _info=None):
    """Pulls System Log events from the real Okta API and archives them.

    Two modes (5.50.0, from Okta's System Log query guide):

    * POLLING (the steady state). Okta orders a request with `since` and no
      `until` by when each event was PERSISTED, "returns every event that
      occurs in your org", and always carries a `next` link. Following those
      links and saving the last one as a cursor (sync_state.poll_cursor)
      therefore catches an event that was persisted long after its
      `published` time, which the old bounded since/until day-walk skipped
      for good once it had walked past that day ("Don't transfer data by
      manually paginating using `since` and `until`, as this may lead to
      skipped or duplicated events"). A run stops at the first empty page.
      The cursor is saved after every page, so a restart continues from it.
      If Okta rejects a stored cursor (HTTP 400) the run falls back, once,
      to `since` = the watermark minus WATERMARK_OVERLAP_SECONDS; events are
      deduplicated by uuid, so the overlap costs nothing.
    * BOUNDED, day by day, only for the first run on an environment with no
      watermark (a 90-day backfill, where the page cap is the real
      constraint) and for a caller-supplied `since`. The first-run backfill
      is followed by one polling pass, which also sets the cursor.

    An install upgraded from before 5.50.0 has a watermark and no cursor: its
    next sync starts a polling pass at watermark minus the overlap. Nothing is
    skipped and nothing is stored twice.

    `since` is clamped to Okta's 180-day limit (clamp_system_log_since). A
    System Log query that Okta times out (HTTP 500 E0000009) is retried with
    a smaller page (polling) or a smaller window (bounded); a refused query
    (HTTP 400, e.g. E0000053 / E0000031 for a bad filter) is an error, never
    an empty result. `last_synced_at` (the published watermark) advances only
    after a pass is complete.

    The bounded walk (BUG FIX DATA-02 / DATA-09, unchanged): one day per
    chunk, never closer than SAFETY_LAG_SECONDS to now, the watermark
    persisted after every chunk, a chunk that hits the page cap resumes from
    the newest instant it returned, and a chunk with no progress at all
    stops the run with last_sync_status "error".

    Returns {"inserted", "scanned", "since", "chunks", "complete",
    "incomplete_chunks", "chain_head", "mode", "pages", "since_clamped",
    "cursor_reset"} (plus "error" when incomplete). Exactly one manifest is
    written per call (5.40.6). Failure (DATA-05): any exception records the
    manifest for rows already inserted, writes last_sync_status="error" and
    re-raises. last_sync_completed_at is written only by a successful
    completion; last_sync_attempt_at records every start."""
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

    # 5.50.0: rows a killed run committed but never sealed get their own recovery manifest before anything new is fetched.
    recovered_events = 0
    try:
        recovered_events = seal_unsealed_events(environment_id)["sealed"]
    except Exception as recovery_exc:  # never blocks the sync; the integrity check keeps reporting them
        recovered_events = None
        import create_secret_folders
        create_secret_folders.log("WARN", f"sealing unsealed events of an interrupted run failed: {type(recovery_exc).__name__}")

    explicit_since = since is not None
    stored = None
    cursor_path = None
    if not explicit_since:
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
            stored = canonical
            cursor_path = _read_poll_cursor(conn, environment_id)

    now_dt = datetime.now(timezone.utc)
    safe_now_dt = now_dt - timedelta(seconds=SAFETY_LAG_SECONDS)
    since_clamped = False
    bounded = True       # run the day-by-day walk
    poll_after = True    # then (or instead) a polling pass
    poll_path = None
    if explicit_since:
        since, since_clamped = clamp_system_log_since(since, now_dt)
        poll_after = False  # the caller asked for a specific window; the next scheduled run switches to polling
    elif stored:
        bounded = False
        watermark_dt = datetime.fromisoformat(stored.replace("Z", "+00:00"))
        resume_since = _iso_ms(watermark_dt - timedelta(seconds=WATERMARK_OVERLAP_SECONDS))
        resume_since, since_clamped = clamp_system_log_since(resume_since, now_dt)
        since = resume_since
        poll_path = cursor_path or _poll_start_path(resume_since)
    else:
        since = _iso_ms(now_dt - timedelta(days=90))

    cursor = datetime.fromisoformat(since.replace("Z", "+00:00"))
    if not bounded and cursor_path:
        # The run continues from the saved cursor, not from a date: report that, not a `since` it never used.
        since_clamped = False
        original_since = None
    else:
        original_since = since
    total_inserted = 0
    total_scanned = 0  # rows fetched, INCLUDING any re-read after a page-cap resume (see DATA-09 above)
    chunks = 0
    incomplete_chunks = 0
    pages_polled = 0
    cursor_reset = False
    all_new_entries = []  # Phase 6: accumulated across every chunk and page, sealed into ONE manifest row for this whole call
    poll_max_published = None
    timeouts = {"n": 0}  # Okta timeouts this run, polling and bounded together
    # Exactly one manifest per call (5.40.6): once this call's rows are
    # sealed, nothing may seal them again.
    sealed = {"head": None, "done": False}
    stopped = {"on_request": False}  # 5.51.0: the refresh job asked this run to stop (progress is saved, as for any partial run)

    def _stop_requested():
        import create_secret_folders as engine
        if engine.cancel_requested():
            stopped["on_request"] = True
        return stopped["on_request"]

    def _seal(until):
        if not sealed["done"]:
            sealed["head"] = _record_ingestion_manifest(
                conn, environment_id, "sync", original_since, until, all_new_entries
            )
            sealed["done"] = True  # only after the commit: a seal that raised rolled back and may be retried
        return sealed["head"]

    def _fail(error_message, until):
        try:
            if stopped["on_request"]:
                # A Stop or a part deadline is not a failure of Okta: the saved position carries on, so the status is "cancelled" (a person's
                # Stop) or "timed_out" (the deadline), with no error text. The failing-sync banner is not armed by either; the scheduler
                # backs off after both, like after a failure, so a stopped or slow run is not restarted at the next poll.
                import create_secret_folders as _engine
                _upsert_sync_state(conn, environment_id, last_sync_status=_engine.cancel_reason(), last_sync_error=None)
            else:
                _upsert_sync_state(conn, environment_id, last_sync_status="error", last_sync_error=error_message)
            if on_progress:
                on_progress("ingest", "error", error_message)
        except Exception:
            _seal(until)  # the rows still get sealed when the status write (or the callback) fails
            raise
        # An interrupted sync still produced real inserted rows -- those
        # must be in the chain too, same "nothing new is silently
        # invisible" reasoning as a zero-new-rows batch. A no-op if this
        # call already sealed them.
        return _seal(until)

    def _result(complete, chain_head, error=None):
        if _info is not None:
            _info["until"] = _iso_ms(safe_now_dt)
        out = {
            "inserted": total_inserted, "scanned": total_scanned, "since": original_since, "chunks": chunks,
            "complete": complete, "incomplete_chunks": incomplete_chunks, "chain_head": chain_head,
            "mode": "bounded" if explicit_since else ("bounded+polling" if bounded else "polling"),
            "pages": pages_polled, "since_clamped": since_clamped, "cursor_reset": cursor_reset,
            "recovered_events": recovered_events, "from_cursor": bool(not bounded and cursor_path),
        }
        if error:
            out["error"] = error
        if stopped["on_request"]:
            out["cancelled"] = True
        return out

    def _fallback_since():
        base = datetime.fromisoformat(stored.replace("Z", "+00:00")) if stored else now_dt - timedelta(days=90)
        return clamp_system_log_since(_iso_ms(base - timedelta(seconds=WATERMARK_OVERLAP_SECONDS)), now_dt)[0]

    def _poll_pass(start_path):
        """Follows the System Log `next` links from start_path until an
        empty page. Returns (complete, error_message)."""
        nonlocal total_inserted, total_scanned, pages_polled, cursor_reset, poll_max_published
        path = start_path
        fell_back = False
        shrinks = 0
        while pages_polled < POLL_MAX_PAGES:
            if _stop_requested():
                return False, ("Stopped on request: the events read so far are stored and the cursor is saved, so the next sync "
                               "continues from where this one stopped.")
            try:
                events, next_path = okta_client.get_system_log_page(path)
            except Exception as exc:
                if _is_timeout_error(exc):
                    timeouts["n"] += 1
                    if timeouts["n"] > MAX_TIMEOUTS_PER_RUN:
                        return False, (f"partial: Okta timed out {timeouts['n']} times in this run; progress is saved and the next sync continues "
                                       "from the saved cursor.")
                    current = _query_limit(path)
                    smaller = max(POLL_MIN_LIMIT, current // 4)
                    if smaller >= current or shrinks >= 3:
                        raise
                    shrinks += 1
                    if on_progress:
                        on_progress("fetch", "progress", f"Okta timed the request out; retrying with pages of {smaller}")
                    path = _path_with_limit(path, smaller)
                    continue
                if str(getattr(exc, "status", "")) == "400" and cursor_path and path == cursor_path and not fell_back:
                    # Okta rejected the saved cursor: start again from the watermark (events dedupe by uuid).
                    fell_back = cursor_reset = True
                    path = _poll_start_path(_fallback_since())
                    if on_progress:
                        on_progress("fetch", "progress", "The saved System Log cursor was refused; resuming from the watermark")
                    continue
                raise
            pages_polled += 1
            total_scanned += len(events)
            if events:
                rows = [_normalize_live_event(e) for e in events if isinstance(e, dict)]
                inserted, max_published, new_entries = _insert_rows(conn, environment_id, rows, ingestion_scope)
                total_inserted += inserted
                all_new_entries.extend(new_entries)
                if max_published and (poll_max_published is None or max_published > poll_max_published):
                    poll_max_published = max_published
                if next_path is not None and _path_with_limit(next_path, 0) == _path_with_limit(path, 0):
                    return False, "Okta returned the same System Log page again; stopping instead of looping."
            stored_path = next_path
            if next_path and _query_limit(next_path) != POLL_LIMIT:
                # Okta echoes the page size in its `next` link: a size shrunk after a timeout must not be saved, or every later
                # healthy run would keep asking for small pages. Only `limit` changes.
                stored_path = _path_with_limit(next_path, POLL_LIMIT)
            if stored_path and _usable_poll_cursor(stored_path):
                # Saved after the page's rows are committed: a crash between the two re-reads one page, which dedupes.
                _upsert_sync_state(conn, environment_id, poll_cursor=stored_path, sync_mode="polling")
            if next_path and _query_limit(next_path) != _query_limit(path):
                next_path = _path_with_limit(next_path, _query_limit(path))  # within this run keep the size that just worked
            if on_progress and events:
                on_progress("fetch", "progress", f"polling: page {pages_polled}, {total_scanned} event(s) read")
            if not events or not next_path:
                return True, None
            path = next_path
        return False, (
            f"Read {POLL_MAX_PAGES} System Log pages in one run; the cursor is saved, so the next sync continues "
            "from where this one stopped."
        )

    chunk_span = timedelta(days=CHUNK_DAYS)
    failed_floor = None  # the smallest window that timed out in this run: the walk never grows back to it
    try:
        while bounded and cursor < safe_now_dt:
            if _stop_requested():
                error_message = (f"Stopped on request: progress up to {_iso_ms(cursor)} is saved and the next sync continues from there.")
                chain_head = _fail(error_message, _iso_ms(cursor))
                return _result(False, chain_head, error_message)
            chunk_until_dt = min(cursor + chunk_span, safe_now_dt)
            chunk_since = _iso_ms(cursor)  # millisecond-exact, so "no progress" below compares like with like
            chunk_until = _iso_ms(chunk_until_dt)

            if on_progress:
                on_progress("fetch", "progress", f"{chunk_since} .. {chunk_until}")
            try:
                events, complete = okta_client.get_system_log(
                    since=chunk_since, until=chunk_until, limit=1000, sort_order="ASCENDING", max_pages=200
                )
            except Exception as exc:
                if _is_timeout_error(exc) and chunk_span > timedelta(minutes=1):
                    timeouts["n"] += 1
                    failed_floor = chunk_span if failed_floor is None else min(failed_floor, chunk_span)
                    if timeouts["n"] > MAX_TIMEOUTS_PER_RUN:
                        error_message = (f"partial: Okta timed out {timeouts['n']} times in this run; progress up to {_iso_ms(cursor)} is saved "
                                         "and the next sync continues from there.")
                        chain_head = _fail(error_message, chunk_since)
                        return _result(False, chain_head, error_message)
                    chunk_span = max(timedelta(minutes=1), chunk_span / 4)  # ask for a smaller window, not for nothing
                    continue
                raise
            grown = min(timedelta(days=CHUNK_DAYS), chunk_span * 1.5)  # recover gradually, and never back to a size that failed here
            if failed_floor is not None and grown >= failed_floor:
                grown = chunk_span
            chunk_span = grown
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
                    return _result(False, chain_head, error_message)
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

        if poll_after:
            if poll_path is None:  # first run: poll from just before where the bounded walk stopped
                poll_path = _poll_start_path(clamp_system_log_since(
                    _iso_ms(min(cursor, safe_now_dt) - timedelta(seconds=WATERMARK_OVERLAP_SECONDS)), now_dt)[0])
            complete, poll_error = _poll_pass(poll_path)
            if not complete:
                chain_head = _fail(poll_error, _iso_ms(safe_now_dt))
                return _result(False, chain_head, poll_error)
            if poll_max_published:
                current = (get_sync_state(environment_id) or {}).get("last_synced_at")
                if not current or poll_max_published > current:
                    _upsert_sync_state(conn, environment_id, last_synced_at=poll_max_published)

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
    except BaseException as exc:
        import create_secret_folders as engine
        if not isinstance(exc, engine.JobCancelled):
            raise
        # A cancel noticed inside a rate-limit wait: end like any other stopped run (stored rows sealed, status written).
        stopped["on_request"] = True
        error_message = ("Stopped on request: the events read so far are stored, so the next sync continues from where this one "
                         "stopped.")
        chain_head = _fail(error_message, _iso_ms(cursor))
        return _result(False, chain_head, error_message)

    if on_progress:
        on_progress("ingest", "done", f"{total_inserted} new row(s) inserted across {chunks} day-chunk(s) and {pages_polled} polled page(s)")
    return _result(True, chain_head)


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

    stamps = [r[2] for r in rows if r[2]]
    run_id = _run_start(environment_id, "import")
    try:
        inserted, _max_published, new_entries = _insert_rows(conn, environment_id, rows, ingestion_scope)
        chain_head = _record_ingestion_manifest(conn, environment_id, "csv_import", None, None, new_entries)
    except BaseException:
        _run_finish(run_id, "failed")
        raise
    # the range of the file's rows, half-open: [oldest, newest + 1 ms)
    import_until = _iso_ms(datetime.fromisoformat(max(stamps).replace("Z", "+00:00")) + timedelta(milliseconds=1)) if stamps else None
    _run_finish(run_id, "ok", min(stamps) if stamps else None, import_until, inserted)

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


def _week_monday(published):
    """The Monday (YYYY-MM-DD) of the week a canonical timestamp falls in: weeks labelled before it ended before it."""
    dt = datetime.strptime(published[:10], "%Y-%m-%d")
    return (dt - timedelta(days=dt.weekday())).strftime("%Y-%m-%d")


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
                _record_prune(environment_id, cutoff, cur.rowcount, "retention")
                # 5.50.0: the per-person weekly sign-in rows follow the events they were counted from (weeks that ended before
                # the cutoff go; the all-people totals hold no names and stay). Snapshots are not touched: they are curated.
                conn.execute("DELETE FROM mfa_week_user WHERE environment_id = ? AND week < ?", (environment_id, _week_monday(cutoff)))
                conn.commit()
            except Exception:
                conn.rollback()  # DATA-11
                raise

    if max_size_mb is not None:
        max_bytes = max_size_mb * 1024 * 1024
        step_days = 1
        pruned_any_by_size = False
        size_pruned = 0
        size_cutoff = None

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
                    size_pruned += cur.rowcount
                    size_cutoff = step_cutoff
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
                _record_prune(environment_id, size_cutoff, size_pruned, "size")
                conn.commit()
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
               UNION SELECT environment_id FROM manifest_entries
               UNION SELECT environment_id FROM config_snapshots
               UNION SELECT environment_id FROM opa_model_cache"""
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
            "snapshot_count": conn.execute(
                "SELECT COUNT(*) FROM config_snapshots WHERE environment_id = ?", (environment_id,)).fetchone()[0],
            "opa_scan_cached": conn.execute(
                "SELECT 1 FROM opa_model_cache WHERE environment_id = ?", (environment_id,)).fetchone() is not None,
        })
    return out


# Every table holding one environment's archive, in purge order (children first).
ARCHIVE_TABLES = ("event_targets", "events", "sync_state", "config_snapshot_items", "config_snapshots", "mfa_week_user", "mfa_week_totals", "mfa_agg_state", "manifest_entries", "chain_heads", "ingestion_manifests", "opa_model_cache", "sync_runs", "prune_history")


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


# ---------------------------------------------------------------------------
# The stored OPA scan (5.51.0)
# ---------------------------------------------------------------------------
# One replaceable row per environment: the Access Explorer model after the redaction pass (create_secret_folders.
# redact_model_for_storage), canonical JSON, zlib. It is what the screens open from after a restart. It is NOT evidence
# (the sealed daily snapshot is); it is never exported or returned as a blob by any route.
OPA_MODEL_CACHE_MAX_BYTES = 96 * 1024 * 1024
OPA_MODEL_COUNT_KEYS = ("users", "groups", "policies", "projects", "servers")


def _model_shape(version):
    """The part of a release number the model's shape is tied to: patch releases never change the shape, a minor release may."""
    parts = str(version or "").split(".")
    return ".".join(parts[:2]) if len(parts) >= 2 else str(version or "")


def opa_model_counts(model):
    return {key: len(model[key]) for key in OPA_MODEL_COUNT_KEYS if isinstance(model.get(key), list)}


def store_opa_model_cache(environment_id, model, built_at=None, duration_seconds=None, source_version=None, already_redacted=False):
    """Replaces this environment's stored scan with `model`. Redacts first (idempotent; `already_redacted` skips the work
    when the caller just did it) -- raises create_secret_folders.ModelRedactionError and writes nothing when the model holds
    a credential-shaped value.

    Returns {"stored": True, "built_at", "sha256", "raw_bytes", "model"} (model: the redacted copy) or, over
    OPA_MODEL_CACHE_MAX_BYTES, {"stored": False, "reason": "too_large", "raw_bytes", "model"} with nothing written (the scan
    stays usable in memory)."""
    import create_secret_folders as engine
    redacted = model if already_redacted else engine.redact_model_for_storage(model)
    text = engine.canonical_model_json(redacted)
    raw = text.encode("utf-8")
    if len(raw) > OPA_MODEL_CACHE_MAX_BYTES:
        return {"stored": False, "reason": "too_large", "raw_bytes": len(raw), "model": redacted}
    built_at = built_at or _iso_ms(datetime.now(timezone.utc))
    digest = hashlib.sha256(raw).hexdigest()
    blob = zlib.compress(raw, 6)
    warnings = [w for w in (redacted.get("warnings") if isinstance(redacted.get("warnings"), list) else []) if not (isinstance(w, dict) and w.get("status") == "redacted")]  # sections the key cannot read; hidden values are counted apart
    conn = _get_connection()
    with _db_lock:
        conn.execute(
            "INSERT OR REPLACE INTO opa_model_cache (environment_id, built_at, duration_seconds, source_version, sha256, "
            "raw_bytes, model_zlib, warnings_json, counts_json, modified_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
            (environment_id, built_at, duration_seconds, source_version or engine.SCRIPT_VERSION, digest, len(raw), blob,
             json.dumps(warnings, sort_keys=True), json.dumps(opa_model_counts(redacted), sort_keys=True)),
        )
        conn.commit()
    return {"stored": True, "built_at": built_at, "sha256": digest, "raw_bytes": len(raw), "model": redacted}


def _cache_info_row(row):
    try:
        counts = json.loads(row["counts_json"])
    except (TypeError, ValueError):
        counts = {}
    try:
        warnings = json.loads(row["warnings_json"]) if row["warnings_json"] else []
    except ValueError:
        warnings = []
    return {
        "built_at": row["built_at"], "duration_seconds": row["duration_seconds"], "source_version": row["source_version"],
        "sha256": row["sha256"], "raw_bytes": row["raw_bytes"], "counts": counts,
        "warnings_count": len(warnings) if isinstance(warnings, list) else 0, "modified_at": row["modified_at"],
    }


def opa_model_cache_info(environment_id):
    """What is stored for this environment, without the model: None when nothing usable is stored (no row, or a row built by
    a release whose model shape differs)."""
    import create_secret_folders as engine
    row = _get_connection().execute(
        "SELECT built_at, duration_seconds, source_version, sha256, raw_bytes, warnings_json, counts_json, modified_at "
        "FROM opa_model_cache WHERE environment_id = ?", (environment_id,)).fetchone()
    if row is None or _model_shape(row["source_version"]) != _model_shape(engine.SCRIPT_VERSION):
        return None
    return _cache_info_row(row)


def load_opa_model_cache(environment_id):
    """The stored scan as {**info, "model": dict}, or None when there is none, it was built by a different model shape, or
    the stored bytes no longer match their recorded hash (a damaged row is treated as absent and logged, never served)."""
    import create_secret_folders as engine
    row = _get_connection().execute(
        "SELECT built_at, duration_seconds, source_version, sha256, raw_bytes, warnings_json, counts_json, modified_at, model_zlib "
        "FROM opa_model_cache WHERE environment_id = ?", (environment_id,)).fetchone()
    if row is None or _model_shape(row["source_version"]) != _model_shape(engine.SCRIPT_VERSION):
        return None
    try:
        raw = zlib.decompress(row["model_zlib"])
        if hashlib.sha256(raw).hexdigest() != row["sha256"]:
            raise ValueError("hash mismatch")
        model = json.loads(raw.decode("utf-8"))
        if not isinstance(model, dict):
            raise ValueError("not an object")
    except (zlib.error, ValueError, UnicodeDecodeError) as exc:
        engine.log("WARN", f"The stored OPA scan for an environment could not be read ({type(exc).__name__}); it is ignored until the next scan.")
        return None
    return {**_cache_info_row(row), "model": model}


def update_opa_model_cache(environment_id, model, modified_at=None):
    """Replaces the stored model of an existing row after a local correction (a user removed from a group), keeping when the
    scan was built and recording `modified_at`. False when there is no usable row."""
    import create_secret_folders as engine
    info = opa_model_cache_info(environment_id)
    if info is None:
        return False
    redacted = engine.redact_model_for_storage(model)
    raw = engine.canonical_model_json(redacted).encode("utf-8")
    if len(raw) > OPA_MODEL_CACHE_MAX_BYTES:
        return False
    conn = _get_connection()
    with _db_lock:
        conn.execute(
            "UPDATE opa_model_cache SET sha256 = ?, raw_bytes = ?, model_zlib = ?, counts_json = ?, modified_at = ? WHERE environment_id = ?",
            (hashlib.sha256(raw).hexdigest(), len(raw), zlib.compress(raw, 6), json.dumps(opa_model_counts(redacted), sort_keys=True),
             modified_at or _iso_ms(datetime.now(timezone.utc)), environment_id))
        conn.commit()
    return True


def delete_opa_model_cache(environment_id):
    """Removes this environment's stored scan. True if a row was removed."""
    conn = _get_connection()
    with _db_lock:
        removed = conn.execute("DELETE FROM opa_model_cache WHERE environment_id = ?", (environment_id,)).rowcount
        conn.commit()
    return removed > 0


def sweep_orphaned_opa_model_caches():
    """Deletes every stored scan whose environment no longer exists (a delete under an older release, a rollback, a
    restored backup). Returns the environment ids removed, for the caller to audit."""
    conn = _get_connection()
    with _db_lock:
        try:
            conn.execute("BEGIN IMMEDIATE")
            ids = [r[0] for r in conn.execute(
                "SELECT environment_id FROM opa_model_cache WHERE environment_id NOT IN (SELECT environment_id FROM app_environments)")]
            for environment_id in ids:
                conn.execute("DELETE FROM opa_model_cache WHERE environment_id = ?", (environment_id,))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    return ids


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
