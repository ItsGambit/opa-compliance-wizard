export type IngestionScope = 'curated' | 'all'

export interface SyncSchedule {
  enabled: boolean
  run_time: string // "HH:MM", UTC
  ingestion_scope: IngestionScope
  retention_days: number | null
  retention_max_size_mb: number | null
}

export interface Environment {
  // The real, stable environment_id (a random UUID4, server/serve.py's
  // _public_entry -- see create_secret_folders.py's Phase 1 UUID
  // migration, docs/fast-follow-redesign.md) -- unambiguous even when two
  // different owners each have an environment named the same thing
  // (confirmed exploitable without this: an admin's edit/share/delete
  // could silently target the wrong owner's environment, and the admin
  // listing could silently drop one of two same-named entries). Carries no
  // information about the owner or display name, unlike the retired
  // "{owner}::{name}" storage_name this replaced -- safe to appear in a
  // URL, browser history, or support screenshot. Send this, not `name`,
  // on any admin-override mutation (share/delete/edit) where ambiguity is
  // possible -- see EnvironmentManagerDialog.tsx.
  id: string
  name: string
  base_domain: string
  team_name: string
  key_id: string
  okta_url: string
  has_okta_token: boolean
  sync_schedule: SyncSchedule
  // Per-user environment scoping (server-hosted, logged-in deployments only --
  // both are always true for a local/standalone run, since there's only ever
  // one unscoped owner). `shared` = visible to every other logged-in user;
  // `is_own` = owned by whichever identity is asking right now. A saved
  // environment can be private to one owner (is_own=true, shared=false, only
  // that owner ever sees it), shared by its owner (is_own=true, shared=true),
  // or someone else's shared environment (is_own=false, shared=true) -- the
  // backend never reveals WHO another owner is, just whether it's yours.
  shared: boolean
  is_own: boolean
  /** 5.40.7 (UI-07): true when this row's NAME resolves to this very row
   * for the caller -- i.e. it is what activating, syncing or reporting by
   * that name would act on. False for another owner's private row (admin
   * view) and for a shared row hidden by the caller's own same-named
   * environment. Older servers omit it (treated as is_own || shared). */
  addressable?: boolean
  /** 5.42.0: what the CALLER may do with this environment -- the server's
   * own resolution (an owner's rows are all "allow", source "owner"). The
   * UI only mirrors it; the server enforces it. Older servers omit it. */
  permissions?: Record<SharedCapabilityKey, EffectivePermission>
  /** 5.42.0, admins only: this environment's stored overrides (a capability
   * absent here inherits the global default). */
  permission_overrides?: Partial<Record<SharedCapabilityKey, PermissionValue>>
}

// ── Shared-environment permissions (5.42.0) ──────────────────────────────

export type SharedCapabilityKey =
  | 'view_archive' | 'live_read' | 'tenant_write' | 'import_csv' | 'reset_watermark' | 'sync_now' | 'sync_settings'

export type PermissionValue = 'allow' | 'deny'
/** A stored setting: "inherit" is the absence of one. */
export type PermissionSetting = PermissionValue | 'inherit'
/** Where an effective value came from ("user" = an exception for the
 * caller themself, 5.43.0). */
export type PermissionSource = 'owner' | 'user' | 'override' | 'default' | 'built_in'

export interface EffectivePermission {
  value: PermissionValue
  source: PermissionSource
}

export interface SharedCapability {
  key: SharedCapabilityKey
  label: string
  description: string
  builtin: PermissionValue
}

export interface SharedPermissionDefault extends EffectivePermission {
  updated_at: string | null
  updated_by: string | null
}

/** 5.43.0: a user as the login gates identify them -- the Okta issuer of
 * the gate that signed them in plus their Okta user id there (an id alone
 * is only unique within one Okta org). */
export interface GrantUser {
  issuer: string
  subject: string
}

/** 5.43.0: one capability allowed or denied to one user on one environment
 * (beats the environment's override). */
export interface SharedPermissionGrant extends GrantUser {
  email: string | null
  capability: SharedCapabilityKey
  value: PermissionValue
}

/** 5.43.0: a user a login gate has vouched for, for the exception picker. */
export interface KnownIdentity extends GrantUser {
  email: string | null
  last_seen_at: string
}

export interface SharedPermissionsResponse {
  capabilities: SharedCapability[]
  defaults: Record<SharedCapabilityKey, SharedPermissionDefault>
  environments: Record<string, {
    name: string
    shared: boolean
    overrides: Partial<Record<SharedCapabilityKey, PermissionValue>>
    /** 5.43.0 (older servers omit it). */
    grants?: SharedPermissionGrant[]
    effective: Record<SharedCapabilityKey, EffectivePermission>
  }>
  /** 5.43.0 (older servers omit it). */
  identities?: KnownIdentity[]
}

/** 5.42.0: an Environments change answered "approve it with MFA first"
 * (hosted mode). Nothing has changed yet; the browser takes action_id
 * through the gate's /step-up and the change is applied on the way back. */
export interface StepUpRequired {
  step_up_required: true
  action_id: string
  action: string
}

export interface EnvironmentsResponse {
  environments: Environment[]
  active: string | null
  /** 5.40.7 (UI-07): the active environment's id -- compare rows by this,
   * never by name (an admin sees several owners' same-named rows). */
  active_id?: string | null
}

/** One archive left behind by a deleted environment (DATA-12). */
export interface OrphanedArchive {
  environment_id: string
  event_count: number
  bytes: number
  oldest_published: string | null
  newest_published: string | null
  manifest_count: number
}

/** GET /api/environments/{name}/integrity (see audit_store.verify_ingestion_chain). */
export interface IntegrityResult {
  valid: boolean
  manifest_count: number
  broken_at: number | string | null
  reason: string | null
  head_hash?: string | null
  legacy_manifests?: number
  deep?: boolean
  deep_applicable?: boolean
  verified_rows?: number
  unverifiable_rows?: number
  checked_at?: string | null
}

export interface SyncStepEvent {
  key: string
  status: 'start' | 'progress' | 'done'
  detail: string | null
}

export interface SyncState {
  environment: string
  last_synced_at: string | null
  /** Set only by a SUCCESSFUL sync as of 5.40.2 (DATA-05). */
  last_sync_completed_at: string | null
  last_sync_status: string | null
  last_sync_error: string | null
  total_events_ingested: number
  ingestion_scope: IngestionScope
  /** When a sync last STARTED (5.40.2). Older servers omit it. */
  last_sync_attempt_at?: string | null
  /** When a CSV import last ran (5.40.2, DATA-03 -- imports no longer move
   * the live-sync watermark). Older servers omit it. */
  last_import_at?: string | null
}

export interface SyncStatusResponse {
  status: 'idle' | 'running' | 'done' | 'error'
  /** "csv_import" while a CSV import holds the ingest slot (not a sync). */
  kind?: string
  steps: SyncStepEvent[]
  error: string | null
  result?: {
    inserted: number; scanned: number; since: string; chunks: number; pruned: number; cutoff: string | null
    /** 5.40.2: day-chunks that hit the page cap and were resumed from
     * their newest returned event (DATA-09), and the evidence chain head
     * sealed by this sync (DATA-04). Older servers omit both. */
    incomplete_chunks?: number
    chain_head?: string
  }
  sync_state: SyncState | null
  is_first_sync: boolean
}

export interface AuditLogEntry {
  timestamp: string
  actor_email: string | null
  actor_sub: string | null
  action: string
  details: Record<string, unknown>
  // New as of 2026-09-30 (Okta's own System Log always captures both;
  // this log never did) -- undefined/null on any entry written before
  // this change, since neither was ever captured for those; rendered as
  // "—", not backfilled (there's no real data to backfill).
  client_ip?: string | null
  user_agent?: string | null
}

export type ComplianceControl = 'CC6' | 'CC7' | 'CC8'

export interface ComplianceReportDef {
  key: string
  label: string
  control: ComplianceControl
  description: string
  event_types: string[]
  count?: number
}

export interface ComplianceReportTarget {
  id: string
  type: string
  alternateId: string
  displayName: string
}

export interface ComplianceReportRow {
  uuid: string
  user: string
  actor_alternate_id: string | null
  action: string
  event_type: string
  timestamp: string
  resource: string
  resource_type: string
  resource_type_detail: string
  resource_id: string
  resource_alternate_id: string
  outcome: string
  /** Why the outcome was what it was -- empty on most success rows, a
   * real string on a denial/failure (e.g. "Authenticator method
   * unanswered"). From Okta's own outcome.reason. */
  outcome_reason: string
  /** From Okta's own client.ipAddress -- empty for system-triggered
   * events with no originating client (e.g. PAM credential rotation). */
  client_ip: string
  /** Short "{city}, {state}, {country}" string from Okta's own
   * client.geographicalContext -- empty when client_ip is. */
  client_geo: string
  /** Okta's own transaction/request id for this event -- lets an admin
   * jump from this row to the exact matching entry in Okta's own System
   * Log UI/API for follow-up investigation. */
  request_id: string | null
  targets: ComplianceReportTarget[]
}

// UI-03/DATA-07 (external review, 2026-10-05): rows is capped at `limit`
// (1000 by default, 5000 max) server-side -- total is the REAL, uncapped
// count for the same filters (audit_store.count_events), and truncated is
// true whenever rows.length < total. Without these, a report silently
// held only the newest `limit` events with nothing on screen saying so,
// dropping the oldest part of a long evidence window.
export interface ComplianceReportResponse {
  report: string
  environment: string
  rows: ComplianceReportRow[]
  total: number
  truncated: boolean
}

/** GET /api/resources/{id}/history -- same ComplianceReportRow shape as
 * every report, just scoped to one resource's own id instead of one
 * report_key's event types. See audit_store.resource_history.
 * total/truncated: see ComplianceReportResponse's comment above. */
export interface ResourceHistoryResponse {
  resource_id: string
  environment: string
  rows: ComplianceReportRow[]
  total: number
  truncated: boolean
}

export type BannerVariant = 'info' | 'warning' | 'danger'

export interface BannerConfig {
  enabled: boolean
  message: string
  variant: BannerVariant
  dismissible: boolean
}

// Okta group IDs (not names) that gate login/admin rights across the whole
// dashboard -- see server/auth_gate.py + create_secret_folders.py's
// get/set_access_control_config. null means "not configured yet."
export interface AccessControlConfig {
  admin_group_id: string | null
  user_group_id: string | null
  restrict_login: boolean
}

// Phase 10: /api/access_control/save's response -- the config plus
// confirmation that THIS exact change was approved via a validated
// step-up MFA transaction (see Phase 3's pending_admin_actions), so the
// admin who just relied on that guarantee can see it confirmed instead
// of a generic "saved" toast.
export interface AccessControlSaveResponse extends AccessControlConfig {
  step_up_verified: boolean
  saved_at: string
}

export interface EnvironmentFormValues {
  // Only set when editing an EXISTING environment (see Environment.id) --
  // an admin editing another owner's environment needs this to
  // disambiguate from a same-named environment under a different owner.
  // Absent on a create (no id exists yet).
  id?: string
  name: string
  base_domain: string
  team_name: string
  key_id: string
  key_secret: string
  okta_url: string
  okta_api_token: string
}

export interface ResourceGroup {
  id: string
  name: string
  description?: string
}

export interface Project {
  id: string
  name: string
}

export interface OpaGroup {
  id: string
  name: string
  roles: string[]
}

export interface CreateGroupResponse {
  created_in_okta: boolean
  pushed: boolean
  visible_in_opa: boolean
  group?: OpaGroup
  message?: string
  // Only present once visible_in_opa is true -- the server tries to add
  // the dashboard's own service account to every group it creates, so
  // callers don't have to do it manually. See ServiceAccountGroupStatus.
  service_account_added?: boolean
  service_account_warning?: string | null
}

export interface ServiceAccountInfo {
  id: string
  name: string
  group_ids: string[]
}

export interface FolderNode {
  id: string // client-only, for React keys / stable identity during edits
  name: string
  description: string
  children: FolderNode[]
}

export interface CsvRow {
  path: string
  description: string
  /** Only present when rows came from "Load Current Structure" (real OPA
   * folders), never from an actual CSV file on disk -- CSV load/save
   * only ever reads/writes path+description. */
  folder_id?: string
}

export interface PreviewTreeItem {
  path: string
  depth: number
  exists: boolean
  folder_id: string
  /** A folder with the same name already exists at this other path in the
   * project (never adopted as this path -- OPA decides on the create). */
  name_in_use_at?: string | null
}

export interface InvalidName {
  path: string
  name: string
}

export interface PreviewResponse {
  tree: PreviewTreeItem[]
  collisions: Record<string, string[]>
  /** Groups of planned paths whose names differ only by letter case. */
  case_variants?: string[][]
  invalid_names: InvalidName[]
}

export type ExecuteStatus = 'created' | 'skipped_exists' | 'error'

export interface ExecuteResultRow {
  path: string
  folder_id: string
  status: ExecuteStatus
  error_message: string
}

export interface ExecuteResponse {
  results: ExecuteResultRow[]
  collisions: Record<string, string[]>
  /** null when the results file could not be written (the run itself completed). */
  output_file: string | null
}

export interface ApiErrorBody {
  error: string
  invalid_names?: InvalidName[]
  /** 502 "Saved, but could not connect": the record WAS written (FE-11). */
  saved?: boolean
  /** Machine-readable cause on some refusals (e.g. step-up "expired",
   * "already_consumed"; audit-log backfill "busy"; 5.42.0
   * "shared_permission_denied", "secrets_expired", "step_up_unavailable"). */
  reason?: string
  /** 5.42.0: the capability a shared_permission_denied refusal names. */
  capability?: string
  /** 5.42.0: the Environments change a step-up save applied (or refused). */
  action?: string
}

// ── Access Explorer ──────────────────────────────────────────────────────

export interface NamedRef {
  id: string
  name: string
  type?: string
}

export interface AccessResourceGroup {
  id: string
  name: string
  description?: string
  team_id?: string
  delegated_resource_admin_groups?: NamedRef[]
}

/** Every field the Project API returns (settings, counts, etc.) plus
 * resource_group_id, which build_access_model adds during the walk since
 * the Project object itself doesn't carry it. Kept as an open record
 * (rather than listing every field) so a "show everything" grid renders
 * new fields automatically if OPA's API grows more. */
export interface AccessProject extends Record<string, unknown> {
  id: string
  name: string
  resource_group_id: string
}

export interface AccessGroup {
  id: string
  name: string
  roles: string[]
  deleted_at?: string | null
}

export interface AccessUser {
  id: string
  name: string
  status?: string
  // "service" for an OPA-native Service User (e.g. this dashboard's own API
  // key) -- no Okta identity behind it, so no email/first/last name either.
  user_type?: 'human' | 'service'
  details?: { email?: string | null; first_name?: string | null; last_name?: string | null; full_name?: string | null }
  groups: NamedRef[]
}

export interface PolicyPrincipals {
  user_groups: NamedRef[]
  workload_roles: NamedRef[]
}

export type PolicyRuleResolution =
  | {
      kind: 'resolved'
      id: string
      name: string
      /** Raw selector_type (e.g. "secret" vs "secret_folder") -- resource_type
       * alone can't distinguish these, but System Log access-tracking only
       * works for one of them. See useUserResourceAccess. */
      resource_kind: string
      project_id: string | null
      project_name: string | null
      resource_group_id: string | null
      /** Only present for resource_kind "secret_folder" -- every secret
       * nested anywhere in this folder's subtree (any depth). A folder grant
       * covers all of these, but System Log access is only attributable per
       * secret, so the UI expands this list to query/report access. */
      child_secrets?: { id: string; name: string }[]
      /** Only present for SaaS/Okta account kinds -- their displayed `id`
       * is the Okta-side identifier (AppUser id / Okta user id), but System
       * Log access events reference the account's separate OPA-internal id
       * instead (that Okta-side id is never logged as a target at all).
       * Query/look up access info by this id when present, falling back
       * to `id` otherwise. */
      access_tracking_id?: string
      /** Only present on relationship-derived resolutions (resource_kind
       * starts with "relationship_assignment:") -- WHICH relationship/
       * assignment produced this grant, so PolicyRuleCard can show it
       * wherever this resolution renders (Projects/ResourceGroups/
       * Policies/Users/Groups tabs all reuse that one card). See
       * create_secret_folders.py's _resolve_relationship_assignment_resources. */
      relationship_name?: string
      assignment_name?: string
    }
  | { kind: 'condition'; description: string }

export interface PolicyRulePrivilege {
  privilege_type: string
  flags: string[]
}

export interface PolicyRuleCondition {
  condition_type: string
  condition_value: Record<string, unknown>
}

export interface PolicyRule {
  name: string
  resource_type: string
  resource_type_label: string
  privileges: PolicyRulePrivilege[]
  conditions: PolicyRuleCondition[]
  resolutions: PolicyRuleResolution[]
}

export interface AccessPolicy {
  id: string
  name: string
  description: string
  active: boolean
  type?: string
  resource_group: NamedRef | null
  principals: PolicyPrincipals
  rules: PolicyRule[]
  /** Raw policy -> relationship link (see AccessRelationship below) --
   * empty for the vast majority of policies, which don't use the
   * relationship/assignment mechanism at all. Lets the Relationships tab
   * answer "which policies use this relationship" directly. */
  relationship_ids: string[]
}

// ── Access Explorer: tenant-wide resource inventory (Resources sub-tab) ──
// All six live-verified 2026-09-30 against a real tenant. Servers
// cover Windows/Linux/Gateway in one shape -- os_type distinguishes
// Windows/Linux, and a gateway is just a server whose services[] includes
// "broker" (confirmed live -- NOT a separate resource type/API).

export interface AccessServer {
  id: string
  hostname: string
  os_type: string
  os: string
  services: string[]
  state: string
  managed: boolean
  access_address: string | null
  cloud_provider: string | null
  project_id: string
  project_name: string
  resource_group_id: string
  resource_group_name: string
}

export interface AccessSaasAccount {
  id: string
  privileged_resource_id?: string
  // Real field names confirmed live 2026-09-30 -- there is no
  // account_name field on the real API object (a prior version of this
  // type guessed wrong, causing every row to silently show a raw UUID
  // instead of a name). `name` is the human label (e.g. "Salesforce
  // account with atko"), `username` is the login identity.
  name?: string
  username?: string
  project_id: string
  project_name: string
  resource_group_id: string
  resource_group_name: string
  [key: string]: unknown
}

export interface AccessOktaAccount {
  id: string
  okta_user_id?: string
  // Same real-field-names fix as AccessSaasAccount above.
  name?: string
  username?: string
  project_id: string
  project_name: string
  resource_group_id: string
  resource_group_name: string
  [key: string]: unknown
}

export interface AccessActiveDirectoryAccount {
  id: string
  account_name: string
  sam_account_name?: string
  distinguished_name?: string
  sid?: string
  domain?: NamedRef
  email?: string
  account_status_detail?: string
  project_id: string
  project_name: string
  resource_group_id: string
  resource_group_name: string
}

export interface AccessDatabaseAccount {
  id: string
  account_name: string
  database_connection?: NamedRef
  database_connection_auth_type?: string
  account_status_detail?: string
  project_id: string
  project_name: string
  resource_group_id: string
  resource_group_name: string
}

export interface AccessWorkloadRole {
  id: string
  name: string
  description: string
  linux_server_username?: string
  created_at?: string
}

// The rest of the "connections" family -- all tenant-wide, all distinct
// from the per-project ACCOUNT resources they back (a connection is the
// integration config; an account is one discovered identity reachable
// through it). All confirmed live 2026-09-30.

export interface AccessWorkloadConnection {
  id: string
  name: string
  type: string
  description?: string
  status?: string
  created_at?: string
  updated_at?: string
}

export interface AccessGateway {
  id: string
  name: string
  access_address?: string
  default_address?: string
  cloud_provider?: string
  refuse_connections?: boolean
  last_seen?: string
}

export interface AccessDatabaseConnection {
  id: string
  name: string
  auth_type?: string
  status?: string
  discovered_accounts_count?: number
  health_issues?: unknown[]
  last_discovery_run_at?: string
}

export interface AccessSaasAppConnection {
  app_instance_id: string
  app_instance_name: string
  global_app_name?: string
  created_at?: string
  updated_at?: string
}

export interface AccessActiveDirectoryConnection {
  id: string
  domain: string
  okta_app_instance_id?: string
  status?: string
}

// A Client is an end user's local OPA client install (laptop/workstation
// running the desktop app or `sft`) -- confirmed live 2026-09-30 against
// the real opa-minimal.yaml spec AND a real tenant (10 real
// enrolled clients). Distinct from a Server/Gateway: this is what a
// HUMAN enrolls to be able to make SSH/RDP connections at all, not a
// managed resource being connected to.
export interface AccessClient {
  id: string
  user_name: string
  description?: string
  hostname: string
  os: string
  encrypted: boolean
  deleted_at?: string | null
  state: 'ACTIVE' | 'PENDING' | 'DELETED'
}

// Okta's own org-wide Device inventory (GET /api/v1/devices) -- confirmed
// live 2026-10-01, deliberately kept separate from AccessClient above (OPA
// client vs. Okta-managed device are genuinely different resources, see
// OktaClient.list_devices' docstring). Only populated when the active
// environment has Okta credentials configured (optional, see
// EnvironmentSetup) -- an empty array otherwise, not an error.
export interface AccessDevice {
  id: string
  status: string
  created?: string
  lastUpdated?: string
  profile: {
    displayName?: string
    platform?: string
    manufacturer?: string
    model?: string
    osVersion?: string
    serialNumber?: string
    registered?: boolean
    secureHardwarePresent?: boolean
    diskEncryptionType?: string
  }
  // GET /api/v1/devices/{id}/authenticator-enrollments -- confirmed live
  // 2026-10-01, only after the user enabled the underlying Okta feature;
  // empty (not missing) on orgs without it, see
  // OktaClient.get_device_authenticator_enrollments' docstring.
  authenticator_enrollments: { id: string; key: string; name: string; status: string }[]
  // GET /api/v1/devices/{id}/users ("List Users for Device") -- confirmed
  // live 2026-10-02 against a real tenant, a device can genuinely have
  // MULTIPLE associated users (shared/kiosk-style device), not just one;
  // see OktaClient.get_device_users' docstring. Flat list of display-ready
  // name strings (email preferred), already extracted server-side.
  users: string[]
}

// A relationship is a named grant type (e.g. "TDI_Safe_Owners"); an
// assignment links one or more relationships to a principal (a real
// user_group, confirmed live) plus the specific resource(s) it grants.
// NOT a separate access-grant mechanism from security policies -- a
// policy with a non-empty `relationships` field on AccessPolicy (see
// above) uses this as an ALTERNATE way to specify both its principal and
// its resource target; that resolution already happens server-side in
// build_access_model, so these two lists exist here mainly for the
// Resources tab's own direct visibility into them, not because the
// frontend needs to re-derive the policy resolution itself.
export interface AccessRelationship {
  id: string
  name: string
  description?: string
}

export interface AccessRelationshipAssignment {
  relationship: NamedRef
  principal: NamedRef
}

export interface AccessAssignment {
  id: string
  name: string
  description?: string
  // Real shape varies by which resource kind was granted (confirmed live:
  // saas_app_account_assignments on a real tenant, secret_or_folder_assignments
  // on dev) -- kept open since more kinds are expected to appear as this
  // OPA feature matures (see create_secret_folders.py's
  // _RELATIONSHIP_ASSIGNMENT_ID_NAME_FIELDS comment).
  resource_assignments: Record<string, unknown> | null
  relationship_assignments: AccessRelationshipAssignment[]
  /** Pre-resolved by build_access_model (same helper used to splice
   * relationship-derived grants into ordinary policy rules) -- real
   * resource names/kinds for this assignment's resource_assignments,
   * ready to render directly (e.g. via the same Tag treatment
   * PolicyRuleCard uses) without the frontend re-deriving anything. */
  resolved_resources: PolicyRuleResolution[]
}

export interface AccessModel {
  resource_groups: AccessResourceGroup[]
  projects: AccessProject[]
  groups: AccessGroup[]
  users: AccessUser[]
  policies: AccessPolicy[]
  servers: AccessServer[]
  saas_accounts: AccessSaasAccount[]
  okta_accounts: AccessOktaAccount[]
  active_directory_accounts: AccessActiveDirectoryAccount[]
  database_accounts: AccessDatabaseAccount[]
  workload_roles: AccessWorkloadRole[]
  workload_connections: AccessWorkloadConnection[]
  gateways: AccessGateway[]
  database_connections: AccessDatabaseConnection[]
  saas_app_connections: AccessSaasAppConnection[]
  active_directory_connections: AccessActiveDirectoryConnection[]
  assignments: AccessAssignment[]
  relationships: AccessRelationship[]
  clients: AccessClient[]
  devices: AccessDevice[]
  /** Sections the service key may not read (shown empty, not "none"). */
  warnings?: AccessModelWarning[]
}

export interface AccessModelWarning {
  section: string
  status: number | string
  message: string
}

// ── Access Explorer: AD account-discovery configuration ──────────────────
// On-demand only (fetched when an AD connection row is clicked in
// ResourcesTab) -- explains WHY an individual AD account got discovered/
// matched to an Okta user at all. See create_secret_folders.py's
// get_ad_connection_discovery_config.

export interface AdConnectionRule {
  id: string
  name: string
  rule_type: string
  organizational_units: string[]
  priority: number
  enable_initial_password_rotation: boolean
  enable_import_okta_users: boolean
  resource_group?: NamedRef
  project?: NamedRef
}

export interface AdConnectionRuleSettings {
  is_configured: boolean
  matching_criteria: Record<string, boolean>
  partial_matching_criteria: { operator: string; match_value: string }[]
  allow_partial_matches: boolean
}

export interface AdConnectionDiscoveryConfig {
  rules: AdConnectionRule[]
  rule_settings: AdConnectionRuleSettings
}

// ── Access Explorer: System Log last-accessed lookup ─────────────────────
// On-demand only (see UsersTab) -- querying this for every user/resource up
// front would be slow and could hit Okta rate limits for no benefit, since
// nobody looks at most of it.

export interface ResourceAccessEvent {
  published: string
  request_id: string | null
  outcome: string | null
}

export interface ResourceAccessInfo {
  resource_kind: string
  /** False for any resource_kind with no verified, ID-matchable System Log
   * event (see create_secret_folders.py's RESOURCE_ACCESS_EVENT_TYPES
   * comment) -- distinct from "supported but zero events found", which
   * means genuinely not accessed (or not within the last 90 days). */
  supported: boolean
  events: ResourceAccessEvent[]
  /** False when the System Log lookup hit its page cap -- "no access" may
   * then just mean "not within what was read". */
  complete?: boolean
}

// ── Folder Builder: policy assignment ────────────────────────────────────
// Deliberately separate from the Access Explorer types above (NamedRef,
// PolicyPrincipals, PolicyRuleCondition are shared/reused) since this
// context already knows which project it's in and never needs project
// attribution — see create_secret_folders.py's summarize_security_policy.

export type FolderPolicyTarget = { kind: 'resolved'; id: string; name: string } | { kind: 'condition'; description: string }

export interface FolderPolicyRulePrivilege {
  privilege_type: string
  flags: string[]
}

export interface FolderPolicyRule {
  name: string
  resource_type: string
  resource_type_label: string
  privileges: FolderPolicyRulePrivilege[]
  conditions: PolicyRuleCondition[]
  targets: FolderPolicyTarget[]
}

export interface FolderSecurityPolicy {
  id: string
  name: string
  description: string
  active: boolean
  type?: string
  resource_group: NamedRef | null
  principals: PolicyPrincipals
  rules: FolderPolicyRule[]
}

export interface WorkloadRole {
  id: string
  name: string
}

export interface FolderAccessEntry {
  policyId: string
  policyName: string
  policyActive: boolean
  ruleName: string
  groups: NamedRef[]
  workloadRoles: NamedRef[]
  privileges: FolderPolicyRulePrivilege[]
  // UI-01 (external review, 2026-10-05): lets AssignAccessDialog prefill
  // from the rule it's about to replace instead of always starting
  // blank -- see that file's own comment for why a blank-start form was
  // a security regression (silently dropping an existing MFA condition).
  conditions: PolicyRuleCondition[]
  // How many resources (folders) the matched rule's own selector names,
  // not just this one -- > 1 means a "replace" from this single-folder
  // form would be destructive to the OTHERS; see
  // create_secret_folders.MultiTargetRuleError.
  targetCount: number
}

// ── Secrets Access Dashboard ──────────────────────────────────────────────
// Merges the live folder/secret walk ("what exists now") with a System Log
// query ("what happened, including to things since deleted") -- see
// create_secret_folders.py's build_secrets_access_report.

export interface AuditEntry {
  by: string | null
  at: string | null
  /** Okta's own transaction/request id for the event behind this entry --
   * lets an admin jump to the exact matching entry in Okta's own System
   * Log for follow-up investigation. Present on created/updated/deleted
   * entries too, not just reveals, as of Phase 8's report-enhancement pass. */
  request_id: string | null
  /** The event's own outcome.result / outcome.reason (5.40.0). Only the
   * Service Accounts report sets these -- a service-account create or
   * rotation genuinely ends DEFERRED / FAILURE on real tenants, so an
   * entry needs to say so. Absent on Secrets entries (undefined). */
  outcome?: string | null
  outcome_reason?: string | null
}

export interface RevealEntry extends AuditEntry {}

export type SecretsAccessStatus = 'active' | 'deleted' | 'unknown'

interface SecretsAccessRowBase {
  id: string
  name: string
  path: string
  /** "active" = present in the live walk right now. "deleted" = absent
   * live but a real delete event was found in the log. "unknown" = absent
   * live with no delete event either (e.g. older than the 90-day log
   * window) -- never inferred, only ever set from direct log evidence. */
  status: SecretsAccessStatus
  created: AuditEntry | null
  /** Most-recent-first. */
  updated: AuditEntry[]
  deleted: AuditEntry | null
}

export interface SecretAccessRow extends SecretsAccessRowBase {
  /** Most-recent-first, capped server-side (see reveal_limit). */
  reveals: RevealEntry[]
}

export type FolderAccessRow = SecretsAccessRowBase

// ── Service Accounts Dashboard (5.40.0) ──────────────────────────────────
// Every SaaS app account and Okta Universal Directory account across the
// tenant, merged with the compliance archive -- see
// create_secret_folders.py's build_service_accounts_report_from_archive
// for the status rules and the live-confirmed event facts behind it.

export type ServiceAccountKind = 'saas' | 'okta'

export interface ServiceAccountCheckoutEntry extends AuditEntry {
  /** debugData.checkoutExpiry on the checkout event, when present. */
  expires_at: string | null
}

export interface ServiceAccountRotationEntry extends AuditEntry {
  /** true = OPA's scheduled rotation, false = a person triggered it, null
   * = the event didn't say. From debugData's "system Initiated" marker. */
  system_initiated: boolean | null
}

export interface ServiceAccountRotations {
  /** Every password_rotation.end row for this account in the archive
   * (counted server-side; never bulk-loaded). */
  total: number
  by_outcome: Record<string, number>
  first_at: string | null
  last_at: string | null
  /** Newest first, capped at the route's rotation_limit (default 25). */
  recent: ServiceAccountRotationEntry[]
}

export interface ServiceAccountReportRow {
  /** The account's own OPA-internal id -- the same id every archived
   * event references it by (access_tracking_id in the Access Explorer). */
  id: string
  kind: ServiceAccountKind
  name: string
  username: string | null
  /** SaaS only: the Okta app instance the account belongs to. */
  app_name: string | null
  /** Okta only: the Okta user ("00u...") the account wraps. */
  okta_user_id: string | null
  /** SaaS only: the "opr..." id security-policy selectors use. */
  privileged_resource_id: string | null
  // All four are null for an account no longer in the live roster -- its
  // project is not knowable from the archive and is never guessed.
  resource_group_id: string | null
  resource_group_name: string | null
  project_id: string | null
  project_name: string | null
  /** Same rules as SecretsAccessStatus: active = in the live roster;
   * deleted = absent live with a SUCCESS delete event; unknown otherwise. */
  status: SecretsAccessStatus
  /** INFORMATIONAL, live-only: OPA's own sync state for the account. A
   * freshly registered SaaS account can legitimately sit NOT_SYNCED (see
   * docs/api-notes.md) -- shown as context, never as a finding. */
  sync_status: string | null
  last_password_change_at: string | null
  /** Most recent SUCCESS create, else the most recent attempt (with its
   * outcome). */
  created: AuditEntry | null
  updated: AuditEntry[]
  assigned: AuditEntry[]
  /** Only ever a SUCCESS delete. */
  deleted: AuditEntry | null
  reveals: RevealEntry[]
  checkouts: ServiceAccountCheckoutEntry[]
  rotations: ServiceAccountRotations
}

export interface ServiceAccountsReport {
  accounts: ServiceAccountReportRow[]
  summary: { total: number; saas: number; okta: number; active: number; deleted: number; unknown: number }
  /** What the live roster walk cost -- surfaced so a large tenant can see
   * what a Refresh does. */
  walked: { resource_groups: number; projects: number }
  /** Account ids seen in the archive but deliberately left out: Database /
   * Active Directory accounts (same event types, different report) and ids
   * with no recognisable family marker (never guessed into a type). */
  excluded: { other_account_types: number; unclassified: number }
  /** Real evidence disagreeing with itself (e.g. a roster SaaS id whose
   * events say DATABASE_ACCOUNT) -- counted, never silently resolved. */
  warnings: { conflicting_family_markers: number }
  /** Lifecycle/reveal/checkout rows in the archive vs. the server-side
   * bulk-load cap -- see ComplianceReportResponse's total/truncated. */
  event_total: number
  truncated: boolean
  since_days: null
  local_retention_enabled: boolean
  oldest_captured_at: string | null
}

export interface SecretsAccessReport {
  secrets: SecretAccessRow[]
  folders: FolderAccessRow[]
  /** The System Log lookback window actually used -- surfaced so the UI
   * can be honest about "no record" possibly meaning "older than this,"
   * not "never happened." */
  since_days: number
  /** True if this report was sourced from the compliance-sync archive
   * (audit_store.py, unlimited history) rather than a live, 90-day-bounded
   * Okta System Log query -- surfaced so the UI can give an accurate
   * completeness caveat either way. */
  local_retention_enabled: boolean
  /** Earliest event timestamp actually available in whichever source
   * produced this report -- null if no history exists at all. */
  oldest_captured_at: string | null
  /** False when the live System Log walk hit its page cap (the oldest
   * events, e.g. creates, are missing). Absent on older servers. */
  complete?: boolean
}
