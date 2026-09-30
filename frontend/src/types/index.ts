export type IngestionScope = 'curated' | 'all'

export interface SyncSchedule {
  enabled: boolean
  run_time: string // "HH:MM", UTC
  ingestion_scope: IngestionScope
  retention_days: number | null
  retention_max_size_mb: number | null
}

export interface Environment {
  name: string
  base_domain: string
  team_name: string
  key_id: string
  okta_url: string
  has_okta_token: boolean
  preserve_logs_locally: boolean
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
}

export interface EnvironmentsResponse {
  environments: Environment[]
  active: string | null
}

export interface SyncStepEvent {
  key: string
  status: 'start' | 'progress' | 'done'
  detail: string | null
}

export interface SyncState {
  environment: string
  last_synced_at: string | null
  last_sync_completed_at: string | null
  last_sync_status: string | null
  last_sync_error: string | null
  total_events_ingested: number
  ingestion_scope: IngestionScope
}

export interface SyncStatusResponse {
  status: 'idle' | 'running' | 'done' | 'error'
  steps: SyncStepEvent[]
  error: string | null
  result?: { inserted: number; scanned: number; since: string; chunks: number; pruned: number; cutoff: string | null }
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
  targets: ComplianceReportTarget[]
}

export interface ComplianceReportResponse {
  report: string
  environment: string
  rows: ComplianceReportRow[]
}

/** GET /api/resources/{id}/history -- same ComplianceReportRow shape as
 * every report, just scoped to one resource's own id instead of one
 * report_key's event types. See audit_store.resource_history. */
export interface ResourceHistoryResponse {
  resource_id: string
  environment: string
  rows: ComplianceReportRow[]
}

export type BannerVariant = 'info' | 'warning' | 'danger'

export interface BannerConfig {
  enabled: boolean
  message: string
  variant: BannerVariant
  dismissible: boolean
}

export interface EnvironmentFormValues {
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
}

export interface InvalidName {
  path: string
  name: string
}

export interface PreviewResponse {
  tree: PreviewTreeItem[]
  collisions: Record<string, string[]>
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
  output_file: string
}

export interface ApiErrorBody {
  error: string
  invalid_names?: InvalidName[]
  saved?: boolean
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
}

// ── Access Explorer: tenant-wide resource inventory (Resources sub-tab) ──
// All six live-verified 2026-09-30 against a real tenant (patlabs). Servers
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
  // saas_app_account_assignments on patlabs, secret_or_folder_assignments
  // on dev) -- kept open since more kinds are expected to appear as this
  // OPA feature matures (see create_secret_folders.py's
  // _RELATIONSHIP_ASSIGNMENT_ID_NAME_FIELDS comment).
  resource_assignments: Record<string, unknown> | null
  relationship_assignments: AccessRelationshipAssignment[]
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
}

// ── Secrets Access Dashboard ──────────────────────────────────────────────
// Merges the live folder/secret walk ("what exists now") with a System Log
// query ("what happened, including to things since deleted") -- see
// create_secret_folders.py's build_secrets_access_report.

export interface AuditEntry {
  by: string | null
  at: string | null
}

export interface RevealEntry extends AuditEntry {
  request_id: string | null
}

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

export interface SecretsAccessReport {
  secrets: SecretAccessRow[]
  folders: FolderAccessRow[]
  /** The System Log lookback window actually used -- surfaced so the UI
   * can be honest about "no record" possibly meaning "older than this,"
   * not "never happened." */
  since_days: number
  /** True if the active environment has "preserve logs locally" on --
   * history below is supplemented from secrets_log_cache.json, not just
   * Okta's live 90-day window. */
  local_retention_enabled: boolean
  /** Earliest event timestamp actually available (merged cache + live
   * query if local_retention_enabled, else just the live query) -- null
   * if no history exists at all. Never further back than whenever local
   * retention was first turned on for this project. */
  oldest_captured_at: string | null
}
