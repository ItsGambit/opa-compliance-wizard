export interface Environment {
  name: string
  base_domain: string
  team_name: string
  key_id: string
  okta_url: string
  has_okta_token: boolean
}

export interface EnvironmentsResponse {
  environments: Environment[]
  active: string | null
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
      project_id: string | null
      project_name: string | null
      resource_group_id: string | null
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

export interface AccessModel {
  resource_groups: AccessResourceGroup[]
  projects: AccessProject[]
  groups: AccessGroup[]
  users: AccessUser[]
  policies: AccessPolicy[]
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
