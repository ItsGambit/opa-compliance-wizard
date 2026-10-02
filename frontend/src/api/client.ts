import type {
  AccessControlConfig,
  AccessControlSaveResponse,
  AccessModel,
  AdConnectionDiscoveryConfig,
  ApiErrorBody,
  AuditLogEntry,
  BannerConfig,
  ComplianceReportDef,
  ComplianceReportResponse,
  CreateGroupResponse,
  CsvRow,
  EnvironmentFormValues,
  EnvironmentsResponse,
  ExecuteResponse,
  FolderSecurityPolicy,
  IngestionScope,
  NamedRef,
  OpaGroup,
  PreviewResponse,
  Project,
  ResourceAccessInfo,
  ResourceGroup,
  ResourceHistoryResponse,
  SecretsAccessReport,
  ServiceAccountInfo,
  SyncSchedule,
  SyncStatusResponse,
  WorkloadRole,
} from '../types'

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...init?.headers },
  })
  if (!res.ok) {
    let body: ApiErrorBody | null = null
    try {
      body = await res.json()
    } catch {
      // ignore — fall through to generic message
    }
    const err = new Error(body?.error || `Request failed with status ${res.status}`) as Error & { body?: ApiErrorBody }
    err.body = body ?? undefined
    throw err
  }
  return res.json() as Promise<T>
}

export function fetchEnvironments(): Promise<EnvironmentsResponse> {
  return apiFetch('/api/environments')
}

export function fetchWhoami(): Promise<{ email: string | null; is_local: boolean; is_admin: boolean }> {
  return apiFetch('/api/whoami')
}

export function fetchVersion(): Promise<{ version: string }> {
  return apiFetch('/api/version')
}

export function fetchBanner(): Promise<BannerConfig> {
  return apiFetch('/api/banner')
}

export function saveBanner(config: BannerConfig): Promise<BannerConfig> {
  return apiFetch('/api/banner', { method: 'POST', body: JSON.stringify(config) })
}

export function fetchAccessControl(): Promise<AccessControlConfig> {
  return apiFetch('/api/access_control')
}

// Validates the proposed config and stores it server-side, keyed by an
// opaque action_id -- the browser carries ONLY that id through the Okta
// step-up redirect (see AccessControlDialog.tsx's handleSaveClick), never
// the actual settings. Closes the gap where a step-up cookie could
// previously be replayed to apply any payload, not just the one reviewed.
export function prepareAccessControl(config: AccessControlConfig): Promise<{ action_id: string }> {
  return apiFetch('/api/access_control/prepare', { method: 'POST', body: JSON.stringify(config) })
}

// Reachable only right after a completed step-up (fresh MFA) redirect --
// see AccessControlDialog.tsx's save flow and nginx's dedicated
// auth_request /verify_stepup gate on this exact path. Takes no body --
// the server retrieves the exact prepared payload via the action_id bound
// into the step-up cookie itself (X-Auth-Action-Id), never trusting
// anything the client sends here. Response includes step_up_verified/
// saved_at (Phase 10) so App.tsx can confirm the save was approved via a
// validated step-up transaction, not just show a generic "saved" toast.
export function saveAccessControl(): Promise<AccessControlSaveResponse> {
  return apiFetch('/api/access_control/save', { method: 'POST' })
}

export function saveEnvironment(values: EnvironmentFormValues): Promise<{ activated: boolean; active: string }> {
  return apiFetch('/api/environments', { method: 'POST', body: JSON.stringify(values) })
}

export function activateEnvironment(name: string): Promise<{ activated: boolean; active: string }> {
  return apiFetch(`/api/environments/${encodeURIComponent(name)}/activate`, { method: 'POST' })
}

// `id` (the real owner-namespaced storage key, see Environment.id) is only
// ever passed for an admin deleting an environment they don't own -- their
// own environments are already unambiguous by name. Omit it (or pass
// undefined) when deleting your own -- the backend falls back to a
// by-name lookup scoped to the caller in that case.
export function deleteEnvironment(name: string, id?: string): Promise<{ deleted: string }> {
  const qs = id ? `?id=${encodeURIComponent(id)}` : ''
  return apiFetch(`/api/environments/${encodeURIComponent(name)}${qs}`, { method: 'DELETE' })
}

// Same `id` reasoning as deleteEnvironment above -- only needed for an
// admin overriding another owner's environment.
export function setEnvironmentShared(name: string, shared: boolean, id?: string): Promise<{ name: string; shared: boolean }> {
  return apiFetch(`/api/environments/${encodeURIComponent(name)}/share`, {
    method: 'POST',
    body: JSON.stringify({ shared, id }),
  })
}

export function saveSyncSchedule(name: string, schedule: SyncSchedule): Promise<{ name: string; sync_schedule: SyncSchedule }> {
  return apiFetch(`/api/environments/${encodeURIComponent(name)}/sync_schedule`, {
    method: 'POST',
    body: JSON.stringify(schedule),
  })
}

export function startSync(name: string, ingestionScope?: IngestionScope): Promise<{ started: boolean; already_running: boolean }> {
  return apiFetch(`/api/environments/${encodeURIComponent(name)}/sync/start`, {
    method: 'POST',
    body: JSON.stringify(ingestionScope ? { ingestion_scope: ingestionScope } : {}),
  })
}

export function fetchSyncStatus(name: string): Promise<SyncStatusResponse> {
  return apiFetch(`/api/environments/${encodeURIComponent(name)}/sync/status`)
}

export function importSyncCsv(
  name: string,
  csvPath: string,
  ingestionScope: IngestionScope
): Promise<{ inserted: number; scanned: number }> {
  return apiFetch(`/api/environments/${encodeURIComponent(name)}/sync/import_csv`, {
    method: 'POST',
    body: JSON.stringify({ csv_path: csvPath, ingestion_scope: ingestionScope }),
  })
}

export function fetchResourceGroups(): Promise<{ resource_groups: ResourceGroup[] }> {
  return apiFetch('/api/resource_groups')
}

export function fetchProjects(resourceGroupId: string): Promise<{ projects: Project[] }> {
  return apiFetch(`/api/resource_groups/${encodeURIComponent(resourceGroupId)}/projects`)
}

export function createResourceGroup(name: string, description: string, groupIds: string[]): Promise<{ resource_group: ResourceGroup }> {
  return apiFetch('/api/resource_groups', {
    method: 'POST',
    body: JSON.stringify({ name, description, group_ids: groupIds }),
  })
}

export function createProject(resourceGroupId: string, name: string): Promise<{ project: Project }> {
  return apiFetch(`/api/resource_groups/${encodeURIComponent(resourceGroupId)}/projects`, {
    method: 'POST',
    body: JSON.stringify({ name }),
  })
}

export function fetchExistingFolders(resourceGroupId: string, projectId: string): Promise<{ rows: CsvRow[] }> {
  return apiFetch(
    `/api/resource_groups/${encodeURIComponent(resourceGroupId)}/projects/${encodeURIComponent(projectId)}/folders`
  )
}

export function deleteFolder(
  resourceGroupId: string,
  projectId: string,
  folderId: string
): Promise<{ deleted: string }> {
  return apiFetch(
    `/api/resource_groups/${encodeURIComponent(resourceGroupId)}/projects/${encodeURIComponent(projectId)}/folders/${encodeURIComponent(folderId)}`,
    { method: 'DELETE' }
  )
}

export function fetchGroups(contains?: string): Promise<{ groups: OpaGroup[] }> {
  const qs = contains ? `?contains=${encodeURIComponent(contains)}` : ''
  return apiFetch(`/api/groups${qs}`)
}

export function createGroup(name: string, description: string): Promise<CreateGroupResponse> {
  return apiFetch('/api/groups', { method: 'POST', body: JSON.stringify({ name, description }) })
}

export function fetchServiceAccount(): Promise<ServiceAccountInfo> {
  return apiFetch('/api/service_account')
}

export function addServiceAccountToGroup(groupId: string): Promise<{ added: boolean; group_id: string }> {
  return apiFetch('/api/service_account/groups', { method: 'POST', body: JSON.stringify({ group_id: groupId }) })
}

export function removeUserFromGroup(groupId: string, userName: string): Promise<{ removed: boolean; group_id: string; user_name: string }> {
  return apiFetch(`/api/groups/${encodeURIComponent(groupId)}/members/${encodeURIComponent(userName)}`, { method: 'DELETE' })
}

export function fetchCsvFiles(): Promise<{ files: string[] }> {
  return apiFetch('/api/csv_files')
}

export function fetchCsv(file: string): Promise<{ rows: CsvRow[] }> {
  return apiFetch(`/api/csv?file=${encodeURIComponent(file)}`)
}

export function saveCsv(file: string, rows: CsvRow[]): Promise<{ saved: boolean; file: string; row_count: number }> {
  return apiFetch('/api/csv', { method: 'POST', body: JSON.stringify({ file, rows }) })
}

export function preview(resourceGroupId: string, projectId: string, rows: CsvRow[]): Promise<PreviewResponse> {
  return apiFetch('/api/preview', {
    method: 'POST',
    body: JSON.stringify({ resource_group_id: resourceGroupId, project_id: projectId, rows }),
  })
}

export function execute(resourceGroupId: string, projectId: string, rows: CsvRow[]): Promise<ExecuteResponse> {
  return apiFetch('/api/execute', {
    method: 'POST',
    body: JSON.stringify({ resource_group_id: resourceGroupId, project_id: projectId, rows }),
  })
}

/** The Access Explorer bootstrap runs as a background job (it's not
 * cheap — see build_access_model's docstring) rather than one blocking
 * request, so the UI can show real step-by-step progress instead of a
 * bare spinner. See useAccessBootstrapJob for the polling loop. */
export interface BootstrapStepEvent {
  key: string
  status: 'start' | 'progress' | 'done'
  detail: string | null
}
export interface BootstrapStartResponse {
  started: boolean
  already_running?: boolean
  steps?: [string, string][]
}
export interface BootstrapStatusResponse {
  status: 'idle' | 'running' | 'done' | 'error'
  steps: BootstrapStepEvent[]
  error: string | null
}

export function startAccessBootstrap(): Promise<BootstrapStartResponse> {
  return apiFetch('/api/access/bootstrap/start', { method: 'POST' })
}

export function fetchAccessBootstrapStatus(): Promise<BootstrapStatusResponse> {
  return apiFetch('/api/access/bootstrap/status')
}

export function fetchAccessBootstrapResult(): Promise<AccessModel> {
  return apiFetch('/api/access/bootstrap/result')
}

// ── Folder Builder: policy assignment ────────────────────────────────────

export function fetchResourceGroupSecurityPolicies(resourceGroupId: string): Promise<{ policies: FolderSecurityPolicy[] }> {
  return apiFetch(`/api/resource_groups/${encodeURIComponent(resourceGroupId)}/security_policies`)
}

export function fetchWorkloadRoles(contains?: string): Promise<{ workload_roles: WorkloadRole[] }> {
  const qs = contains ? `?contains=${encodeURIComponent(contains)}` : ''
  return apiFetch(`/api/workload_roles${qs}`)
}

export interface AssignFolderPolicyPayload {
  mode: 'new' | 'existing'
  policy_id?: string
  name?: string
  description?: string
  folder_name: string
  rule_name?: string
  group_refs: NamedRef[]
  workload_role_refs: NamedRef[]
  privileges: Record<string, boolean>
  mfa: { reauth_seconds: number; acr_values: string } | null
}

export function assignFolderPolicy(
  resourceGroupId: string,
  projectId: string,
  folderId: string,
  payload: AssignFolderPolicyPayload
): Promise<{ policy: FolderSecurityPolicy }> {
  return apiFetch(
    `/api/resource_groups/${encodeURIComponent(resourceGroupId)}/projects/${encodeURIComponent(projectId)}/folders/${encodeURIComponent(folderId)}/policy`,
    { method: 'POST', body: JSON.stringify(payload) }
  )
}

export function fetchUserResourceAccess(
  userId: string,
  resources: { resource_kind: string; resource_id: string }[]
): Promise<{ results: Record<string, ResourceAccessInfo> }> {
  return apiFetch(`/api/access/users/${encodeURIComponent(userId)}/resource_access`, {
    method: 'POST',
    body: JSON.stringify({ resources }),
  })
}

// ── Secrets Access Dashboard ──────────────────────────────────────────────

export function fetchSecretsAccessReport(resourceGroupId: string, projectId: string): Promise<SecretsAccessReport> {
  return apiFetch(
    `/api/resource_groups/${encodeURIComponent(resourceGroupId)}/projects/${encodeURIComponent(projectId)}/secrets_access_report`
  )
}

// ── Compliance Reports ────────────────────────────────────────────────────

export function fetchReportDefs(environment?: string, from?: string, to?: string): Promise<{ reports: ComplianceReportDef[] }> {
  const params = new URLSearchParams()
  if (environment) params.set('environment', environment)
  if (from) params.set('from', from)
  if (to) params.set('to', to)
  const qs = params.toString()
  return apiFetch(`/api/reports${qs ? `?${qs}` : ''}`)
}

export function runReport(
  reportKey: string,
  environment?: string,
  from?: string,
  to?: string
): Promise<ComplianceReportResponse> {
  const params = new URLSearchParams()
  if (environment) params.set('environment', environment)
  if (from) params.set('from', from)
  if (to) params.set('to', to)
  const qs = params.toString()
  return apiFetch(`/api/reports/${encodeURIComponent(reportKey)}${qs ? `?${qs}` : ''}`)
}

/** The Resources tab's per-resource drill-down -- every compliance report
 * row about one specific resource (server/AD account/DB account/gateway/
 * etc.), scoped by that resource's own real id AND/OR its exact display
 * name. See audit_store.resource_history and server/serve.py's
 * /api/resources/* route.
 *
 * resourceName is a real, needed fallback (not a nice-to-have) -- confirmed
 * live 2026-09-30 that database accounts and individual Active Directory
 * accounts have NO discoverable log-side id at all (the System Log
 * references a different, unresolvable "Service Account" id for those two
 * kinds), so matching by resourceId alone finds nothing for them. Passing
 * both is safe for every other kind too -- the backend OR-matches whichever
 * is given, so this never narrows results for a kind that already works by
 * id alone. */
export function fetchResourceHistory(
  resourceId: string,
  environment?: string,
  from?: string,
  to?: string,
  resourceName?: string
): Promise<ResourceHistoryResponse> {
  const params = new URLSearchParams()
  if (environment) params.set('environment', environment)
  if (from) params.set('from', from)
  if (to) params.set('to', to)
  if (resourceName) params.set('resource_name', resourceName)
  const qs = params.toString()
  return apiFetch(`/api/resources/${encodeURIComponent(resourceId)}/history${qs ? `?${qs}` : ''}`)
}

/** On-demand only (fetched when an AD connection row is clicked in
 * ResourcesTab) -- see AdConnectionDiscoveryConfig's own comment for why
 * this isn't part of the bootstrap. */
export function fetchAdConnectionDiscoveryConfig(connectionId: string): Promise<AdConnectionDiscoveryConfig> {
  return apiFetch(`/api/active_directory_connections/${encodeURIComponent(connectionId)}/discovery_config`)
}

// ── Audit log (admin-only, see server/serve.py's /api/audit_log) ─────────

export function fetchAuditLog(limit?: number, offset?: number): Promise<{ entries: AuditLogEntry[] }> {
  const params = new URLSearchParams()
  if (limit != null) params.set('limit', String(limit))
  if (offset != null) params.set('offset', String(offset))
  const qs = params.toString()
  return apiFetch(`/api/audit_log${qs ? `?${qs}` : ''}`)
}

// Re-queries Okta's System Log for any access_control.update entries still
// missing MFA corroboration (indexing lag at save time -- see
// engine.backfill_mfa_log_events) and rewrites them in place. Called from
// AuditLogPage's Refresh button, right before re-fetching the log itself,
// so a delayed corroboration shows up without a separate action.
export function backfillMfaLogEvents(): Promise<{ updated_count: number }> {
  return apiFetch('/api/audit_log/backfill_mfa', { method: 'POST' })
}
