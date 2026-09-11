import type {
  AccessModel,
  ApiErrorBody,
  CreateGroupResponse,
  CsvRow,
  EnvironmentFormValues,
  EnvironmentsResponse,
  ExecuteResponse,
  FolderSecurityPolicy,
  NamedRef,
  OpaGroup,
  PreviewResponse,
  Project,
  ResourceAccessInfo,
  ResourceGroup,
  SecretsAccessReport,
  ServiceAccountInfo,
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

export function fetchWhoami(): Promise<{ email: string | null; is_local: boolean }> {
  return apiFetch('/api/whoami')
}

export function saveEnvironment(values: EnvironmentFormValues): Promise<{ activated: boolean; active: string }> {
  return apiFetch('/api/environments', { method: 'POST', body: JSON.stringify(values) })
}

export function activateEnvironment(name: string): Promise<{ activated: boolean; active: string }> {
  return apiFetch(`/api/environments/${encodeURIComponent(name)}/activate`, { method: 'POST' })
}

export function deleteEnvironment(name: string): Promise<{ deleted: string }> {
  return apiFetch(`/api/environments/${encodeURIComponent(name)}`, { method: 'DELETE' })
}

export function setPreserveLogsLocally(name: string, enabled: boolean): Promise<{ name: string; preserve_logs_locally: boolean }> {
  return apiFetch(`/api/environments/${encodeURIComponent(name)}/preserve_logs_locally`, {
    method: 'POST',
    body: JSON.stringify({ enabled }),
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
