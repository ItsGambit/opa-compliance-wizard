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
  GrantUser,
  ExecuteResponse,
  FolderSecurityPolicy,
  IngestionScope,
  IntegrityResult,
  NamedRef,
  OrphanedArchive,
  OpaGroup,
  PreviewResponse,
  Project,
  ResourceAccessInfo,
  ResourceGroup,
  ResourceHistoryResponse,
  SecretsAccessReport,
  ServiceAccountInfo,
  SharedPermissionsResponse,
  PermissionSetting,
  SharedCapabilityKey,
  StepUpRequired,
  ServiceAccountsReport,
  SyncSchedule,
  SyncStatusResponse,
  WorkloadRole,
} from '../types'

/** Thrown for any non-2xx answer from the API. `status` lets callers (and
 * the QueryClient's retry policy, see queryClient.ts) tell a request that
 * can never succeed (4xx) from one worth retrying (5xx). */
export class ApiError extends Error {
  status: number
  body?: ApiErrorBody
  constructor(message: string, status: number, body?: ApiErrorBody) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.body = body
  }
}

/** FE-05 (external review, 2026-10-05): the hosted login gate answers an
 * expired session with 401 -> nginx's error_page -> a redirect to Okta.
 * fetch() used to follow that cross-origin redirect and die as an opaque
 * "Failed to fetch". Requests now use redirect: 'manual', which hands back
 * a filtered response of type "opaqueredirect" (status 0, MDN
 * Response.type) instead -- and serve.py never redirects an /api call
 * itself, so that response (or a plain 401) can only mean the gate wants a
 * fresh login. */
export class SessionExpiredError extends Error {
  constructor(message = 'Your session has expired. Sign in again to continue.') {
    super(message)
    this.name = 'SessionExpiredError'
  }
}

type SessionExpiredListener = () => void
const sessionExpiredListeners = new Set<SessionExpiredListener>()

/** Subscribes to "the login gate refused a request" -- SessionExpiredDialog
 * listens and offers a fresh sign-in once, however many requests failed. */
export function onSessionExpired(listener: SessionExpiredListener): () => void {
  sessionExpiredListeners.add(listener)
  return () => { sessionExpiredListeners.delete(listener) }
}

export function isSessionExpiredError(err: unknown): err is SessionExpiredError {
  return err instanceof SessionExpiredError
}

type SessionRestoredListener = () => void
const sessionRestoredListeners = new Set<SessionRestoredListener>()

/** Fired when the user says they have signed in again (SessionExpiredDialog's
 * Continue) -- lets progress hooks re-attach to a job whose polling the
 * expiry stopped. */
export function onSessionRestored(listener: SessionRestoredListener): () => void {
  sessionRestoredListeners.add(listener)
  return () => { sessionRestoredListeners.delete(listener) }
}

export function notifySessionRestored(): void {
  sessionRestoredListeners.forEach(l => l())
}

interface ApiFetchOptions {
  /** false: report a gate redirect to the caller only (no global "session
   * expired" prompt) -- for the step-up save, where the redirect means the
   * two-minute step-up proof lapsed, not the session. */
  notifySessionExpired?: boolean
}

async function apiFetch<T>(path: string, init?: RequestInit, { notifySessionExpired = true }: ApiFetchOptions = {}): Promise<T> {
  // Content-Type only when there is a body to describe (FE-15).
  const headers: Record<string, string> = init?.body != null ? { 'Content-Type': 'application/json' } : {}
  const res = await fetch(path, {
    ...init,
    redirect: 'manual',
    headers: { ...headers, ...(init?.headers as Record<string, string> | undefined) },
  })
  let body: ApiErrorBody | null = null
  if (!res.ok && res.type !== 'opaqueredirect') {
    try {
      body = await res.json()
    } catch {
      // ignore — fall through to generic message
    }
  }
  // The gate's answer is a redirect (nginx turns its 401 into /login). A
  // bare 401 with no JSON error is treated the same; serve.py's own 401
  // (a proxy-secret misconfiguration) carries a JSON error and is shown as
  // that error -- signing in again can't fix it.
  if (res.type === 'opaqueredirect' || (res.status === 401 && !body?.error)) {
    const err = new SessionExpiredError()
    if (notifySessionExpired) sessionExpiredListeners.forEach(l => l())
    throw err
  }
  if (!res.ok) {
    throw new ApiError(body?.error || `Request failed with status ${res.status}`, res.status, body ?? undefined)
  }
  return res.json() as Promise<T>
}

export function fetchEnvironments(): Promise<EnvironmentsResponse> {
  return apiFetch('/api/environments')
}

// can_admin (UI-06): whether the admin-only routes will serve THIS caller --
// true for a verified admin, and for the operator of a local-mode run (no
// login gate there; the server exempts it). is_admin stays the verified-admin
// flag (Access Control needs the hosted step-up flow, so it keys off that).
export function fetchWhoami(): Promise<{ email: string | null; is_local: boolean; is_admin: boolean; can_admin?: boolean }> {
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
  // A redirect here means the step-up proof lapsed (nginx's /verify_stepup
  // gate), not the session: App.tsx says so; no global sign-in prompt.
  return apiFetch('/api/access_control/save', { method: 'POST' }, { notifySessionExpired: false })
}

// ── Step-up MFA for Environments changes (5.42.0) ────────────────────────
// Behind the hosted login gate every change made from the Environments area
// answers 202 StepUpRequired first: the server has checked and stored the
// change, nothing is applied yet. utils/stepUp.ts takes the browser through
// the gate's /step-up (the same round trip as the Access Control save) and
// App.tsx applies it on the way back with saveEnvironmentChange(). In local
// mode (no gate, no identity provider) the same calls apply at once.

export function isStepUpRequired(value: unknown): value is StepUpRequired {
  return typeof value === 'object' && value !== null && (value as { step_up_required?: unknown }).step_up_required === true
}

/** Applies the change the current step-up approval was for. No body: the
 * server runs the request it stored before the redirect (X-Auth-Action-Id,
 * from the step-up cookie), never anything sent here. */
export function saveEnvironmentChange(): Promise<Record<string, unknown> & { action: string; step_up_verified: boolean }> {
  // A redirect here means the step-up proof lapsed, not the session (same as saveAccessControl).
  return apiFetch('/api/environment_changes/save', { method: 'POST' }, { notifySessionExpired: false })
}

// activated=false (5.40.3): an admin edited ANOTHER owner's environment --
// it was saved, but it isn't the admin's to activate, so `active` is the
// admin's unchanged active environment (possibly null).
export function saveEnvironment(values: EnvironmentFormValues): Promise<{ activated: boolean; active: string | null; saved?: boolean } | StepUpRequired> {
  return apiFetch('/api/environments', { method: 'POST', body: JSON.stringify(values) })
}

/** `id` (5.40.7, UI-07): the row the user clicked. The server refuses
 * (409) if `name` no longer resolves to that environment for this user, so
 * a stale list can never activate a different, same-named tenant. */
export function activateEnvironment(name: string, id?: string): Promise<{ activated: boolean; active: string; active_id?: string }> {
  return apiFetch(`/api/environments/${encodeURIComponent(name)}/activate`, {
    method: 'POST',
    body: JSON.stringify(id ? { id } : {}),
  })
}

// `id` (the real owner-namespaced storage key, see Environment.id) is only
// ever passed for an admin deleting an environment they don't own -- their
// own environments are already unambiguous by name. Omit it (or pass
// undefined) when deleting your own -- the backend falls back to a
// by-name lookup scoped to the caller in that case.
export function deleteEnvironment(name: string, id?: string): Promise<{ deleted: string } | StepUpRequired> {
  const qs = id ? `?id=${encodeURIComponent(id)}` : ''
  return apiFetch(`/api/environments/${encodeURIComponent(name)}${qs}`, { method: 'DELETE' })
}

// Same `id` reasoning as deleteEnvironment above -- only needed for an
// admin overriding another owner's environment.
export function setEnvironmentShared(name: string, shared: boolean, id?: string): Promise<{ name: string; shared: boolean } | StepUpRequired> {
  return apiFetch(`/api/environments/${encodeURIComponent(name)}/share`, {
    method: 'POST',
    body: JSON.stringify({ shared, id }),
  })
}

export function saveSyncSchedule(name: string, schedule: SyncSchedule): Promise<{ name: string; sync_schedule: SyncSchedule } | StepUpRequired> {
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
): Promise<{ inserted: number; scanned: number; skipped_unparseable?: number; chain_head?: string } | StepUpRequired> {
  return apiFetch(`/api/environments/${encodeURIComponent(name)}/sync/import_csv`, {
    method: 'POST',
    body: JSON.stringify({ csv_path: csvPath, ingestion_scope: ingestionScope }),
  })
}

/** DATA-03 remedy (5.40.2): clears the live-sync watermark so the next sync
 * backfills the full 90-day window. Only offered when the server reports an
 * unusable watermark. */
export function resetSyncWatermark(name: string): Promise<{ name: string; previous_watermark: string | null } | StepUpRequired> {
  return apiFetch(`/api/environments/${encodeURIComponent(name)}/sync/reset_watermark`, { method: 'POST' })
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

export function fetchGroups(): Promise<{ groups: OpaGroup[] }> {
  return apiFetch('/api/groups')
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

export function fetchWorkloadRoles(): Promise<{ workload_roles: WorkloadRole[] }> {
  return apiFetch('/api/workload_roles')
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

// ── Service Accounts Dashboard (5.40.0) ──────────────────────────────────

/** Tenant-wide by design (see the route's own comment in server/serve.py)
 * -- no resource group/project in the URL; the dashboard filters
 * client-side. 409 with reason "not_synced" until the active environment
 * has completed a compliance sync. */
export function fetchServiceAccountsReport(rotationLimit?: number): Promise<ServiceAccountsReport> {
  const qs = rotationLimit != null ? `?rotation_limit=${encodeURIComponent(String(rotationLimit))}` : ''
  return apiFetch(`/api/service_accounts_report${qs}`)
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

// ── Orphaned archives (admin-only, DATA-12; UI 5.40.7) ───────────────────

/** Archives a deleted environment left behind. Admin-only on the server
 * (local mode exempt), same rule as the audit log. */
export function fetchOrphanedArchives(): Promise<{ archives: OrphanedArchive[] }> {
  return apiFetch('/api/archives/orphaned')
}

/** Irreversibly deletes every archive row for one orphaned environment_id.
 * The server refuses (409) while that environment still exists or a sync
 * is running, and audit-logs the per-table counts. */
export function purgeOrphanedArchive(environmentId: string): Promise<({ purged: string } & Record<string, number | string>) | StepUpRequired> {
  return apiFetch(`/api/archives/${encodeURIComponent(environmentId)}`, { method: 'DELETE' })
}

// ── Evidence chain (FE-15: was reachable only by URL) ────────────────────

/** Basic check (any user who can see the environment) or, with deep=true,
 * the admin-only re-hash of every sealed event. Deep answers 202
 * {status: "running"} while the background check is still going -- call
 * again until it answers 200 (hooks/useIntegrityCheck does). */
export function fetchIntegrity(name: string, deep = false): Promise<IntegrityResult | { status: 'running' }> {
  return apiFetch(`/api/environments/${encodeURIComponent(name)}/integrity${deep ? '?deep=1' : ''}`)
}

// ── Shared-environment permissions (admin-only, 5.42.0) ───────────────────

export function fetchSharedPermissions(): Promise<SharedPermissionsResponse> {
  return apiFetch('/api/shared_permissions')
}

/** The global defaults (no environmentId), one environment's overrides, or
 * (5.43.0, with `user`) one user's exceptions on that environment.
 * Step-up MFA in hosted mode, like every Environments change. */
export function saveSharedPermissions(
  changes: Partial<Record<SharedCapabilityKey, PermissionSetting>>,
  environmentId?: string,
  user?: GrantUser,
): Promise<{ changed: { capability: string; before: string; after: string }[] } | StepUpRequired> {
  const body = environmentId
    ? { environment_id: environmentId, changes, ...(user ? { user: { issuer: user.issuer, subject: user.subject } } : {}) }
    : { changes }
  return apiFetch('/api/shared_permissions', { method: 'POST', body: JSON.stringify(body) })
}
