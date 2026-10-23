import { useQuery } from '@tanstack/react-query'
import type { AuditLogEntry } from '../types'
import {
  fetchAccessControl,
  fetchAdConnectionDiscoveryConfig,
  fetchBanner,
  fetchCsvFiles,
  fetchEnvironments,
  fetchGroups,
  fetchProjects,
  fetchReportDefs,
  fetchResourceGroupSecurityPolicies,
  fetchResourceGroups,
  fetchResourceHistory,
  fetchSecretsAccessReport,
  fetchServiceAccount,
  fetchServiceAccountsReport,
  fetchSettingsEnvironments,
  fetchSettingsStatus,
  fetchSharedPermissions,
  fetchSyncStatus,
  fetchAuditLog,
  fetchConfigSnapshotDiff,
  fetchConfigSnapshots,
  fetchCrossChecks,
  fetchOktaAdminsReport,
  fetchOverview,
  fetchPeopleList,
  fetchUpgradeNotice,
  fetchUpgradeStatus,
  fetchUserResourceAccess,
  fetchVersion,
  fetchWhoami,
  fetchWorkloadRoles,
  runReport,
} from './client'

export function useEnvironments() {
  return useQuery({
    queryKey: ['environments'],
    queryFn: fetchEnvironments,
    // The server session (and so the active environment) is per user, not
    // per tab: another tab's Activate changes it here too. Refetching this
    // cheap list on focus is what lets App notice and reset the tenant
    // scope (UI-05) -- an exception to the app-wide no-focus-refetch rule.
    refetchOnWindowFocus: true,
    staleTime: 0,
  })
}

/** 5.53.0: the environment list WITH its configuration (OPA domain, team, key id, Okta URL, sync schedule). Server-side it needs
 * the Settings unlock, so it is only asked for from inside an unlocked Settings screen. */
export function useSettingsEnvironments(enabled = true) {
  return useQuery({
    queryKey: ['settings_environments'],
    queryFn: fetchSettingsEnvironments,
    enabled,
    refetchOnWindowFocus: true,
    staleTime: 0,
  })
}

/** 5.53.0: where this sign-in stands with the Settings unlock. `area` makes a local-mode server record the opening. Polled
 * gently so a lock from another tab, or a save that renewed the window, shows up; the countdown itself runs in the browser
 * from `seconds_left` (the browser never compares its clock with the server's). */
export function useSettingsStatus(area: 'settings' | 'updates', enabled = true) {
  return useQuery({
    queryKey: ['settings_status', area],
    queryFn: () => fetchSettingsStatus(area),
    enabled,
    staleTime: 0,
    refetchOnWindowFocus: true,
    refetchInterval: 30_000,
  })
}

/** 5.46.0: the update-check status. Admin-only on the server, so it is only
 * asked for when the caller can admin; refreshed gently (the check itself
 * runs once a day on the server). */
export function useUpgradeStatus(enabled: boolean, pollMs?: number) {
  return useQuery({
    queryKey: ['upgrade_status'],
    queryFn: () => fetchUpgradeStatus(),
    enabled,
    staleTime: pollMs ? 0 : 60_000,
    // 5.48.0: while an upgrade is starting or running the page polls (2 s). The server restarts underneath it, so a failed
    // poll is not retried here (the next tick is the retry) and the last good answer stays on screen.
    refetchInterval: pollMs ?? 10 * 60_000,
    ...(pollMs ? { retry: false, refetchIntervalInBackground: true } : {}),
  })
}

/** 5.48.0: the one-line upgrade banner for every signed-in user (scheduled / running / failed; admins also "available"). */
export function useUpgradeNotice() {
  return useQuery({
    queryKey: ['upgrade_notice'],
    queryFn: fetchUpgradeNotice,
    refetchOnWindowFocus: true,
    staleTime: 30_000,
    refetchInterval: 60_000,
  })
}

export function useBanner() {
  return useQuery({
    queryKey: ['banner'],
    queryFn: fetchBanner,
    refetchOnWindowFocus: true,
    staleTime: 0,
    // Refetch on focus/reconnect (not staleTime: Infinity like
    // useWhoami/useVersion above) -- unlike identity/version, a banner is
    // meant to change while the page is already open (an admin flips it
    // on mid-incident) and should show up without a manual reload.
  })
}

export function useAccessControl(enabled: boolean) {
  return useQuery({
    queryKey: ['access_control'],
    queryFn: fetchAccessControl,
    // Always fresh when the dialog opens: another admin may have changed it.
    staleTime: 0,
    // Only ever opened by an admin from the dialog -- gated by `enabled`
    // (React Query's own conditional-fetch flag) so a non-admin's browser
    // never even attempts this admin-only request in the background.
    enabled,
  })
}

/** 5.42.0, admin-only: the shared-environment permission settings. Fetched
 * only while an admin screen that shows them is open. */
export function useSharedPermissions(enabled: boolean) {
  return useQuery({
    queryKey: ['shared_permissions'],
    queryFn: fetchSharedPermissions,
    staleTime: 0,
    enabled,
  })
}

export function useWhoami() {
  return useQuery({
    queryKey: ['whoami'],
    queryFn: fetchWhoami,
    // Identity for a given browser session never changes mid-session (a
    // change means a real re-login, which reloads the page anyway) --
    // no point refetching on focus/reconnect like data-bearing queries do.
    staleTime: Infinity,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  })
}

export function useVersion() {
  return useQuery({
    queryKey: ['version'],
    queryFn: fetchVersion,
    // Version only changes on a real deploy, which restarts the server --
    // same no-refetch reasoning as useWhoami above.
    staleTime: Infinity,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  })
}

export function useResourceGroups(enabled = true) {
  return useQuery({
    queryKey: ['resource_groups'],
    queryFn: async () => (await fetchResourceGroups()).resource_groups,
    enabled,
  })
}

export function useProjects(resourceGroupId: string | undefined, enabled = true) {
  return useQuery({
    queryKey: ['projects', resourceGroupId],
    queryFn: async () => (await fetchProjects(resourceGroupId!)).projects,
    enabled: enabled && !!resourceGroupId,
  })
}

export function useCsvFiles() {
  return useQuery({
    queryKey: ['csv_files'],
    queryFn: async () => (await fetchCsvFiles()).files,
  })
}

/** Identity + current group memberships of the service account running
 * this dashboard -- used to render "already a member" / "+ Add" wherever
 * a group is shown as (or picked to become) a security-policy or
 * resource-group principal. See ServiceAccountGroupStatus. */
export function useServiceAccount(enabled = true) {
  return useQuery({
    queryKey: ['service_account'],
    queryFn: fetchServiceAccount,
    enabled,
  })
}

export function useGroups(enabled = true) {
  return useQuery({
    queryKey: ['groups'],
    queryFn: async () => (await fetchGroups()).groups,
    enabled,
  })
}

export function useResourceGroupSecurityPolicies(resourceGroupId: string | undefined, enabled = true) {
  return useQuery({
    queryKey: ['security_policies', resourceGroupId],
    queryFn: async () => (await fetchResourceGroupSecurityPolicies(resourceGroupId!)).policies,
    enabled: enabled && !!resourceGroupId,
  })
}

export function useWorkloadRoles(enabled = true) {
  return useQuery({
    queryKey: ['workload_roles'],
    queryFn: async () => (await fetchWorkloadRoles()).workload_roles,
    enabled,
  })
}

/** Fires automatically once `userId` and `resources` are both non-empty
 * (e.g. right after selecting a user in UsersTab) -- not a manual
 * "check access" button. Kept on-demand per-user rather than folded into
 * the big Access Explorer bootstrap: fetching this for every user's every
 * resource up front would be slow and mostly wasted, since nobody looks
 * at most of it. */
export function useUserResourceAccess(
  userId: string | undefined,
  resources: { resource_kind: string; resource_id: string; account_name?: string; name_unique?: boolean; server_id?: string }[],
  // A service user (e.g. this dashboard's own service account) has no
  // Okta identity/email, so System Log's actor lookup can never resolve
  // for it — the server already fails that gracefully rather than
  // crashing, but there's no point firing a request known to fail before
  // it's even sent. Callers pass false for a service-type user.
  trackable = true
) {
  const resourceKey = resources.map(r => `${r.resource_kind}:${r.resource_id}`).sort().join(',')
  return useQuery({
    queryKey: ['user_resource_access', userId, resourceKey],
    queryFn: async () => (await fetchUserResourceAccess(userId!, resources)).results,
    enabled: trackable && !!userId && resources.length > 0,
  })
}

export function useSecretsAccessReport(resourceGroupId: string | undefined, projectId: string | undefined) {
  return useQuery({
    queryKey: ['secrets_access_report', resourceGroupId, projectId],
    queryFn: () => fetchSecretsAccessReport(resourceGroupId!, projectId!),
    enabled: !!resourceGroupId && !!projectId,
    retry: false, // a 409 (no Okta token configured) won't resolve by retrying
  })
}

/** Tenant-wide SaaS / Okta service-account report (5.40.0) -- fires as
 * soon as the dashboard mounts (no picker to wait for, unlike
 * useSecretsAccessReport). Keyed by the active environment so switching
 * environments can never keep showing the previous one's accounts.
 *
 * No automatic refetch (staleTime: Infinity, no focus/reconnect refetch,
 * same as useWhoami/useVersion): every fetch re-walks EVERY resource
 * group and project on the OPA side (1 + R + 2P calls) plus the archive
 * queries, so React Query's default "stale immediately, refetch on
 * window focus" would re-run that whole walk every time the tab regains
 * focus -- a real rate-limit risk on a large tenant. Refresh is an
 * explicit button, and the Footer invalidates this key when a global
 * sync completes, same as every other archive-backed view. */
export function useServiceAccountsReport(environment: string | undefined, rotationLimit?: number) {
  return useQuery({
    queryKey: ['service_accounts_report', environment, rotationLimit],
    queryFn: () => fetchServiceAccountsReport(rotationLimit),
    enabled: !!environment,
    retry: false, // a 409 (never synced / no environment) won't resolve by retrying
    staleTime: Infinity,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  })
}

export function useReportDefs(environment: string | undefined, from?: string, to?: string) {
  return useQuery({
    queryKey: ['report_defs', environment, from, to],
    queryFn: async () => (await fetchReportDefs(environment, from, to)).reports,
    enabled: !!environment,
  })
}

/** `enabled` false (e.g. an invalid date range) runs nothing. While a new
 * range loads, the previous rows stay on screen (UI-04; isPlaceholderData
 * tells the caller they are the old range's). */
export function useReport(reportKey: string | undefined, environment: string | undefined, from?: string, to?: string, enabled = true) {
  return useQuery({
    queryKey: ['report', reportKey, environment, from, to],
    queryFn: () => runReport(reportKey!, environment, from, to),
    enabled: enabled && !!reportKey && !!environment,
    // Only across a date-range change of the SAME report and environment --
    // never another report's rows under this report's title.
    // Never while disabled (an invalid range): TanStack applies
    // placeholderData to a disabled pending query too, which would label
    // the old rows "loading" forever.
    placeholderData: (prev, prevQuery) =>
      enabled && prevQuery && prevQuery.queryKey[1] === reportKey && prevQuery.queryKey[2] === environment ? prev : undefined,
  })
}

/** The Resources tab's per-resource drill-down -- mirrors useReport's exact
 * shape, just keyed by a resource's own id (and, for kinds with no
 * log-side id at all -- see fetchResourceHistory -- an exact display-name
 * fallback) instead of a report_key. */
export function useResourceHistory(
  resourceId: string | undefined,
  environment: string | undefined,
  from?: string,
  to?: string,
  resourceName?: string,
  enabled = true
) {
  return useQuery({
    queryKey: ['resource_history', resourceId, environment, from, to, resourceName],
    queryFn: () => fetchResourceHistory(resourceId!, environment, from, to, resourceName),
    enabled: enabled && !!resourceId && !!environment,
    // Same resource only: never show another resource's history under
    // this one's name while it loads.
    placeholderData: (prev, prevQuery) =>
      enabled && prevQuery && prevQuery.queryKey[1] === resourceId && prevQuery.queryKey[2] === environment && prevQuery.queryKey[5] === resourceName
        ? prev
        : undefined,
  })
}

/** A plain point-in-time read of one environment's sync state -- "when was
 * this last actually synced from live Okta" (e.g. the Footer's "Last Okta
 * import" line). Deliberately NOT useSyncJob (frontend/src/hooks/
 * useSyncJob.ts) -- that hook exists to DRIVE a sync job (start + poll
 * until done), which is overkill for something that just wants to display
 * a timestamp once. No polling here; a caller that needs live progress
 * should use useSyncJob instead. */
export function useSyncStatus(environmentName: string | undefined) {
  return useQuery({
    queryKey: ['sync_status', environmentName],
    queryFn: () => fetchSyncStatus(environmentName!),
    enabled: !!environmentName,
  })
}

/** On-demand fetch of one AD connection's discovery configuration --
 * explains WHY an individual AD account got discovered/matched. Only
 * fired once a connection row is actually clicked in ResourcesTab, not
 * bootstrapped for every AD connection up front. */
export function useAdConnectionDiscoveryConfig(connectionId: string | undefined) {
  return useQuery({
    queryKey: ['ad_connection_discovery_config', connectionId],
    queryFn: () => fetchAdConnectionDiscoveryConfig(connectionId!),
    enabled: !!connectionId,
  })
}

/** 5.48.0: the audit entries of one upgrade (same correlation id), from the most recent 200 entries. Admin-only (the audit log is). */
export function useRunAudit(correlationId: string | null | undefined, enabled = true) {
  return useQuery({
    queryKey: ['audit_log', 'run', correlationId],
    queryFn: async () => (await fetchAuditLog(200, 0)).entries,
    select: (entries: AuditLogEntry[]) => entries.filter(e => (e.details as { correlation_id?: unknown } | undefined)?.correlation_id === correlationId),
    enabled: enabled && !!correlationId,
    staleTime: 15_000,
  })
}

// ── Okta Admins report, cross-checks, snapshots, overview (5.50.0) ────────
// All read stored snapshots (no Okta call); a capture runs in the background on
// the server, so these poll while one is running and stop when it finishes.
const POLL_WHILE_CAPTURING = (query: { state: { data?: { capture?: { status?: string } } } }) =>
  query.state.data?.capture?.status === 'running' ? 2000 : false

export function useOktaAdminsReport(environment: string | undefined, asOf?: string) {
  return useQuery({
    queryKey: ['okta_admins_report', environment, asOf ?? null],
    queryFn: () => fetchOktaAdminsReport(environment!, asOf),
    enabled: !!environment,
    retry: false,
    refetchInterval: POLL_WHILE_CAPTURING,
    refetchOnWindowFocus: false,
  })
}

export function useCrossChecks(environment: string | undefined, enabled = true) {
  return useQuery({
    queryKey: ['cross_checks', environment],
    queryFn: () => fetchCrossChecks(environment!),
    enabled: !!environment && enabled,
    retry: false,
    refetchInterval: POLL_WHILE_CAPTURING,
    refetchOnWindowFocus: false,
  })
}

export function useConfigSnapshots(environment: string | undefined, kind?: string) {
  return useQuery({
    queryKey: ['config_snapshots', environment, kind ?? null],
    queryFn: async () => (await fetchConfigSnapshots(environment!, kind)).snapshots,
    enabled: !!environment,
    retry: false,
    refetchOnWindowFocus: false,
  })
}

export function useConfigSnapshotDiff(environment: string | undefined, older: number | null, newer: number | null) {
  return useQuery({
    queryKey: ['config_snapshot_diff', environment, older, newer],
    queryFn: () => fetchConfigSnapshotDiff(environment!, older!, newer!),
    enabled: !!environment && older != null && newer != null && older !== newer,
    retry: false,
    refetchOnWindowFocus: false,
  })
}

export function useOverview(environment: string | undefined, asOf?: string, enabled = true, weeks?: number) {
  return useQuery({
    queryKey: ['overview', environment, asOf ?? null, weeks ?? null],
    queryFn: () => fetchOverview(environment!, asOf, weeks),
    refetchInterval: (query: { state: { data?: { capture?: { status?: string } } } }) => (query.state.data?.capture?.status === 'running' ? 2000 : false),
    enabled: !!environment && enabled,
    retry: false,
    refetchOnWindowFocus: false,
  })
}

export function usePeopleList(environment: string | undefined, list: 'c1' | 'c5' | 'mfa_nonpr' | 'mfa_smsvoice' | null, asOf?: string) {
  return useQuery({
    queryKey: ['people_list', environment, list, asOf ?? null],
    queryFn: () => fetchPeopleList(environment!, list!, asOf),
    enabled: !!environment && !!list,
    retry: false,
    staleTime: 0,
    gcTime: 0, // names are not kept in the client cache once the drawer closes
    refetchOnWindowFocus: false,
  })
}
