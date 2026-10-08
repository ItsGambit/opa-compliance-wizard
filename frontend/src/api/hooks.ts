import { useQuery } from '@tanstack/react-query'
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
  fetchSyncStatus,
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
  })
}

export function useBanner() {
  return useQuery({
    queryKey: ['banner'],
    queryFn: fetchBanner,
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
    // Only ever opened by an admin from the dialog -- gated by `enabled`
    // (React Query's own conditional-fetch flag) so a non-admin's browser
    // never even attempts this admin-only request in the background.
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
  resources: { resource_kind: string; resource_id: string }[],
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

export function useReport(reportKey: string | undefined, environment: string | undefined, from?: string, to?: string) {
  return useQuery({
    queryKey: ['report', reportKey, environment, from, to],
    queryFn: () => runReport(reportKey!, environment, from, to),
    enabled: !!reportKey && !!environment,
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
  resourceName?: string
) {
  return useQuery({
    queryKey: ['resource_history', resourceId, environment, from, to, resourceName],
    queryFn: () => fetchResourceHistory(resourceId!, environment, from, to, resourceName),
    enabled: !!resourceId && !!environment,
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
