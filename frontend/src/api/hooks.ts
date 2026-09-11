import { useQuery } from '@tanstack/react-query'
import {
  fetchCsvFiles,
  fetchEnvironments,
  fetchGroups,
  fetchProjects,
  fetchResourceGroupSecurityPolicies,
  fetchResourceGroups,
  fetchSecretsAccessReport,
  fetchServiceAccount,
  fetchUserResourceAccess,
  fetchWhoami,
  fetchWorkloadRoles,
} from './client'

export function useEnvironments() {
  return useQuery({
    queryKey: ['environments'],
    queryFn: fetchEnvironments,
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
