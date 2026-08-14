import { useQuery } from '@tanstack/react-query'
import {
  fetchCsvFiles,
  fetchEnvironments,
  fetchGroups,
  fetchProjects,
  fetchResourceGroupSecurityPolicies,
  fetchResourceGroups,
  fetchWorkloadRoles,
} from './client'

export function useEnvironments() {
  return useQuery({
    queryKey: ['environments'],
    queryFn: fetchEnvironments,
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
