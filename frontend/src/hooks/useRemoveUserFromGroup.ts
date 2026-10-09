import { useMutation, useQueryClient } from '@tanstack/react-query'
import { removeUserFromGroup } from '../api/client'
import type { ApiErrorBody } from '../types'
import { toast } from './useToast'

/** Removes a user (human or service) from a group via OPA's own
 * membership API — the counterpart to useAddServiceAccountToGroup, but
 * generic: used from Access Explorer's Users tab to revoke access granted
 * through group membership, for whichever user is selected. The caller
 * (UsersTab) is responsible for updating the already-loaded AccessModel
 * locally on success, since that model isn't held in TanStack Query's
 * cache — this hook just does the mutation, the toast, and refreshes the
 * service-account query in case the removed user IS the service account
 * running this dashboard (cheap either way, since it's a no-op refetch of
 * unrelated data otherwise). */
export function useRemoveUserFromGroup(onRemoved: (groupId: string) => void) {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (vars: { groupId: string; userName: string }) => removeUserFromGroup(vars.groupId, vars.userName),
    onSuccess: (resp) => {
      queryClient.invalidateQueries({ queryKey: ['service_account'] })
      queryClient.invalidateQueries({ queryKey: ['groups'] })
      queryClient.invalidateQueries({ queryKey: ['user_resource_access'] })
      toast({ title: 'Access removed', variant: 'success' })
      onRemoved(resp.group_id)
    },
    onError: (err: Error & { body?: ApiErrorBody }) =>
      toast({ title: 'Could not remove access', description: err.body?.error ?? err.message, variant: 'error' }),
  })
}
