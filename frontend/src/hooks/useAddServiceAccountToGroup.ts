import { useMutation, useQueryClient } from '@tanstack/react-query'
import { addServiceAccountToGroup } from '../api/client'
import type { ApiErrorBody } from '../types'
import { toast } from './useToast'

/** Opt-in counterpart to the automatic add in useCreateGroup — for a group
 * that already existed before the dashboard touched it (so there was never
 * an automatic moment to add the service account), this is the "if it's
 * not already there" action a user triggers explicitly. See
 * ServiceAccountGroupStatus, which renders the button that calls this. */
export function useAddServiceAccountToGroup() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (groupId: string) => addServiceAccountToGroup(groupId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['service_account'] })
      toast({ title: 'Service account added to group', variant: 'success' })
    },
    onError: (err: Error & { body?: ApiErrorBody }) =>
      toast({ title: 'Could not add service account to group', description: err.body?.error ?? err.message, variant: 'error' }),
  })
}
