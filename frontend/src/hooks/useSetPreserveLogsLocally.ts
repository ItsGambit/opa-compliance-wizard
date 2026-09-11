import { useMutation, useQueryClient } from '@tanstack/react-query'
import { setPreserveLogsLocally } from '../api/client'
import { toast } from './useToast'

/** Toggles an environment's opt-in to caching Secrets Access Dashboard
 * System Log events locally (secrets_log_cache.json) past Okta's 90-day
 * retention — see LogRetentionIndicator for where this is surfaced.
 * Invalidates ['environments'] (drives the indicator everywhere) and
 * ['secrets_access_report'] (its since_days/local_retention_enabled note
 * changes as soon as this toggles). */
export function useSetPreserveLogsLocally() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (vars: { name: string; enabled: boolean }) => setPreserveLogsLocally(vars.name, vars.enabled),
    onSuccess: (resp) => {
      queryClient.invalidateQueries({ queryKey: ['environments'] })
      queryClient.invalidateQueries({ queryKey: ['secrets_access_report'] })
      toast({
        title: resp.preserve_logs_locally ? 'Preserving System Log locally' : 'Local log preservation turned off',
        variant: 'success',
      })
    },
    onError: (err: Error) => toast({ title: 'Could not update setting', description: err.message, variant: 'error' }),
  })
}
