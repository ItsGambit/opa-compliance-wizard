import { useMutation, useQueryClient } from '@tanstack/react-query'
import { createGroup } from '../api/client'
import type { OpaGroup } from '../types'
import { toast } from './useToast'

/** Shared "create in Okta, push into OPA" mutation used anywhere a group
 * picker offers a "New Group" affordance — group CRUD intentionally always
 * flows through Okta (see create_secret_folders.py's OPA_APP_CATALOG_NAME
 * comment), never OPA's own local-group endpoint.
 *
 * onCreated only fires once the group is confirmed visible in OPA (i.e.
 * push has propagated) — if it hasn't yet, the caller sees a toast telling
 * them to refresh shortly instead.
 *
 * The server also tries to add this dashboard's own service account to
 * every group it creates here (so the group is immediately usable by the
 * dashboard without a manual step) — that's silent on success (the group's
 * own success toast below is enough), surfaced as a second warning toast
 * only if it failed, and never blocks group creation either way. */
export function useCreateGroup(onCreated: (group: OpaGroup) => void) {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (vars: { name: string; description: string }) =>
      createGroup(vars.name.trim(), vars.description.trim()),
    onSuccess: (resp) => {
      queryClient.invalidateQueries({ queryKey: ['groups'] })
      if (resp.visible_in_opa && resp.group) {
        toast({ title: `Group '${resp.group.name}' created and pushed from Okta`, variant: 'success' })
        if (resp.service_account_added) {
          queryClient.invalidateQueries({ queryKey: ['service_account'] })
        } else if (resp.service_account_warning) {
          toast({ title: 'Service account not added automatically', description: resp.service_account_warning, variant: 'default', duration: 8000 })
        }
        onCreated(resp.group)
      } else {
        toast({
          title: 'Created in Okta, still propagating',
          description: resp.message ?? 'Refresh the group list in a few seconds.',
          variant: 'default',
        })
      }
    },
    onError: (err: Error) => toast({ title: 'Could not create group', description: err.message, variant: 'error' }),
  })
}
