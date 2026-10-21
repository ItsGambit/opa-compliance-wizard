import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { isStepUpRequired, requestUpgrade } from '../../api/client'
import { toast } from '../../hooks/useToast'
import type { UpgradeRequestBody, UpgradeStatus } from '../../types'
import { updaterTooOld } from '../../utils/upgradeFlow'
import { UPDATER_REFRESH_COMMAND } from '../../utils/links'
import { beginStepUp } from '../../utils/stepUp'
import { markBundleRequested, rememberRequested, type RequestedUpgrade } from '../../utils/upgradeRequested'

const OPERATIONS: string[] = ['rollback', 'restore', 'clear_failure', 'bundle']

/** One request to the updater through the step-up transaction: hosted mode answers 202 and the browser leaves for the MFA challenge
 * (App.tsx finishes it on the way back); local mode applies at once. `label` names it in the toasts. */
export function useUpgradeRequest(label: string, onDone?: () => void) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: UpgradeRequestBody) => requestUpgrade(body),
    onSuccess: (resp, body) => {
      if (isStepUpRequired(resp)) {
        beginStepUp(resp.action_id, { kind: 'environment_change', action: resp.action, label, startedAt: Date.now(), reopen: 'updates' })
        return
      }
      if (body.kind === 'bundle') markBundleRequested()
      if (resp.correlation_id && OPERATIONS.includes(body.kind)) {
        rememberRequested({ correlationId: resp.correlation_id, version: '', approvedAt: new Date().toISOString(), email: null, stepUp: false, kind: body.kind as RequestedUpgrade['kind'] })
      }
      for (const key of ['upgrade_status', 'upgrade_notice', 'audit_log']) queryClient.invalidateQueries({ queryKey: [key] })
      toast({ title: `${label}: requested`, description: 'Applied at once (local install: no identity provider).', variant: 'success' })
      onDone?.()
    },
    onError: (err: Error & { body?: { reason?: string } }) => {
      const reason = err.body?.reason
      if (reason === 'activator_too_old') queryClient.setQueryData(['upgrade_activator_old'], true)      // the buttons switch off with the command to run
      toast({
        title: `Could not start: ${label}`,
        description: reason === 'backup_changed' ? 'The backup changed since you looked; reload the page.'
          : reason === 'activator_too_old' ? `Update the server's updater first: ${UPDATER_REFRESH_COMMAND}` : err.message,
        variant: 'error',
      })
      if (reason === 'backup_changed' || reason === 'needs_operator') queryClient.invalidateQueries({ queryKey: ['upgrade_status'] })
    },
  })
}

/** True once the server said "the updater predates this action" (409 activator_too_old) in this session. */
export function useActivatorOld(): boolean {
  return !!useQuery({ queryKey: ['upgrade_activator_old'], queryFn: () => false, staleTime: Infinity, initialData: false }).data
}

/** Why the in-app operations are off (the updater predates them), or null. */
export function useOperationsBlock(status: UpgradeStatus): string | null {
  const reactive = useActivatorOld()
  return reactive || updaterTooOld(status) ? `Update the server's updater first: ${UPDATER_REFRESH_COMMAND}` : null
}
