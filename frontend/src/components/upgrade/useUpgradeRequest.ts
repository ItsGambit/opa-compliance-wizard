import { useMutation, useQueryClient } from '@tanstack/react-query'
import { isStepUpRequired, requestUpgrade } from '../../api/client'
import { toast } from '../../hooks/useToast'
import type { UpgradeRequestBody } from '../../types'
import { beginStepUp } from '../../utils/stepUp'
import { rememberRequested, type RequestedUpgrade } from '../../utils/upgradeRequested'

const OPERATIONS: string[] = ['rollback', 'restore', 'clear_failure', 'bundle', 'prune_backups']

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
      if (resp.correlation_id && OPERATIONS.includes(body.kind)) {
        rememberRequested({ correlationId: resp.correlation_id, version: '', approvedAt: new Date().toISOString(), email: null, stepUp: false, kind: body.kind as RequestedUpgrade['kind'] })
      }
      for (const key of ['upgrade_status', 'upgrade_notice', 'audit_log']) queryClient.invalidateQueries({ queryKey: [key] })
      toast({ title: `${label}: requested`, description: 'Applied at once (local install: no identity provider).', variant: 'success' })
      onDone?.()
    },
    onError: (err: Error) => toast({ title: `Could not start: ${label}`, description: err.message, variant: 'error' }),
  })
}
