import { useEffect, useState } from 'react'
import * as AlertDialog from '@radix-ui/react-alert-dialog'
import { useQueryClient } from '@tanstack/react-query'
import { notifySessionRestored, onSessionExpired } from '../api/client'

/** FE-05 (external review, 2026-10-05): when the login gate refuses a
 * request (expired session), say so once and offer a way back in, instead
 * of a stream of "Failed to fetch" toasts. Signing in in a NEW tab keeps
 * this page (and any unsaved Folder Builder tree) intact: the gate's
 * cookie is shared, so once that tab has signed in, "Continue" here simply
 * retries. Reloading is offered too, with the cost stated. */
export function SessionExpiredDialog() {
  const [open, setOpen] = useState(false)
  const queryClient = useQueryClient()

  useEffect(() => onSessionExpired(() => setOpen(true)), [])

  // Retry only what failed (not every live Okta/OPA walk on screen), and
  // let progress hooks re-attach to a job the expiry interrupted.
  const handleContinue = () => {
    setOpen(false)
    queryClient.invalidateQueries({ queryKey: ['whoami'] })
    queryClient.invalidateQueries({ queryKey: ['environments'] })
    queryClient.refetchQueries({ type: 'active', predicate: q => q.state.status === 'error' })
    notifySessionRestored()
  }

  return (
    <AlertDialog.Root open={open} onOpenChange={setOpen}>
      <AlertDialog.Portal>
        <AlertDialog.Overlay className="fixed inset-0 bg-black/60 z-[60]" />
        <AlertDialog.Content className="card fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-[61] w-[calc(100vw-2rem)] sm:w-[26rem] p-5">
          <AlertDialog.Title className="text-sm font-semibold text-text">Your session has expired</AlertDialog.Title>
          <AlertDialog.Description className="text-xs text-text-dim mt-2 leading-relaxed">
            The server needs you to sign in again. Sign in in a new tab to keep this page as it is (including
            unsaved changes), then come back and choose Continue. Reloading signs you in here but discards anything
            not yet saved.
          </AlertDialog.Description>
          <div className="flex flex-wrap justify-end gap-2 mt-4">
            <button type="button" className="btn-secondary" onClick={() => window.location.reload()}>
              Reload and sign in
            </button>
            <button type="button" className="btn-secondary" onClick={() => window.open('/login', '_blank', 'noopener')}>
              Sign in in a new tab
            </button>
            <AlertDialog.Action asChild>
              <button type="button" className="btn-primary" onClick={handleContinue}>
                Continue
              </button>
            </AlertDialog.Action>
          </div>
        </AlertDialog.Content>
      </AlertDialog.Portal>
    </AlertDialog.Root>
  )
}
