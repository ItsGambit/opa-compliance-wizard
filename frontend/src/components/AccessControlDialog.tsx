import { useEffect, useState } from 'react'
import * as Dialog from '@radix-ui/react-dialog'
import { DialogCloseButton } from './DialogCloseButton'
import { useMutation } from '@tanstack/react-query'
import { toast } from '../hooks/useToast'
import { useAccessControl } from '../api/hooks'
import { prepareAccessControl } from '../api/client'
import type { AccessControlConfig } from '../types'
import { beginStepUp } from '../utils/stepUp'

interface Props {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function AccessControlDialog({ open, onOpenChange: setOpen }: Props) {
  const { data: config } = useAccessControl(open)

  const [adminGroupId, setAdminGroupId] = useState('')
  const [userGroupId, setUserGroupId] = useState('')
  const [restrictLogin, setRestrictLogin] = useState(false)

  // Re-seed the form from the server every time the dialog opens, same
  // reasoning as BannerSettingsDialog -- a second admin's more recent edit
  // isn't silently clobbered by whatever this browser happened to have open.
  useEffect(() => {
    if (open && config) {
      setAdminGroupId(config.admin_group_id ?? '')
      setUserGroupId(config.user_group_id ?? '')
      setRestrictLogin(config.restrict_login)
    }
  }, [open, config])

  // Phase 3: validates+stores the proposed config server-side (keyed by
  // an opaque action_id) BEFORE ever leaving this page -- the browser
  // carries only that id through the step-up redirect, never the actual
  // settings (closes the gap where a step-up cookie, once issued, could
  // previously be replayed to apply ANY payload within its TTL, not just
  // the one shown on screen here).
  const prepareMutation = useMutation({
    mutationFn: (values: AccessControlConfig) => prepareAccessControl(values),
    // 5.42.0: the shared step-up helper -- it also records that this round
    // trip is the Access Control save, so App.tsx finishes the right change.
    onSuccess: ({ action_id }) => beginStepUp(action_id, { kind: 'access_control' }),
    onError: (err: Error) => toast({ title: 'Could not start the save flow', description: err.message, variant: 'error' }),
  })

  const canSave = !restrictLogin || adminGroupId.trim() || userGroupId.trim()

  // Saving requires a FRESH MFA challenge, not just the existing admin
  // session -- prepare the pending change server-side, then leave the
  // page entirely for Okta's step-up redirect (see server/auth_gate.py's
  // /step-up route). There's no reliable popup/iframe path for step-up
  // given third-party cookie restrictions, and this app's ordinary login
  // is already a full redirect, so this follows the same shape rather
  // than inventing a new one. App.tsx finalizes the save on the way back
  // in (?stepup_complete=1) -- it needs no payload of its own anymore,
  // since the server already has the exact reviewed values.
  const handleSaveClick = () => {
    prepareMutation.mutate({
      admin_group_id: adminGroupId.trim() || null,
      user_group_id: userGroupId.trim() || null,
      restrict_login: restrictLogin,
    })
  }

  return (
    <Dialog.Root open={open} onOpenChange={setOpen}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/60 z-40" />
        <Dialog.Content aria-describedby={undefined} className="card fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-50 w-[calc(100vw-2rem)] sm:w-[28rem] p-5">
          <div className="flex items-center justify-between mb-3">
            <Dialog.Title className="text-sm font-semibold text-text">Access control</Dialog.Title>
            <DialogCloseButton />
          </div>

          <p className="text-xs text-text-faint mb-4">
            Okta group IDs (not names — find each group in the Okta Admin Console,
            the ID is in the URL) that control who can use this dashboard and who
            gets admin rights. Saving requires a fresh MFA challenge.
          </p>

          <div className="flex flex-col gap-3">
            <div className="field">
              <label htmlFor="access-control-admin-group" className="section-label block mb-1">Admin Group ID</label>
              <input
                id="access-control-admin-group"
                className="text-input w-full"
                value={adminGroupId}
                onChange={e => setAdminGroupId(e.target.value)}
                placeholder="e.g. 00g1a2b3c4d5e6f7g8h9"
              />
            </div>

            <div className="field">
              <label htmlFor="access-control-user-group" className="section-label block mb-1">User Group ID</label>
              <input
                id="access-control-user-group"
                className="text-input w-full"
                value={userGroupId}
                onChange={e => setUserGroupId(e.target.value)}
                placeholder="e.g. 00g9z8y7x6w5v4u3t2s1"
              />
            </div>

            <label className="flex items-start gap-2 text-sm text-text cursor-pointer">
              <input
                type="checkbox"
                checked={restrictLogin}
                onChange={e => setRestrictLogin(e.target.checked)}
                className="accent-accent mt-0.5"
              />
              <span>
                Restrict login to these groups
                <span className="block text-xs text-text-faint mt-0.5">
                  When off (default), any authenticated Okta user can log in — only
                  admin rights are gated. When on, anyone in neither group is denied
                  at login. A change takes effect on each user's next login, not
                  instantly.
                </span>
              </span>
            </label>
          </div>

          <div className="flex justify-end gap-2 mt-5">
            <Dialog.Close asChild>
              <button type="button" className="btn-secondary">Cancel</button>
            </Dialog.Close>
            <button
              type="button"
              className="btn-primary"
              disabled={prepareMutation.isPending || !canSave}
              onClick={handleSaveClick}
            >
              Verify &amp; Save
            </button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}
