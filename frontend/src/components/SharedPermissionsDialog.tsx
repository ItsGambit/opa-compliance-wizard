import { useEffect, useRef, useState } from 'react'
import * as Dialog from '@radix-ui/react-dialog'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { isStepUpRequired, saveSharedPermissions } from '../api/client'
import { useSharedPermissions } from '../api/hooks'
import { toast } from '../hooks/useToast'
import type { PermissionSetting, SharedCapabilityKey } from '../types'
import { SOURCE_LABELS, changedSettings, mainAddressOnly } from '../utils/sharedPermissions'
import { beginStepUp } from '../utils/stepUp'
import { DialogCloseButton } from './DialogCloseButton'
import { ErrorNotice } from './ErrorNotice'
import { PermissionSettingsList } from './PermissionSettingsList'

interface Props {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Settings restored after an MFA approval that didn't complete. */
  draft?: Partial<Record<SharedCapabilityKey, PermissionSetting>>
}

/** 5.42.0, admin-only: the GLOBAL defaults for what users may do with an
 * environment someone else owns and has shared with them. Owners decide
 * whether to share; admins decide what sharing allows. Each environment can
 * override these in the Environments dialog. Saving needs a fresh MFA
 * approval behind the hosted login gate. */
export function SharedPermissionsDialog({ open, onOpenChange, draft }: Props) {
  const queryClient = useQueryClient()
  const { data, isLoading, isError, error, refetch, isFetching } = useSharedPermissions(open)
  const [settings, setSettings] = useState<Partial<Record<SharedCapabilityKey, PermissionSetting>>>({})

  // Seeded once per opening (a background refetch must not wipe an edit).
  const seeded = useRef(false)
  const stored = (): Partial<Record<SharedCapabilityKey, PermissionSetting>> => {
    const out: Partial<Record<SharedCapabilityKey, PermissionSetting>> = {}
    for (const cap of data?.capabilities ?? []) {
      const d = data?.defaults[cap.key]
      out[cap.key] = d && d.source === 'default' ? d.value : 'inherit'
    }
    return out
  }
  useEffect(() => {
    if (!open) {
      seeded.current = false
      return
    }
    if (data && !seeded.current) {
      seeded.current = true
      setSettings({ ...stored(), ...(draft ?? {}) })
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, data])

  const changes = data ? changedSettings(stored(), settings) : {}
  const hasChanges = Object.keys(changes).length > 0

  const save = useMutation({
    mutationFn: () => saveSharedPermissions(changes),
    onSuccess: (resp) => {
      if (isStepUpRequired(resp)) {
        beginStepUp(resp.action_id, {
          kind: 'environment_change', action: resp.action, label: 'Shared permissions (global defaults)',
          startedAt: Date.now(), reopen: 'shared_permissions', permissionsDraft: { settings },
        })
        return
      }
      toast({ title: 'Shared permissions saved', variant: 'success' })
      queryClient.invalidateQueries({ queryKey: ['shared_permissions'] })
      queryClient.invalidateQueries({ queryKey: ['environments'] })
      onOpenChange(false)
    },
    onError: (err: Error) => toast({ title: 'Could not save shared permissions', description: err.message, variant: 'error' }),
  })

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/60 z-40" />
        <Dialog.Content className="card fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-50 w-[calc(100vw-2rem)] sm:w-[34rem] max-h-[85vh] overflow-y-auto p-5">
          <div className="flex items-center justify-between mb-2">
            <Dialog.Title className="text-sm font-semibold text-text">Shared permissions</Dialog.Title>
            <DialogCloseButton />
          </div>
          <Dialog.Description className="text-xs text-text-dim mb-4 leading-relaxed">
            What a user may do with an environment that another user owns and has shared. Shared users act with the
            owner's stored credentials. Owners are never limited by these settings, and they still decide whether to
            share at all. Each environment can override these defaults (Environments → Shared permissions). Saving
            needs a fresh MFA approval.
          </Dialog.Description>

          {isLoading && <div className="text-xs text-text-dim">Loading…</div>}
          {isError && <ErrorNotice title="Could not load shared permissions" error={mainAddressOnly(error)} onRetry={() => refetch()} retrying={isFetching} />}
          {data && (
            <PermissionSettingsList
              capabilities={data.capabilities}
              settings={settings}
              onChange={(key, value) => setSettings(s => ({ ...s, [key]: value }))}
              inherited={key => ({ value: data.capabilities.find(c => c.key === key)!.builtin, from: 'built-in default' })}
              current={key => ({ value: data.defaults[key].value, from: SOURCE_LABELS[data.defaults[key].source] })}
              disabled={save.isPending}
            />
          )}

          <div className="flex justify-end gap-2 mt-5">
            <Dialog.Close asChild>
              <button type="button" className="btn-secondary">Cancel</button>
            </Dialog.Close>
            <button
              type="button"
              className="btn-primary"
              disabled={!hasChanges || save.isPending}
              onClick={() => save.mutate()}
            >
              Verify &amp; Save
            </button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}
