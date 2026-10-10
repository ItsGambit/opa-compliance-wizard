import { useEffect, useRef, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { isStepUpRequired, saveSharedPermissions } from '../api/client'
import { useSharedPermissions } from '../api/hooks'
import { toast } from '../hooks/useToast'
import type { Environment, GrantUser, PermissionSetting, SharedCapabilityKey } from '../types'
import { SOURCE_LABELS, changedSettings, mainAddressOnly } from '../utils/sharedPermissions'
import { beginStepUp } from '../utils/stepUp'
import { ErrorNotice } from './ErrorNotice'
import { PermissionSettingsList } from './PermissionSettingsList'
import { UserPermissionExceptions } from './UserPermissionExceptions'

/** 5.42.0, admin-only: one environment's overrides of the global
 * shared-environment defaults (inherit / allow / deny per capability), with
 * the value in effect and where it comes from; since 5.43.0 also its
 * per-user exceptions. */
export function EnvironmentPermissionsEditor({ env, draft, draftUser }: {
  env: Environment
  /** Settings restored after an MFA approval that didn't complete. */
  draft?: Partial<Record<SharedCapabilityKey, PermissionSetting>>
  /** Set when `draft` was one user's exceptions, not the environment's. */
  draftUser?: GrantUser
}) {
  const queryClient = useQueryClient()
  const { data, isLoading, isError, error, refetch, isFetching } = useSharedPermissions(true)
  const [settings, setSettings] = useState<Partial<Record<SharedCapabilityKey, PermissionSetting>>>({})
  const row = data?.environments[env.id]

  const stored = (): Partial<Record<SharedCapabilityKey, PermissionSetting>> => {
    const out: Partial<Record<SharedCapabilityKey, PermissionSetting>> = {}
    for (const cap of data?.capabilities ?? []) out[cap.key] = row?.overrides[cap.key] ?? 'inherit'
    return out
  }
  const seeded = useRef(false)
  useEffect(() => {
    if (data && !seeded.current) {
      seeded.current = true
      setSettings({ ...stored(), ...(draftUser ? {} : draft ?? {}) })
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data])

  const changes = data ? changedSettings(stored(), settings) : {}
  const save = useMutation({
    mutationFn: () => saveSharedPermissions(changes, env.id),
    onSuccess: (resp) => {
      if (isStepUpRequired(resp)) {
        beginStepUp(resp.action_id, {
          kind: 'environment_change', action: resp.action, label: `Shared permissions for '${env.name}'`,
          startedAt: Date.now(), reopen: 'environments', permissionsDraft: { environmentId: env.id, settings },
        })
        return
      }
      toast({ title: `Shared permissions for '${env.name}' saved`, variant: 'success' })
      seeded.current = false
      queryClient.invalidateQueries({ queryKey: ['shared_permissions'] })
      queryClient.invalidateQueries({ queryKey: ['environments'] })
    },
    onError: (err: Error) => toast({ title: 'Could not save shared permissions', description: err.message, variant: 'error' }),
  })

  if (isLoading) return <div className="text-xs text-text-dim">Loading…</div>
  if (isError) return <ErrorNotice title="Could not load shared permissions" error={mainAddressOnly(error)} onRetry={() => refetch()} retrying={isFetching} />
  if (!data || !row) return null
  return (
    <div className="flex flex-col gap-2 border-t border-border-sub pt-2" role="group" aria-label={`Shared permissions for ${env.name}`}>
      <p className="text-[0.6875rem] text-text-dim">
        What other users may do with '{env.name}' when it is shared{row.shared ? '' : ' (it is private now; these apply once it is shared)'}.
        Its owner is never limited.
      </p>
      <PermissionSettingsList
        capabilities={data.capabilities}
        settings={settings}
        onChange={(key, value) => setSettings(s => ({ ...s, [key]: value }))}
        inherited={key => ({ value: data.defaults[key].value, from: data.defaults[key].source === 'default' ? 'global default' : 'built-in default' })}
        current={key => ({ value: row.effective[key].value, from: SOURCE_LABELS[row.effective[key].source] })}
        disabled={save.isPending}
      />
      <button
        type="button"
        className="btn-primary self-start !py-0.5 !px-2 text-xs"
        disabled={Object.keys(changes).length === 0 || save.isPending}
        onClick={() => save.mutate()}
      >
        Verify &amp; Save
      </button>
      <UserPermissionExceptions env={env} data={data} draftUser={draftUser} draft={draftUser ? draft : undefined} />
    </div>
  )
}
