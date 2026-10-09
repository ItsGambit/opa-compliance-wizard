import { useEffect, useState } from 'react'
import * as Dialog from '@radix-ui/react-dialog'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Globe, KeyRound, Lock, Pencil, Plus, Trash2, X } from 'lucide-react'
import { activateEnvironment, deleteEnvironment, isStepUpRequired, saveEnvironment, setEnvironmentShared, type ApiError } from '../api/client'
import { toast } from '../hooks/useToast'
import type { Environment, EnvironmentFormValues, EnvironmentsResponse } from '../types'
import { can, canManageSync, isActiveRow, isAddressable } from '../utils/environmentRows'
import { beginStepUp, environmentDraftFrom, type PendingStepUp } from '../utils/stepUp'
import { EnvironmentPermissionsEditor } from './EnvironmentPermissionsEditor'
import { DialogCloseButton } from './DialogCloseButton'
import { EnvironmentForm } from './EnvironmentForm'
import { StatusBadge } from './StatusBadge'
import { SyncScheduleDialog } from './SyncScheduleDialog'

interface Props {
  data: EnvironmentsResponse | undefined
  open: boolean
  onOpenChange: (open: boolean) => void
  // True only for a verified Okta-admin-group member (see
  // server/auth_gate.py's OKTA_ADMIN_GROUP_ID check + serve.py's
  // _is_admin_from_headers). When true, Edit/Delete/Share are enabled on
  // EVERY environment, not just this user's own -- the backend already
  // enforces the real permission boundary (upsert_environment/
  // delete_environment/set_environment_shared's is_admin bypass); this is
  // purely about not showing disabled controls to someone who can
  // actually use them.
  isAdmin?: boolean
  /** 5.42.0: may edit shared-environment permissions (verified admin, or
   * the local-mode operator -- /api/whoami's can_admin). */
  canAdmin?: boolean
  /** 5.42.0: a change from this dialog whose MFA approval didn't complete --
   * its form reopens with the user's input. */
  restore?: Extract<PendingStepUp, { kind: 'environment_change' }> | null
}

const SHARED_ROW_CAPABILITIES = [
  ['view_archive', 'archived reports'], ['live_read', 'live queries'], ['tenant_write', 'changes in OPA / Okta'],
  ['sync_now', 'Sync now'], ['sync_settings', 'sync settings'], ['import_csv', 'CSV import'],
  ['reset_watermark', 'watermark reset'],
] as const

export function EnvironmentManagerDialog({ data, open, onOpenChange, isAdmin, canAdmin, restore }: Props) {
  const [editing, setEditingState] = useState<Environment | 'new' | null>(null)
  const [formDraft, setFormDraft] = useState<Partial<EnvironmentFormValues> | undefined>(undefined)
  const [permissionsFor, setPermissionsFor] = useState<string | null>(null)
  const [confirmingDelete, setConfirmingDelete] = useState<string | null>(null)
  // UI-16: sharing hands every logged-in user working use of the
  // environment's credentials -- one click no longer does it.
  const [confirmingShare, setConfirmingShare] = useState<string | null>(null)
  const queryClient = useQueryClient()

  // Environment-scoped caches are dropped by App when the active
  // environment actually changes (UI-05); here only the list itself.
  const invalidateList = () => queryClient.invalidateQueries({ queryKey: ['environments'] })

  const saveMutation = useMutation({
    mutationFn: (values: EnvironmentFormValues) => saveEnvironment(values),
    onSuccess: (resp, values) => {
      if (isStepUpRequired(resp)) {
        // 5.42.0: hosted mode -- approve this save with MFA first.
        beginStepUp(resp.action_id, {
          kind: 'environment_change', action: resp.action, label: `Save environment '${values.name.trim()}'`,
          startedAt: Date.now(), environmentDraft: environmentDraftFrom(values), reopen: 'environments',
        })
        return
      }
      toast(resp.activated
        ? { title: `Connected to '${resp.active}'`, variant: 'success' }
        : { title: `Saved '${values.name}'`, description: "It belongs to another user, so your active environment didn't change.", variant: 'success' })
      setEditing(null)
      invalidateList()
      // UI-22: drop the submitted secrets from the mutation's memory.
      saveMutation.reset()
    },
    onError: (err: ApiError) => {
      if (err.body?.saved) {
        // FE-11/UI-16: the record WAS written (502 "Saved, but could not
        // connect") -- show it in the list and close the form, so a second
        // submit doesn't look like the only way forward.
        toast({ title: 'Saved, but could not connect', description: err.message, variant: 'error' })
        setEditing(null)
        invalidateList()
        saveMutation.reset()
        return
      }
      toast({ title: 'Could not connect', description: err.message, variant: 'error' })
    },
  })

  // UI-16: a fresh form never shows the previous attempt's error.
  const setEditing = (next: Environment | 'new' | null) => {
    saveMutation.reset()
    setFormDraft(undefined)
    setEditingState(next)
  }

  // 5.42.0: reopen the per-environment permissions a not-applied save came from.
  useEffect(() => {
    if (open && restore?.permissionsDraft?.environmentId) setPermissionsFor(restore.permissionsDraft.environmentId)
  }, [open, restore])

  // 5.42.0: reopen the form a not-applied save came from, with its input.
  useEffect(() => {
    if (!open || !restore?.environmentDraft || !data) return
    const draft = restore.environmentDraft
    const target = draft.id ? data.environments.find(e => e.id === draft.id) : undefined
    saveMutation.reset()
    setEditingState(target ?? 'new')
    setFormDraft(draft)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, restore, data !== undefined])

  const activateMutation = useMutation({
    // UI-07: by name (what the server resolves) plus the row's id, so the
    // server refuses instead of activating a different same-named tenant.
    mutationFn: (env: Environment) => activateEnvironment(env.name, env.id),
    onSuccess: (resp) => {
      toast({ title: `Switched to '${resp.active}'`, variant: 'success' })
      invalidateList()
    },
    onError: (err: Error) => {
      toast({ title: 'Could not activate', description: err.message, variant: 'error' })
      invalidateList()
    },
  })

  const deleteMutation = useMutation({
    mutationFn: ({ name, id }: { name: string; id: string }) => deleteEnvironment(name, id),
    onSuccess: (resp, { name }) => {
      if (isStepUpRequired(resp)) {
        beginStepUp(resp.action_id, {
          kind: 'environment_change', action: resp.action, label: `Delete '${name}'`, startedAt: Date.now(), reopen: 'environments',
        })
        return
      }
      toast({ title: `Deleted '${name}'`, variant: 'default' })
      setConfirmingDelete(null)
      invalidateList()
    },
    onError: (err: Error) => toast({ title: 'Could not delete', description: err.message, variant: 'error' }),
  })

  const shareMutation = useMutation({
    // `id` (the real storage key -- see Environment.id) disambiguates an
    // admin's share toggle from a same-named environment under a
    // different owner.
    mutationFn: ({ name, shared, id }: { name: string; shared: boolean; id: string }) => setEnvironmentShared(name, shared, id),
    onSuccess: (resp, { name, shared }) => {
      if (isStepUpRequired(resp)) {
        beginStepUp(resp.action_id, {
          kind: 'environment_change', action: resp.action, label: shared ? `Share '${name}'` : `Make '${name}' private`,
          startedAt: Date.now(), reopen: 'environments',
        })
        return
      }
      toast({ title: resp.shared ? `'${resp.name}' is now shared` : `'${resp.name}' is now private`, variant: 'success' })
      setConfirmingShare(null)
      invalidateList()
    },
    onError: (err: Error) => toast({ title: 'Could not change sharing', description: err.message, variant: 'error' }),
  })

  const handleOpenChange = (next: boolean) => {
    if (!next) {
      // UI-16: reopening starts clean -- no half-open edit panel or
      // pending "Delete …?" prompt from an earlier visit.
      setEditing(null)
      setConfirmingDelete(null)
      setConfirmingShare(null)
      setPermissionsFor(null)
    }
    onOpenChange(next)
  }

  const saveApiError = (saveMutation.error as ApiError | null)?.body?.error

  return (
    <Dialog.Root open={open} onOpenChange={handleOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/60 z-40" />
        <Dialog.Content
          aria-describedby={undefined}
          className="card fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-50 w-[calc(100vw-2rem)] sm:w-[30rem] max-h-[85vh] overflow-y-auto p-5"
        >
          <div className="flex items-center justify-between mb-3">
            <Dialog.Title className="text-sm font-semibold text-text">Environments</Dialog.Title>
            <DialogCloseButton />
          </div>

          <div className="flex flex-col gap-2 mb-4">
            {(data?.environments ?? []).length === 0 && (
              <div className="text-xs text-text-faint">No environments saved yet.</div>
            )}
            {(data?.environments ?? []).map(env => {
              const active = isActiveRow(env, data)
              const addressable = isAddressable(env)
              const canEdit = env.is_own || !!isAdmin
              return (
                <div key={env.id} className="card p-2.5 flex flex-col gap-1.5">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-text">{env.name}</span>
                    {active && <StatusBadge label="active" variant="exists" />}
                    {canEdit ? (
                      <button
                        type="button"
                        title={env.shared ? 'Shared — click to make private' : 'Private — click to share with every other logged-in user'}
                        aria-label={env.shared ? `Sharing for ${env.name}: shared. Make private` : `Sharing for ${env.name}: private. Share`}
                        disabled={shareMutation.isPending}
                        onClick={() => {
                          if (env.shared) shareMutation.mutate({ name: env.name, shared: false, id: env.id })
                          else setConfirmingShare(env.id)
                        }}
                        className={`flex items-center gap-1 text-[0.6875rem] font-medium px-1.5 py-0.5 rounded border whitespace-nowrap ${
                          env.shared
                            ? 'bg-accent-dim text-text border-accent/40'
                            : 'bg-bg-hover text-text-dim border-border'
                        }`}
                      >
                        {env.shared ? <Globe size={11} aria-hidden="true" /> : <Lock size={11} aria-hidden="true" />}
                        {env.shared ? 'Shared' : 'Private'}
                      </button>
                    ) : (
                      <span
                        title="Shared with you by another user — you can use it, but only its owner can change sharing or delete it"
                        className="flex items-center gap-1 text-[0.6875rem] font-medium px-1.5 py-0.5 rounded border whitespace-nowrap bg-bg-hover text-text-dim border-border"
                      >
                        <Globe size={11} aria-hidden="true" /> Shared with you
                      </span>
                    )}
                    {!env.is_own && isAdmin && (
                      <span
                        title="You're viewing/managing this via admin override — it's owned by another user"
                        className="text-[0.6875rem] font-medium px-1.5 py-0.5 rounded border whitespace-nowrap bg-warn/10 text-warn border-warn/40"
                      >
                        Admin
                      </span>
                    )}
                    <div className="flex-1" />
                    {!active && addressable && (
                      <button
                        type="button"
                        className="btn-secondary !py-0.5 !px-2 text-xs"
                        disabled={activateMutation.isPending}
                        onClick={() => activateMutation.mutate(env)}
                        aria-label={`Activate ${env.name}`}
                      >
                        Activate
                      </button>
                    )}
                    <button
                      type="button"
                      className="btn-secondary !px-1.5 !py-1"
                      title={canEdit ? 'Edit' : "Owned by another user — you can't edit it"}
                      aria-label={`Edit ${env.name}`}
                      disabled={!canEdit}
                      onClick={() => setEditing(env)}
                    >
                      <Pencil size={12} aria-hidden="true" />
                    </button>
                    <button
                      type="button"
                      className="btn-secondary !px-1.5 !py-1 hover:!text-loss"
                      title={canEdit ? 'Delete' : "Owned by another user — you can't delete it"}
                      aria-label={`Delete ${env.name}`}
                      disabled={!canEdit}
                      onClick={() => setConfirmingDelete(env.id)}
                    >
                      <Trash2 size={12} aria-hidden="true" />
                    </button>
                  </div>
                  <div className="text-[0.6875rem] text-text-faint">
                    {env.base_domain} · team {env.team_name} · key {env.key_id.slice(0, 8)}…
                    {env.has_okta_token ? ' · Okta connected' : ' · no Okta token (can\'t create groups)'}
                  </div>
                  {!addressable && (
                    <div className="text-[0.6875rem] text-text-faint">
                      {env.is_own || env.shared
                        ? `Hidden by your own environment named '${env.name}' — rename one of them to use this one.`
                        : "Another user's private environment — you can manage it here, but not activate it."}
                    </div>
                  )}
                  {!env.is_own && env.permissions && (
                    <div className="text-[0.6875rem] text-text-dim">
                      {/* 5.42.0: what this shared environment lets YOU do (an admin decides). */}
                      You can use: {SHARED_ROW_CAPABILITIES.filter(([k]) => can(env, k)).map(([, label]) => label).join(', ') || 'nothing beyond activating it'}.
                      {SHARED_ROW_CAPABILITIES.some(([k]) => !can(env, k)) && (
                        <> Not allowed for shared users: {SHARED_ROW_CAPABILITIES.filter(([k]) => !can(env, k)).map(([, label]) => label).join(', ')}.</>
                      )}
                    </div>
                  )}
                  <div className="flex items-center gap-1.5">
                    {canManageSync(env) && (
                      <SyncScheduleDialog
                        env={env}
                        restoreDraft={restore?.syncDraft?.environmentId === env.id ? restore.syncDraft.schedule : undefined}
                      />
                    )}
                    {canAdmin && (
                      <button
                        type="button"
                        className="btn-secondary !py-0.5 !px-1.5 text-[0.6875rem]"
                        aria-expanded={permissionsFor === env.id}
                        aria-label={`Shared permissions for ${env.name}`}
                        title="What other users may do with this environment when it is shared (admins only)"
                        onClick={() => setPermissionsFor(p => (p === env.id ? null : env.id))}
                      >
                        <KeyRound size={11} aria-hidden="true" /> Shared permissions
                      </button>
                    )}
                    {env.sync_schedule.enabled && (
                      <span className="text-[0.6875rem] text-win">Compliance sync on</span>
                    )}
                  </div>
                  {canAdmin && permissionsFor === env.id && (
                    <EnvironmentPermissionsEditor
                      env={env}
                      draft={restore?.permissionsDraft?.environmentId === env.id ? restore.permissionsDraft.settings : undefined}
                    />
                  )}
                  {confirmingShare === env.id && (
                    <div className="flex flex-wrap items-center gap-2 text-xs text-warn" role="group" aria-label={`Confirm sharing ${env.name}`}>
                      Share "{env.name}"? Every logged-in user will be able to use its service credentials (read and
                      write through this app).
                      <button
                        type="button"
                        className="btn-primary !py-0.5 !px-2"
                        disabled={shareMutation.isPending}
                        onClick={() => shareMutation.mutate({ name: env.name, shared: true, id: env.id })}
                      >
                        {shareMutation.isPending ? 'Sharing…' : 'Yes, share'}
                      </button>
                      <button type="button" className="btn-secondary !py-0.5 !px-2" onClick={() => setConfirmingShare(null)}>
                        Cancel
                      </button>
                    </div>
                  )}
                  {confirmingDelete === env.id && (
                    <div className="flex items-center gap-2 text-xs text-loss" role="group" aria-label={`Confirm deleting ${env.name}`}>
                      Delete "{env.name}"?
                      <button
                        type="button"
                        className="btn-danger !py-0.5 !px-2"
                        disabled={deleteMutation.isPending}
                        onClick={() => deleteMutation.mutate({ name: env.name, id: env.id })}
                      >
                        Yes, delete
                      </button>
                      <button type="button" className="btn-secondary !py-0.5 !px-2" onClick={() => setConfirmingDelete(null)}>
                        Cancel
                      </button>
                    </div>
                  )}
                </div>
              )
            })}
          </div>

          {editing === null ? (
            <button type="button" className="btn-secondary self-start" onClick={() => setEditing('new')}>
              <Plus size={13} aria-hidden="true" /> Add environment
            </button>
          ) : (
            <div className="card p-3">
              <div className="flex items-center justify-between mb-2">
                <span className="section-label">{editing === 'new' ? 'New environment' : `Edit '${editing.name}'`}</span>
                <button type="button" aria-label="Close the form" title="Close the form" className="text-text-faint hover:text-text-dim" onClick={() => setEditing(null)}>
                  <X size={14} aria-hidden="true" />
                </button>
              </div>
              <EnvironmentForm
                key={`${editing === 'new' ? 'new' : editing.id}-${formDraft ? 'draft' : 'clean'}`}
                initial={editing === 'new' ? undefined : editing}
                draft={formDraft}
                submitLabel={editing === 'new' ? 'Save & Connect' : 'Save & Reconnect'}
                isSubmitting={saveMutation.isPending}
                errorMessage={saveApiError}
                onSubmit={values => saveMutation.mutate(values)}
              />
            </div>
          )}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}
