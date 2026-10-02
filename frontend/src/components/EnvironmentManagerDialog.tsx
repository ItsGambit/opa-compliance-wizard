import { useState } from 'react'
import * as Dialog from '@radix-ui/react-dialog'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Globe, Lock, Pencil, Plus, Settings, Trash2, X } from 'lucide-react'
import { activateEnvironment, deleteEnvironment, saveEnvironment, setEnvironmentShared } from '../api/client'
import { toast } from '../hooks/useToast'
import type { ApiErrorBody, Environment, EnvironmentFormValues, EnvironmentsResponse } from '../types'
import { EnvironmentForm } from './EnvironmentForm'
import { StatusBadge } from './StatusBadge'
import { SyncScheduleDialog } from './SyncScheduleDialog'

interface Props {
  data: EnvironmentsResponse | undefined
  // Both optional -- omit for the existing self-contained gear-icon trigger
  // (falls back to internal state, unchanged behavior). Pass both when
  // something else (e.g. SideNav's "Environments" nav item) needs to open
  // this same dialog without duplicating its content.
  open?: boolean
  onOpenChange?: (open: boolean) => void
  // True only for a verified Okta-admin-group member (see
  // server/auth_gate.py's OKTA_ADMIN_GROUP_ID check + serve.py's
  // _is_admin_from_headers). When true, Edit/Delete/Share are enabled on
  // EVERY environment, not just this user's own -- the backend already
  // enforces the real permission boundary (upsert_environment/
  // delete_environment/set_environment_shared's is_admin bypass); this is
  // purely about not showing disabled controls to someone who can
  // actually use them.
  isAdmin?: boolean
}

export function EnvironmentManagerDialog({ data, open: openProp, onOpenChange, isAdmin }: Props) {
  const [openState, setOpenState] = useState(false)
  const open = openProp ?? openState
  const setOpen = onOpenChange ?? setOpenState
  const [editing, setEditing] = useState<Environment | 'new' | null>(null)
  const [confirmingDelete, setConfirmingDelete] = useState<string | null>(null)
  const queryClient = useQueryClient()

  const invalidateAll = () => {
    queryClient.invalidateQueries({ queryKey: ['environments'] })
    queryClient.invalidateQueries({ queryKey: ['resource_groups'] })
  }

  const saveMutation = useMutation({
    mutationFn: (values: EnvironmentFormValues) => saveEnvironment(values),
    onSuccess: (resp) => {
      toast({ title: `Connected to '${resp.active}'`, variant: 'success' })
      setEditing(null)
      invalidateAll()
    },
    onError: (err: Error) => toast({ title: 'Could not connect', description: err.message, variant: 'error' }),
  })

  const activateMutation = useMutation({
    mutationFn: (name: string) => activateEnvironment(name),
    onSuccess: (resp) => {
      toast({ title: `Switched to '${resp.active}'`, variant: 'success' })
      invalidateAll()
    },
    onError: (err: Error) => toast({ title: 'Could not activate', description: err.message, variant: 'error' }),
  })

  const deleteMutation = useMutation({
    mutationFn: ({ name, id }: { name: string; id: string }) => deleteEnvironment(name, id),
    onSuccess: (_resp, { name }) => {
      toast({ title: `Deleted '${name}'`, variant: 'default' })
      setConfirmingDelete(null)
      invalidateAll()
    },
    onError: (err: Error) => toast({ title: 'Could not delete', description: err.message, variant: 'error' }),
  })

  const shareMutation = useMutation({
    // `id` (the real storage key -- see Environment.id) disambiguates an
    // admin's share toggle from a same-named environment under a
    // different owner; always passed since this dialog always has a full
    // Environment object in hand.
    mutationFn: ({ name, shared, id }: { name: string; shared: boolean; id: string }) => setEnvironmentShared(name, shared, id),
    onSuccess: (resp) => {
      toast({ title: resp.shared ? `'${resp.name}' is now shared` : `'${resp.name}' is now private`, variant: 'success' })
      invalidateAll()
    },
    onError: (err: Error) => toast({ title: 'Could not change sharing', description: err.message, variant: 'error' }),
  })

  const saveApiError = (saveMutation.error as (Error & { body?: ApiErrorBody }) | null)?.body?.error

  return (
    <Dialog.Root open={open} onOpenChange={setOpen}>
      {openProp === undefined && (
        <Dialog.Trigger asChild>
          <button type="button" className="btn-secondary !px-2" title="Manage environments">
            <Settings size={14} />
          </button>
        </Dialog.Trigger>
      )}
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/60 z-40" />
        <Dialog.Content className="card fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-50 w-[calc(100vw-2rem)] sm:w-[30rem] max-h-[85vh] overflow-y-auto p-5">
          <div className="flex items-center justify-between mb-3">
            <Dialog.Title className="text-sm font-semibold text-text">Environments</Dialog.Title>
            <Dialog.Close asChild>
              <button type="button" className="text-text-faint hover:text-text-dim">
                <X size={16} />
              </button>
            </Dialog.Close>
          </div>

          <div className="flex flex-col gap-2 mb-4">
            {(data?.environments ?? []).length === 0 && (
              <div className="text-xs text-text-faint">No environments saved yet.</div>
            )}
            {(data?.environments ?? []).map(env => (
              <div key={env.id} className="card p-2.5 flex flex-col gap-1.5">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-text">{env.name}</span>
                  {data?.active === env.name && <StatusBadge label="active" variant="exists" />}
                  {env.is_own || isAdmin ? (
                    <button
                      type="button"
                      title={env.shared ? 'Shared — click to make private' : 'Private — click to share with every other logged-in user'}
                      disabled={shareMutation.isPending}
                      onClick={() => shareMutation.mutate({ name: env.name, shared: !env.shared, id: env.id })}
                      className={`flex items-center gap-1 text-[0.6875rem] font-medium px-1.5 py-0.5 rounded border whitespace-nowrap ${
                        env.shared
                          ? 'bg-accent-dim text-accent border-accent/40'
                          : 'bg-bg-hover text-text-faint border-border'
                      }`}
                    >
                      {env.shared ? <Globe size={11} /> : <Lock size={11} />}
                      {env.shared ? 'Shared' : 'Private'}
                    </button>
                  ) : (
                    <span
                      title="Shared with you by another user — you can use it, but only its owner can change sharing or delete it"
                      className="flex items-center gap-1 text-[0.6875rem] font-medium px-1.5 py-0.5 rounded border whitespace-nowrap bg-bg-hover text-text-faint border-border"
                    >
                      <Globe size={11} /> Shared with you
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
                  {data?.active !== env.name && (
                    <button
                      type="button"
                      className="btn-secondary !py-0.5 !px-2 text-xs"
                      disabled={activateMutation.isPending}
                      onClick={() => activateMutation.mutate(env.name)}
                    >
                      Activate
                    </button>
                  )}
                  <button
                    type="button"
                    className="btn-secondary !px-1.5 !py-1"
                    title={env.is_own || isAdmin ? 'Edit' : "Owned by another user — you can't edit it"}
                    disabled={!env.is_own && !isAdmin}
                    onClick={() => setEditing(env)}
                  >
                    <Pencil size={12} />
                  </button>
                  <button
                    type="button"
                    className="btn-secondary !px-1.5 !py-1 hover:!text-loss"
                    title={env.is_own || isAdmin ? 'Delete' : "Owned by another user — you can't delete it"}
                    disabled={!env.is_own && !isAdmin}
                    onClick={() => setConfirmingDelete(env.id)}
                  >
                    <Trash2 size={12} />
                  </button>
                </div>
                <div className="text-[0.6875rem] text-text-faint">
                  {env.base_domain} · team {env.team_name} · key {env.key_id.slice(0, 8)}…
                  {env.has_okta_token ? ' · Okta connected' : ' · no Okta token (can\'t create groups)'}
                </div>
                <div className="flex items-center gap-1.5">
                  <SyncScheduleDialog env={env} />
                  {env.sync_schedule.enabled && (
                    <span className="text-[0.6875rem] text-win">Compliance sync on</span>
                  )}
                </div>
                {confirmingDelete === env.id && (
                  <div className="flex items-center gap-2 text-xs text-loss">
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
            ))}
          </div>

          {editing === null ? (
            <button type="button" className="btn-secondary self-start" onClick={() => setEditing('new')}>
              <Plus size={13} /> Add environment
            </button>
          ) : (
            <div className="card p-3">
              <div className="flex items-center justify-between mb-2">
                <span className="section-label">{editing === 'new' ? 'New environment' : `Edit '${editing.name}'`}</span>
                <button type="button" className="text-text-faint hover:text-text-dim" onClick={() => setEditing(null)}>
                  <X size={14} />
                </button>
              </div>
              <EnvironmentForm
                initial={editing === 'new' ? undefined : editing}
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
