import { useState } from 'react'
import * as Dialog from '@radix-ui/react-dialog'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Pencil, Plus, Settings, Trash2, X } from 'lucide-react'
import { activateEnvironment, deleteEnvironment, saveEnvironment } from '../api/client'
import { toast } from '../hooks/useToast'
import type { ApiErrorBody, Environment, EnvironmentFormValues, EnvironmentsResponse } from '../types'
import { EnvironmentForm } from './EnvironmentForm'
import { LogRetentionIndicator } from './LogRetentionIndicator'
import { StatusBadge } from './StatusBadge'

interface Props {
  data: EnvironmentsResponse | undefined
}

export function EnvironmentManagerDialog({ data }: Props) {
  const [open, setOpen] = useState(false)
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
    mutationFn: (name: string) => deleteEnvironment(name),
    onSuccess: (_resp, name) => {
      toast({ title: `Deleted '${name}'`, variant: 'default' })
      setConfirmingDelete(null)
      invalidateAll()
    },
    onError: (err: Error) => toast({ title: 'Could not delete', description: err.message, variant: 'error' }),
  })

  const saveApiError = (saveMutation.error as (Error & { body?: ApiErrorBody }) | null)?.body?.error

  return (
    <Dialog.Root open={open} onOpenChange={setOpen}>
      <Dialog.Trigger asChild>
        <button type="button" className="btn-secondary !px-2" title="Manage environments">
          <Settings size={14} />
        </button>
      </Dialog.Trigger>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/60 z-40" />
        <Dialog.Content className="card fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-50 w-[30rem] max-h-[85vh] overflow-y-auto p-5">
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
              <div key={env.name} className="card p-2.5 flex flex-col gap-1.5">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-text">{env.name}</span>
                  {data?.active === env.name && <StatusBadge label="active" variant="exists" />}
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
                    title="Edit"
                    onClick={() => setEditing(env)}
                  >
                    <Pencil size={12} />
                  </button>
                  <button
                    type="button"
                    className="btn-secondary !px-1.5 !py-1 hover:!text-loss"
                    title="Delete"
                    onClick={() => setConfirmingDelete(env.name)}
                  >
                    <Trash2 size={12} />
                  </button>
                </div>
                <div className="text-[0.6875rem] text-text-faint">
                  {env.base_domain} · team {env.team_name} · key {env.key_id.slice(0, 8)}…
                  {env.has_okta_token ? ' · Okta connected' : ' · no Okta token (can\'t create groups)'}
                </div>
                <LogRetentionIndicator enabled={env.preserve_logs_locally} envName={env.name} />
                {confirmingDelete === env.name && (
                  <div className="flex items-center gap-2 text-xs text-loss">
                    Delete "{env.name}"?
                    <button
                      type="button"
                      className="btn-danger !py-0.5 !px-2"
                      disabled={deleteMutation.isPending}
                      onClick={() => deleteMutation.mutate(env.name)}
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
