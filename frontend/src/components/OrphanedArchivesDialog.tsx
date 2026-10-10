import { useState } from 'react'
import * as Dialog from '@radix-ui/react-dialog'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Trash2 } from 'lucide-react'
import { fetchOrphanedArchives, isStepUpRequired, purgeOrphanedArchive } from '../api/client'
import { toast } from '../hooks/useToast'
import { formatDateTime } from '../utils/format'
import { formatBytes, purgeConfirmationToken } from '../utils/orphanedArchives'
import { mainAddressOnly } from '../utils/sharedPermissions'
import { beginStepUp } from '../utils/stepUp'
import { DialogCloseButton } from './DialogCloseButton'
import { ErrorNotice } from './ErrorNotice'
import { Field } from './Field'

interface Props {
  open: boolean
  onOpenChange: (open: boolean) => void
}

/** DATA-12 admin UI (5.40.7): archives whose environment was deleted --
 * evidence that no other screen can reach any more. Lists them (GET
 * /api/archives/orphaned) and purges one (DELETE /api/archives/{id}).
 * Purging destroys compliance evidence, so it takes an explicit typed
 * confirmation here; the server re-checks admin rights, refuses while the
 * environment exists or a sync runs, and audit-logs the per-table counts. */
export function OrphanedArchivesDialog({ open, onOpenChange }: Props) {
  const queryClient = useQueryClient()
  const [confirmingId, setConfirmingId] = useState<string | null>(null)
  const [typed, setTyped] = useState('')

  const { data, isLoading, isError, error, refetch, isFetching } = useQuery({
    queryKey: ['orphaned_archives'],
    queryFn: async () => (await fetchOrphanedArchives()).archives,
    enabled: open,
    // An on-demand admin scan (an index scan of the whole archive): fresh
    // every time the dialog opens, never in the background.
    staleTime: 0,
  })

  const purge = useMutation({
    mutationFn: (environmentId: string) => purgeOrphanedArchive(environmentId),
    onSuccess: (resp, environmentId) => {
      if (isStepUpRequired(resp)) {
        // 5.42.0: hosted mode -- approve the purge with MFA first.
        beginStepUp(resp.action_id, {
          kind: 'environment_change', action: resp.action, label: `Purge the archive of ${environmentId.slice(0, 8)}…`,
          startedAt: Date.now(), reopen: 'orphaned_archives',
        })
        return
      }
      const events = typeof resp.events === 'number' ? resp.events : 0
      const manifests = typeof resp.ingestion_manifests === 'number' ? resp.ingestion_manifests : 0
      toast({
        title: 'Archive purged',
        description: `Removed ${events.toLocaleString()} event(s) and ${manifests.toLocaleString()} manifest(s). The purge is recorded in the audit log.`,
        variant: 'success',
      })
      setConfirmingId(null)
      setTyped('')
      queryClient.invalidateQueries({ queryKey: ['orphaned_archives'] })
      queryClient.invalidateQueries({ queryKey: ['audit_log'] })
    },
    onError: (err: Error) => toast({ title: 'Could not purge the archive', description: err.message, variant: 'error' }),
  })

  const handleOpenChange = (next: boolean) => {
    if (!next) {
      setConfirmingId(null)
      setTyped('')
    }
    onOpenChange(next)
  }

  const archives = data ?? []

  return (
    <Dialog.Root open={open} onOpenChange={handleOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/60 z-40" />
        <Dialog.Content className="card fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-50 w-[calc(100vw-2rem)] sm:w-[34rem] max-h-[85vh] overflow-y-auto p-5">
          <div className="flex items-center justify-between mb-2">
            <Dialog.Title className="text-sm font-semibold text-text">Orphaned archives</Dialog.Title>
            <DialogCloseButton />
          </div>
          <Dialog.Description className="text-xs text-text-dim mb-4 leading-relaxed">
            Compliance archives whose environment has been deleted. Nothing else in the app can show, sync or export
            them. Purging one permanently deletes its events and evidence-chain records; take a backup of the
            database first if you may need them (see docs/hosting.md).
          </Dialog.Description>

          {isLoading && <div className="text-xs text-text-faint">Loading…</div>}
          {isError && <ErrorNotice title="Could not list orphaned archives" error={mainAddressOnly(error)} onRetry={() => refetch()} retrying={isFetching} />}
          {!isLoading && !isError && archives.length === 0 && (
            <div className="text-xs text-text-dim">No orphaned archives. Every archive belongs to an existing environment.</div>
          )}

          <ul className="flex flex-col gap-2">
            {archives.map(a => {
              const token = purgeConfirmationToken(a.environment_id)
              const confirming = confirmingId === a.environment_id
              return (
                <li key={a.environment_id} className="card p-2.5 flex flex-col gap-1.5">
                  <div className="flex items-center gap-2">
                    <code className="text-xs text-text break-all flex-1">{a.environment_id}</code>
                    {!confirming && (
                      <button
                        type="button"
                        className="btn-secondary !px-2 !py-0.5 text-xs hover:!text-loss"
                        onClick={() => { setConfirmingId(a.environment_id); setTyped('') }}
                        disabled={purge.isPending}
                      >
                        <Trash2 size={12} aria-hidden="true" /> Purge…
                      </button>
                    )}
                  </div>
                  <div className="text-[0.6875rem] text-text-dim">
                    {a.event_count.toLocaleString()} event(s) · {formatBytes(a.bytes)} · {a.manifest_count.toLocaleString()} manifest(s)
                    {a.oldest_published && <> · {formatDateTime(a.oldest_published)} to {formatDateTime(a.newest_published)}</>}
                  </div>
                  {confirming && (
                    <div className="flex flex-col gap-2 border-t border-border-sub pt-2">
                      <p className="text-xs text-loss">
                        This permanently deletes {a.event_count.toLocaleString()} archived event(s) and{' '}
                        {a.manifest_count.toLocaleString()} evidence manifest(s). It cannot be undone.
                      </p>
                      <Field label={<>Type <code className="normal-case">{token}</code> to confirm</>}>
                        {id => (
                          <input
                            id={id}
                            className="text-input w-40 font-mono"
                            value={typed}
                            autoComplete="off"
                            spellCheck={false}
                            onChange={e => setTyped(e.target.value)}
                          />
                        )}
                      </Field>
                      <div className="flex gap-2">
                        <button
                          type="button"
                          className="btn-danger !py-0.5 !px-2 text-xs"
                          disabled={typed.trim() !== token || purge.isPending}
                          onClick={() => purge.mutate(a.environment_id)}
                        >
                          {purge.isPending ? 'Purging…' : 'Purge archive'}
                        </button>
                        <button
                          type="button"
                          className="btn-secondary !py-0.5 !px-2 text-xs"
                          disabled={purge.isPending}
                          onClick={() => { setConfirmingId(null); setTyped('') }}
                        >
                          Cancel
                        </button>
                      </div>
                    </div>
                  )}
                </li>
              )
            })}
          </ul>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}
