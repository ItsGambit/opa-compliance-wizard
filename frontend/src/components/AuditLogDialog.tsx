import { useState } from 'react'
import * as Dialog from '@radix-ui/react-dialog'
import { useQuery } from '@tanstack/react-query'
import { RefreshCw, X } from 'lucide-react'
import { fetchAuditLog } from '../api/client'
import { formatDateTime } from '../utils/format'

interface Props {
  // Both optional -- omit for a self-contained trigger button, matching
  // EnvironmentManagerDialog's own open/onOpenChange pattern, since this
  // dialog is also opened remotely from SideNav's admin-only nav item.
  open?: boolean
  onOpenChange?: (open: boolean) => void
}

const PAGE_SIZE = 50

/** Admin-only audit log viewer (see server/serve.py's admin-gated
 * GET /api/audit_log). Every mutating action in this app -- environment
 * create/edit/delete/share, sync start/schedule, policy/group changes,
 * admin overrides on another user's environment -- already gets written
 * to audit_log.jsonl via engine.log_audit_event; this is the first UI
 * that actually reads it back. Renders as a flat, most-recent-first list
 * (not a table) since entries carry a free-form `details` object whose
 * shape varies by action -- forcing that into fixed columns would either
 * truncate real information or need a column per possible action. */
export function AuditLogDialog({ open: openProp, onOpenChange }: Props) {
  const [openState, setOpenState] = useState(false)
  const open = openProp ?? openState
  const setOpen = onOpenChange ?? setOpenState
  const [visibleCount, setVisibleCount] = useState(PAGE_SIZE)

  const { data, isLoading, isFetching, refetch } = useQuery({
    queryKey: ['audit_log', visibleCount],
    queryFn: () => fetchAuditLog(visibleCount, 0),
    enabled: open,
  })
  const entries = data?.entries ?? []

  return (
    <Dialog.Root open={open} onOpenChange={setOpen}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/60 z-40" />
        <Dialog.Content className="card fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-50 w-[36rem] max-h-[85vh] overflow-y-auto p-5">
          <div className="flex items-center justify-between mb-3">
            <div>
              <Dialog.Title className="text-sm font-semibold text-text">Audit Log</Dialog.Title>
              <p className="text-[0.6875rem] text-text-faint mt-0.5">
                Every write action across every environment and user — admin-only, for compliance visibility.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button type="button" className="btn-secondary !px-2" title="Refresh" onClick={() => refetch()} disabled={isFetching}>
                <RefreshCw size={12} className={isFetching ? 'animate-spin' : ''} />
              </button>
              <Dialog.Close asChild>
                <button type="button" className="text-text-faint hover:text-text-dim">
                  <X size={16} />
                </button>
              </Dialog.Close>
            </div>
          </div>

          {isLoading ? (
            <div className="text-xs text-text-faint py-6 text-center">Loading…</div>
          ) : entries.length === 0 ? (
            <div className="text-xs text-text-faint py-6 text-center">No audit log entries yet.</div>
          ) : (
            <div className="flex flex-col gap-1.5">
              {entries.map((entry, i) => (
                <div key={i} className="card p-2.5 text-xs">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-medium text-text">{entry.action}</span>
                    <span className="text-text-faint whitespace-nowrap">{formatDateTime(entry.timestamp)}</span>
                  </div>
                  <div className="text-text-faint mt-0.5">
                    {entry.actor_email ?? (entry.actor_sub ? entry.actor_sub : 'local / CLI')}
                  </div>
                  {entry.details && Object.keys(entry.details).length > 0 && (
                    <pre className="text-[0.6875rem] text-text-dim bg-bg-hover rounded p-1.5 mt-1.5 overflow-x-auto whitespace-pre-wrap">
                      {JSON.stringify(entry.details, null, 2)}
                    </pre>
                  )}
                </div>
              ))}
            </div>
          )}

          {entries.length >= visibleCount && (
            <button
              type="button"
              className="btn-secondary self-center mt-3 text-xs"
              disabled={isFetching}
              onClick={() => setVisibleCount(c => c + PAGE_SIZE)}
            >
              Load more
            </button>
          )}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}
