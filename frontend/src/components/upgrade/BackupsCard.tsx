import { useState } from 'react'
import type { UpgradeStatus } from '../../types'
import { formatDateTime } from '../../utils/format'
import { formatBytes } from '../../utils/upgrade'
import { CARD_TITLE } from './parts'
import { TypedConfirmDialog } from './TypedConfirmDialog'
import { useUpgradeRequest } from './useUpgradeRequest'

/** Artboard 01, "Pre-upgrade backups": what the updater kept before each upgrade (names, sizes, dates and the integrity result it
 * recorded; the directory itself is root-only). Never deleted automatically; the delete is typed, needs MFA, and always keeps the newest copy
 * and the last upgrade's. */
export function BackupsCard({ status }: { status: UpgradeStatus }) {
  const rows = status.upgrade?.backups?.backups ?? []
  const [open, setOpen] = useState(false)
  const [keep, setKeep] = useState(1)
  const prune = useUpgradeRequest('Delete old pre-upgrade backups', () => setOpen(false))
  if (!status.upgrade?.backups) return null
  const newestFirst = [...rows].sort((a, b) => b.taken_at.localeCompare(a.taken_at))
  const doomed = newestFirst.slice(Math.max(keep, 1))
  const busy = status.upgrade.run?.result === null && !!status.upgrade.run?.step
  return (
    <section className="card p-4" aria-labelledby="t-backups">
      <h2 className={CARD_TITLE} id="t-backups">Pre-upgrade backups</h2>
      {rows.length === 0 ? <p className="text-xs text-text-dim m-0">None yet: one is taken before each upgrade.</p> : (
        <table className="w-full text-xs border-collapse">
          <thead><tr className="text-left">
            {['Taken before', 'Size', 'Integrity'].map(h => <th key={h} scope="col" className="section-label pb-1 pr-3">{h}</th>)}
          </tr></thead>
          <tbody>
            {newestFirst.map(b => (
              <tr key={b.name} className="border-t border-border-sub">
                <td className="py-1.5 pr-3 text-text-dim">{b.taken_before ?? 'earlier version'} · {formatDateTime(b.taken_at)}</td>
                <td className="py-1.5 pr-3 text-text-dim">{formatBytes(b.size)}</td>
                <td className="py-1.5 text-text-dim">{b.integrity === 'ok' ? <><span className="text-win" aria-hidden="true">✓</span> ok</> : b.integrity ?? 'not recorded'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div className="flex gap-2 flex-wrap items-center mt-3">
        <button type="button" className="btn-secondary !text-text-dim" disabled={rows.length < 2 || busy} onClick={() => setOpen(true)}>Delete older backups…</button>
        <span className="text-xs text-muted">Never deleted automatically. Typed confirmation and step-up required; the newest copy is always kept. From the server: <code className="font-mono">sudo ocw-updater prune-backups --keep N --confirm PRUNE</code></span>
      </div>
      <TypedConfirmDialog open={open} onOpenChange={setOpen} title="Delete older pre-upgrade backups?" word="PRUNE" confirmLabel="Delete" danger
        busy={prune.isPending} onConfirm={() => prune.mutate({ kind: 'prune_backups', confirm: 'PRUNE', keep_last: Math.max(keep, 1) })}>
        <label className="flex items-center gap-2">Keep the newest
          <input type="number" min={1} max={50} className="text-input w-16" value={keep} aria-label="Number of newest backups to keep"
            onChange={e => setKeep(Math.min(50, Math.max(1, Number(e.target.value) || 1)))} /> backups.</label>
        <p className="m-0">{doomed.length === 0 ? 'Nothing would be deleted.' : <>This deletes {doomed.length} backup{doomed.length === 1 ? '' : 's'} ({formatBytes(doomed.reduce((n, b) => n + (b.size ?? 0), 0))}), oldest first:</>}</p>
        {doomed.length > 0 && <ul className="m-0 pl-4 list-disc">{doomed.map(b => <li key={b.name}>{b.taken_before ?? 'earlier version'} · {formatDateTime(b.taken_at)}</li>)}</ul>}
        <p className="m-0">The copy the last upgrade took is never deleted (a restore needs it). Deleted copies cannot be brought back.</p>
      </TypedConfirmDialog>
    </section>
  )
}
