import type { UpgradeStatus } from '../../types'
import { formatDateTime } from '../../utils/format'
import { formatBytes } from '../../utils/upgrade'
import { CARD_TITLE, CommandBlock } from './parts'

/** Artboard 01, "Pre-upgrade backups": what the updater kept before each upgrade (names, sizes, dates and the integrity result it
 * recorded; the directory itself is root-only). Never deleted automatically. Deleting is a command-line action: these copies are the only
 * ones the web application cannot reach, so removing them needs a shell on the server. */
export function BackupsCard({ status }: { status: UpgradeStatus }) {
  const known = status.upgrade?.backups
  const rows = known?.backups ?? []
  const newestFirst = [...rows].sort((a, b) => b.taken_at.localeCompare(a.taken_at))
  return (
    <section className="card p-4" aria-labelledby="t-backups">
      <h2 className={CARD_TITLE} id="t-backups">Pre-upgrade backups</h2>
      {!known ? (
        <p className="text-xs text-text-dim m-0">Backups will be listed after the first upgrade with this version.</p>
      ) : rows.length === 0 ? <p className="text-xs text-text-dim m-0">None yet: one is taken before each upgrade.</p> : (
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
      <p className="text-xs text-muted mt-3 mb-1.5">
        Never deleted automatically. Deleting the only copies of the archive the web application cannot touch needs shell access; the newest copy and the last upgrade's are always kept:
      </p>
      <CommandBlock label="Delete older backups command">sudo ocw-updater prune-backups --keep N --confirm PRUNE</CommandBlock>
    </section>
  )
}
