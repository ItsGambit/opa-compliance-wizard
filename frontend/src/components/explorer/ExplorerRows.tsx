import type { ReactNode } from 'react'
import { useExplorerLayout } from './explorerContext'
import { stripeFor } from './layout'

export interface ExplorerRowData {
  /** Unique across the whole view (the one-open-at-a-time key). */
  id: string
  /** Plain text name: also the accessible name of the row's detail region. */
  label: string
  /** Small muted qualifier next to the name. */
  hint?: ReactNode
  /** Name cell content when it should differ from `label` (e.g. highlighted). */
  name?: ReactNode
  /** Second column ("what they can do" / a summary). */
  can?: ReactNode
  /** Third column ("how they get it", muted). */
  via?: ReactNode
  /** Last column, right aligned ("last used" / a state). */
  used?: ReactNode
  usedTitle?: string
  /** Called only while the row is open (rows render their detail lazily). */
  detail: () => ReactNode
}

/** The rows of one section. Pass ONLY the rows that are visible (already
 * searched and filtered): the zebra stripe is the position in this list, so
 * hiding a row re-stripes the rest. One row of the whole view is open at a
 * time (state lives in ExplorerLayout); the open row is framed. */
export function ExplorerRows({ rows }: { rows: ExplorerRowData[] }) {
  const { openRowId, setOpenRowId } = useExplorerLayout()
  return (
    <div role="list">
      {rows.map((row, i) => {
        const open = openRowId === row.id
        const detailId = `xp-detail-${row.id}`
        return (
          <div key={row.id} role="listitem" className="xp-row" data-stripe={stripeFor(i)} data-open={open}>
            <button
              type="button"
              className="xp-sum"
              aria-expanded={open}
              aria-controls={open ? detailId : undefined}
              onClick={() => setOpenRowId(open ? null : row.id)}
            >
              <span className="xp-name">
                {row.name ?? row.label}
                {row.hint && <small>{row.hint}</small>}
              </span>
              <span className="xp-can" title={typeof row.can === 'string' ? row.can : undefined}>{row.can}</span>
              <span className="xp-via" title={typeof row.via === 'string' ? row.via : undefined}>{row.via}</span>
              <span className="xp-used" title={row.usedTitle}>{row.used}</span>
            </button>
            {open && (
              <div id={detailId} className="xp-detail" role="region" aria-label={`Details for ${row.label}`}>
                {row.detail()}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}
