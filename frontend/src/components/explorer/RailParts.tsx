import { useId, useState, type ReactNode } from 'react'
import { useExplorerLayout } from './explorerContext'

export interface CountItem {
  id: string
  /** Already counted-correctly, e.g. "servers" or "domain". */
  label: string
  count: number
}

/** The per-type counts ("4 servers  1 domain ..."): a vertical list in the
 * wide rail, a band when stacked. Each entry opens and jumps to its section
 * (or does whatever `onSelect` says). */
export function CountList({ items, onSelect }: { items: CountItem[]; onSelect: (id: string) => void }) {
  if (items.length === 0) return null
  return (
    <nav aria-label="Quick view">
      <ul className="xp-counts">
        {items.map(item => (
          <li key={item.id}>
            <button type="button" className="xp-count" onClick={() => onSelect(item.id)}>
              <span className="xp-count-v">{item.count}</span>{' '}
              <span className="xp-count-l">{item.label}</span>
            </button>
          </li>
        ))}
      </ul>
    </nav>
  )
}

/** A rail entry that expands a body (the groups of a user, the members of a
 * group ...): looks like a count, "12 groups". */
export function RailExpander({ count, label, children }: { count: number; label: string; children: ReactNode }) {
  const [open, setOpen] = useState(false)
  const bodyId = useId()
  return (
    <div>
      <button type="button" className="xp-count" aria-expanded={open} aria-controls={open ? bodyId : undefined} onClick={() => setOpen(o => !o)}>
        <span className="xp-count-v">{count}</span>{' '}
        <span className="xp-count-l">{label} <span aria-hidden="true">{open ? '▴' : '▾'}</span></span>
      </button>
      {open && <div id={bodyId} className="xp-expander-body">{children}</div>}
    </div>
  )
}

export interface FilterItem {
  id: string
  label: string
  count?: number
  disabled?: boolean
}

/** The Filter menu. In the wide rail it is an always-open checkbox list; when
 * stacked it is a disclosure ("Filter"). Only filters the view can really
 * compute from its data are passed in. */
export function FilterMenu({ items, active, onToggle }: { items: FilterItem[]; active: Set<string>; onToggle: (id: string) => void }) {
  const { wide } = useExplorerLayout()
  const [open, setOpen] = useState(false)
  const listId = useId()
  if (items.length === 0) return null
  const list = (
    <div id={listId} className="xp-filter-list" role="group" aria-label="Filter">
      {items.map(item => (
        <label key={item.id} data-disabled={item.disabled ? 'true' : undefined}>
          <input type="checkbox" checked={active.has(item.id)} disabled={item.disabled} onChange={() => onToggle(item.id)} />
          {item.label}
          {item.count !== undefined && <span className="xp-filter-count">{item.count}</span>}
        </label>
      ))}
    </div>
  )
  if (wide) {
    return (
      <div>
        <div className="xp-filter-title">Filter</div>
        {list}
      </div>
    )
  }
  return (
    <div>
      <button type="button" className="btn-secondary" aria-expanded={open} aria-controls={open ? listId : undefined} onClick={() => setOpen(o => !o)}>
        Filter{active.size > 0 ? ` (${active.size})` : ''} {open ? '▴' : '▾'}
      </button>
      {open && list}
    </div>
  )
}

/** A labelled control in the rail (a selector). */
export function RailField({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="section-label">{label}</span>
      {children}
    </div>
  )
}

/** A small headed block in the rail (chips, a note). */
export function RailBlock({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div>
      <div className="xp-filter-title">{title}</div>
      {children}
    </div>
  )
}
