import { useId, useState, type ReactNode } from 'react'
import { useExplorerLayout } from './explorerContext'

export interface CountEntry {
  /** The id of the row this entry opens (the same id the main pane's row uses). */
  id: string
  /** The row label as shown in the main pane. */
  label: string
}

export interface CountItem {
  id: string
  /** Already counted-correctly, e.g. "servers" or "domain". */
  label: string
  /** The total in this type. */
  count: number
  /** The resources of this type that are currently visible (after search and
   * filters). When given, the entry is a dropdown listing them; without it
   * the entry only jumps to its section. */
  entries?: CountEntry[]
}

/** The per-type counts ("4 servers  1 domain ..."): a vertical list in the
 * wide rail, a band when stacked. An entry with `entries` is a dropdown (a
 * button with aria-expanded, several can be open): inside it, "Go to section"
 * jumps to the type's section and each name jumps to that resource's row.
 * Stacked, the open lists show as panels under the band. An entry without
 * `entries` just jumps (or does whatever `onSelect` says). */
export function CountList({ items, onSelect }: { items: CountItem[]; onSelect: (id: string, rowId?: string) => void }) {
  const { wide, setOpenRowId } = useExplorerLayout()
  const [open, setOpen] = useState<Set<string>>(new Set())
  const baseId = useId()
  if (items.length === 0) return null
  const bodyId = (id: string) => `${baseId}-${id}`
  const toggle = (id: string) => setOpen(prev => {
    const next = new Set(prev)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    return next
  })
  const openRow = (sectionId: string, rowId: string) => {
    setOpenRowId(rowId)
    onSelect(sectionId, rowId)
  }
  const body = (item: CountItem) => (
    <div id={bodyId(item.id)} className="xp-expander-body" role="group" aria-label={`${item.label} list`}>
      <button type="button" className="xp-linkbtn" onClick={() => onSelect(item.id)}>Go to section</button>
      {item.entries!.length === 0 ? (
        <span className="xp-note xp-typelist-empty">None match the current search and filters</span>
      ) : (
        <ul className="xp-typelist">
          {item.entries!.map(entry => (
            <li key={entry.id}>
              <button type="button" title={entry.label} onClick={() => openRow(item.id, entry.id)}>{entry.label}</button>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
  const openItems = items.filter(i => i.entries && open.has(i.id))
  return (
    <nav aria-label="Quick view">
      <ul className="xp-counts">
        {items.map(item => {
          const dropdown = !!item.entries
          const isOpen = dropdown && open.has(item.id)
          const shown = item.entries && item.entries.length !== item.count ? `${item.entries.length} of ${item.count}` : String(item.count)
          return (
            <li key={item.id}>
              <button
                type="button"
                className="xp-count"
                aria-expanded={dropdown ? isOpen : undefined}
                aria-controls={isOpen ? bodyId(item.id) : undefined}
                onClick={() => (dropdown ? toggle(item.id) : onSelect(item.id))}
              >
                <span className="xp-count-v">{shown}</span>{' '}
                <span className="xp-count-l">{item.label}{dropdown && <> <span aria-hidden="true">{isOpen ? '▴' : '▾'}</span></>}</span>
              </button>
              {wide && isOpen && body(item)}
            </li>
          )
        })}
      </ul>
      {!wide && openItems.map(item => <div key={item.id}>{body(item)}</div>)}
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
