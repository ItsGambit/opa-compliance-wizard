import type { ReactNode } from 'react'
import { RailExpander } from './RailParts'

export interface RailNameItem {
  id: string
  name: string
  /** Muted note after the name (e.g. "no policy"). */
  note?: string
  /** An inline action (e.g. a GroupRemoveControl); leave out for a plain name. */
  action?: ReactNode
}

/** "12 groups" in the rail; expands to the names, each with an optional
 * inline action. Used for a user's groups (with Remove) and a group's
 * members (plain). */
export function RailGroupsExpander({ count, label, items, emptyText = 'None' }: { count: number; label: string; items: RailNameItem[]; emptyText?: string }) {
  return (
    <RailExpander count={count} label={label}>
      {items.length === 0 ? (
        <span className="xp-note">{emptyText}</span>
      ) : (
        <ul className="xp-namelist">
          {items.map(item => (
            <li key={item.id}>
              <span>{item.name}{item.note && <span className="xp-mute"> · {item.note}</span>}</span>
              {item.action}
            </li>
          ))}
        </ul>
      )}
    </RailExpander>
  )
}
