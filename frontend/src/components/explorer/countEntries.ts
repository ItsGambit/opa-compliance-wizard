import type { CountEntry, CountItem } from './RailParts'

/** Adds the visible rows of each section to the matching count item (the
 * item id is the section id). Sections with no visible rows give an empty
 * list, so the count reads "0 of N" while a filter hides the whole type. */
export function withCountEntries(items: CountItem[], sections: { id: string; rows: CountEntry[] }[]): CountItem[] {
  const byId = new Map(sections.map(s => [s.id, s.rows.map(r => ({ id: r.id, label: r.label }))]))
  return items.map(item => ({ ...item, entries: byId.get(item.id) ?? [] }))
}
