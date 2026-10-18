import { Search } from 'lucide-react'
import type { SectionState } from './useSectionState'

/** The search box plus Expand all / Collapse all. Search itself is done by
 * the caller with the shared useFuzzyFilter. */
export function ExplorerToolbar({
  query, onQueryChange, label, placeholder = 'Search', sections,
}: {
  query: string
  onQueryChange: (q: string) => void
  /** Accessible name, e.g. "Search this user's access". */
  label: string
  placeholder?: string
  sections?: Pick<SectionState, 'expandAll' | 'collapseAll'>
}) {
  return (
    <div className="xp-toolbar">
      <label className="xp-search">
        <Search size={15} aria-hidden="true" />
        <input type="search" aria-label={label} placeholder={placeholder} value={query} onChange={e => onQueryChange(e.target.value)} />
      </label>
      {sections && (
        <div className="xp-toolbar-links">
          <button type="button" className="xp-linkbtn" onClick={sections.expandAll}>Expand all</button>
          <button type="button" className="xp-linkbtn" onClick={sections.collapseAll}>Collapse all</button>
        </div>
      )}
    </div>
  )
}
