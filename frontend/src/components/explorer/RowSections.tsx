import { ExplorerRows, type ExplorerRowData } from './ExplorerRows'
import { TypeSection } from './TypeSection'
import type { SectionState } from './useSectionState'

export interface RowSectionData {
  id: string
  title: string
  /** The VISIBLE rows (already searched and filtered). */
  rows: ExplorerRowData[]
}

/** One TypeSection per entry, each holding its rows. Sections without
 * visible rows are left out so a filter never leaves empty headers. */
export function RowSections({ sections, state }: { sections: RowSectionData[]; state: Pick<SectionState, 'isOpen' | 'toggle'> }) {
  return (
    <div>
      {sections.filter(s => s.rows.length > 0).map(section => (
        <TypeSection
          key={section.id}
          id={section.id}
          title={section.title}
          count={section.rows.length}
          open={state.isOpen(section.id)}
          onToggle={() => state.toggle(section.id)}
        >
          <ExplorerRows rows={section.rows} />
        </TypeSection>
      ))}
    </div>
  )
}
