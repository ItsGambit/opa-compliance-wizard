import type { ReactNode } from 'react'
import type { AccessResource } from '../../utils/accessResources'
import { HighlightedText } from '../../utils/fuzzySearch'
import { lastUsedText } from './lastUsedText'
import { ExplorerRows, type ExplorerRowData } from './ExplorerRows'
import { ExplorerToolbar } from './ExplorerToolbar'
import { TypeSection } from './TypeSection'
import type { GrantsExplorer } from './useGrantsExplorer'

function joinWithMore(names: string[]): string {
  if (names.length === 0) return ''
  return names.length === 1 ? names[0] : `${names[0]} +${names.length - 1}`
}

interface Props {
  ex: GrantsExplorer
  now: number
  searchLabel: string
  /** The muted third column: groups (Users, Projects) or policies (Groups). */
  viaOf?: (r: AccessResource) => string[]
  renderDetail: (r: AccessResource) => ReactNode
  /** Shown when the subject has no access resources at all. */
  emptyMessage: string
}

/** The main pane of the resource-centred views: search, Expand/Collapse all,
 * the "showing X of Y" line and one TypeSection per resource type. */
export function GrantsMain({ ex, now, searchLabel, viaOf = r => r.viaNames, renderDetail, emptyMessage }: Props) {
  const shown = ex.visible.length
  return (
    <>
      <ExplorerToolbar query={ex.query} onQueryChange={ex.setQuery} label={searchLabel} sections={ex.sections} />
      {ex.filtering && (
        <p className="xp-note" role="status">
          Showing {shown} of {ex.total}
          {ex.active.size > 0 || ex.query.trim() ? ' · ' : ''}
          <button type="button" className="xp-linkbtn" onClick={ex.clearFilters}>Clear</button>
        </p>
      )}
      {ex.total === 0 && <p className="xp-note">{emptyMessage}</p>}
      {ex.total > 0 && shown === 0 && <p className="xp-note">Nothing matches the current search and filters.</p>}
      <div>
        {ex.visibleSections.map(section => {
          const rows: ExplorerRowData[] = section.visible.map(({ resource, nameIndices, lastUsed }) => {
            const used = lastUsedText(lastUsed, now)
            return {
              id: `${section.id}:${resource.key}`,
              label: resource.name,
              name: <HighlightedText text={resource.name} indices={nameIndices} />,
              hint: resource.hint,
              can: resource.actions.join(', '),
              via: joinWithMore(viaOf(resource)),
              used: used.text,
              usedTitle: used.title,
              detail: () => renderDetail(resource),
            }
          })
          return (
            <TypeSection
              key={section.id}
              id={section.id}
              title={section.title}
              count={rows.length}
              open={ex.sections.isOpen(section.id)}
              onToggle={() => ex.sections.toggle(section.id)}
            >
              <ExplorerRows rows={rows} />
            </TypeSection>
          )
        })}
      </div>
    </>
  )
}
