import type { ReactNode } from 'react'
import type { AccessResource } from '../../utils/accessResources'
import { firstPlusMore } from '../../utils/format'
import { HighlightedText } from '../../utils/fuzzySearch'
import { lastUsedText } from './lastUsedText'
import type { ExplorerRowData } from './ExplorerRows'
import { ExplorerToolbar, ResultsNote } from './ExplorerToolbar'
import { RowSections } from './RowSections'
import type { GrantsExplorer } from './useGrantsExplorer'

interface Props {
  ex: GrantsExplorer
  now: number
  searchLabel: string
  /** The muted third column: groups (Users, Projects) or policies (Groups). */
  viaOf?: (r: AccessResource) => string[]
  renderDetail: (r: AccessResource) => ReactNode
  /** Shown when the subject has no access resources at all. */
  emptyMessage: string
  /** Extra sections after the resource types (e.g. a project's settings). */
  after?: ReactNode
}

/** The main pane of the resource-centred views: search, Expand/Collapse all,
 * the "showing X of Y" line and one TypeSection per resource type. */
export function GrantsMain({ ex, now, searchLabel, viaOf = r => r.viaNames, renderDetail, emptyMessage, after }: Props) {
  const shown = ex.visible.length
  return (
    <>
      <ExplorerToolbar query={ex.query} onQueryChange={ex.setQuery} label={searchLabel} sections={ex.sections} />
      {ex.filtering && <ResultsNote shown={shown} total={ex.total} onClear={ex.clearFilters} />}
      {ex.total === 0 && <p className="xp-note">{emptyMessage}</p>}
      {ex.total > 0 && shown === 0 && <p className="xp-note">Nothing matches the current search and filters.</p>}
      <RowSections
        state={ex.sections}
        sections={ex.visibleSections.map(section => ({
          id: section.id,
          title: section.title,
          rows: section.visible.map(({ resource, nameIndices, lastUsed }): ExplorerRowData => {
            const used = lastUsedText(lastUsed, now)
            return {
              id: `${section.id}:${resource.key}`,
              label: resource.name,
              name: <HighlightedText text={resource.name} indices={nameIndices} />,
              hint: resource.hint,
              can: resource.actions.join(', '),
              via: firstPlusMore(viaOf(resource)),
              used: used.text,
              usedTitle: used.title,
              detail: () => renderDetail(resource),
            }
          }),
        }))}
      />
      {after && <div className="xp-after">{after}</div>}
    </>
  )
}
