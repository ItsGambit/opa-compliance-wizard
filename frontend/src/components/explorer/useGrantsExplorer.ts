import { useMemo } from 'react'
import { useFuzzyFilter } from '../../utils/fuzzySearch'
import {
  countLabel, lastUsedFor, sectionsByType,
  type AccessLookup, type AccessResource, type LastUsed, type ResourceSection,
} from '../../utils/accessResources'
import type { CountItem, FilterItem } from './RailParts'
import { withCountEntries } from './countEntries'
import { useFilterState } from './useFilterState'
import { useSectionState } from './useSectionState'

export const FILTER_RISK = 'risk'
export const FILTER_USED = 'used'
export const FILTER_NEVER = 'never'
export const FILTER_UNTRACKED = 'untracked'

const SEARCH_KEYS = ['name', 'hint', 'typeLabel', 'actions', 'conditions', 'viaNames', 'policyNames', 'selectors']

export interface VisibleResource {
  resource: AccessResource
  /** Fuzzy match ranges inside the name, for highlighting. */
  nameIndices?: [number, number][]
  lastUsed: LastUsed
}

/** Search + Filter + sections state shared by every resource-centred view
 * (Users, Groups, Projects). Search is the shared fuzzy matcher; the Filter
 * entries are only those the data can really answer: "No approval or MFA"
 * always (it reads the rule conditions), the three usage entries only when
 * a last-accessed lookup exists (the Users view). */
export function useGrantsExplorer({ resources, lookup, resetKey }: { resources: AccessResource[]; lookup?: AccessLookup; resetKey: string }) {
  const { query, setQuery, active, toggle: toggleFilter, clear: clearFilters, filtering, autoOpenKey } = useFilterState()

  const lastUsedByKey = useMemo(() => {
    const map = new Map<string, LastUsed>()
    for (const r of resources) map.set(r.key, lastUsedFor(r, lookup))
    return map
  }, [resources, lookup])

  const searched = useFuzzyFilter(resources, query, SEARCH_KEYS)

  const visible: VisibleResource[] = useMemo(() => {
    const usageSelected = [FILTER_USED, FILTER_NEVER, FILTER_UNTRACKED].filter(f => active.has(f))
    const out: VisibleResource[] = []
    for (const { item, matches } of searched) {
      const lastUsed = lastUsedByKey.get(item.key) ?? { state: 'none' as const }
      if (active.has(FILTER_RISK) && !item.risky) continue
      if (usageSelected.length > 0) {
        const ok = usageSelected.some(f => (f === FILTER_USED ? lastUsed.state === 'used' : f === FILTER_NEVER ? lastUsed.state === 'never' : lastUsed.state === 'untracked'))
        if (!ok) continue
      }
      out.push({ resource: item, lastUsed, nameIndices: matches.find(m => m.key === 'name')?.indices })
    }
    return out
  }, [searched, active, lastUsedByKey])

  const visibleSections: (ResourceSection & { visible: VisibleResource[] })[] = useMemo(() => {
    const byKey = new Map(visible.map(v => [v.resource.key, v]))
    return sectionsByType(visible.map(v => v.resource)).map(s => ({ ...s, visible: s.resources.map(r => byKey.get(r.key)!) }))
  }, [visible])

  const allSections = useMemo(() => sectionsByType(resources), [resources])
  const sectionIds = visibleSections.map(s => s.id)
  const sections = useSectionState(sectionIds, { resetKey, autoOpenKey })

  const countItems: CountItem[] = useMemo(
    () => withCountEntries(
      allSections.map(s => ({ id: s.id, label: countLabel(s.title, s.resources.length), count: s.resources.length })),
      visibleSections.map(s => ({ id: s.id, rows: s.visible.map(v => ({ id: `${s.id}:${v.resource.key}`, label: v.resource.name })) }))
    ),
    [allSections, visibleSections]
  )

  const filterItems: FilterItem[] = useMemo(() => {
    const items: FilterItem[] = [{ id: FILTER_RISK, label: 'No approval or MFA', count: resources.filter(r => r.risky).length }]
    if (lookup) {
      const ready = lookup.status === 'ready'
      const count = (state: LastUsed['state']) => (ready ? [...lastUsedByKey.values()].filter(l => l.state === state).length : undefined)
      items.push(
        { id: FILTER_USED, label: 'Used in the last 90 days', count: count('used'), disabled: !ready },
        { id: FILTER_NEVER, label: 'Not used in 90 days', count: count('never'), disabled: !ready },
        { id: FILTER_UNTRACKED, label: 'Not tracked', count: count('untracked'), disabled: !ready },
      )
    }
    return items
  }, [resources, lookup, lastUsedByKey])

  return {
    query, setQuery, active, toggleFilter, clearFilters, filtering,
    visible, visibleSections, countItems, filterItems, sections,
    total: resources.length,
    /** Jump target for a count in the rail: only sections that exist. */
    jump: sections.jumpTo,
  }
}

export type GrantsExplorer = ReturnType<typeof useGrantsExplorer>
