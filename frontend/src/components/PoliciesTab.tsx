import { useMemo } from 'react'
import type { AccessModel, AccessPolicy } from '../types'
import { ruleHasApprovalOrMfa } from '../utils/accessResources'
import type { ExportSection } from '../utils/export'
import { grantRows, policySummaryRows } from '../utils/exportSections'
import { firstPlusMore } from '../utils/format'
import { HighlightedText, useFuzzyFilter } from '../utils/fuzzySearch'
import { ExplorerLayout } from './explorer/ExplorerLayout'
import type { ExplorerRowData } from './explorer/ExplorerRows'
import { ExplorerToolbar, ResultsNote } from './explorer/ExplorerToolbar'
import { PolicyDetail } from './explorer/PolicyDetail'
import { CountList, FilterMenu, type FilterItem } from './explorer/RailParts'
import { withCountEntries } from './explorer/countEntries'
import { RowSections } from './explorer/RowSections'
import { useFilterState } from './explorer/useFilterState'
import { useSectionState } from './explorer/useSectionState'
import { ExportButtons } from './ExportButtons'

interface Props {
  model: AccessModel
}

interface Entry {
  policy: AccessPolicy
  groupNames: string[]
  types: string[]
  ruleNames: string[]
  resourceGroupName: string
  /** At least one rule needs neither MFA nor an access request. */
  openRule: boolean
}

const FILTER_INACTIVE = 'inactive'
const FILTER_RISK = 'risk'
const SEARCH_KEYS = ['policy.name', 'policy.description', 'resourceGroupName', 'groupNames', 'types', 'ruleNames']

function policyExport(policy: AccessPolicy): ExportSection[] {
  return [
    {
      title: `Policy: ${policy.name}`,
      rows: [
        {
          Description: policy.description ?? '',
          Active: policy.active ? 'Yes' : 'No',
          'Resource Group': policy.resource_group?.name ?? 'Team-wide',
          'Principal Groups': policy.principals.user_groups.map(g => g.name).join(', '),
          'Workload Roles': policy.principals.workload_roles.map(w => w.name).join(', '),
        },
      ],
    },
    { title: 'Rules', rows: grantRows(policy.rules.map(rule => ({ policy, rule }))) },
  ]
}

export function PoliciesTab({ model }: Props) {
  const { query, setQuery, active, toggle, clear, filtering, autoOpenKey } = useFilterState()

  const entries: Entry[] = useMemo(
    () => [...model.policies].sort((a, b) => a.name.localeCompare(b.name)).map(policy => ({
      policy,
      groupNames: [...policy.principals.user_groups.map(g => g.name), ...policy.principals.workload_roles.map(w => `${w.name} (workload role)`)],
      types: [...new Set(policy.rules.map(r => r.resource_type_label))],
      ruleNames: policy.rules.map(r => r.name),
      resourceGroupName: policy.resource_group?.name ?? 'Team-wide',
      openRule: policy.rules.some(r => !ruleHasApprovalOrMfa(r)),
    })),
    [model.policies]
  )

  const hits = useFuzzyFilter(entries, query, SEARCH_KEYS)
  const visible = hits.filter(({ item }) => (!active.has(FILTER_INACTIVE) || !item.policy.active) && (!active.has(FILTER_RISK) || item.openRule))

  const toRow = ({ item: e, matches }: (typeof hits)[number]): ExplorerRowData => ({
    id: `policy:${e.policy.id}`,
    label: e.policy.name,
    name: <HighlightedText text={e.policy.name} indices={matches.find(m => m.key === 'policy.name')?.indices} />,
    hint: e.policy.active ? undefined : 'inactive',
    can: e.policy.description || e.types.join(', '),
    via: firstPlusMore(e.groupNames),
    used: `${e.policy.rules.length} rule${e.policy.rules.length === 1 ? '' : 's'}`,
    detail: () => <PolicyDetail policy={e.policy} showLastModified exportSections={policyExport(e.policy)} exportName={`opa-policy-${e.policy.name}`} />,
  })
  const scoped = visible.filter(h => h.item.policy.resource_group)
  const teamWide = visible.filter(h => !h.item.policy.resource_group)
  const sections = [
    { id: 'scoped', title: 'Scoped to a resource group', rows: scoped.map(toRow) },
    { id: 'team-wide', title: 'Team-wide', rows: teamWide.map(toRow) },
  ]
  const visibleIds = sections.filter(s => s.rows.length > 0).map(s => s.id)
  const state = useSectionState(visibleIds, { autoOpenKey })

  const allScoped = entries.filter(e => e.policy.resource_group).length
  const allTeam = entries.length - allScoped
  const filterItems: FilterItem[] = [
    { id: FILTER_INACTIVE, label: 'Inactive policies', count: entries.filter(e => !e.policy.active).length },
    { id: FILTER_RISK, label: 'A rule with no approval or MFA', count: entries.filter(e => e.openRule).length },
  ]

  const exportSectionsForView: ExportSection[] = useMemo(() => [{ title: 'Policies', rows: policySummaryRows(model.policies) }], [model.policies])

  const rail = (
    <>
      <div className="flex flex-col gap-1">
        <span className="xp-rail-title">Policies</span>
        <span className="xp-rail-sub">Open one to see who it is for and every rule.</span>
      </div>
      <CountList
        items={withCountEntries([
          { id: 'scoped', label: 'scoped to a resource group', count: allScoped },
          ...(allTeam > 0 ? [{ id: 'team-wide', label: 'team-wide', count: allTeam }] : []),
        ], sections)}
        onSelect={state.jumpTo}
      />
      <FilterMenu items={filterItems} active={active} onToggle={toggle} />
      <div className="xp-rail-actions">
        <ExportButtons sections={exportSectionsForView} filenameBase="opa-policies" />
      </div>
    </>
  )

  return (
    <ExplorerLayout rail={rail} railLabel="Policy quick view and filters">
      <ExplorerToolbar query={query} onQueryChange={setQuery} label="Search policies" sections={state} />
      {filtering && <ResultsNote shown={visible.length} total={entries.length} onClear={clear} />}
      {entries.length === 0 && <p className="xp-note">No policies were found.</p>}
      {entries.length > 0 && visible.length === 0 && <p className="xp-note">Nothing matches the current search and filters.</p>}
      <RowSections sections={sections} state={state} />
    </ExplorerLayout>
  )
}
