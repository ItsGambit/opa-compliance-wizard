import { useMemo, useState } from 'react'
import type { AccessModel, AccessPolicy, AccessProject } from '../types'
import type { ExportSection } from '../utils/export'
import { grantRows } from '../utils/exportSections'
import { firstPlusMore } from '../utils/format'
import { HighlightedText, useFuzzyFilter } from '../utils/fuzzySearch'
import { policiesForResourceGroup } from '../utils/policy'
import { Chip } from './explorer/DetailBlocks'
import { ExplorerLayout } from './explorer/ExplorerLayout'
import type { ExplorerRowData } from './explorer/ExplorerRows'
import { ExplorerToolbar } from './explorer/ExplorerToolbar'
import { PolicyDetail } from './explorer/PolicyDetail'
import { RailGroupsExpander } from './explorer/RailGroupsExpander'
import { CountList, RailBlock, RailField } from './explorer/RailParts'
import { withCountEntries } from './explorer/countEntries'
import { RowSections } from './explorer/RowSections'
import { useSectionState } from './explorer/useSectionState'
import { ExportButtons } from './ExportButtons'
import { KeyValueGrid } from './KeyValueGrid'
import { Select } from './Select'

interface Props {
  model: AccessModel
}

interface PolicyEntry {
  policy: AccessPolicy
  groupNames: string[]
  types: string[]
  ruleNames: string[]
}

function projectCounts(p: AccessProject): string {
  const active = typeof p.active_resource_count === 'number' ? `${p.active_resource_count} active` : ''
  const stale = typeof p.stale_resource_count === 'number' && p.stale_resource_count > 0 ? `${p.stale_resource_count} stale` : ''
  return [active, stale].filter(Boolean).join(' · ')
}

export function ResourceGroupsTab({ model }: Props) {
  const [rgId, setRgId] = useState<string | undefined>(undefined)
  const [query, setQuery] = useState('')
  const rg = model.resource_groups.find(r => r.id === rgId)

  const projects = useMemo(() => model.projects.filter(p => p.resource_group_id === rgId), [model.projects, rgId])
  const policies = useMemo(() => (rgId ? policiesForResourceGroup(model.policies, rgId) : []), [model.policies, rgId])
  const policyEntries: PolicyEntry[] = useMemo(
    () => policies.map(policy => ({
      policy,
      groupNames: policy.principals.user_groups.map(g => g.name),
      types: [...new Set(policy.rules.map(r => r.resource_type_label))],
      ruleNames: policy.rules.map(r => r.name),
    })),
    [policies]
  )

  const accessGroups = useMemo(() => {
    const seen = new Map<string, string>()
    for (const p of policies) {
      for (const g of p.principals.user_groups) seen.set(g.id, g.name)
    }
    return [...seen.entries()].map(([id, name]) => ({ id, name }))
  }, [policies])

  const resourceTypes = useMemo(() => {
    const seen = new Set<string>()
    for (const p of policies) for (const r of p.rules) seen.add(r.resource_type_label)
    return [...seen]
  }, [policies])

  const exportSectionsForRg: ExportSection[] = useMemo(() => {
    if (!rg) return []
    return [
      {
        title: `Resource Group: ${rg.name}`,
        rows: [
          {
            Description: rg.description ?? '',
            'Delegated Admin Groups': (rg.delegated_resource_admin_groups ?? []).map(g => g.name).join(', '),
          },
        ],
      },
      {
        title: 'Projects',
        rows: projects.map(p => ({
          Project: p.name,
          'Active Resources': typeof p.active_resource_count === 'number' ? String(p.active_resource_count) : '',
          'Stale Resources': typeof p.stale_resource_count === 'number' ? String(p.stale_resource_count) : '',
        })),
      },
      { title: 'Policies & Rules', rows: grantRows(policies.flatMap(policy => policy.rules.map(rule => ({ policy, rule })))) },
    ]
  }, [rg, projects, policies])

  const projectHits = useFuzzyFilter(projects, query, ['name'])
  const policyHits = useFuzzyFilter(policyEntries, query, ['policy.name', 'policy.description', 'groupNames', 'types', 'ruleNames'])

  const projectRows: ExplorerRowData[] = projectHits.map(({ item: p, matches }) => ({
    id: `projects:${p.id}`,
    label: p.name,
    name: <HighlightedText text={p.name} indices={matches.find(m => m.key === 'name')?.indices} />,
    can: projectCounts(p),
    detail: () => <KeyValueGrid data={p} />,
  }))
  const policyRows: ExplorerRowData[] = policyHits.map(({ item: e, matches }) => ({
    id: `policies:${e.policy.id}`,
    label: e.policy.name,
    name: <HighlightedText text={e.policy.name} indices={matches.find(m => m.key === 'policy.name')?.indices} />,
    hint: e.policy.active ? undefined : 'inactive',
    can: e.types.join(', '),
    via: firstPlusMore(e.groupNames),
    used: `${e.policy.rules.length} rule${e.policy.rules.length === 1 ? '' : 's'}`,
    detail: () => <PolicyDetail policy={e.policy} />,
  }))
  const sections = [
    { id: 'projects', title: 'Projects', rows: projectRows },
    { id: 'policies', title: 'Policies scoped to this resource group', rows: policyRows },
  ]
  const visibleIds = sections.filter(s => s.rows.length > 0).map(s => s.id)
  const state = useSectionState(visibleIds, { resetKey: rgId ?? '', autoOpenKey: query.trim() })

  const rail = (
    <>
      <RailField label="Resource group">
        <Select
          ariaLabel="Resource group"
          value={rgId}
          onValueChange={id => { setRgId(id); setQuery('') }}
          placeholder="Select a resource group"
          options={model.resource_groups.map(r => ({ value: r.id, label: r.name, keywords: r.description ? [r.description] : undefined }))}
        />
      </RailField>
      {rg && (
        <>
          <div className="flex flex-col gap-1">
            <span className="xp-rail-title">{rg.name}</span>
            {rg.description && <span className="xp-rail-sub">{rg.description}</span>}
          </div>
          <CountList
            items={withCountEntries([
              { id: 'projects', label: projects.length === 1 ? 'project' : 'projects', count: projects.length },
              { id: 'policies', label: policies.length === 1 ? 'policy' : 'policies', count: policies.length },
            ], sections)}
            onSelect={state.jumpTo}
          />
          <RailBlock title="Delegated admin group(s)">
            {rg.delegated_resource_admin_groups?.length
              ? <div>{rg.delegated_resource_admin_groups.map(g => <Chip key={g.id}>{g.name}</Chip>)}</div>
              : <span className="xp-note">None</span>}
          </RailBlock>
          <RailGroupsExpander
            count={accessGroups.length}
            label="groups have access"
            emptyText="No policies grant access via a group here"
            items={accessGroups}
          />
          <RailBlock title="Resource types covered">
            {resourceTypes.length ? <div>{resourceTypes.map(t => <Chip key={t}>{t}</Chip>)}</div> : <span className="xp-note">None</span>}
          </RailBlock>
          <div className="xp-rail-actions">
            <ExportButtons sections={exportSectionsForRg} filenameBase={`opa-resource-group-${rg.name}`} />
          </div>
        </>
      )}
    </>
  )

  return (
    <ExplorerLayout rail={rail} railLabel="Resource group and quick view">
      {!rg ? (
        <p className="xp-note">Select a resource group to see its projects and the policies scoped to it.</p>
      ) : (
        <>
          <ExplorerToolbar query={query} onQueryChange={setQuery} label="Search this resource group" sections={state} />
          {projects.length === 0 && <p className="xp-note">No projects in this resource group.</p>}
          {policies.length === 0 && <p className="xp-note">No policies are scoped to this resource group.</p>}
          {(projects.length > 0 || policies.length > 0) && visibleIds.length === 0 && <p className="xp-note">Nothing matches the current search.</p>}
          <RowSections sections={sections} state={state} />
        </>
      )}
    </ExplorerLayout>
  )
}
