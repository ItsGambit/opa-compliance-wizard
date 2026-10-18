import { useMemo } from 'react'
import type { AccessAssignment, AccessModel, AccessRelationship } from '../types'
import type { ExportSection } from '../utils/export'
import { relationshipAssignmentRows } from '../utils/exportSections'
import { HighlightedText, useFuzzyFilter } from '../utils/fuzzySearch'
import { assignmentsForRelationship, policiesUsingAssignment, principalsForRelationship } from '../utils/relationships'
import { Chip, ChipList, DetailGrid, DetailSection } from './explorer/DetailBlocks'
import { ExplorerLayout } from './explorer/ExplorerLayout'
import type { ExplorerRowData } from './explorer/ExplorerRows'
import { ExplorerToolbar, ResultsNote } from './explorer/ExplorerToolbar'
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
  relationship: AccessRelationship
  assignments: AccessAssignment[]
  assignmentNames: string[]
  policyCount: number
}

const FILTER_NO_ASSIGNMENTS = 'no-assignments'
const FILTER_UNUSED = 'unused'
const SEARCH_KEYS = ['relationship.name', 'relationship.description', 'assignmentNames']

/** Relationship -> Assignment -> Policy, browsable: a relationship is a named
 * grant type (e.g. "Safe Owners"); an assignment links it to a principal
 * group plus specific resources; a policy referencing the relationship
 * effectively inherits every assignment's principal+resources (see
 * create_secret_folders.py's assignments_by_relationship_id, one-to-MANY by
 * design). Each relationship is a row; opening it lists every assignment
 * with its principals, resolved resources and the policies using it. The
 * same data is already folded into ordinary policy rules elsewhere (via
 * "via {relationship} -> {assignment}"), so this view exists for browsing
 * the relationship/assignment CONFIG itself. */
export function RelationshipsTab({ model }: Props) {
  const { query, setQuery, active, toggle, clear, filtering, autoOpenKey } = useFilterState()

  const entries: Entry[] = useMemo(
    () => model.relationships.map(relationship => {
      const assignments = assignmentsForRelationship(model, relationship.id)
      return {
        relationship,
        assignments,
        assignmentNames: assignments.map(a => a.name),
        policyCount: model.policies.filter(p => p.relationship_ids.includes(relationship.id)).length,
      }
    }),
    [model]
  )

  const hits = useFuzzyFilter(entries, query, SEARCH_KEYS)
  const visible = hits.filter(({ item }) =>
    (!active.has(FILTER_NO_ASSIGNMENTS) || item.assignments.length === 0) && (!active.has(FILTER_UNUSED) || item.policyCount === 0))

  const exportFor = (e: Entry): ExportSection[] => e.assignments.map(a => ({
    title: `Assignment: ${a.name}`,
    rows: [
      {
        Relationship: e.relationship.name,
        Principals: principalsForRelationship(a, e.relationship.id).map(p => p.name).join(', '),
        'Resolved Resources': a.resolved_resources.map(r => (r.kind === 'resolved' ? r.name : r.description)).join(', '),
        'Policies Using This': policiesUsingAssignment(a, model.policies).map(p => p.name).join(', '),
      },
    ],
  }))

  const rows: ExplorerRowData[] = visible.map(({ item: e, matches }) => ({
    id: `relationship:${e.relationship.id}`,
    label: e.relationship.name,
    name: <HighlightedText text={e.relationship.name} indices={matches.find(m => m.key === 'relationship.name')?.indices} />,
    can: e.relationship.description ?? '',
    via: `${e.assignments.length} assignment${e.assignments.length === 1 ? '' : 's'}`,
    used: `${e.policyCount} polic${e.policyCount === 1 ? 'y' : 'ies'}`,
    detail: () => (
      <DetailGrid>
        <DetailSection title="What it is">
          <p>{e.relationship.description || 'A named grant type with no description.'}</p>
          {e.assignments.length > 0 && <ExportButtons sections={exportFor(e)} filenameBase={`opa-relationship-${e.relationship.name}`} />}
        </DetailSection>
        <DetailSection title={`Assignments using this relationship (${e.assignments.length})`}>
          {e.assignments.length === 0 && <p className="xp-mute">No assignments reference this relationship.</p>}
        </DetailSection>
        {e.assignments.map(a => {
          const principals = principalsForRelationship(a, e.relationship.id)
          const policies = policiesUsingAssignment(a, model.policies)
          return (
            <DetailSection key={a.id} title={`Assignment: ${a.name}`} full>
              {a.description && <p className="xp-mute">{a.description}</p>}
              <p className="xp-mute">Principal(s) for this relationship</p>
              <ChipList empty="None">{principals.map(p => <Chip key={p.id}>{p.name}</Chip>)}</ChipList>
              <p className="xp-mute mt-2">Resolved resources granted</p>
              <ChipList empty="None">
                {a.resolved_resources.map((r, i) => (r.kind === 'resolved' ? <Chip key={i}>{r.name}</Chip> : <span key={i} className="xp-mute italic">{r.description} </span>))}
              </ChipList>
              <p className="xp-mute mt-2">Policies using this assignment ({policies.length})</p>
              <ChipList empty="No policy currently references this relationship.">{policies.map(p => <Chip key={p.id}>{p.name}</Chip>)}</ChipList>
            </DetailSection>
          )
        })}
      </DetailGrid>
    ),
  }))

  const sections = [{ id: 'relationships', title: 'Relationships', rows }]
  const state = useSectionState(rows.length > 0 ? ['relationships'] : [], { autoOpenKey })

  const filterItems: FilterItem[] = [
    { id: FILTER_NO_ASSIGNMENTS, label: 'No assignments', count: entries.filter(e => e.assignments.length === 0).length },
    { id: FILTER_UNUSED, label: 'Not used by any policy', count: entries.filter(e => e.policyCount === 0).length },
  ]

  const exportSections: ExportSection[] = useMemo(() => [{ title: 'Relationships', rows: relationshipAssignmentRows(model) }], [model])
  const assignmentTotal = model.assignments.length

  const rail = (
    <>
      <div className="flex flex-col gap-1">
        <span className="xp-rail-title">Relationships</span>
        <span className="xp-rail-sub">Open one to see its assignments, principals and the policies using it.</span>
      </div>
      <CountList
        items={withCountEntries([
          { id: 'relationships', label: model.relationships.length === 1 ? 'relationship' : 'relationships', count: model.relationships.length },
        ], sections)}
        onSelect={state.jumpTo}
      />
      <p className="xp-note">{assignmentTotal} assignment{assignmentTotal === 1 ? '' : 's'} in total.</p>
      <FilterMenu items={filterItems} active={active} onToggle={toggle} />
      <div className="xp-rail-actions">
        <ExportButtons sections={exportSections} filenameBase="opa-relationships" />
      </div>
    </>
  )

  return (
    <ExplorerLayout rail={rail} railLabel="Relationship quick view and filters">
      <ExplorerToolbar query={query} onQueryChange={setQuery} label="Search relationships" sections={state} />
      {filtering && <ResultsNote shown={visible.length} total={entries.length} onClear={clear} />}
      {model.relationships.length === 0 && <p className="xp-note">None configured in this tenant.</p>}
      {entries.length > 0 && visible.length === 0 && <p className="xp-note">Nothing matches the current search and filters.</p>}
      <RowSections sections={sections} state={state} />
    </ExplorerLayout>
  )
}
