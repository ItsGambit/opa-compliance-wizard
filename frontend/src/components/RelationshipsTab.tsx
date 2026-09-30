import { useMemo, useState } from 'react'
import type { AccessAssignment, AccessModel } from '../types'
import type { ExportSection } from '../utils/export'
import { relationshipAssignmentRows } from '../utils/exportSections'
import { ExportButtons } from './ExportButtons'
import { Select } from './Select'
import { Tag } from './PolicyRuleCard'

interface Props {
  model: AccessModel
}

/** Relationship -> Assignment -> Policy drill-down, mirroring
 * ProjectsTab's resource-group -> project master-detail pattern. A
 * relationship is a named grant type (e.g. "TDI_Safe_Owners"); an
 * assignment links it to a principal group plus specific resources; a
 * policy referencing the relationship effectively inherits every
 * assignment's principal+resources (see create_secret_folders.py's
 * assignments_by_relationship_id, one-to-MANY by design). This tab makes
 * that chain directly browsable -- the same data is already folded into
 * ordinary policy rules elsewhere (Projects/ResourceGroups/Policies/
 * Users/Groups tabs, via PolicyRuleCard's "via {relationship} ->
 * {assignment}" annotation), so this tab exists for browsing the
 * relationship/assignment CONFIG itself, not to duplicate that
 * resolution logic. */
export function RelationshipsTab({ model }: Props) {
  const [relationshipId, setRelationshipId] = useState<string | undefined>(undefined)
  const [assignmentId, setAssignmentId] = useState<string | undefined>(undefined)

  const assignmentsForRelationship = useMemo(
    () =>
      relationshipId
        ? model.assignments.filter(a =>
            a.relationship_assignments.some(ra => ra.relationship.id === relationshipId)
          )
        : [],
    [model.assignments, relationshipId]
  )
  const relationship = model.relationships.find(r => r.id === relationshipId)
  const assignment = model.assignments.find(a => a.id === assignmentId)

  // Principal(s) this assignment grants specifically FOR the selected
  // relationship -- one assignment can carry relationship_assignments for
  // more than one relationship (confirmed live: see
  // assignments_by_relationship_id's docstring), so this is scoped to the
  // one currently selected, not every principal on the assignment.
  const principalsForSelection = useMemo(() => {
    if (!assignment || !relationshipId) return []
    const seen = new Map<string, string>()
    for (const ra of assignment.relationship_assignments) {
      if (ra.relationship.id === relationshipId && ra.principal?.id) {
        seen.set(ra.principal.id, ra.principal.name)
      }
    }
    return [...seen.entries()].map(([id, name]) => ({ id, name }))
  }, [assignment, relationshipId])

  const policiesUsingAssignment = useMemo(() => {
    if (!assignment) return []
    const relIds = new Set(assignment.relationship_assignments.map(ra => ra.relationship.id))
    return model.policies.filter(p => p.relationship_ids.some(id => relIds.has(id)))
  }, [assignment, model.policies])

  const handleRelationshipChange = (id: string) => {
    setRelationshipId(id)
    setAssignmentId(undefined)
  }

  const exportSectionsForSelection: ExportSection[] = useMemo(() => {
    if (!assignment || !relationship) return [{ title: 'Relationships', rows: relationshipAssignmentRows(model) }]
    return [
      {
        title: `Assignment: ${assignment.name}`,
        rows: [
          {
            Relationship: relationship.name,
            Principals: principalsForSelection.map(p => p.name).join(', '),
            'Resolved Resources': assignment.resolved_resources.map(r => (r.kind === 'resolved' ? r.name : r.description)).join(', '),
            'Policies Using This': policiesUsingAssignment.map(p => p.name).join(', '),
          },
        ],
      },
    ]
  }, [assignment, relationship, principalsForSelection, policiesUsingAssignment, model])

  return (
    <div className="flex flex-col gap-4">
      <div className="flex justify-end">
        <ExportButtons sections={exportSectionsForSelection} filenameBase={assignment ? `opa-assignment-${assignment.name}` : 'opa-relationships'} />
      </div>

      <div className="flex flex-col md:flex-row gap-4">
        <div className="card p-2 flex flex-col gap-1 w-full md:w-64 shrink-0 max-h-[70vh] overflow-y-auto">
          <span className="section-label px-1 py-1">Relationships ({model.relationships.length})</span>
          {model.relationships.length === 0 && (
            <span className="text-xs text-text-faint px-1 py-1">None configured in this tenant.</span>
          )}
          {model.relationships.map(r => (
            <button
              key={r.id}
              type="button"
              onClick={() => handleRelationshipChange(r.id)}
              className={`text-left text-sm rounded px-2 py-1.5 transition-colors ${
                r.id === relationshipId ? 'bg-accent-dim text-text' : 'text-text-dim hover:bg-bg-hover'
              }`}
            >
              {r.name}
            </button>
          ))}
        </div>

        <div className="flex-1 flex flex-col gap-3">
          {!relationship && <span className="text-sm text-text-faint">Select a relationship to see its assignments.</span>}

          {relationship && (
            <>
              <div className="card p-3 flex flex-col gap-2">
                <span className="text-sm font-medium text-text">{relationship.name}</span>
                {relationship.description && <p className="text-sm text-text-dim">{relationship.description}</p>}
              </div>

              <div className="card p-3 flex flex-col gap-1">
                <span className="section-label">Assignments using this relationship ({assignmentsForRelationship.length})</span>
                {assignmentsForRelationship.length === 0 && (
                  <span className="text-xs text-text-faint">No assignments reference this relationship.</span>
                )}
                <Select
                  value={assignmentId}
                  onValueChange={setAssignmentId}
                  placeholder="Select an assignment"
                  options={assignmentsForRelationship.map((a: AccessAssignment) => ({ value: a.id, label: a.name }))}
                />
              </div>

              {assignment && (
                <div className="card p-3 flex flex-col gap-3">
                  <span className="text-sm font-medium text-text">{assignment.name}</span>
                  {assignment.description && <p className="text-sm text-text-dim">{assignment.description}</p>}

                  <div className="flex flex-col gap-1">
                    <span className="section-label">Principal(s) for this relationship</span>
                    <div className="flex flex-wrap gap-1.5">
                      {principalsForSelection.map(p => <Tag key={p.id}>{p.name}</Tag>)}
                      {principalsForSelection.length === 0 && <span className="text-xs text-text-faint">None</span>}
                    </div>
                  </div>

                  <div className="flex flex-col gap-1">
                    <span className="section-label">Resolved resources granted</span>
                    <div className="flex flex-wrap gap-1.5">
                      {assignment.resolved_resources.map((r, i) =>
                        r.kind === 'resolved' ? (
                          <Tag key={i}>{r.name}</Tag>
                        ) : (
                          <span key={i} className="text-xs text-text-faint italic">{r.description}</span>
                        )
                      )}
                      {assignment.resolved_resources.length === 0 && <span className="text-xs text-text-faint">None</span>}
                    </div>
                  </div>

                  <div className="flex flex-col gap-1">
                    <span className="section-label">Policies using this assignment ({policiesUsingAssignment.length})</span>
                    <div className="flex flex-wrap gap-1.5">
                      {policiesUsingAssignment.map(p => <Tag key={p.id}>{p.name}</Tag>)}
                      {policiesUsingAssignment.length === 0 && (
                        <span className="text-xs text-text-faint">No policy currently references this relationship.</span>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}
