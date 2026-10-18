import type { AccessAssignment, AccessModel, AccessPolicy, NamedRef } from '../types'

/** Every assignment that carries a relationship_assignment for `relationshipId`. */
export function assignmentsForRelationship(model: Pick<AccessModel, 'assignments'>, relationshipId: string): AccessAssignment[] {
  return model.assignments.filter(a => a.relationship_assignments.some(ra => ra.relationship.id === relationshipId))
}

/** Principal(s) an assignment grants specifically FOR the given relationship.
 * One assignment can carry relationship_assignments for more than one
 * relationship (confirmed live: see assignments_by_relationship_id's
 * docstring), so this is scoped to one relationship, not every principal on
 * the assignment. */
export function principalsForRelationship(assignment: AccessAssignment, relationshipId: string): NamedRef[] {
  const seen = new Map<string, string>()
  for (const ra of assignment.relationship_assignments) {
    if (ra.relationship.id === relationshipId && ra.principal?.id) seen.set(ra.principal.id, ra.principal.name)
  }
  return [...seen.entries()].map(([id, name]) => ({ id, name }))
}

/** Policies that reference any relationship this assignment belongs to. */
export function policiesUsingAssignment(assignment: AccessAssignment, policies: AccessPolicy[]): AccessPolicy[] {
  const relIds = new Set(assignment.relationship_assignments.map(ra => ra.relationship.id))
  return policies.filter(p => p.relationship_ids.some(id => relIds.has(id)))
}
