import { describe, expect, it } from 'vitest'
import { exampleModel } from '../test/accessFixtures'
import { assignmentsForRelationship, policiesUsingAssignment, principalsForRelationship } from './relationships'

describe('relationship helpers', () => {
  const assignment = exampleModel.assignments[0]

  it('finds the assignments of a relationship', () => {
    expect(assignmentsForRelationship(exampleModel, 'rel1').map(a => a.id)).toEqual(['as1'])
    expect(assignmentsForRelationship(exampleModel, 'rel2')).toEqual([])
  })

  it('scopes principals to the selected relationship and de-duplicates them', () => {
    const twoRelationships = {
      ...assignment,
      relationship_assignments: [
        ...assignment.relationship_assignments,
        ...assignment.relationship_assignments,
        { relationship: { id: 'rel2', name: 'Unused Relationship' }, principal: { id: 'g2', name: 'Example-Linux-Admins' } },
      ],
    }
    expect(principalsForRelationship(twoRelationships, 'rel1')).toEqual([{ id: 'g1', name: 'Example-All-Users' }])
    expect(principalsForRelationship(twoRelationships, 'rel2')).toEqual([{ id: 'g2', name: 'Example-Linux-Admins' }])
  })

  it('finds the policies that reference the assignment\'s relationships', () => {
    expect(policiesUsingAssignment(assignment, exampleModel.policies).map(p => p.id)).toEqual(['pol1'])
  })
})
