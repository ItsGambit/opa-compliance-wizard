/** UI-20: the warning names new workload roles as well as groups. */
import { describe, expect, it } from 'vitest'
import type { FolderSecurityPolicy } from '../types'
import { computeBlastRadius, describeBlastRadius } from './blastRadius'

const policy = {
  id: 'p', name: 'P', description: '', active: true, resource_group: null,
  principals: { user_groups: [{ id: 'g1', name: 'existing' }], workload_roles: [] },
  rules: [
    { name: 'this', targets: [{ kind: 'resolved', id: 'folder-1' }] },
    { name: 'other', targets: [{ kind: 'resolved', id: 'folder-2' }] },
  ],
} as unknown as FolderSecurityPolicy

describe('computeBlastRadius', () => {
  it('names a new workload role when it is the only new principal', () => {
    const b = computeBlastRadius(policy, new Set(['g1']), new Set(['r1']), 'folder-1', [{ id: 'g1', name: 'existing' }], [{ id: 'r1', name: 'ci-bot' }])
    expect(b).toEqual({ newGroupNames: [], newRoleNames: ['ci-bot'], otherRuleCount: 1 })
    expect(describeBlastRadius(b!)).toBe('The workload role ci-bot is not currently a principal on this policy. Adding it will also grant access to 1 other rule already in this policy — principals apply policy-wide, not per-rule.')
  })

  it('names groups and roles together', () => {
    const b = computeBlastRadius(policy, new Set(['g2']), new Set(['r1']), 'folder-1', [{ id: 'g2', name: 'ops' }], [{ id: 'r1', name: 'ci-bot' }])
    expect(describeBlastRadius(b!)).toMatch(/^The group ops and workload role ci-bot are not/)
  })

  it('is null when nothing new is added or no other rule exists', () => {
    expect(computeBlastRadius(policy, new Set(['g1']), new Set(), 'folder-1', [], [])).toBeNull()
    const single = { ...policy, rules: [policy.rules[0]] }
    expect(computeBlastRadius(single, new Set(['g9']), new Set(), 'folder-1', [], [])).toBeNull()
  })
})
