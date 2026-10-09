import type { FolderSecurityPolicy, NamedRef } from '../types'

export interface BlastRadius {
  newGroupNames: string[]
  newRoleNames: string[]
  otherRuleCount: number
}

/** Principals apply policy-wide, not per rule: adding a group or workload
 * role to an existing policy (to grant one folder) also grants every other
 * rule already in it. Returns what the warning must name, or null when
 * nothing new is being added or there is no other rule.
 *
 * UI-20 (external review, 2026-10-05): the warning fired for new workload
 * roles but only ever named groups, so adding just a role rendered
 * " are not currently a principal…" with no subject -- the case (a service
 * identity gaining every other rule) where it matters most. */
export function computeBlastRadius(
  policy: FolderSecurityPolicy | undefined,
  selectedGroupIds: Set<string>,
  selectedRoleIds: Set<string>,
  folderId: string,
  groups: NamedRef[],
  roles: NamedRef[],
): BlastRadius | null {
  if (!policy) return null
  const existingGroupIds = new Set(policy.principals.user_groups.map(g => g.id))
  const existingRoleIds = new Set(policy.principals.workload_roles.map(r => r.id))
  const newGroups = [...selectedGroupIds].filter(id => !existingGroupIds.has(id))
  const newRoles = [...selectedRoleIds].filter(id => !existingRoleIds.has(id))
  if (newGroups.length === 0 && newRoles.length === 0) return null
  const otherRuleCount = policy.rules.filter(r => !r.targets.some(t => t.kind === 'resolved' && t.id === folderId)).length
  if (otherRuleCount === 0) return null
  const nameOf = (list: NamedRef[], id: string) => list.find(x => x.id === id)?.name ?? id
  return {
    newGroupNames: newGroups.map(id => nameOf(groups, id)),
    newRoleNames: newRoles.map(id => nameOf(roles, id)),
    otherRuleCount,
  }
}

/** One readable sentence for the warning, naming groups and roles. */
export function describeBlastRadius(b: BlastRadius): string {
  const parts: string[] = []
  if (b.newGroupNames.length) parts.push(`${b.newGroupNames.length === 1 ? 'group' : 'groups'} ${b.newGroupNames.join(', ')}`)
  if (b.newRoleNames.length) parts.push(`workload ${b.newRoleNames.length === 1 ? 'role' : 'roles'} ${b.newRoleNames.join(', ')}`)
  const count = b.newGroupNames.length + b.newRoleNames.length
  const subject = parts.join(' and ')
  const rules = `${b.otherRuleCount} other rule${b.otherRuleCount === 1 ? '' : 's'}`
  return `The ${subject} ${count === 1 ? 'is' : 'are'} not currently a principal on this policy. Adding ${count === 1 ? 'it' : 'them'} will also grant access to ${rules} already in this policy — principals apply policy-wide, not per-rule.`
}
