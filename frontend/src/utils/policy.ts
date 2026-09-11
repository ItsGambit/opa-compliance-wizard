import type { AccessPolicy, PolicyRule, PolicyRuleCondition } from '../types'

/** Human-readable description of a rule-level condition (MFA / gateway /
 * access request) — these shapes are simple and stable, unlike the
 * dynamic resource selectors the backend already describes for us. */
export function describeCondition(condition: PolicyRuleCondition): string {
  const v = condition.condition_value ?? {}
  switch (condition.condition_type) {
    case 'mfa': {
      const freq = v.re_auth_frequency_in_seconds
      const freqText = typeof freq === 'number' && freq > 0 ? `every ${freq}s` : 'once per session'
      return `MFA required (${freqText}${v.acr_values ? `, ${v.acr_values}` : ''})`
    }
    case 'gateway': {
      const parts: string[] = []
      if (v.traffic_forwarding) parts.push('traffic forwarding')
      if (v.session_recording) parts.push('session recording')
      return `Gateway: ${parts.length ? parts.join(', ') : 'required'}`
    }
    case 'access_request': {
      const name = typeof v.request_type_name === 'string' ? v.request_type_name : 'request'
      const expires = v.expires_after_seconds
      return `Access request "${name}"${typeof expires === 'number' ? ` — expires after ${expires}s` : ''}`
    }
    default:
      return condition.condition_type
  }
}

export interface GrantedRule {
  policy: AccessPolicy
  rule: PolicyRule
}

/** Every (policy, rule) pair whose policy's principals.user_groups
 * includes any of the given group IDs — the shared "what does this
 * group/user have access to" join used by the Users and Groups tabs.
 * A rule appears once per matching policy, even if the policy grants
 * access via more than one of the given groups. */
export function rulesGrantedToGroupIds(policies: AccessPolicy[], groupIds: Set<string>): GrantedRule[] {
  const out: GrantedRule[] = []
  for (const policy of policies) {
    const grants = policy.principals.user_groups.some(g => groupIds.has(g.id))
    if (!grants) continue
    for (const rule of policy.rules) {
      out.push({ policy, rule })
    }
  }
  return out
}

/** Every (policy, rule) pair whose rule resolves to the given project. */
export function rulesGrantedForProject(policies: AccessPolicy[], projectId: string): GrantedRule[] {
  const out: GrantedRule[] = []
  for (const policy of policies) {
    for (const rule of policy.rules) {
      if (rule.resolutions.some(r => r.kind === 'resolved' && r.project_id === projectId)) {
        out.push({ policy, rule })
      }
    }
  }
  return out
}

/** Every policy scoped to the given resource group (policy.resource_group.id
 * match) — policies with no resource_group at all ("team-wide") never match. */
export function policiesForResourceGroup(policies: AccessPolicy[], resourceGroupId: string): AccessPolicy[] {
  return policies.filter(p => p.resource_group?.id === resourceGroupId)
}

/** Every policy whose principals.user_groups includes the given group id —
 * the "blast radius" check before removing a user from a group: if more
 * than the one policy you're currently looking at uses this same group,
 * removing membership takes away access granted by all of them, not just
 * the one you started from. Mirrors AssignAccessDialog's existing warning
 * for the opposite direction (adding a group to a policy). */
export function policiesUsingGroup(policies: AccessPolicy[], groupId: string): AccessPolicy[] {
  return policies.filter(p => p.principals.user_groups.some(g => g.id === groupId))
}
