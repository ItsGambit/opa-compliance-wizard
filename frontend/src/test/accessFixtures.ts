import type { AccessModel, AccessPolicy, AccessUser, PolicyRule } from '../types'

/** Fictional Access Explorer data for component tests. */

export function resolved(id: string, name: string, kind = 'individual_server_account', project = 'Example Project') {
  return { kind: 'resolved' as const, id, name, resource_kind: kind, project_id: 'p1', project_name: project, resource_group_id: 'rg1' }
}

export function rule(name: string, typeLabel: string, resolutions: PolicyRule['resolutions'], opts: Partial<PolicyRule> = {}): PolicyRule {
  return {
    name,
    resource_type: 'server_based_resource',
    resource_type_label: typeLabel,
    privileges: [{ privilege_type: 'reveal_password', flags: ['reveal_password'] }],
    conditions: [],
    resolutions,
    ...opts,
  }
}

export function policy(id: string, name: string, groups: { id: string; name: string }[], rules: PolicyRule[], extra: Partial<AccessPolicy> = {}): AccessPolicy {
  return {
    id, name, description: '', active: true, resource_group: { id: 'rg1', name: 'Example Group' },
    principals: { user_groups: groups, workload_roles: [] }, rules, relationship_ids: [], ...extra,
  }
}

export const MFA = { condition_type: 'mfa', condition_value: {} }

export const exampleUser: AccessUser = {
  id: 'u1', name: 'admin@example.test', status: 'ACTIVE', user_type: 'human',
  details: { email: 'admin@example.test', first_name: 'Example', last_name: 'Admin', full_name: 'Example Admin' },
  groups: [{ id: 'g1', name: 'Example-All-Users' }, { id: 'g2', name: 'Example-Linux-Admins' }, { id: 'g3', name: 'Example-No-Policy' }],
}

export const examplePolicies: AccessPolicy[] = [
  policy('pol1', 'Linux Servers Policy', [{ id: 'g1', name: 'Example-All-Users' }], [
    rule('Server access', 'Servers', [resolved('s1', 'lab-linux-example-01'), resolved('s2', 'lab-linux-example-02')], { conditions: [MFA] }),
  ], { relationship_ids: ['rel1'], description: 'Linux access for everyone' }),
  policy('pol2', 'Pull SaaS Policy', [{ id: 'g1', name: 'Example-All-Users' }, { id: 'g2', name: 'Example-Linux-Admins' }], [
    rule('Pull CRM accounts', 'Managed SaaS app accounts', [
      resolved('a1', 'crm-svc@example.test', 'individual_managed_saas_app_account'),
      resolved('a2', 'crm-readonly@example.test', 'individual_managed_saas_app_account'),
      resolved('a3', 'crm-integration@example.test', 'individual_managed_saas_app_account'),
    ]),
  ]),
  policy('pol3', 'Other Policy', [{ id: 'g9', name: 'Example-Other' }], [
    rule('Unrelated', 'Servers', [resolved('s9', 'lab-other-example-09')]),
  ], { resource_group: null, active: false }),
]

export const exampleModel = {
  resource_groups: [
    { id: 'rg1', name: 'Example Group', description: 'Example description', delegated_resource_admin_groups: [{ id: 'g2', name: 'Example-Linux-Admins' }] },
    { id: 'rg2', name: 'Empty Group' },
  ],
  projects: [
    { id: 'p1', name: 'Example Project', resource_group_id: 'rg1', active_resource_count: 4, stale_resource_count: 1 },
    { id: 'p2', name: 'Second Project', resource_group_id: 'rg1', active_resource_count: 2 },
  ],
  groups: [
    { id: 'g1', name: 'Example-All-Users', roles: ['ADMIN'] },
    { id: 'g2', name: 'Example-Linux-Admins', roles: [] },
  ],
  users: [exampleUser],
  policies: examplePolicies,
  servers: [], gateways: [], clients: [], devices: [], okta_accounts: [], saas_accounts: [],
  relationships: [
    { id: 'rel1', name: 'Example Safe Owners', description: 'Owners of a safe' },
    { id: 'rel2', name: 'Unused Relationship' },
  ],
  assignments: [
    {
      id: 'as1', name: 'Example Assignment', description: 'Assignment one', resource_assignments: null,
      relationship_assignments: [{ relationship: { id: 'rel1', name: 'Example Safe Owners' }, principal: { id: 'g1', name: 'Example-All-Users' } }],
      resolved_resources: [resolved('s1', 'lab-linux-example-01'), { kind: 'condition', description: 'Servers labeled role=bastion' }],
    },
  ],
} as unknown as AccessModel
