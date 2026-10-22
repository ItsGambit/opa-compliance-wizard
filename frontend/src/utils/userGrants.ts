import type { GrantedRule } from './policy'

const KIND_LABEL: Record<string, [string, string]> = {
  individual_server: ['server', 'servers'], server: ['server', 'servers'], secret_folder: ['secret folder', 'secret folders'], secret: ['secret', 'secrets'],
  individual_saas_account: ['SaaS account', 'SaaS accounts'], individual_okta_account: ['Okta account', 'Okta accounts'],
  individual_server_account: ['server account', 'server accounts'], individual_active_directory_account: ['Active Directory account', 'Active Directory accounts'],
}
const label = (kind: string | undefined, n: number) => {
  const pair = KIND_LABEL[kind ?? ''] ?? [String(kind ?? 'resource').replace(/_/g, ' '), `${String(kind ?? 'resource').replace(/_/g, ' ')}s`]
  return n === 1 ? pair[0] : pair[1]
}

/** "22 servers in payments-prod; 2 secret folders in finance": what a policy's rules resolve to, from the stored scan. */
export function grantsText(rules: GrantedRule['rule'][]): string {
  const groups = new Map<string, { kind: string | undefined; project: string | null | undefined; n: number }>()
  const unresolved = new Set<string>()
  for (const rule of rules) {
    for (const res of rule.resolutions) {
      if (res.kind === 'resolved') {
        const key = `${res.resource_kind}|${res.project_name ?? ''}`
        const g = groups.get(key) ?? { kind: res.resource_kind, project: res.project_name, n: 0 }
        g.n += 1
        groups.set(key, g)
      } else unresolved.add(rule.resource_type_label || rule.resource_type || 'resources')
    }
  }
  const parts = [...groups.values()].map(g => `${g.n} ${label(g.kind, g.n)}${g.project ? ` in ${g.project}` : ''}`)
  for (const u of unresolved) parts.push(`${u} (by selector)`)
  return parts.join('; ') || 'nothing resolved'
}
