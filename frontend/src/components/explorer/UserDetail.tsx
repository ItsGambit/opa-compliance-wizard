import { useMemo } from 'react'
import type { AccessModel, AccessUser } from '../../types'
import { describeCondition, type GrantedRule } from '../../utils/policy'
import { formatDateTime } from '../../utils/format'
import { StatusBadge } from '../StatusBadge'

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

interface Props {
  user: AccessUser
  model: AccessModel
  grants: GrantedRule[]
  groupIds: Set<string>
  /** The Okta lifecycle read (cross-check C1) for this person, if a lookup was run. */
  okta?: { state: string | null; flag: 'inactive' | 'absent' | 'unknown' | null; capturedAt: string | null }
  /** Resource-type counts line from the Users view ("38 servers, 2 secret folders ..."). */
  reach: string
  evidenceTarget: string
}

/** The Users view's detail card (the approved design): name and badges, the summary line, the Resource evidence button, and a table of the
 * policies that reach this person (Policy, Via group, Grants, Conditions) read from the stored scan. "Last accessed" has no per-policy
 * source (the model holds last-use per resource), so it stays in the resource list below; nothing here is invented. */
export function UserDetail({ user, model, grants, groupIds, okta, reach, evidenceTarget }: Props) {
  const isService = user.user_type === 'service'
  const byPolicy = useMemo(() => {
    const map = new Map<string, { name: string; via: string[]; rules: GrantedRule['rule'][]; active: boolean }>()
    for (const { policy, rule } of grants) {
      const row = map.get(policy.id) ?? {
        name: policy.name, active: policy.active, rules: [],
        via: policy.principals.user_groups.filter(g => groupIds.has(g.id)).map(g => g.name),
      }
      row.rules.push(rule)
      map.set(policy.id, row)
    }
    return [...map.values()]
  }, [grants, groupIds])
  const powerful = useMemo(() => {
    const roles = new Set<string>()
    for (const g of model.groups) if (groupIds.has(g.id)) for (const r of g.roles ?? []) if (/admin$/.test(r)) roles.add(r)
    return [...roles][0]
  }, [model.groups, groupIds])
  const oktaBadge = okta && okta.state ? `Okta: ${okta.state.toLowerCase()}${okta.capturedAt ? `, read ${formatDateTime(okta.capturedAt)}` : ''}` : null
  const summary = [user.details?.email, isService ? 'service user · API key' : user.user_type ?? 'human',
    `${user.groups.length} group${user.groups.length === 1 ? '' : 's'} → ${byPolicy.length} polic${byPolicy.length === 1 ? 'y' : 'ies'}${reach ? ` → ${reach}` : ''}`].filter(Boolean).join(' · ')
  return (
    <section className="card p-4 flex flex-col gap-3" aria-label="Selected user">
      <div className="flex justify-between items-start gap-3 flex-wrap">
        <div>
          <h2 className="text-sm font-semibold text-text flex items-center gap-2 flex-wrap m-0">
            {user.details?.full_name || user.name}
            {powerful && <StatusBadge label={`${powerful} via group`} variant="exists" />}
            {isService && <StatusBadge label="Service account" variant="warn" />}
            {oktaBadge && <StatusBadge label={oktaBadge} variant={okta?.flag === 'inactive' || okta?.flag === 'absent' ? 'warn' : 'active'} />}
          </h2>
          <p className="text-xs text-muted mt-1 mb-0">{summary}</p>
        </div>
        <a href={`#${evidenceTarget}`} className="btn-secondary no-underline" onClick={e => { e.preventDefault(); document.getElementById(evidenceTarget)?.scrollIntoView?.({ behavior: 'smooth', block: 'start' }) }}>
          Resource evidence (live + archive)
        </a>
      </div>
      {okta?.flag && okta.flag !== 'unknown' && (
        <p className="text-xs text-warn m-0" role="status">
          {okta.flag === 'inactive' ? "Okta: this person's Okta user is deprovisioned or suspended, yet they are still an OPA principal. A candidate for review." : 'Okta: no Okta user was found for this person, yet they are still an OPA principal. A candidate for review.'}
          {okta.capturedAt && <> Looked up {formatDateTime(okta.capturedAt)}.</>}
        </p>
      )}
      {okta?.flag === 'unknown' && <p className="text-xs text-muted m-0" role="status">Okta: the status could not be read in the last lookup.</p>}
      {isService && <p className="text-xs text-muted m-0">No Okta identity — API-key-only, so "last used" (System Log) doesn't apply to it.</p>}
      {user.groups_error && <p className="text-xs text-warn m-0">Groups could not be read for this user, so their access is unknown (not "none").</p>}
      {byPolicy.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-xs border-collapse">
            <thead><tr className="text-left text-muted">
              {['Policy', 'Via group', 'Grants', 'Conditions'].map(h => <th key={h} scope="col" className="py-1.5 pr-3 font-semibold uppercase tracking-wide text-[0.6875rem] border-b border-border">{h}</th>)}
            </tr></thead>
            <tbody>
              {byPolicy.map(row => {
                const conditions = [...new Set(row.rules.flatMap(r => r.conditions.map(describeCondition)))]
                return (
                  <tr key={row.name} className="align-top">
                    <td className="py-1.5 pr-3 border-b border-border-sub text-text-dim">{row.name}{!row.active && <span className="text-muted"> (inactive)</span>}</td>
                    <td className="py-1.5 pr-3 border-b border-border-sub text-text-dim">{row.via.join(', ')}</td>
                    <td className="py-1.5 pr-3 border-b border-border-sub text-text-dim">{grantsText(row.rules)}</td>
                    <td className="py-1.5 pr-3 border-b border-border-sub text-text-dim">{conditions.length ? conditions.join(' · ') : 'none'}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
      <p className="text-xs text-muted m-0">
        Policy grants come from the stored OPA scan. "Last accessed" and "Resource evidence" read the archive and the live System Log when you ask; they are in the list below and are not part of the scan.
      </p>
    </section>
  )
}
