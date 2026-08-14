import type { ReactNode } from 'react'
import type { PolicyRule } from '../types'
import { describeCondition } from '../utils/policy'

interface Props {
  rule: PolicyRule
  /** Shown when this card appears outside its own policy's detail view
   * (e.g. in the Project/User/Group tabs, where rules from many different
   * policies are listed together) so it's clear which policy granted it. */
  policyName?: string
}

function Tag({ children }: { children: ReactNode }) {
  return (
    <span className="text-[0.6875rem] font-medium px-1.5 py-0.5 rounded border bg-bg-hover text-text-dim border-border whitespace-nowrap">
      {children}
    </span>
  )
}

export function PolicyRuleCard({ rule, policyName }: Props) {
  return (
    <div className="card p-3 flex flex-col gap-2">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-text">{rule.name}</span>
          <Tag>{rule.resource_type_label}</Tag>
        </div>
        {policyName && <span className="text-xs text-text-faint">via {policyName}</span>}
      </div>

      <div className="flex flex-col gap-1">
        <span className="section-label">Applies to</span>
        <div className="flex flex-wrap gap-1.5">
          {rule.resolutions.map((res, i) =>
            res.kind === 'resolved' ? (
              <Tag key={i}>
                {res.name}
                {res.project_name ? ` — ${res.project_name}` : ' (project unknown)'}
              </Tag>
            ) : (
              <span key={i} className="text-xs text-text-faint italic">
                {res.description}
              </span>
            )
          )}
        </div>
      </div>

      {rule.privileges.length > 0 && (
        <div className="flex flex-col gap-1">
          <span className="section-label">Privileges</span>
          <div className="flex flex-wrap gap-1.5">
            {rule.privileges.map((p, i) => (
              <Tag key={i}>
                {p.privilege_type}
                {p.flags.length > 0 ? `: ${p.flags.join(', ')}` : ''}
              </Tag>
            ))}
          </div>
        </div>
      )}

      {rule.conditions.length > 0 && (
        <div className="flex flex-col gap-1">
          <span className="section-label">Conditions</span>
          <div className="flex flex-wrap gap-1.5">
            {rule.conditions.map((c, i) => (
              <Tag key={i}>{describeCondition(c)}</Tag>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
