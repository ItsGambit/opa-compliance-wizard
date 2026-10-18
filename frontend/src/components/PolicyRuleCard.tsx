import type { PolicyRule } from '../types'
import { rowQualifier } from '../utils/accessResources'
import { describeCondition } from '../utils/policy'
import { Chip } from './explorer/DetailBlocks'

interface Props {
  rule: PolicyRule
  /** Shown when this card appears outside its own policy's detail view
   * (e.g. listing rules from several policies together) so it is clear
   * which policy granted it. */
  policyName?: string
}

/** The one tag style of the Access Explorer (shared with the new views). */
export const Tag = Chip

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
                {rowQualifier(res) ? ` · ${rowQualifier(res)}` : ''}
                {res.project_name
                  ? ` — ${res.project_name}`
                  // relationship_assignment resolutions (see
                  // create_secret_folders.py's
                  // _resolve_relationship_assignment_resources) are
                  // team-wide grants with no project by design -- "(project
                  // unknown)" would wrongly imply a data gap here.
                  : res.resource_kind.startsWith('relationship_assignment:')
                    ? ''
                    : ' (project unknown)'}
                {res.relationship_name && res.assignment_name && (
                  <span className="text-text-faint"> · via {res.relationship_name} → {res.assignment_name}</span>
                )}
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
