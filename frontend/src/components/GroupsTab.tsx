import { useMemo, useState } from 'react'
import type { AccessModel } from '../types'
import type { ExportSection } from '../utils/export'
import { grantRows } from '../utils/exportSections'
import { rulesGrantedToGroupIds } from '../utils/policy'
import { ExportButtons } from './ExportButtons'
import { PolicyRuleCard } from './PolicyRuleCard'
import { Select } from './Select'

interface Props {
  model: AccessModel
}

export function GroupsTab({ model }: Props) {
  const [groupId, setGroupId] = useState<string | undefined>(undefined)
  const group = model.groups.find(g => g.id === groupId)

  const members = useMemo(
    () => model.users.filter(u => u.groups.some(g => g.id === groupId)),
    [model.users, groupId]
  )
  const grants = useMemo(
    () => (groupId ? rulesGrantedToGroupIds(model.policies, new Set([groupId])) : []),
    [model.policies, groupId]
  )

  const exportSectionsForGroup: ExportSection[] = useMemo(() => {
    if (!group) return []
    return [
      {
        title: `Group: ${group.name}`,
        rows: [{ Roles: group.roles.join(', '), Members: members.map(u => u.details?.full_name || u.name).join(', ') }],
      },
      { title: 'Access Granted', rows: grantRows(grants) },
    ]
  }, [group, members, grants])

  return (
    <div className="flex flex-col gap-4">
      <div className="card p-3 flex flex-col gap-1">
        <span className="section-label">Group</span>
        <Select
          value={groupId}
          onValueChange={setGroupId}
          placeholder="Select a group"
          options={model.groups.map(g => ({ value: g.id, label: g.name }))}
        />
      </div>

      {group && (
        <>
          <div className="card p-3 flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium text-text">{group.name}</span>
              <ExportButtons sections={exportSectionsForGroup} filenameBase={`opa-group-${group.name}`} />
            </div>

            <div className="flex flex-col gap-1">
              <span className="section-label">RBAC role(s) (team-level admin roles, not resource access)</span>
              <div className="flex flex-wrap gap-1.5">
                {group.roles.map(r => (
                  <span key={r} className="text-xs text-text-dim bg-bg-hover border border-border rounded px-1.5 py-0.5">
                    {r}
                  </span>
                ))}
                {group.roles.length === 0 && <span className="text-xs text-text-faint">None</span>}
              </div>
            </div>

            <div className="flex flex-col gap-1">
              <span className="section-label">Members ({members.length})</span>
              <div className="flex flex-wrap gap-1.5">
                {members.map(u => (
                  <span key={u.id} className="text-xs text-text-dim bg-bg-hover border border-border rounded px-1.5 py-0.5">
                    {u.details?.full_name || u.name}
                  </span>
                ))}
                {members.length === 0 && <span className="text-xs text-text-faint">None found among fetched users</span>}
              </div>
            </div>
          </div>

          <div className="flex flex-col gap-2">
            <span className="section-label">Everything this group grants access to ({grants.length})</span>
            {grants.length === 0 && <span className="text-xs text-text-faint">No policy names this group as a principal.</span>}
            {grants.map(({ policy, rule }, i) => (
              <PolicyRuleCard key={`${policy.id}-${i}`} rule={rule} policyName={policy.name} />
            ))}
          </div>
        </>
      )}
    </div>
  )
}
