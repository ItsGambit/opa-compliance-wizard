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

export function UsersTab({ model }: Props) {
  const [userId, setUserId] = useState<string | undefined>(undefined)
  const user = model.users.find(u => u.id === userId)

  const groupIds = useMemo(() => new Set(user?.groups.map(g => g.id) ?? []), [user])
  const grants = useMemo(() => (user ? rulesGrantedToGroupIds(model.policies, groupIds) : []), [model.policies, groupIds, user])

  const exportSectionsForUser: ExportSection[] = useMemo(() => {
    if (!user) return []
    return [
      {
        title: `User: ${user.details?.full_name || user.name}`,
        rows: [
          {
            Email: user.details?.email ?? '',
            Status: user.status ?? '',
            Groups: user.groups.map(g => g.name).join(', '),
          },
        ],
      },
      { title: 'Access Granted', rows: grantRows(grants) },
    ]
  }, [user, grants])

  return (
    <div className="flex flex-col gap-4">
      <div className="card p-3 flex flex-col gap-1">
        <span className="section-label">User</span>
        <Select
          value={userId}
          onValueChange={setUserId}
          placeholder="Select a user"
          options={model.users.map(u => ({ value: u.id, label: u.details?.full_name || u.name }))}
        />
      </div>

      {user && (
        <>
          <div className="card p-3 flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium text-text">{user.details?.full_name || user.name}</span>
              <div className="flex items-center gap-2">
                <span className="text-xs text-text-faint">{user.status}</span>
                <ExportButtons sections={exportSectionsForUser} filenameBase={`opa-user-${user.name}`} />
              </div>
            </div>
            {user.details?.email && <span className="text-xs text-text-faint">{user.details.email}</span>}

            <div className="flex flex-col gap-1">
              <span className="section-label">Groups ({user.groups.length})</span>
              <div className="flex flex-wrap gap-1.5">
                {user.groups.map(g => (
                  <span key={g.id} className="text-xs text-text-dim bg-bg-hover border border-border rounded px-1.5 py-0.5">
                    {g.name}
                  </span>
                ))}
                {user.groups.length === 0 && <span className="text-xs text-text-faint">None</span>}
              </div>
            </div>
          </div>

          <div className="flex flex-col gap-2">
            <span className="section-label">Everything this user has access to (via their groups) ({grants.length})</span>
            {grants.length === 0 && <span className="text-xs text-text-faint">No policy grants access via this user's groups.</span>}
            {grants.map(({ policy, rule }, i) => (
              <PolicyRuleCard key={`${policy.id}-${i}`} rule={rule} policyName={policy.name} />
            ))}
          </div>
        </>
      )}
    </div>
  )
}
