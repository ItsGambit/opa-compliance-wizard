import { useMemo, useState } from 'react'
import { useEnvironments, useResourceHistory } from '../api/hooks'
import type { AccessModel } from '../types'
import type { ExportSection } from '../utils/export'
import { grantRows, policySummaryRows } from '../utils/exportSections'
import { formatDateTime } from '../utils/format'
import { ExportButtons } from './ExportButtons'
import { PolicyRuleCard } from './PolicyRuleCard'

interface Props {
  model: AccessModel
}

/** "Last modified by {user} on {date}" for one policy -- reuses the exact
 * same per-resource history lookup ResourcesTab's drill-down already uses
 * (pam.security_policy.create/.update events target the policy's own id,
 * confirmed live 2026-10-02), not a new backend call. No date range passed
 * (full history) -- this just needs the single most recent create/update
 * entry, not a browsable table. */
function PolicyLastModified({ policyId }: { policyId: string }) {
  const { data: environments } = useEnvironments()
  const activeEnv = environments?.active ?? undefined  // null (no active env) -> undefined, which the hooks treat as "disabled"
  const { data, isLoading } = useResourceHistory(policyId, activeEnv)
  const latest = data?.rows.find(r => r.event_type === 'pam.security_policy.create' || r.event_type === 'pam.security_policy.update')
  if (isLoading) return null
  if (!latest) return null
  return (
    <span className="text-xs text-text-faint">
      Last modified by {latest.user} on {formatDateTime(latest.timestamp)}
    </span>
  )
}

export function PoliciesTab({ model }: Props) {
  const [policyId, setPolicyId] = useState<string | undefined>(undefined)

  const scoped = useMemo(
    () => model.policies.filter(p => p.resource_group).sort((a, b) => a.name.localeCompare(b.name)),
    [model.policies]
  )
  const teamWide = useMemo(
    () => model.policies.filter(p => !p.resource_group).sort((a, b) => a.name.localeCompare(b.name)),
    [model.policies]
  )
  const policy = model.policies.find(p => p.id === policyId)

  const exportSectionsForView: ExportSection[] = useMemo(() => {
    if (!policy) return [{ title: 'Policies', rows: policySummaryRows(model.policies) }]
    return [
      {
        title: `Policy: ${policy.name}`,
        rows: [
          {
            Description: policy.description ?? '',
            Active: policy.active ? 'Yes' : 'No',
            'Resource Group': policy.resource_group?.name ?? 'Team-wide',
            'Principal Groups': policy.principals.user_groups.map(g => g.name).join(', '),
            'Workload Roles': policy.principals.workload_roles.map(w => w.name).join(', '),
          },
        ],
      },
      { title: 'Rules', rows: grantRows(policy.rules.map(rule => ({ policy, rule }))) },
    ]
  }, [policy, model.policies])

  return (
    <div className="flex flex-col gap-3">
      <div className="flex justify-end">
        <ExportButtons
          sections={exportSectionsForView}
          filenameBase={policy ? `opa-policy-${policy.name}` : 'opa-policies'}
        />
      </div>
      <div className="flex flex-col md:flex-row gap-4">
      <div className="card p-2 flex flex-col gap-1 w-full md:w-64 shrink-0 max-h-[70vh] overflow-y-auto">
        <span className="section-label px-1 py-1">Scoped to a resource group ({scoped.length})</span>
        {scoped.map(p => (
          <button
            key={p.id}
            type="button"
            onClick={() => setPolicyId(p.id)}
            className={`text-left text-sm rounded px-2 py-1.5 transition-colors ${
              p.id === policyId ? 'bg-accent-dim text-text' : 'text-text-dim hover:bg-bg-hover'
            }`}
          >
            {p.name}
            {!p.active && <span className="text-text-faint text-xs"> (inactive)</span>}
          </button>
        ))}

        {teamWide.length > 0 && (
          <>
            <span className="section-label px-1 py-1 mt-2">Team-wide ({teamWide.length})</span>
            {teamWide.map(p => (
              <button
                key={p.id}
                type="button"
                onClick={() => setPolicyId(p.id)}
                className={`text-left text-sm rounded px-2 py-1.5 transition-colors ${
                  p.id === policyId ? 'bg-accent-dim text-text' : 'text-text-dim hover:bg-bg-hover'
                }`}
              >
                {p.name}
                {!p.active && <span className="text-text-faint text-xs"> (inactive)</span>}
              </button>
            ))}
          </>
        )}
      </div>

      <div className="flex-1 flex flex-col gap-3">
        {!policy && <span className="text-sm text-text-faint">Select a policy to see its detail.</span>}
        {policy && (
          <>
            <div className="card p-3 flex flex-col gap-2">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium text-text">{policy.name}</span>
                <span className="text-xs text-text-faint">
                  {policy.resource_group ? policy.resource_group.name : 'Team-wide'} · {policy.active ? 'Active' : 'Inactive'}
                </span>
              </div>
              {policy.description && <p className="text-sm text-text-dim">{policy.description}</p>}
              <PolicyLastModified policyId={policy.id} />

              <div className="flex flex-col gap-1">
                <span className="section-label">Principals</span>
                <div className="flex flex-wrap gap-1.5">
                  {policy.principals.user_groups.map(g => (
                    <span key={g.id} className="text-xs text-text-dim bg-bg-hover border border-border rounded px-1.5 py-0.5">
                      {g.name}
                    </span>
                  ))}
                  {policy.principals.workload_roles.map(w => (
                    <span key={w.id} className="text-xs text-text-dim bg-bg-hover border border-border rounded px-1.5 py-0.5">
                      {w.name} (workload role)
                    </span>
                  ))}
                  {policy.principals.user_groups.length === 0 && policy.principals.workload_roles.length === 0 && (
                    <span className="text-xs text-text-faint">None</span>
                  )}
                </div>
              </div>
            </div>

            <div className="flex flex-col gap-2">
              {policy.rules.map((rule, i) => (
                <PolicyRuleCard key={i} rule={rule} />
              ))}
            </div>
          </>
        )}
      </div>
      </div>
    </div>
  )
}
