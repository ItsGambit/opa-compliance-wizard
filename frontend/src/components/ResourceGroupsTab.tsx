import { useMemo, useState } from 'react'
import type { AccessModel } from '../types'
import type { ExportSection } from '../utils/export'
import { grantRows } from '../utils/exportSections'
import { policiesForResourceGroup } from '../utils/policy'
import { ExportButtons } from './ExportButtons'
import { PolicyRuleCard } from './PolicyRuleCard'
import { Select } from './Select'

interface Props {
  model: AccessModel
}

export function ResourceGroupsTab({ model }: Props) {
  const [rgId, setRgId] = useState<string | undefined>(undefined)
  const rg = model.resource_groups.find(r => r.id === rgId)

  const projects = useMemo(() => model.projects.filter(p => p.resource_group_id === rgId), [model.projects, rgId])
  const policies = useMemo(() => (rgId ? policiesForResourceGroup(model.policies, rgId) : []), [model.policies, rgId])

  const accessGroups = useMemo(() => {
    const seen = new Map<string, string>()
    for (const p of policies) {
      for (const g of p.principals.user_groups) seen.set(g.id, g.name)
    }
    return [...seen.values()]
  }, [policies])

  const resourceTypes = useMemo(() => {
    const seen = new Set<string>()
    for (const p of policies) for (const r of p.rules) seen.add(r.resource_type_label)
    return [...seen]
  }, [policies])

  const exportSectionsForRg: ExportSection[] = useMemo(() => {
    if (!rg) return []
    return [
      {
        title: `Resource Group: ${rg.name}`,
        rows: [
          {
            Description: rg.description ?? '',
            'Delegated Admin Groups': (rg.delegated_resource_admin_groups ?? []).map(g => g.name).join(', '),
          },
        ],
      },
      {
        title: 'Projects',
        rows: projects.map(p => ({
          Project: p.name,
          'Active Resources': typeof p.active_resource_count === 'number' ? String(p.active_resource_count) : '',
          'Stale Resources': typeof p.stale_resource_count === 'number' ? String(p.stale_resource_count) : '',
        })),
      },
      { title: 'Policies & Rules', rows: grantRows(policies.flatMap(policy => policy.rules.map(rule => ({ policy, rule })))) },
    ]
  }, [rg, projects, policies])

  return (
    <div className="flex flex-col gap-4">
      <div className="card p-3 flex items-end justify-between gap-4">
        <div className="flex flex-col gap-1">
          <span className="section-label">Resource group</span>
          <Select
            value={rgId}
            onValueChange={setRgId}
            placeholder="Select a resource group"
            options={model.resource_groups.map(r => ({ value: r.id, label: r.name }))}
          />
        </div>
        {rg && <ExportButtons sections={exportSectionsForRg} filenameBase={`opa-resource-group-${rg.name}`} />}
      </div>

      {rg && (
        <>
          <div className="card p-3 flex flex-col gap-3">
            {rg.description && <p className="text-sm text-text-dim">{rg.description}</p>}

            <div className="flex flex-col gap-1">
              <span className="section-label">Delegated admin group(s)</span>
              {rg.delegated_resource_admin_groups?.length ? (
                <div className="flex flex-wrap gap-1.5">
                  {rg.delegated_resource_admin_groups.map(g => (
                    <span key={g.id} className="text-xs text-text-dim bg-bg-hover border border-border rounded px-1.5 py-0.5">
                      {g.name}
                    </span>
                  ))}
                </div>
              ) : (
                <span className="text-xs text-text-faint">None</span>
              )}
            </div>

            <div className="flex flex-col gap-1">
              <span className="section-label">Who has access (via policies scoped here)</span>
              {accessGroups.length ? (
                <div className="flex flex-wrap gap-1.5">
                  {accessGroups.map(name => (
                    <span key={name} className="text-xs text-text-dim bg-bg-hover border border-border rounded px-1.5 py-0.5">
                      {name}
                    </span>
                  ))}
                </div>
              ) : (
                <span className="text-xs text-text-faint">No policies grant access via a group here</span>
              )}
            </div>

            <div className="flex flex-col gap-1">
              <span className="section-label">Resource types covered</span>
              {resourceTypes.length ? (
                <div className="flex flex-wrap gap-1.5">
                  {resourceTypes.map(t => (
                    <span key={t} className="text-xs text-text-dim bg-bg-hover border border-border rounded px-1.5 py-0.5">
                      {t}
                    </span>
                  ))}
                </div>
              ) : (
                <span className="text-xs text-text-faint">None</span>
              )}
            </div>
          </div>

          <div className="card p-3 flex flex-col gap-2">
            <span className="section-label">Projects ({projects.length})</span>
            {projects.length === 0 && <span className="text-xs text-text-faint">No projects in this resource group</span>}
            {projects.map(p => (
              <div key={p.id} className="flex items-center justify-between text-sm">
                <span className="text-text-dim">{p.name}</span>
                <span className="text-xs text-text-faint">
                  {typeof p.active_resource_count === 'number' ? `${p.active_resource_count} active` : ''}
                  {typeof p.stale_resource_count === 'number' && p.stale_resource_count > 0
                    ? ` · ${p.stale_resource_count} stale`
                    : ''}
                </span>
              </div>
            ))}
          </div>

          <div className="flex flex-col gap-2">
            <span className="section-label">Policies scoped to this resource group ({policies.length})</span>
            {policies.length === 0 && <span className="text-xs text-text-faint">None</span>}
            {policies.map(policy => (
              <div key={policy.id} className="flex flex-col gap-2">
                {policy.rules.map((rule, i) => (
                  <PolicyRuleCard key={i} rule={rule} policyName={policy.name} />
                ))}
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  )
}
