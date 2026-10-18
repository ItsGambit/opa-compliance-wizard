import { useEnvironments, useResourceHistory } from '../../api/hooks'
import type { AccessPolicy } from '../../types'
import type { ExportSection } from '../../utils/export'
import { formatDateTime } from '../../utils/format'
import { ExportButtons } from '../ExportButtons'
import { PolicyRuleCard } from '../PolicyRuleCard'
import { Chip, DetailGrid, DetailSection } from './DetailBlocks'

/** "Last modified by {user} on {date}" for one policy -- reuses the exact
 * same per-resource history lookup ResourcesTab's drill-down already uses
 * (pam.security_policy.create/.update events target the policy's own id,
 * confirmed live 2026-10-02), not a new backend call. No date range passed
 * (full history) -- this just needs the single most recent create/update
 * entry, not a browsable table. */
function PolicyLastModified({ policyId }: { policyId: string }) {
  const { data: environments } = useEnvironments()
  const activeEnv = environments?.active ?? undefined  // null (no active env) -> undefined, which the hooks treat as "disabled"
  const { data, isLoading, isError } = useResourceHistory(policyId, activeEnv)
  const latest = data?.rows.find(r => r.event_type === 'pam.security_policy.create' || r.event_type === 'pam.security_policy.update')
  if (isLoading) return null
  // UI-04: a failed lookup says so instead of looking like "never modified".
  if (isError) return <p className="text-warn">Last modified: could not load the history</p>
  if (!latest) return null
  return <p className="xp-mute">Last modified by {latest.user} on {formatDateTime(latest.timestamp)}</p>
}

/** The expanded view of one policy: who it is for, its rules, and (where
 * asked) when it last changed and a per-policy export. */
export function PolicyDetail({
  policy, showLastModified, exportSections, exportName,
}: {
  policy: AccessPolicy
  showLastModified?: boolean
  exportSections?: ExportSection[]
  exportName?: string
}) {
  return (
    <DetailGrid>
      <DetailSection title="What it is">
        <p>{policy.resource_group ? `Scoped to the resource group ${policy.resource_group.name}` : 'Team-wide (no resource group)'} · {policy.active ? 'Active' : 'Inactive'}.</p>
        {policy.description && <p className="xp-mute">{policy.description}</p>}
        {showLastModified && <PolicyLastModified policyId={policy.id} />}
      </DetailSection>
      <DetailSection title="Who it is for">
        {policy.principals.user_groups.length === 0 && policy.principals.workload_roles.length === 0 ? (
          <p className="xp-mute">None</p>
        ) : (
          <div>
            {policy.principals.user_groups.map(g => <Chip key={g.id}>{g.name}</Chip>)}
            {policy.principals.workload_roles.map(w => <Chip key={w.id}>{w.name} (workload role)</Chip>)}
          </div>
        )}
        {exportSections && exportName && (
          <div className="mt-2"><ExportButtons sections={exportSections} filenameBase={exportName} /></div>
        )}
      </DetailSection>
      <DetailSection title={`Rules (${policy.rules.length})`} full>
        {policy.rules.length === 0 && <p className="xp-mute">This policy has no rules.</p>}
        <div className="flex flex-col gap-2">
          {policy.rules.map((rule, i) => <PolicyRuleCard key={i} rule={rule} />)}
        </div>
      </DetailSection>
    </DetailGrid>
  )
}
