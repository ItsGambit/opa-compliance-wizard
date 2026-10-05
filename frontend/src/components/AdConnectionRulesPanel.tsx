import { useAdConnectionDiscoveryConfig } from '../api/hooks'
import type { ExportSection } from '../utils/export'
import { ExportButtons } from './ExportButtons'

const MATCHING_CRITERIA_LABEL: Record<string, string> = {
  username: 'username',
  display_name: 'display name',
  email: 'email',
  first_and_last_name: 'first and last name',
}

/** Plain-English summary of rule_settings.matching_criteria +
 * partial_matching_criteria -- e.g. "Matches by username, partial match:
 * starts with 'a1', 'adm2'". Real values confirmed live 2026-09-30. */
function describeRuleSettings(settings: { matching_criteria: Record<string, boolean>; partial_matching_criteria: { operator: string; match_value: string }[]; allow_partial_matches: boolean }): string {
  const activeFields = Object.entries(settings.matching_criteria)
    .filter(([, on]) => on)
    .map(([key]) => MATCHING_CRITERIA_LABEL[key] ?? key)
  const base = activeFields.length > 0 ? `Matches by ${activeFields.join(', ')}` : 'No matching criteria configured'
  if (settings.partial_matching_criteria.length === 0) return base
  const partials = settings.partial_matching_criteria
    .map(p => `${p.operator.toLowerCase()} '${p.match_value}'`)
    .join(', ')
  return `${base}, partial match: ${partials}`
}

/** Discovery configuration for one Active Directory connection -- explains
 * WHY an individual AD account got discovered/matched to an Okta user at
 * all (confirmed live 2026-09-30 this is exactly how real accounts like
 * user1.lastname@example.com were matched). A genuinely different
 * UX shape from ResourceHistoryPanel (that's "show me compliance events,"
 * this is "show me discovery configuration") -- not a variant of it. */
export function AdConnectionRulesPanel({ connectionId, connectionLabel, onClose }: { connectionId: string; connectionLabel: string; onClose: () => void }) {
  const { data, isLoading } = useAdConnectionDiscoveryConfig(connectionId)
  const rules = data?.rules ?? []

  const exportSections: ExportSection[] = data
    ? [
        {
          title: `Discovery config: ${connectionLabel}`,
          rows: rules.map(r => ({
            Name: r.name,
            Type: r.rule_type,
            'Organizational Unit(s)': r.organizational_units.join('; '),
            Priority: String(r.priority),
            'Resource Group': r.resource_group?.name ?? '',
            Project: r.project?.name ?? '',
          })),
        },
      ]
    : []

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-text">Discovery config — {connectionLabel}</h3>
        <div className="flex items-center gap-2">
          <ExportButtons sections={exportSections} filenameBase={`opa-ad-discovery-${connectionLabel}`} />
          <button type="button" className="btn-secondary text-xs" onClick={onClose}>
            Close
          </button>
        </div>
      </div>

      {isLoading ? (
        <div className="card p-4 text-sm text-text-faint">Loading…</div>
      ) : !data ? (
        <div className="card p-4 text-sm text-text-faint">Could not load discovery configuration.</div>
      ) : (
        <>
          <div className="card p-3 text-xs text-text-dim">{describeRuleSettings(data.rule_settings)}</div>

          <div className="card p-0 overflow-x-auto">
            {rules.length === 0 ? (
              <div className="p-4 text-sm text-text-faint">No discovery rules configured for this connection.</div>
            ) : (
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-border">
                    {['Name', 'Type', 'Organizational Unit(s)', 'Priority', 'Resource Group', 'Project'].map(h => (
                      <th key={h} className="text-left font-semibold text-text-faint uppercase text-[0.625rem] tracking-wide px-3 py-2 whitespace-nowrap">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {rules.map(rule => (
                    <tr key={rule.id} className="border-b border-border-sub hover:bg-bg-hover">
                      <td className="px-3 py-2 text-text-dim whitespace-nowrap">{rule.name}</td>
                      <td className="px-3 py-2 text-text-dim whitespace-nowrap">{rule.rule_type}</td>
                      <td className="px-3 py-2 text-text-dim">{rule.organizational_units.join('; ')}</td>
                      <td className="px-3 py-2 text-text-dim whitespace-nowrap">{rule.priority}</td>
                      <td className="px-3 py-2 text-text-dim whitespace-nowrap">{rule.resource_group?.name ?? <span className="text-text-faint">—</span>}</td>
                      <td className="px-3 py-2 text-text-dim whitespace-nowrap">{rule.project?.name ?? <span className="text-text-faint">—</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </>
      )}
    </div>
  )
}
