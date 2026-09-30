import { useState } from 'react'
import { AlertTriangle, FileClock, KeyRound, Shield, Users } from 'lucide-react'
import { useEnvironments, useReportDefs } from '../api/hooks'
import type { ComplianceControl, ComplianceReportDef } from '../types'
import { ComplianceReportDetail } from './ComplianceReportDetail'
import { complianceReportExportSections } from '../utils/exportSections'
import { exportSections } from '../utils/export'
import { runReport } from '../api/client'

const CONTROL_LABELS: Record<ComplianceControl, string> = {
  CC6: 'Access Controls — CC6',
  CC7: 'System Operations — CC7',
  CC8: 'Change Management — CC8',
}

const CONTROL_ORDER: ComplianceControl[] = ['CC6', 'CC7', 'CC8']

const REPORT_ICON: Record<string, typeof Shield> = {
  mfa_enforcement: Shield,
  session_activity: Users,
  provisioning: Users,
  role_group_changes: Users,
  admin_privilege_grants: Shield,
  jit_access_requests: KeyRound,
  threat_detection: AlertTriangle,
  api_token_lifecycle: KeyRound,
  policy_modifications: FileClock,
  pam_secrets: KeyRound,
  pam_jit_access: KeyRound,
  pam_sessions: KeyRound,
  pam_credential_reveals: KeyRound,
  pam_policy_modifications: FileClock,
}

function ReportCard({ def, environment, onClick }: { def: ComplianceReportDef; environment: string | undefined; onClick: () => void }) {
  const Icon = REPORT_ICON[def.key] ?? Shield

  return (
    <div className="relative group">
      <button
        type="button"
        onClick={onClick}
        className="card p-3.5 flex items-start gap-3 w-full text-left hover:border-accent hover:bg-accent-dim transition-colors"
      >
        <div className="w-8 h-8 rounded-lg bg-accent-dim text-accent flex items-center justify-center shrink-0">
          <Icon size={16} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="text-sm font-medium text-text">{def.label}</div>
          <div className="text-xs text-text-faint leading-snug mt-0.5">{def.description}</div>
        </div>
        <div className="text-right shrink-0">
          <div className="text-lg font-bold text-text">{def.count ?? '—'}</div>
          <div className="text-[0.625rem] text-text-faint">events</div>
        </div>
      </button>
      <button
        type="button"
        title="Export CSV"
        className="absolute top-2 right-2 w-6 h-6 rounded-md border border-border bg-bg-card text-text-faint
          opacity-0 group-hover:opacity-100 hover:text-accent hover:border-accent transition-opacity flex items-center justify-center"
        onClick={async e => {
          e.stopPropagation()
          const resp = await runReport(def.key, environment)
          const sections = complianceReportExportSections(def.label, resp.rows)
          exportSections(sections, 'csv', `opa-report-${def.key}`)
        }}
      >
        ⬇
      </button>
    </div>
  )
}

export function ComplianceReports() {
  const { data: environments } = useEnvironments()
  const activeEnv = environments?.active
  const { data: reports } = useReportDefs(activeEnv)
  const [selectedReport, setSelectedReport] = useState<string | null>(null)

  if (selectedReport && reports) {
    const def = reports.find(r => r.key === selectedReport)
    if (def) {
      return <ComplianceReportDetail def={def} environment={activeEnv} onBack={() => setSelectedReport(null)} />
    }
  }

  const grouped = CONTROL_ORDER.map(control => ({
    control,
    reports: (reports ?? []).filter(r => r.control === control),
  })).filter(g => g.reports.length > 0)

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-end">
        <button
          type="button"
          className="btn-secondary text-xs"
          onClick={async () => {
            if (!reports) return
            const sections = await Promise.all(
              reports.map(async def => {
                const resp = await runReport(def.key, activeEnv)
                return { title: def.label, rows: resp.rows.map(r => ({
                  User: r.user, Action: r.action, Timestamp: r.timestamp, 'Affected Resource': r.resource, Outcome: r.outcome,
                })) }
              })
            )
            exportSections(sections, 'csv', 'opa-compliance-reports-all')
          }}
        >
          ⬇ Export all (CSV)
        </button>
      </div>

      {!reports && <div className="text-sm text-text-faint">Loading reports…</div>}

      {grouped.map(({ control, reports: controlReports }) => (
        <div key={control} className="flex flex-col gap-2">
          <div className="section-label">{CONTROL_LABELS[control]}</div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {controlReports.map(def => (
              <ReportCard key={def.key} def={def} environment={activeEnv} onClick={() => setSelectedReport(def.key)} />
            ))}
          </div>
        </div>
      ))}
      {reports && reports.length === 0 && (
        <div className="text-sm text-text-faint">No reports available.</div>
      )}
    </div>
  )
}
