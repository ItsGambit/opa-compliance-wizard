import { useMutation } from '@tanstack/react-query'
import { AlertTriangle, Download, FileClock, KeyRound, Shield, Users } from 'lucide-react'
import { useEnvironments, useReportDefs, useSyncStatus } from '../api/hooks'
import type { ComplianceControl, ComplianceReportDef } from '../types'
import { ComplianceReportDetail } from './ComplianceReportDetail'
import { complianceReportExportSections } from '../utils/exportSections'
import { exportSections } from '../utils/export'
import { runReport } from '../api/client'
import { toast } from '../hooks/useToast'
import { ErrorNotice } from './ErrorNotice'
import { exportAllReports } from '../utils/reportExports'

// UI-03/DATA-07 (external review, 2026-10-05): both export paths below
// call runReport with no `from`/`to` and no `limit`, so a tenant with
// more than the server's default 1000-row cap for that report used to
// write a silently-partial CSV with no indication the file was missing
// its oldest rows. There's no truncation UI here the way the detail
// view's ReportRowsTable has (this is a direct-to-file export, not a
// table render) -- a toast after the fact is the simplest honest signal
// without blocking the export outright.
function warnIfTruncated(label: string, truncated: boolean, total: number, shown: number) {
  if (!truncated) return
  toast({
    title: `Export of "${label}" is incomplete`,
    description: `Showing the newest ${shown.toLocaleString()} of ${total.toLocaleString()} events. Open the report and narrow the date range to export the rest.`,
    variant: 'error',
  })
}

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
  // UI-14 (external review, 2026-10-05): a pending state (no duplicate
  // downloads from impatient clicks) and an error toast (a failed export
  // used to be a silent unhandled rejection).
  const exportMutation = useMutation({
    mutationFn: () => runReport(def.key, environment),
    onSuccess: resp => {
      warnIfTruncated(def.label, resp.truncated, resp.total, resp.rows.length)
      exportSections(complianceReportExportSections(def.label, resp.rows), 'csv', `opa-report-${def.key}`)
    },
    onError: (err: Error) => toast({ title: `Could not export "${def.label}"`, description: err.message, variant: 'error' }),
  })

  return (
    <div className="relative group">
      <button
        type="button"
        onClick={onClick}
        className="card p-3.5 flex items-start gap-3 w-full text-left hover:border-accent hover:bg-accent-dim transition-colors"
      >
        <div className="w-8 h-8 rounded-lg bg-accent-dim text-accent flex items-center justify-center shrink-0" aria-hidden="true">
          <Icon size={16} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="text-sm font-medium text-text">{def.label}</div>
          <div className="text-xs text-text-faint leading-snug mt-0.5">{def.description}</div>
        </div>
        <div className="text-right shrink-0">
          <div className="text-lg font-bold text-text">{def.count ?? '—'}</div>
          {/* UI-14: this count covers the whole archive; the report itself
              opens on the last 90 days, so the two numbers can differ. */}
          <div className="text-[0.625rem] text-text-faint">events, all time</div>
        </div>
      </button>
      <button
        type="button"
        title={`Export "${def.label}" (all time) as CSV`}
        aria-label={`Export ${def.label} as CSV`}
        disabled={exportMutation.isPending}
        className="absolute top-2 right-2 w-6 h-6 rounded-md border border-border bg-bg-card text-text-faint
          opacity-0 group-hover:opacity-100 focus-visible:opacity-100 disabled:opacity-100 hover:text-accent hover:border-accent transition-opacity flex items-center justify-center"
        onClick={e => {
          e.stopPropagation()
          exportMutation.mutate()
        }}
      >
        {exportMutation.isPending
          ? <span className="inline-block w-3 h-3 rounded-full border-2 border-accent border-t-transparent animate-spin" aria-hidden="true" />
          : <Download size={12} aria-hidden="true" />}
      </button>
    </div>
  )
}

interface Props {
  /** The open report's key, or null for the home grid. Controlled by
   * App.tsx's hash route (5.40.1) so opening a report is a browser
   * history entry and the back button returns here instead of leaving
   * the app. An unknown key (e.g. a stale link) just shows the grid. */
  selectedReport: string | null
  onSelectReport: (key: string | null) => void
}

export function ComplianceReports({ selectedReport, onSelectReport }: Props) {
  const { data: environments } = useEnvironments()
  const activeEnv = environments?.active ?? undefined  // null (no active env) -> undefined, which the hooks treat as "disabled"
  const { data: reports, isError: reportsError, error: reportsErrorValue, refetch: refetchReports, isFetching: reportsFetching } = useReportDefs(activeEnv)
  // Phase 10: point-in-time, non-polling read (see useSyncStatus's own
  // doc comment) -- this page just needs to know "is the data behind
  // these reports currently degraded," not live sync progress.
  const { data: syncStatus } = useSyncStatus(activeEnv)

  const exportAllMutation = useMutation({
    mutationFn: () => exportAllReports(reports ?? [], activeEnv),
    onSuccess: ({ sections, failed }) => {
      // A file named "all reports" must contain all of them: if any report
      // failed, nothing is downloaded (as before) -- but the failures are
      // now named instead of being a silent unhandled rejection (UI-14).
      if (failed.length > 0) {
        toast({
          title: 'Export failed — nothing was downloaded',
          description: `Could not load ${failed.length} of ${sections.length + failed.length} reports: ${failed.map(f => `${f.def.label} (${f.error})`).join('; ')}. Try again, or export reports one at a time from their cards.`,
          variant: 'error',
        })
        return
      }
      for (const { def, resp } of sections) warnIfTruncated(def.label, resp.truncated, resp.total, resp.rows.length)
      exportSections(sections.map(({ section }) => section), 'csv', 'opa-compliance-reports-all')
    },
  })

  if (selectedReport && reports) {
    const def = reports.find(r => r.key === selectedReport)
    if (def) {
      return <ComplianceReportDetail def={def} environment={activeEnv} onBack={() => onSelectReport(null)} />
    }
  }

  const grouped = CONTROL_ORDER.map(control => ({
    control,
    reports: (reports ?? []).filter(r => r.control === control),
  })).filter(g => g.reports.length > 0)

  const syncState = syncStatus?.sync_state

  return (
    <div className="flex flex-col gap-4">
      {/* Phase 10: shown by default, not dismissible -- a compliance
          report viewer must never silently see partial/stale data
          presented as complete. Scoped to the MOST RECENT sync's status
          (not "any day in this report's window"), which is what
          sync_state actually tracks today. */}
      {syncState?.last_sync_status === 'error' && (
        <div className="card p-2.5 text-xs text-loss flex items-start gap-2">
          <AlertTriangle size={14} className="shrink-0 mt-0.5" />
          <div>
            This report's source data has a known gap — the last sync for{' '}
            <span className="font-medium">{activeEnv}</span> failed: {syncState.last_sync_error}.{' '}
            {syncState.last_sync_completed_at
              ? `Last successful sync: ${new Date(syncState.last_sync_completed_at).toLocaleString()}.`
              : 'No successful sync has completed yet.'}
          </div>
        </div>
      )}

      <div className="flex items-center justify-end">
        <button
          type="button"
          className="btn-secondary text-xs"
          disabled={!reports || reports.length === 0 || exportAllMutation.isPending}
          onClick={() => exportAllMutation.mutate()}
        >
          <Download size={12} aria-hidden="true" /> {exportAllMutation.isPending ? 'Exporting…' : 'Export all (CSV)'}
        </button>
      </div>

      {/* UI-04: a failed list used to read "Loading reports…" forever. */}
      {reportsError && (
        <ErrorNotice title="Could not load the reports" error={reportsErrorValue} onRetry={() => refetchReports()} retrying={reportsFetching} />
      )}
      {!reports && !reportsError && <div className="text-sm text-text-faint">Loading reports…</div>}

      {grouped.map(({ control, reports: controlReports }) => (
        <div key={control} className="flex flex-col gap-2">
          <div className="section-label">{CONTROL_LABELS[control]}</div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {controlReports.map(def => (
              <ReportCard key={def.key} def={def} environment={activeEnv} onClick={() => onSelectReport(def.key)} />
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
