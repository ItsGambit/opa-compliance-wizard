import { useMemo, useState } from 'react'
import { useEnvironments, useResourceHistory } from '../api/hooks'
import { complianceReportExportSections } from '../utils/exportSections'
import { ExportButtons } from './ExportButtons'
import { ReportRowsTable } from './ReportRowsTable'

/** The per-resource compliance-report history drill-down -- clicking a row
 * in the Access Explorer's Resources tab (or the Service Accounts
 * Dashboard, 5.40.0, which is why this moved out of ResourcesTab.tsx into
 * its own file) shows every report row (across EVERY report, not one)
 * where this resource appears as ANY target on the event, matched by id
 * AND/OR its exact display name (resourceLabel, passed through as
 * resourceName -- needed for database/AD accounts, which have no log-side
 * id at all -- see audit_store.resource_history's docstring for the full
 * live-verified explanation). Carries the same date range, fuzzy filters,
 * truncation notice and export the generic report detail view has.
 *
 * matchByName (default true) is the display-name fallback above. The
 * Service Accounts Dashboard passes false: SaaS/Okta accounts DO have a
 * log-side id (their OPA-internal id), and a service-account name like
 * "admin" can repeat across apps or collide with a DB/AD account, user
 * or server -- a compliance drill-down must never mix another
 * resource's events into this one's history. */
export function ResourceHistoryPanel({
  resourceId,
  resourceLabel,
  onClose,
  matchByName = true,
}: {
  resourceId: string
  resourceLabel: string
  onClose: () => void
  matchByName?: boolean
}) {
  const { data: environments } = useEnvironments()
  const activeEnv = environments?.active
  const today = new Date().toISOString().slice(0, 10)
  const ninetyDaysAgo = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10)
  const [from, setFrom] = useState(ninetyDaysAgo)
  const [to, setTo] = useState(today)

  // No per-view Refresh here -- every resource's history reads the SAME
  // shared audit_store.db archive as every ordinary report, so pulling
  // fresh Okta data is one global action (the Footer's "Sync now"), not
  // something duplicated per screen. This query auto-refetches when that
  // global sync completes, via queryClient.invalidateQueries on the
  // ['resource_history'] key prefix (see Footer.tsx).
  const { data, isLoading } = useResourceHistory(resourceId, activeEnv, from, to, matchByName ? resourceLabel : undefined)
  // FIX (external review, 2026-09-30): `data?.rows ?? []` creates a brand
  // new [] literal on every render while data is still loading --
  // useFuzzyFilter callers downstream (see e.g. ResourceRowList) rebuild
  // their whole Fuse search index every render instead of only when the
  // underlying data actually changes, since useMemo there keys off this
  // array's REFERENCE, not its contents.
  const rows = useMemo(() => data?.rows ?? [], [data])
  const [filteredRows, setFilteredRows] = useState(rows)

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-text">Access history — {resourceLabel}</h3>
        <div className="flex items-center gap-2">
          <ExportButtons
            sections={complianceReportExportSections(`History: ${resourceLabel}`, filteredRows)}
            filenameBase={`opa-resource-history-${resourceLabel}`}
          />
          <button type="button" className="btn-secondary text-xs" onClick={onClose}>
            Close
          </button>
        </div>
      </div>

      <div className="card p-3 flex items-end gap-3">
        <div className="field">
          <label className="section-label block mb-1">From</label>
          <input type="date" className="text-input" value={from} onChange={e => setFrom(e.target.value)} />
        </div>
        <div className="field">
          <label className="section-label block mb-1">To</label>
          <input type="date" className="text-input" value={to} onChange={e => setTo(e.target.value)} />
        </div>
      </div>

      <ReportRowsTable
        rows={rows}
        isLoading={isLoading}
        emptyMessage="No compliance-report activity found for this resource in this date range."
        onFilteredRowsChange={setFilteredRows}
        total={data?.total}
        truncated={data?.truncated}
      />
    </div>
  )
}
