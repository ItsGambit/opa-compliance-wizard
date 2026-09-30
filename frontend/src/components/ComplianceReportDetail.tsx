import { useState } from 'react'
import { ArrowLeft, RefreshCw } from 'lucide-react'
import { useReport } from '../api/hooks'
import type { ComplianceReportDef, ComplianceReportRow } from '../types'
import { complianceReportExportSections } from '../utils/exportSections'
import { ExportButtons } from './ExportButtons'
import { ReportRowsTable } from './ReportRowsTable'

interface Props {
  def: ComplianceReportDef
  environment: string | undefined
  onBack: () => void
}

const CONTROL_LABEL: Record<string, string> = { CC6: 'CC6', CC7: 'CC7', CC8: 'CC8' }

export function ComplianceReportDetail({ def, environment, onBack }: Props) {
  const today = new Date().toISOString().slice(0, 10)
  const ninetyDaysAgo = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10)
  const [from, setFrom] = useState(ninetyDaysAgo)
  const [to, setTo] = useState(today)

  const { data, isLoading, refetch, isFetching } = useReport(def.key, environment, from, to)
  const rows = data?.rows ?? []

  // ExportButtons exports whatever ReportRowsTable's own filters have
  // currently narrowed the rows down to -- same "export what's on screen"
  // convention this table always had, now just reported back up via this
  // callback since the filter state itself moved into ReportRowsTable.
  const [filteredRows, setFilteredRows] = useState<ComplianceReportRow[]>(rows)

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <button type="button" className="btn-secondary text-xs" onClick={onBack}>
          <ArrowLeft size={12} /> Back to reports
        </button>
        <div className="flex items-center gap-2">
          <ExportButtons sections={complianceReportExportSections(def.label, filteredRows)} filenameBase={`opa-report-${def.key}`} />
          <button type="button" className="btn-secondary text-xs" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw size={12} className={isFetching ? 'animate-spin' : ''} /> Refresh
          </button>
        </div>
      </div>

      <div>
        <h2 className="text-base font-semibold text-text flex items-center gap-2">
          {def.label}
          <span className="text-[0.6875rem] font-bold bg-accent-dim text-accent px-2 py-0.5 rounded-full">
            {CONTROL_LABEL[def.control] ?? def.control}
          </span>
        </h2>
        <p className="text-xs text-text-faint mt-1">{def.description}</p>
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
        emptyMessage="No events found in this date range."
        onFilteredRowsChange={setFilteredRows}
      />
    </div>
  )
}
