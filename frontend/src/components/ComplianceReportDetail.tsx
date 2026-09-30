import { useState } from 'react'
import { ArrowLeft, RefreshCw } from 'lucide-react'
import { useReport } from '../api/hooks'
import type { ComplianceReportDef } from '../types'
import { formatDateTime } from '../utils/format'
import { complianceReportExportSections } from '../utils/exportSections'
import { ExportButtons } from './ExportButtons'

interface Props {
  def: ComplianceReportDef
  environment: string | undefined
  onBack: () => void
}

const CONTROL_LABEL: Record<string, string> = { CC6: 'CC6', CC7: 'CC7', CC8: 'CC8' }

function outcomeVariant(outcome: string): string {
  const o = outcome.toUpperCase()
  if (o === 'SUCCESS' || o === 'ALLOW') return 'bg-win/10 text-win'
  if (o === 'DENY' || o === 'FAILURE') return 'bg-loss/10 text-loss'
  return 'bg-warn/10 text-warn'
}

export function ComplianceReportDetail({ def, environment, onBack }: Props) {
  const today = new Date().toISOString().slice(0, 10)
  const ninetyDaysAgo = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10)
  const [from, setFrom] = useState(ninetyDaysAgo)
  const [to, setTo] = useState(today)

  const { data, isLoading, refetch, isFetching } = useReport(def.key, environment, from, to)
  const rows = data?.rows ?? []

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <button type="button" className="btn-secondary text-xs" onClick={onBack}>
          <ArrowLeft size={12} /> Back to reports
        </button>
        <div className="flex items-center gap-2">
          <ExportButtons sections={complianceReportExportSections(def.label, rows)} filenameBase={`opa-report-${def.key}`} />
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

      <div className="card p-0 overflow-x-auto">
        {isLoading ? (
          <div className="p-4 text-sm text-text-faint">Loading…</div>
        ) : rows.length === 0 ? (
          <div className="p-4 text-sm text-text-faint">No events found in this date range.</div>
        ) : (
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left font-semibold text-text-faint uppercase text-[0.625rem] tracking-wide px-3 py-2">User</th>
                <th className="text-left font-semibold text-text-faint uppercase text-[0.625rem] tracking-wide px-3 py-2">Action</th>
                <th className="text-left font-semibold text-text-faint uppercase text-[0.625rem] tracking-wide px-3 py-2">Timestamp</th>
                <th className="text-left font-semibold text-text-faint uppercase text-[0.625rem] tracking-wide px-3 py-2">Affected Resource</th>
                <th className="text-left font-semibold text-text-faint uppercase text-[0.625rem] tracking-wide px-3 py-2">Outcome</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(row => (
                <tr key={row.uuid} className="border-b border-border-sub hover:bg-bg-hover">
                  <td className="px-3 py-2 text-text-dim">
                    {row.user}
                    {row.actor_alternate_id && row.actor_alternate_id !== row.user && (
                      <div className="text-text-faint text-[0.6875rem]">{row.actor_alternate_id}</div>
                    )}
                  </td>
                  <td className="px-3 py-2 text-text-dim">{row.action}</td>
                  <td className="px-3 py-2 text-text-faint whitespace-nowrap">{formatDateTime(row.timestamp)}</td>
                  <td className="px-3 py-2 text-text-dim">
                    {row.resource || <span className="text-text-faint">—</span>}
                    {row.resource_type && <span className="text-text-faint text-[0.6875rem]"> ({row.resource_type})</span>}
                  </td>
                  <td className="px-3 py-2">
                    {row.outcome ? (
                      <span className={`inline-block px-1.5 py-0.5 rounded text-[0.6875rem] font-medium ${outcomeVariant(row.outcome)}`}>
                        {row.outcome}
                      </span>
                    ) : (
                      <span className="text-text-faint">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
