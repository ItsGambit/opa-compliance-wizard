import { useMutation } from '@tanstack/react-query'
import { Download } from 'lucide-react'
import { toast } from '../hooks/useToast'
import type { ComplianceReportRow } from '../types'
import { exportSections } from '../utils/export'
import { complianceReportExportSections } from '../utils/exportSections'
import { downloadReportCsv, eventCount } from '../utils/reportExports'

interface Props {
  environment: string | undefined
  reportKey: string
  reportLabel: string
  /** The date range on screen (UTC days), or undefined while it is invalid. */
  range: { from: string; to: string } | undefined
  /** The rows loaded on screen and the ones left after the table's own filters. */
  rows: ComplianceReportRow[]
  filteredRows: ComplianceReportRow[]
  /** The server's count for the range and whether the on-screen list was cut at its limit. */
  total: number | undefined
  truncated: boolean | undefined
  /** Why export is unavailable right now (the rows on screen belong to the previous range, the report did not load). */
  disabledReason?: string
}

/** The report page's export (5.53.0).
 *
 * CSV is the server's file for the date range on screen: every event of the range, none dropped, the same columns and
 * rules as the evidence package. The table's own filters are not applied to it, and the button says so.
 *
 * Markdown is still made here from the rows on screen (the table's filtered rows). It states its limit in plain words
 * next to the buttons and in the file's own heading whenever the list on screen was cut or filtered, so it is never
 * mistaken for the whole range. */
export function ReportExportButtons({ environment, reportKey, reportLabel, range, rows, filteredRows, total, truncated, disabledReason }: Props) {
  const csv = useMutation({
    mutationFn: () => downloadReportCsv(environment as string, reportKey, range!.from, range!.to),
    onSuccess: ({ rows: written }) => {
      if (written !== null) toast({ title: `Exported "${reportLabel}"`, description: `${eventCount(written)}, ${range!.from} to ${range!.to} (UTC).`, variant: 'success' })
    },
    onError: (err: Error) => toast({ title: `Could not export "${reportLabel}"`, description: err.message, variant: 'error' }),
  })

  const csvBlocked = disabledReason ?? (!environment ? 'No environment is selected' : !range ? 'Fix the date range first' : undefined)
  const filtered = filteredRows.length < rows.length
  const mdTitle = truncated
    ? `${reportLabel} (newest ${rows.length.toLocaleString()} of ${(total ?? rows.length).toLocaleString()} events in the range${filtered ? `, ${filteredRows.length.toLocaleString()} after filters` : ''})`
    : filtered
      ? `${reportLabel} (${filteredRows.length.toLocaleString()} of ${rows.length.toLocaleString()} events after filters)`
      : reportLabel
  const mdBlocked = disabledReason ?? (filteredRows.length === 0 ? 'There are no rows on screen to export' : undefined)

  let note: string | null = null
  if (truncated) {
    note = `Markdown has only the ${filtered ? `${filteredRows.length.toLocaleString()} filtered rows of the ` : ''}newest ${rows.length.toLocaleString()} of ${(total ?? rows.length).toLocaleString()} events on screen. The CSV has every event in the range.`
  } else if (filtered) {
    note = `Markdown has the ${filteredRows.length.toLocaleString()} rows left by the filters. The CSV has every event in the range.`
  }

  return (
    <div className="flex flex-col items-end gap-1">
      <div className="flex items-center gap-1.5">
        <button
          type="button"
          className="btn-secondary !px-2 text-xs"
          disabled={!!csvBlocked || csv.isPending}
          onClick={() => csv.mutate()}
          title={csvBlocked ?? `Download every event from ${range!.from} to ${range!.to} (UTC) as CSV. The table filters are not applied.`}
        >
          {csv.isPending
            ? <span className="inline-block w-3 h-3 rounded-full border-2 border-accent border-t-transparent animate-spin" aria-hidden="true" />
            : <Download size={12} aria-hidden="true" />}{' '}
          {csv.isPending ? 'Exporting…' : 'Export CSV (whole range)'}
        </button>
        <button
          type="button"
          className="btn-secondary !px-2 text-xs"
          disabled={!!mdBlocked}
          onClick={() => exportSections(complianceReportExportSections(mdTitle, filteredRows), 'md', `opa-report-${reportKey}`)}
          title={mdBlocked ?? 'Export the rows on screen as Markdown'}
        >
          <Download size={12} aria-hidden="true" /> Markdown (rows on screen)
        </button>
      </div>
      {note && <p className="text-[0.6875rem] text-text-dim max-w-md text-right" role="note">{note}</p>}
    </div>
  )
}
