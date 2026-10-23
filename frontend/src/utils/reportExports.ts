import { fetchReportCsv, runReport } from '../api/client'
import type { ComplianceReportDef, ComplianceReportResponse } from '../types'
import { utcDaysAgo, utcToday } from '../hooks/useReportDateRange'
import { downloadBlob } from './export'
import type { ExportSection } from './export'

/** The range a report card exports: the report's default window, the last 90 UTC days, today included. */
export const CARD_EXPORT_DAYS = 90
export function cardExportRange(now: number = Date.now()): { from: string; to: string } {
  return { from: utcDaysAgo(CARD_EXPORT_DAYS, now), to: utcToday(now) }
}

/** "5 events" / "1 event". */
export function eventCount(n: number): string {
  return `${n.toLocaleString()} ${n === 1 ? 'event' : 'events'}`
}

/** Downloads one report's CSV for a UTC range from the server: every event of the range, none dropped. Resolves with the
 * number of data rows the server wrote; rejects (the caller shows the error) if the server refuses or the transfer fails.
 * Nothing is written from a capped list. */
export async function downloadReportCsv(
  environment: string,
  reportKey: string,
  from: string,
  to: string
): Promise<{ rows: number | null }> {
  const { blob, rows } = await fetchReportCsv(environment, reportKey, from, to)
  downloadBlob(`opa-report-${reportKey}-${from}-to-${to}.csv`, blob)
  return { rows }
}

export interface TruncatedReport {
  def: ComplianceReportDef
  total: number
  shown: number
}

/** "Export all (CSV)" on the reports home: one request per report; every
 * result is collected (not just the first rejection) so the caller can
 * name each report that failed (UI-14). The caller writes the file only
 * when none failed.
 *
 * `truncated` names every report whose list came back capped (the server holds more events than it returned). The file
 * built here is made from those capped lists, so a caller must not write it while `truncated` is not empty (5.53.0):
 * see truncationRefusal(). The complete per-report CSV comes from the server (downloadReportCsv).
 *
 * The row shape here (five columns, the raw stored timestamp) is exactly
 * what this export has always written; aligning it with the per-report
 * export (UI-08) changes evidence files, so it waits for that decision. */
export async function exportAllReports(reports: ComplianceReportDef[], environment: string | undefined) {
  const settled = await Promise.allSettled(reports.map(def => runReport(def.key, environment)))
  const sections: { def: ComplianceReportDef; resp: ComplianceReportResponse; section: ExportSection }[] = []
  const failed: { def: ComplianceReportDef; error: string }[] = []
  const truncated: TruncatedReport[] = []
  settled.forEach((result, i) => {
    const def = reports[i]
    if (result.status === 'fulfilled') {
      const resp = result.value
      if (resp.truncated) truncated.push({ def, total: resp.total, shown: resp.rows.length })
      sections.push({
        def,
        resp,
        section: {
          title: def.label,
          rows: resp.rows.map(r => ({
            User: r.user, Action: r.action, Timestamp: r.timestamp, 'Affected Resource': r.resource, Outcome: r.outcome,
          })),
        },
      })
    } else {
      failed.push({ def, error: result.reason instanceof Error ? result.reason.message : String(result.reason) })
    }
  })
  return { sections, failed, truncated }
}

/** What to tell the person when "Export all" wrote nothing because a list was cut at the server's limit: said before
 * any file is made, never after. Null when no list was cut. */
export function truncationRefusal(truncated: TruncatedReport[]): { title: string; description: string } | null {
  if (truncated.length === 0) return null
  return {
    title: 'Export all stopped — nothing was downloaded',
    description:
      `${truncated.map(t => `${t.def.label} has ${eventCount(t.total)} and only ${t.shown.toLocaleString()} can be listed here`).join('; ')}. ` +
      'A combined file would silently leave events out. Export each report as CSV from its card or its page: that file has every event in the date range.',
  }
}
