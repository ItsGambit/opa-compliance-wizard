import { runReport } from '../api/client'
import type { ComplianceReportDef, ComplianceReportResponse } from '../types'
import type { ExportSection } from './export'

/** "Export all (CSV)" on the reports home: one request per report; every
 * result is collected (not just the first rejection) so the caller can
 * name each report that failed (UI-14). The caller writes the file only
 * when none failed.
 *
 * The row shape here (five columns, the raw stored timestamp) is exactly
 * what this export has always written; aligning it with the per-report
 * export (UI-08) changes evidence files, so it waits for that decision. */
export async function exportAllReports(reports: ComplianceReportDef[], environment: string | undefined) {
  const settled = await Promise.allSettled(reports.map(def => runReport(def.key, environment)))
  const sections: { def: ComplianceReportDef; resp: ComplianceReportResponse; section: ExportSection }[] = []
  const failed: { def: ComplianceReportDef; error: string }[] = []
  settled.forEach((result, i) => {
    const def = reports[i]
    if (result.status === 'fulfilled') {
      const resp = result.value
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
  return { sections, failed }
}
