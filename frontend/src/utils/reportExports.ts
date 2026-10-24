import { fetchReportCsv } from '../api/client'
import { utcDaysAgo, utcToday } from '../hooks/useReportDateRange'
import { downloadBlob } from './export'

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
