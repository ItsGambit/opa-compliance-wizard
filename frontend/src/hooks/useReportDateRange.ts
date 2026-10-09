import { useState } from 'react'

const DAY_MS = 24 * 60 * 60 * 1000

/** Today's date as the UTC calendar day (YYYY-MM-DD) -- what the archive's
 * date filter compares against (audit_store normalises a bare date to
 * T00:00:00Z / T23:59:59.999Z). */
export function utcToday(now: number = Date.now()): string {
  return new Date(now).toISOString().slice(0, 10)
}

export function utcDaysAgo(days: number, now: number = Date.now()): string {
  return new Date(now - days * DAY_MS).toISOString().slice(0, 10)
}

/** The From/To pair every report and history view shares (UI-18).
 *
 * - Both are UTC calendar days, and the fields say so.
 * - An untouched "To" follows today (it used to freeze at mount, so a page
 *   left open past midnight UTC silently excluded the newest events).
 * - From after To is reported as an error, and `range` is undefined so the
 *   caller doesn't run a query that can only come back empty. */
export function useReportDateRange(defaultDays = 90) {
  const [from, setFrom] = useState(() => utcDaysAgo(defaultDays))
  const [toInput, setToInput] = useState<string | null>(null)
  const to = toInput ?? utcToday()
  const error = from && to && from > to ? '"From" is after "To". Pick a From date on or before the To date.' : null
  return {
    from,
    to,
    setFrom,
    setTo: (value: string) => setToInput(value),
    error,
    range: error ? undefined : { from, to },
  }
}
