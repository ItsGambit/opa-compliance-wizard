import type { EvidenceCoverage, EvidencePeriod } from '../types'

/** Evidence package page logic (5.53.0): UTC periods, presets and the wording of the coverage check. No React here. */

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/

function iso(d: Date): string {
  return d.toISOString().slice(0, 10)
}

function utcDate(year: number, month: number, day: number): Date {
  return new Date(Date.UTC(year, month, day))
}

/** Today's UTC calendar date. */
export function utcToday(now: Date = new Date()): string {
  return iso(now)
}

/** The last complete calendar quarter (UTC): Jan-Mar, Apr-Jun, Jul-Sep or Oct-Dec before today's. */
export function lastQuarter(now: Date = new Date()): EvidencePeriod {
  const q = Math.floor(now.getUTCMonth() / 3)
  const startMonth = (q - 1) * 3
  const start = utcDate(now.getUTCFullYear(), startMonth, 1)         // a negative month rolls into the previous year
  const end = utcDate(now.getUTCFullYear(), startMonth + 3, 0)       // day 0 = the last day of the previous month
  return { start: iso(start), end: iso(end) }
}

/** The 365 days ending yesterday (UTC): yesterday, because today's events are still arriving. */
export function last12Months(now: Date = new Date()): EvidencePeriod {
  const end = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - 1))
  const start = new Date(end.getTime() - 364 * 86_400_000)
  return { start: iso(start), end: iso(end) }
}

export type PeriodPreset = 'last_quarter' | 'last_12_months' | 'custom'

export function presetPeriod(preset: Exclude<PeriodPreset, 'custom'>, now: Date = new Date()): EvidencePeriod {
  return preset === 'last_quarter' ? lastQuarter(now) : last12Months(now)
}

/** A date that survives a round trip (the browser's parser rolls 30 February over to March). */
function isRealDate(value: string): boolean {
  const t = Date.parse(value)
  return !Number.isNaN(t) && new Date(t).toISOString().slice(0, 10) === value
}

/** '' when the period is usable, else the sentence to show. Mirrors the server's rule (two UTC dates, start not after end, end not
 * after today, at most ten years); the server decides. */
export function periodError(period: EvidencePeriod, now: Date = new Date()): string {
  if (!DATE_RE.test(period.start) || !DATE_RE.test(period.end)) return 'Pick a start date and an end date.'
  if (!isRealDate(period.start) || !isRealDate(period.end)) return 'One of the dates is not a real calendar date.'
  if (period.start > period.end) return 'The start date is after the end date.'
  if (period.end > utcToday(now)) return 'The end date is in the future (dates are UTC).'
  const days = (Date.parse(period.end) - Date.parse(period.start)) / 86_400_000 + 1
  if (days > 3660) return 'The period is longer than 3,660 days.'
  return ''
}

export function dayCount(period: EvidencePeriod): number {
  return Math.round((Date.parse(period.end) - Date.parse(period.start)) / 86_400_000) + 1
}

/** "2026-03-01" or "2026-03-01 to 2026-03-04". */
export function rangeText([a, b]: [string, string]): string {
  return a === b ? a : `${a} to ${b}`
}

/** A list of date ranges as text, with the number left out when the server capped the list. */
export function rangesText(ranges: [string, string][], total: number): string {
  const shown = ranges.map(rangeText).join('; ')
  return total > ranges.length ? `${shown}; and ${total - ranges.length} more ranges` : shown
}

function plural(n: number, one: string, many: string): string {
  return `${n.toLocaleString()} ${n === 1 ? one : many}`
}

/** The acknowledgement checkbox label: a fact and its consequence, naming the days. '' when there is nothing to acknowledge. */
export function gapAcknowledgementLabel(cov: EvidenceCoverage): string {
  if (!cov.needs_acknowledgement) return ''
  return `The archive has no record of reading ${plural(cov.gap_days_total, 'day', 'days')} of this period (${rangesText(cov.gap_ranges, cov.gap_ranges_total)}), `
    + 'so events from those days may be missing from the package. Build it with these days listed as gaps.'
}

/** One text line per coverage state, in a fixed order, so the meaning never rests on colour. */
export function coverageLines(cov: EvidenceCoverage): { key: string; label: string; text: string }[] {
  const c = cov.counts
  const lines = [
    { key: 'with_events', label: 'Covered, with events', text: plural(c.covered_with_events, 'day', 'days') },
    { key: 'zero', label: 'Covered, zero events', text: plural(c.covered_zero_events, 'day', 'days') + (cov.zero_days_total ? ` (${rangesText(cov.zero_ranges, cov.zero_ranges_total)})` : '') },
    { key: 'pruned', label: 'Pruned by retention', text: plural(c.pruned_by_retention, 'day', 'days') + (cov.pruned_days_total ? ` (${rangesText(cov.pruned_ranges, cov.pruned_ranges_total)}); not gaps` : '') },
    { key: 'gap', label: 'Gap: not covered', text: plural(c.not_covered, 'day', 'days') + (cov.gap_days_total ? ` (${rangesText(cov.gap_ranges, cov.gap_ranges_total)})` : '') },
    { key: 'before', label: 'Before the archive began', text: plural(c.before_archive, 'day', 'days') },
    { key: 'after', label: 'After the last successful sync', text: plural(c.after_data_as_of, 'day', 'days') + (c.after_data_as_of ? '; later events are not included, and that is not a gap' : '') },
  ]
  return lines
}

/** The headline sentence of the coverage check. */
export function coverageHeadline(cov: EvidenceCoverage): string {
  if (!cov.has_coverage) return 'No coverage: the archive has no record of reading any day of this period, so there is nothing to put in a package.'
  const gaps = cov.gap_days_total
  return `Coverage: ${cov.coverage_pct}% of ${plural(cov.days, 'day', 'days')}. `
    + (gaps ? `${plural(gaps, 'day', 'days')} not covered (gaps).` : 'No gap days.')
}

/** Minutes left from a number of seconds, rounded up ("15 minutes", "1 minute", "less than a minute"). */
export function minutesLeftText(seconds: number): string {
  if (seconds <= 0) return 'the download window has ended'
  if (seconds < 60) return 'less than a minute left'
  const m = Math.ceil(seconds / 60)
  return `${m} ${m === 1 ? 'minute' : 'minutes'} left`
}
