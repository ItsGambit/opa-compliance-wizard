import { describe, expect, it } from 'vitest'
import type { EvidenceCoverage } from '../types'
import {
  coverageHeadline, coverageLines, dayCount, gapAcknowledgementLabel, last12Months, lastQuarter, minutesLeftText, periodError, rangesText,
} from './evidencePackage'

const at = (iso: string) => new Date(iso)

describe('presets are UTC calendar dates', () => {
  it('last quarter is the complete quarter before the current one', () => {
    expect(lastQuarter(at('2026-10-23T12:00:00Z'))).toEqual({ start: '2026-07-01', end: '2026-09-30' })
    expect(lastQuarter(at('2026-01-02T00:00:00Z'))).toEqual({ start: '2025-10-01', end: '2025-12-31' })
    expect(lastQuarter(at('2026-04-01T00:00:00Z'))).toEqual({ start: '2026-01-01', end: '2026-03-31' })
    expect(lastQuarter(at('2026-06-30T23:59:59Z'))).toEqual({ start: '2026-01-01', end: '2026-03-31' })
  })

  it('last 12 months is 365 days ending yesterday (UTC)', () => {
    const p = last12Months(at('2026-10-23T01:00:00Z'))
    expect(p).toEqual({ start: '2025-10-23', end: '2026-10-22' })
    expect(dayCount(p)).toBe(365)
    expect(last12Months(at('2026-01-01T00:30:00Z')).end).toBe('2025-12-31')
  })

  it('a local evening that is already tomorrow in UTC uses the UTC date', () => {
    // 23:30 at UTC-5 on 22 October is 04:30 UTC on 23 October
    expect(last12Months(at('2026-10-22T23:30:00-05:00')).end).toBe('2026-10-22')
  })
})

describe('periodError mirrors the server rule', () => {
  const now = at('2026-10-23T12:00:00Z')
  it('accepts a normal period and today', () => {
    expect(periodError({ start: '2026-10-01', end: '2026-10-23' }, now)).toBe('')
    expect(periodError({ start: '2026-10-23', end: '2026-10-23' }, now)).toBe('')
  })
  it('refuses empty, impossible, reversed, future and over-long periods', () => {
    expect(periodError({ start: '', end: '2026-10-01' }, now)).toMatch(/Pick a start/)
    expect(periodError({ start: '2026-02-30', end: '2026-03-01' }, now)).toMatch(/real calendar date/)
    expect(periodError({ start: '2026-10-05', end: '2026-10-01' }, now)).toMatch(/after the end/)
    expect(periodError({ start: '2026-10-01', end: '2026-10-24' }, now)).toMatch(/future/)
    expect(periodError({ start: '2010-01-01', end: '2026-10-01' }, now)).toMatch(/3,660/)
  })
})

const cov = (over: Partial<EvidenceCoverage> = {}): EvidenceCoverage => ({
  period: { start: '2026-10-12', end: '2026-10-22' }, days: 11, has_coverage: true, coverage_pct: 81.8, covered_days: 9,
  counts: { covered_with_events: 6, covered_zero_events: 3, not_covered: 2, pruned_by_retention: 0, before_archive: 0, after_data_as_of: 0 },
  gap_days_total: 2, gap_ranges: [['2026-10-15', '2026-10-16']], gap_ranges_total: 1,
  zero_days_total: 3, zero_ranges: [['2026-10-12', '2026-10-12'], ['2026-10-17', '2026-10-17']], zero_ranges_total: 2,
  pruned_days_total: 0, pruned_ranges: [], pruned_ranges_total: 0, before_archive_days: 0, after_data_as_of_days: 0,
  needs_acknowledgement: true, archive_start_date: '2026-10-11', data_as_of: '2026-10-23T10:00:00.000Z', pruned_basis: 'none', limits: [],
  events_in_period: 14, chain_head: 'abc', controls: [], ...over,
})

describe('the coverage check is worded as text', () => {
  it('the acknowledgement is a fact and its consequence, naming the days', () => {
    const label = gapAcknowledgementLabel(cov())
    expect(label).toContain('2 days')
    expect(label).toContain('2026-10-15 to 2026-10-16')
    expect(label).toMatch(/may be missing/)
    expect(gapAcknowledgementLabel(cov({ needs_acknowledgement: false, gap_days_total: 0 }))).toBe('')
  })

  it('every state has its own text line, pruned days are "not gaps", after-the-sync days are "not a gap"', () => {
    const lines = Object.fromEntries(coverageLines(cov({
      counts: { covered_with_events: 1, covered_zero_events: 0, not_covered: 0, pruned_by_retention: 2, before_archive: 3, after_data_as_of: 1 },
      gap_days_total: 0, gap_ranges: [], gap_ranges_total: 0, pruned_days_total: 2, pruned_ranges: [['2026-10-01', '2026-10-02']], pruned_ranges_total: 1,
    })).map(l => [l.key, l.text]))
    expect(lines.pruned).toMatch(/2 days \(2026-10-01 to 2026-10-02\); not gaps/)
    expect(lines.after).toMatch(/not a gap/)
    expect(lines.before).toBe('3 days')
    expect(lines.gap).toBe('0 days')
    expect(Object.keys(lines)).toEqual(['with_events', 'zero', 'pruned', 'gap', 'before', 'after'])
  })

  it('says plainly when nothing is covered', () => {
    expect(coverageHeadline(cov({ has_coverage: false }))).toMatch(/^No coverage/)
    expect(coverageHeadline(cov())).toBe('Coverage: 81.8% of 11 days. 2 days not covered (gaps).')
    expect(coverageHeadline(cov({ gap_days_total: 0 }))).toContain('No gap days.')
  })

  it('a capped list says how many ranges are left out', () => {
    expect(rangesText([['2026-01-01', '2026-01-01']], 3)).toBe('2026-01-01; and 2 more ranges')
  })

  it('the download window is told in minutes', () => {
    expect(minutesLeftText(900)).toBe('15 minutes left')
    expect(minutesLeftText(61)).toBe('2 minutes left')
    expect(minutesLeftText(30)).toBe('less than a minute left')
    expect(minutesLeftText(0)).toMatch(/ended/)
  })
})
