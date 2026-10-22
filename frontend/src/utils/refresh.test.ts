import { describe, expect, it } from 'vitest'
import type { RefreshStatus } from '../types'
import { formatDateTimeZone } from './format'
import { ageText, completedText, elapsedText, finishToast, latestRefresh, scanFreshness, staleBadgeText } from './refresh'

const job = (states: Record<string, string>): RefreshStatus => ({
  status: 'done', job_id: 'j', trigger: 'manual', started_at: null, finished_at: '2026-10-21T08:48:00.000Z', cancel_requested: false, summary: null,
  parts_requested: Object.keys(states) as RefreshStatus['parts_requested'],
  parts: { opa: { state: 'not_requested' }, okta: { state: 'not_requested' }, log: { state: 'not_requested' }, ...Object.fromEntries(Object.entries(states).map(([k, v]) => [k, { state: v }])) } as RefreshStatus['parts'],
})
const H = 3_600_000

describe('refresh wording', () => {
  it('counts parts the way the Overview and the toast say it', () => {
    expect(completedText(3, 3)).toBe('all three parts completed')
    expect(completedText(2, 3)).toBe('2 of 3 parts completed')
    expect(completedText(1, 1)).toBe('completed')
  })

  it('the finish toast names the parts that did not complete, and says the rest is updated', () => {
    const all = job({ opa: 'ok', okta: 'ok', log: 'ok' })
    all.parts.okta.sub = { admins: { state: 'ok' }, principal_status: { state: 'ok' }, inventory: { state: 'ok' }, mfa_aggregates: { state: 'skipped' } }
    expect(finishToast(all)).toEqual({ title: 'Refresh finished: all three parts completed', variant: 'success',
      description: 'Audit Log: refresh.started, access_scan.completed, sync.manual_completed, okta_snapshot.captured ×3, refresh.completed.' })
    const partial = finishToast(job({ opa: 'ok', okta: 'refused', log: 'timed_out' }))
    expect(partial.variant).toBe('warning')
    expect(partial.title).toBe('Refresh finished: 1 of 3 parts completed')
    expect(partial.description).toBe('System Log timed out. Okta scan refused. The figures from the other parts are updated.')
    expect(finishToast(job({ opa: 'ok' })).title).toBe('Refresh finished: OPA scan completed')
    expect(finishToast(job({ opa: 'error' })).title).toBe('Refresh finished: OPA scan failed')
  })

  it('stale thresholds are 24 hours and 7 days (shared with the server)', () => {
    const now = Date.parse('2026-10-21T12:00:00.000Z')
    const at = (h: number) => new Date(now - h * H).toISOString()
    expect(scanFreshness(at(23), now)).toBe('current')
    expect(scanFreshness(at(24), now)).toBe('stale')
    expect(scanFreshness(at(24 * 7 - 1), now)).toBe('stale')
    expect(scanFreshness(at(24 * 7), now)).toBe('very_stale')
    expect(scanFreshness(null, now)).toBe('unknown')
    expect(staleBadgeText(at(50), now)).toBe('Stale · 2 days')
    expect(staleBadgeText(at(24 * 9), now)).toBe('Very stale · 9 days')
    expect(staleBadgeText(at(2), now)).toBeNull()
  })

  it('ages and elapsed times read plainly', () => {
    const now = Date.parse('2026-10-21T12:00:00.000Z')
    expect(ageText(new Date(now - 6 * H).toISOString(), now)).toBe('6 h ago')
    expect(ageText(new Date(now - 3 * 24 * H).toISOString(), now)).toBe('3 days ago')
    expect(ageText(new Date(now - 90_000).toISOString(), now)).toBe('1 min ago')
    expect(elapsedText('2026-10-21T08:41:00.000Z', '2026-10-21T08:43:12.000Z', now)).toBe('2 min 12 s')
    expect(elapsedText('2026-10-21T08:41:00.000Z', '2026-10-21T08:41:38.000Z', now)).toBe('38 s')
  })

  it('the latest refresh is the newest of the live job and the stored scheduled and manual records', () => {
    const stored = {
      scheduled: { finished_at: '2026-10-21T02:20:00.000Z', parts: { opa: { state: 'ok' }, log: { state: 'ok' }, okta: { state: 'refused' } } },
      manual: { finished_at: '2026-10-20T10:00:00.000Z', parts: { opa: { state: 'ok' } } },
    } as never
    expect(latestRefresh(undefined, stored)).toEqual({ finishedAt: '2026-10-21T02:20:00.000Z', done: 2, total: 3, failing: ['Okta scan'] })
    expect(latestRefresh(job({ opa: 'ok', log: 'ok', okta: 'ok' }), stored)?.finishedAt).toBe('2026-10-21T08:48:00.000Z')
    expect(latestRefresh(undefined, null)).toBeNull()
  })

  it('formatDateTimeZone does not throw (dateStyle cannot be combined with a time zone name) and says the zone', () => {
    expect(formatDateTimeZone('2026-10-21T02:20:00.000Z')).toMatch(/2026/)
    expect(formatDateTimeZone('2026-10-21T02:20:00.000Z')).toMatch(/[A-Z]{2,5}|GMT/)
    expect(formatDateTimeZone(null)).toBe('—')
    expect(formatDateTimeZone('not a date')).toBe('not a date')
  })
})

import { completedWords, formatTimeOnly, ordinal } from './refresh'
describe('wording helpers (mockup fidelity)', () => {
  it('ordinals and "all three parts"', () => {
    expect([1, 2, 3, 4, 11, 12, 13, 21, 13].map(ordinal)).toEqual(['1st', '2nd', '3rd', '4th', '11th', '12th', '13th', '21st', '13th'])
    expect(completedWords(3, 3)).toBe('all three parts completed')
    expect(completedWords(2, 3)).toBe('2 of 3 parts completed')
    expect(formatTimeOnly('2026-10-21T08:48:00.000Z')).toMatch(/\d{2}:\d{2}/)
  })
})
