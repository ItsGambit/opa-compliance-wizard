import { describe, expect, it } from 'vitest'
import { describeReason, formatInZone, stepNumber, untilText, wallFields, wallToUtc, zoneOffsetMinutes } from './upgradeFlow'
import { makeRun } from '../test/upgradeFixtures'

describe('time zones', () => {
  it('converts wall time in a zone to the right instant, across a clock change', () => {
    expect(new Date(wallToUtc('2026-10-21', '03:30', 'Europe/London')).toISOString()).toBe('2026-10-21T02:30:00.000Z')   // BST
    expect(new Date(wallToUtc('2026-11-21', '03:30', 'Europe/London')).toISOString()).toBe('2026-11-21T03:30:00.000Z')   // GMT
    expect(new Date(wallToUtc('2026-10-20', '22:30', 'America/New_York')).toISOString()).toBe('2026-10-21T02:30:00.000Z')
    expect(new Date(wallToUtc('2026-10-21', '02:30', 'UTC')).toISOString()).toBe('2026-10-21T02:30:00.000Z')
  })
  it('refuses malformed fields', () => {
    expect(wallToUtc('2026-13-45', '99:99', 'UTC')).toBeNaN()
    expect(wallToUtc('', '', 'UTC')).toBeNaN()
    expect(wallToUtc('2026-10-21', '03:30', 'Not/AZone')).toBeNaN()
  })
  it('round-trips through the wall fields and formats with the offset', () => {
    const ms = Date.parse('2026-10-21T02:30:00Z')
    expect(wallFields(ms, 'Europe/London')).toEqual({ date: '2026-10-21', time: '03:30' })
    expect(zoneOffsetMinutes('America/New_York', ms)).toBe(-240)
    expect(formatInZone(ms, 'Europe/London')).toMatch(/^Wed 21 Oct 2026, 03:30.*\(UTC\+1\)$/)
    expect(formatInZone(ms, 'America/New_York')).toMatch(/22:30.*\(UTC−4\)$/)
  })
  it('says how long until a time', () => {
    const now = Date.parse('2026-10-19T16:30:00Z')
    expect(untilText(now + 30_000, now)).toBe('Now')
    expect(untilText(now + 35 * 60_000, now)).toBe('In 35 min')
    expect(untilText(now + (35 * 60 + 15) * 60_000, now)).toBe('In 1 day 11 h')
  })
})

describe('run helpers', () => {
  it('numbers steps and explains reason codes in words', () => {
    expect(stepNumber(makeRun({ step: 'switching' }))).toBe(6)
    expect(stepNumber(makeRun({ step: 'rolling_back', steps_done: [{ step: 'validated', at: '', seconds: 0 }] }))).toBe(1)
    expect(describeReason('health_healthz')).toMatch(/health check failed/)
    expect(describeReason('version_failed_before')).toMatch(/clear the failure/)
    expect(describeReason('something_new')).toBe('reason code something_new')
    expect(describeReason(null)).toBe('unknown reason')
  })
})

describe('reason sentences and the bundle cool-down', () => {
  it('every refusal the status can show has a plain sentence', () => {
    for (const code of ['target_changed', 'backup_changed', 'needs_operator', 'in_flight', 'request_invalid', 'rollback_unavailable', 'activator_too_old', 'cli_only', 'no_backup', 'backup_required']) {
      expect(describeReason(code)).not.toMatch(/^reason code /)
    }
    expect(describeReason('activator_too_old')).toContain('--refresh-updater')
  })

  it('a bundle request keeps the bundle buttons off for five minutes', async () => {
    const { markBundleRequested, bundleCoolingDown } = await import('./upgradeRequested')
    localStorage.clear()
    expect(bundleCoolingDown()).toBe(false)
    markBundleRequested(1_000_000)
    expect(bundleCoolingDown(1_000_000 + 4 * 60_000)).toBe(true)
    expect(bundleCoolingDown(1_000_000 + 5 * 60_000 + 1)).toBe(false)
  })
})
