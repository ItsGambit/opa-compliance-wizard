import { describe, expect, it } from 'vitest'
import { makeRun } from '../test/upgradeFixtures'
import type { UpgradeNoticeRun } from '../types'
import { mergeRun } from './upgradeRun'

const note = (over: Partial<UpgradeNoticeRun> = {}): UpgradeNoticeRun => ({
  correlation_id: 'upg-7f3a9c2e', action: 'apply', version_from: '5.46.0', version_to: '5.48.0', step: 'health_check', result: null, reason_code: null, failed_step: null,
  started_at: '2026-10-21T02:30:02Z', updated_at: '2026-10-21T02:30:50Z', seconds: null, rolled_back_to: null, step_started_at: null,
  steps_done: [{ step: 'validated', at: '2026-10-21T02:30:02Z', seconds: 1 }, { step: 'restarting', at: '2026-10-21T02:30:40Z', seconds: 9 }], health: [{ id: 'unit_active', ok: true }], ...over,
})

describe('mergeRun (5.53.0)', () => {
  it('is the status run when there is no notice run, and the notice run when there is no status', () => {
    const run = makeRun()
    expect(mergeRun(run, null)).toBe(run)
    expect(mergeRun(run, note({ correlation_id: null }))).toBe(run)
    const only = mergeRun(null, note())!
    expect(only.step).toBe('health_check')
    expect(only.steps_done).toHaveLength(2)
    expect(only.health).toEqual([{ id: 'unit_active', ok: true, detail: '' }])
    expect(mergeRun(null, null)).toBeNull()
  })

  it('keeps the status detail and takes the newer progress from the notice for the same run', () => {
    const base = makeRun({ result: null, step: 'restarting', updated_at: '2026-10-21T02:30:40Z',
      steps_done: [{ step: 'validated', at: '2026-10-21T02:30:02Z', seconds: 1, detail: { request: 'r1' } }], health: [] })
    const merged = mergeRun(base, note())!
    expect(merged.step).toBe('health_check')
    expect(merged.steps_done?.map(s => s.step)).toEqual(['validated', 'restarting'])
    expect(merged.steps_done?.[0].detail).toEqual({ request: 'r1' })          // not replaced by the detail-less copy
    expect(merged.backup).toEqual(base.backup)
    expect(merged.health).toEqual([{ id: 'unit_active', ok: true, detail: '' }])
  })

  it('ignores an older notice run, and a notice run of an older upgrade', () => {
    const base = makeRun({ result: null, step: 'restarting', updated_at: '2026-10-21T02:31:00Z' })
    expect(mergeRun(base, note())).toBe(base)
    expect(mergeRun(base, note({ correlation_id: 'upg-old', started_at: '2026-10-01T00:00:00Z' }))).toBe(base)
    expect(mergeRun(base, note({ correlation_id: 'upg-new', started_at: '2026-11-01T00:00:00Z' }))!.correlation_id).toBe('upg-new')
  })
})
