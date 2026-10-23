/** 5.42.0: what survives the step-up MFA redirect -- never secrets. */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { beginStepUp, clearPendingStepUp, environmentDraftFrom, readPendingStepUp, stepUpReturnAction } from './stepUp'

beforeEach(() => sessionStorage.clear())

describe('step-up round trip', () => {
  it('stores the pending change and goes to the gate with the action id', () => {
    const navigate = vi.fn()
    const values = { name: 'dev', base_domain: 'b', team_name: 't', key_id: 'k', key_secret: 'TOP-SECRET', okta_url: '', okta_api_token: 'TOKEN' }
    beginStepUp('abc/=+', {
      kind: 'environment_change', action: 'environment.upsert', label: "Save environment 'dev'", startedAt: Date.now(),
      environmentDraft: environmentDraftFrom(values), reopen: 'environments',
    }, navigate)
    expect(navigate).toHaveBeenCalledWith('/step-up?action_id=abc%2F%3D%2B')
    const raw = sessionStorage.getItem('opa.pendingStepUp')!
    expect(raw).not.toContain('TOP-SECRET')
    expect(raw).not.toContain('TOKEN')
    const pending = readPendingStepUp()
    expect(pending?.kind).toBe('environment_change')
    expect(pending && pending.kind === 'environment_change' && pending.environmentDraft?.base_domain).toBe('b')
    clearPendingStepUp()
    expect(readPendingStepUp()).toBeNull()
  })

  it('forgets a stale or malformed record', () => {
    sessionStorage.setItem('opa.pendingStepUp', JSON.stringify({ kind: 'environment_change', action: 'x', label: 'x', startedAt: 0 }))
    expect(readPendingStepUp()).toBeNull()
    // ...but on the way back from the gate a stale Environments record still
    // routes to its own save (the server answers "expired").
    expect(readPendingStepUp(Date.now(), true)?.kind).toBe('environment_change')
    sessionStorage.setItem('opa.pendingStepUp', '{not json')
    expect(readPendingStepUp()).toBeNull()
    sessionStorage.setItem('opa.pendingStepUp', JSON.stringify({ kind: 'access_control' }))
    expect(readPendingStepUp()).toEqual({ kind: 'access_control' })
  })
})

describe('stepUpReturnAction', () => {
  const env = { kind: 'environment_change' as const, action: 'environment.share', label: 'x', startedAt: 1 }
  it('finishes the change the user started, never the other kind', () => {
    expect(stepUpReturnAction(true, env)).toBe('finish_environment_change')
    expect(stepUpReturnAction(true, { kind: 'access_control' })).toBe('finish_access_control')
    expect(stepUpReturnAction(true, null)).toBe('finish_access_control')
  })
  it('reports an Environments change whose approval never completed', () => {
    expect(stepUpReturnAction(false, env)).toBe('environment_change_abandoned')
    expect(stepUpReturnAction(false, null)).toBeNull()
    expect(stepUpReturnAction(false, { kind: 'access_control' })).toBeNull()
  })
})


describe('5.53.0: settings_unlock and evidence_package', () => {
  const unlock = { kind: 'settings_unlock' as const, startedAt: Date.now(), reopen: 'updates' as const }
  const evidence = {
    kind: 'evidence_package' as const, startedAt: Date.now(), environmentId: 'env-1',
    period: { start: '2026-01-01', end: '2026-03-31' }, gapsAcknowledged: true,
  }

  it('a Settings unlock round trip is remembered with where it came from, and carries nothing else', () => {
    const navigate = vi.fn()
    beginStepUp('act-9', unlock, navigate)
    expect(navigate).toHaveBeenCalledWith('/step-up?action_id=act-9')
    expect(readPendingStepUp()).toEqual(unlock)
    expect(Object.keys(JSON.parse(sessionStorage.getItem('opa.pendingStepUp')!)).sort()).toEqual(['kind', 'reopen', 'startedAt'])
  })

  it('finishes an unlock with its own action, never as the Access Control save or an Environments change', () => {
    expect(stepUpReturnAction(true, unlock)).toBe('finish_settings_unlock')
    expect(stepUpReturnAction(false, unlock)).toBe('settings_unlock_abandoned')
  })

  it('an evidence package approval has its own actions too', () => {
    expect(stepUpReturnAction(true, evidence)).toBe('finish_evidence_package')
    expect(stepUpReturnAction(false, evidence)).toBe('evidence_package_abandoned')
    sessionStorage.setItem('opa.pendingStepUp', JSON.stringify(evidence))
    expect(readPendingStepUp()).toEqual(evidence)
  })

  it('forgets a malformed or stale record of the new kinds; a stale one still routes back from the gate', () => {
    for (const bad of [
      { kind: 'settings_unlock', startedAt: Date.now(), reopen: 'elsewhere' },
      { kind: 'settings_unlock', reopen: 'settings' },
      { kind: 'evidence_package', startedAt: Date.now(), environmentId: 'e', period: { start: 'a' }, gapsAcknowledged: true },
      { kind: 'evidence_package', startedAt: Date.now(), environmentId: 'e', period: { start: 'a', end: 'b' } },
    ]) {
      sessionStorage.setItem('opa.pendingStepUp', JSON.stringify(bad))
      expect(readPendingStepUp(Date.now(), true)).toBeNull()
    }
    sessionStorage.setItem('opa.pendingStepUp', JSON.stringify({ ...unlock, startedAt: 0 }))
    expect(readPendingStepUp()).toBeNull()
    expect(readPendingStepUp(Date.now(), true)?.kind).toBe('settings_unlock')
  })
})
