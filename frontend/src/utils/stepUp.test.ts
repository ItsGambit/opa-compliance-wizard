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
