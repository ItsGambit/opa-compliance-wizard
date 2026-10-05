/** Covers usableEnvironments (5.38.4): a new identity (e.g. a second Okta org's gate)
 * with environments shared to it must be able to pick one from the setup screen. */
import { describe, expect, it } from 'vitest'
import type { Environment } from '../types'
import { usableEnvironments } from './usableEnvironments'

function env(name: string, is_own: boolean, shared: boolean, id = `${name}-${is_own}-${shared}`): Environment {
  return { id, name, is_own, shared, base_domain: '', team_name: '', key_id: '', okta_url: '',
           has_okta_token: false, sync_schedule: {} as Environment['sync_schedule'] }
}

describe('usableEnvironments', () => {
  it('keeps own and shared environments, drops other owners’ private ones', () => {
    const out = usableEnvironments([env('mine', true, false), env('team', false, true), env('private', false, false)])
    expect(out.map(e => e.name)).toEqual(['mine', 'team'])
  })

  it('lists a name once, preferring the caller’s own over a same-named shared one', () => {
    const out = usableEnvironments([env('dev', false, true), env('dev', true, false), env('dev', false, true, 'x')])
    expect(out).toHaveLength(1)
    expect(out[0].is_own).toBe(true)
  })

  it('handles no environments', () => {
    expect(usableEnvironments(undefined)).toEqual([])
    expect(usableEnvironments([])).toEqual([])
  })
})
