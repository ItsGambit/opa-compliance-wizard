/** UI-07: rows are compared by id and acted on only when addressable. */
import { describe, expect, it } from 'vitest'
import type { Environment, EnvironmentsResponse } from '../types'
import { activeRow, canManageSync, isActiveRow, isAddressable } from './environmentRows'
import { usableEnvironments } from './usableEnvironments'

const env = (id: string, name: string, o: Partial<Environment> = {}): Environment => ({
  id, name, base_domain: '', team_name: '', key_id: '', okta_url: '', has_okta_token: false,
  sync_schedule: {} as Environment['sync_schedule'], shared: false, is_own: true, ...o,
})

describe('environment rows', () => {
  const mine = env('a', 'prod', { addressable: true })
  const theirs = env('b', 'prod', { is_own: false, addressable: false })
  const data: EnvironmentsResponse = { environments: [mine, theirs], active: 'prod', active_id: 'a' }

  it('marks only the active id, not every row with the active name', () => {
    expect(isActiveRow(mine, data)).toBe(true)
    expect(isActiveRow(theirs, data)).toBe(false)
    expect(activeRow(data)).toBe(mine)
  })

  it('falls back to name + addressable for a server without active_id', () => {
    const old: EnvironmentsResponse = { environments: [env('a', 'prod'), env('b', 'prod', { is_own: false })], active: 'prod' }
    expect(old.environments.filter(e => isActiveRow(e, old)).map(e => e.id)).toEqual(['a'])
  })

  it('uses the server addressable flag, with the old rule as fallback', () => {
    expect(isAddressable(theirs)).toBe(false)
    expect(isAddressable(env('c', 'x', { is_own: false, shared: true, addressable: false }))).toBe(false)
    expect(isAddressable(env('d', 'x', { is_own: false, shared: true }))).toBe(true)
    expect(isAddressable(env('e', 'x', { is_own: false, shared: false }))).toBe(false)
  })

  it('offers sync controls only on the caller’s own rows', () => {
    expect(canManageSync(mine)).toBe(true)
    expect(canManageSync(env('f', 'team', { is_own: false, shared: true, addressable: true }))).toBe(false)
  })

  it('the setup screen offers exactly the addressable rows', () => {
    const shadowed = env('g', 'dev', { is_own: false, shared: true, addressable: false })
    const own = env('h', 'dev', { addressable: true })
    expect(usableEnvironments([shadowed, own]).map(e => e.id)).toEqual(['h'])
  })
})

describe('environmentScopeKey', () => {
  it('changes when the active environment is reconnected to another team, not only on a switch', async () => {
    const { environmentScopeKey } = await import('./environmentRows')
    const base = env('a', 'prod', { addressable: true, team_name: 'team-1' })
    const before = environmentScopeKey({ environments: [base], active: 'prod', active_id: 'a' })
    const after = environmentScopeKey({ environments: [{ ...base, team_name: 'team-2' }], active: 'prod', active_id: 'a' })
    expect(before).not.toBe(after)
    expect(environmentScopeKey(undefined)).toBeUndefined()
    // rotating the API key of the same team keeps the page
    expect(environmentScopeKey({ environments: [{ ...base, key_id: 'new-key' }], active: 'prod', active_id: 'a' })).toBe(before)
  })
})
