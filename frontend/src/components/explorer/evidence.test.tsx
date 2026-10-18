/** 5.45.0: the access-evidence UI -- the row text and count chip, the Recent
 * activity list, the evidence footer and its flags, and the export that
 * matches the screen. Fictional data only. */
import { act, cleanup, render, renderHook, screen, within } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import { policy, resolved, rule } from '../../test/accessFixtures'
import type { ResourceAccessInfo } from '../../types'
import { aggregateResources, lastUsedFor, type AccessLookup } from '../../utils/accessResources'
import { visibleAccessSections } from '../../utils/exportSections'
import { rulesGrantedToGroupIds } from '../../utils/policy'
import { LastAccessed, NoTracking } from './LastAccessed'
import { lastUsedText } from './lastUsedText'
import { ResourceAccessView } from './ResourceAccessView'
import { FILTER_IN_EFFECT, useGrantsExplorer } from './useGrantsExplorer'

afterEach(cleanup)

const NOW = Date.parse('2026-10-18T09:00:00Z')
const info = (over: Partial<ResourceAccessInfo> = {}): ResourceAccessInfo => ({
  resource_kind: 'secret', supported: true, complete: true, source: 'archive+live', uses: 3, window_days: 120,
  coverage_from: '2026-06-20T00:00:00.000Z', last_synced_at: '2026-10-18T06:00:00.000Z',
  event_types: ['pam.secret.reveal'],
  events: [
    { published: '2026-10-17T09:00:00Z', request_id: '2b7e1c40-5a9d', outcome: 'SUCCESS', event_type: 'pam.secret.reveal', source: 'live' },
    { published: '2026-10-02T09:00:00Z', request_id: '6f1a9c3d-2e8b', outcome: 'FAILURE', event_type: 'pam.secret.reveal', source: 'archive' },
  ],
  ...over,
})
const lookup = (i: ResourceAccessInfo): AccessLookup => ({ status: 'ready', byId: new Map([['sec-1', i]]) })
const targets = [{ id: 'sec-1', label: 'db-password' }]

describe('the evidence block', () => {
  it('lists recent activity in plain words, with outcome and copyable request ids, and a footer', () => {
    render(<LastAccessed lookup={lookup(info())} targets={targets} now={NOW} />)
    const table = screen.getByRole('table', { name: 'Recent activity' })
    expect(within(table).getAllByText('Revealed secret').length).toBe(2)
    expect(within(table).getByText('FAILURE')).toBeTruthy()
    expect(within(table).getByRole('button', { name: 'Copy request id 2b7e1c40-5a9d' })).toBeTruthy()
    expect(screen.getByText('3 uses · 120d')).toBeTruthy()
    expect(screen.getByText('Source: archive + live · covers 2026-06-20 to now · last synced 3 hours ago')).toBeTruthy()
  })

  it('says when activity is newer than the last sync and when the live top-up failed', () => {
    render(<LastAccessed lookup={lookup(info({ newer_than_sync: true, live_error: 'the live System Log could not be read', source: 'archive', complete: false }))} targets={targets} now={NOW} />)
    expect(screen.getByText(/newer than the last sync/)).toBeTruthy()
    expect(screen.getByText(/newest events could not be checked/)).toBeTruthy()
  })

  it('never used always states its window and what was counted', () => {
    render(<LastAccessed lookup={lookup(info({ events: [], uses: 0 }))} targets={targets} now={NOW} />)
    expect(screen.getByText(/Never used in the last 120 days \(counts: revealed secret\)/)).toBeTruthy()
    expect(screen.getByText(/covers 2026-06-20 to now/)).toBeTruthy()
  })

  it('an incomplete empty answer is Unknown, not Never used', () => {
    render(<LastAccessed lookup={lookup(info({ events: [], uses: 0, complete: false, archive_note: 'stale_gap' }))} targets={targets} now={NOW} />)
    expect(screen.getByText(/^Unknown: no use found in the events read/)).toBeTruthy()
    expect(screen.queryByText(/Never used/)).toBeNull()
    expect(screen.getByText(/more than 90 days ago/)).toBeTruthy()
  })

  it('names the reason when the archive could not be used', () => {
    render(<LastAccessed lookup={lookup(info({ source: 'live', archive_note: 'type_not_stored', window_days: 90 }))} targets={targets} now={NOW} />)
    expect(screen.getByText(/does not hold this event type: showing live 90-day data/)).toBeTruthy()
    expect(screen.getByText(/Source: live · covers 2026-06-20 to now/)).toBeTruthy()
  })

  it('an ambiguous name is reported as ambiguity', () => {
    render(<LastAccessed lookup={lookup(info({ events: [], uses: 0, ambiguous: true }))} targets={targets} now={NOW} />)
    expect(screen.getByText(/Unknown: cannot tell which account/)).toBeTruthy()
  })

  it('NoTracking says why, as Unknown or Not tracked', () => {
    render(<NoTracking gap={{ state: 'unknown', reason: 'no id' }} />)
    expect(screen.getByText('Unknown: no id')).toBeTruthy()
    cleanup()
    render(<NoTracking gap={{ state: 'untracked', reason: 'empty folder' }} />)
    expect(screen.getByText('Not tracked: empty folder')).toBeTruthy()
  })

  it('server-level matches are labelled as such', () => {
    render(<LastAccessed lookup={lookup(info({ events: [{ published: '2026-10-17T09:00:00Z', request_id: 'r1', outcome: 'SUCCESS', event_type: 'pam.gateway_creds.issue', matched_by: 'server' }] }))} targets={targets} now={NOW} />)
    expect(screen.getByText('Issued gateway credentials')).toBeTruthy()
    expect(screen.getByText(/server-level/)).toBeTruthy()
  })
})

describe('the row text', () => {
  it('last used with a count chip and a title that lists what counts', () => {
    const t = lastUsedText({ state: 'used', at: '2026-10-15T09:00:00Z', uses: 12, windowDays: 90, eventTypes: ['pam.secret.reveal', 'pam.resource.checkout'], newerThanSync: true }, NOW)
    expect(t.text).toBe('Last used 3 days ago')
    expect(t.chip).toBe('12 uses · 90d')
    expect(t.title).toContain('Counts: revealed secret, checked out')
    expect(t.title).toContain('Newer than the last sync')
  })

  it('an unresolved selector says any account', () => {
    expect(lastUsedText({ state: 'used', at: '2026-10-15T09:00:00Z', anyAccount: true }, NOW).text).toBe('Last used 3 days ago (any account)')
  })

  it('never used names its window; unknown and not tracked carry their reason', () => {
    expect(lastUsedText({ state: 'never', windowDays: 120 }, NOW).text).toBe('Never used in 120 days')
    expect(lastUsedText({ state: 'never' }, NOW).text).toBe('Never used')
    expect(lastUsedText({ state: 'unknown', reason: 'why' }, NOW)).toEqual({ text: 'Unknown', title: 'why' })
    expect(lastUsedText({ state: 'untracked', reason: 'empty' }, NOW).title).toBe('empty')
  })
})

describe('the opened row', () => {
  const G = [{ id: 'g1', name: 'G' }]
  const make = (res: object, opts: { active?: boolean } = {}) => aggregateResources(rulesGrantedToGroupIds([
    policy('p', 'P', G, [rule('R', 'Secrets', [res as never])], { active: opts.active ?? true }),
  ], new Set(['g1'])))[0]

  it('marks an inactive policy and a deleted object', () => {
    const r = make({ ...resolved('sec-1', 'old', 'secret'), missing: true }, { active: false })
    render(<ResourceAccessView resource={r} now={NOW} />)
    expect(screen.getByText(/inactive policy: gives no access right now/)).toBeTruthy()
    expect(screen.getByText(/probably been deleted/)).toBeTruthy()
  })

  it('shows server / account details for a server account', () => {
    const r = make({ ...resolved('srv-1', 'host-1 / root', 'individual_server_account'), server_id: 'srv-1', server_name: 'host-1', account_name: 'root' })
    render(<ResourceAccessView resource={r} now={NOW} />)
    expect(screen.getByText('Account root on server host-1.')).toBeTruthy()
  })

  it('explains an untrackable resource instead of a bare dash', () => {
    const r = make({ ...resolved('f-x', 'gone', 'secret_folder') })
    render(<ResourceAccessView resource={r} lookup={{ status: 'ready', byId: new Map() }} now={NOW} />)
    expect(screen.getByText(/^Unknown: This folder was not found/)).toBeTruthy()
  })
})

describe('M5: exports match the screen', () => {
  const G = [{ id: 'g1', name: 'G' }]
  const all = aggregateResources(rulesGrantedToGroupIds([
    policy('p', 'P', G, [rule('R', 'Secrets', [resolved('sec-1', 'shown', 'secret'), resolved('sec-2', 'hidden-by-filter', 'secret')])]),
  ], new Set(['g1'])))

  it('exports only the visible resources, with last-used columns when the view has them', () => {
    const visible = [{ resource: all.find(r => r.name === 'shown')!, lastUsed: { state: 'used' as const, at: '2026-10-15T09:00:00Z', uses: 5 } }]
    const [resources, rules] = visibleAccessSections(visible, NOW)
    expect(resources.rows.length).toBe(1)
    expect(resources.rows[0]).toMatchObject({ Resource: 'shown', Via: 'G', Policies: 'P', 'Policy Active': 'Yes', 'Last Used': 'Last used 3 days ago', Uses: '5' })
    expect(rules.rows.length).toBe(1)
  })

  it('has no usage columns in a view without a lookup', () => {
    const [resources] = visibleAccessSections(all.map(resource => ({ resource, lastUsed: lastUsedFor(resource, undefined) })), NOW)
    expect(resources.rows.length).toBe(2)
    expect(Object.keys(resources.rows[0])).not.toContain('Last Used')
  })

  it('says an inactive-only resource is not in effect', () => {
    const inactive = aggregateResources(rulesGrantedToGroupIds([
      policy('p', 'P', G, [rule('R', 'Secrets', [resolved('sec-3', 'off', 'secret')])], { active: false }),
    ], new Set(['g1'])))
    const [resources] = visibleAccessSections(inactive.map(resource => ({ resource, lastUsed: { state: 'none' as const } })), NOW)
    expect(resources.rows[0]).toMatchObject({ 'Policy Active': 'No', 'What They Can Do': 'Not in effect (inactive policy)' })
  })
})

describe('C1: the in-effect filter', () => {
  it('is offered only when some access comes from an inactive policy, and hides it', () => {
    const G = [{ id: 'g1', name: 'G' }]
    const resources = aggregateResources(rulesGrantedToGroupIds([
      policy('p1', 'On', G, [rule('R', 'Secrets', [resolved('sec-1', 'live-one', 'secret')])]),
      policy('p2', 'Off', G, [rule('R', 'Secrets', [resolved('sec-2', 'off-one', 'secret')])], { active: false }),
    ], new Set(['g1'])))
    const { result } = renderHook(() => useGrantsExplorer({ resources, resetKey: 'x' }))
    expect(result.current.filterItems.find(f => f.id === FILTER_IN_EFFECT)?.count).toBe(1)
    expect(result.current.visible.length).toBe(2)
    act(() => result.current.toggleFilter(FILTER_IN_EFFECT))
    expect(result.current.visible.map(v => v.resource.name)).toEqual(['live-one'])
    const none = renderHook(() => useGrantsExplorer({ resources: resources.filter(r => !r.inactiveOnly), resetKey: 'y' }))
    expect(none.result.current.filterItems.some(f => f.id === FILTER_IN_EFFECT)).toBe(false)
  })
})
