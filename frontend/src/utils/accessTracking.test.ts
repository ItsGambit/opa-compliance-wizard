/** 5.45.0: what gets looked up for each kind of resource, and what the answer
 * says. Fictional names and ids only. */
import { describe, expect, it } from 'vitest'
import { examplePolicies, policy, resolved, rule } from '../test/accessFixtures'
import type { AccessPolicy, ResourceAccessInfo } from '../types'
import { coverageNote, describeEventTypes, evidenceFooter, usesChip } from './accessEvidence'
import {
  aggregateResources, EMPTY_FOLDER_REASON, fnvHex, lastUsedFor, NO_TRACKING_ID_REASON, trackedRequests, trackingFor, UNRESOLVED_FOLDER_REASON,
  type AccessLookup,
} from './accessResources'
import { rulesGrantedToGroupIds } from './policy'

const G = [{ id: 'g1', name: 'G' }]
const rows = (policies: AccessPolicy[]) => aggregateResources(rulesGrantedToGroupIds(policies, new Set(['g1'])))
const one = (res: object, ruleOpts = {}, polOpts: Partial<AccessPolicy> = {}) =>
  rows([policy('p', 'P', G, [rule('R', 'Things', [res as never], ruleOpts)], polOpts)])[0]
const ready = (entries: Record<string, Partial<ResourceAccessInfo>>): AccessLookup => ({
  status: 'ready',
  byId: new Map(Object.entries(entries).map(([k, v]) => [k, { resource_kind: 'x', supported: true, events: [], ...v }])),
})
const ev = (published: string, extra = {}) => ({ published, request_id: 'r', outcome: 'SUCCESS', ...extra })

describe('C2: SaaS / Okta accounts never fall back to the Okta-side id', () => {
  const noTrackingId = { ...resolved('opr-okta-side', 'crm', 'individual_managed_saas_app_account'), access_tracking_id: undefined }

  it('has no lookup target and says Unknown with the reason, not Never used', () => {
    const r = one(noTrackingId)
    expect(trackingFor(r).targets).toEqual([])
    expect(trackedRequests([r])).toEqual([])
    const lu = lastUsedFor(r, ready({}))
    expect(lu).toEqual({ state: 'unknown', reason: NO_TRACKING_ID_REASON })
  })

  it('a result keyed by the Okta-side id is ignored', () => {
    const r = one(noTrackingId)
    expect(lastUsedFor(r, ready({ 'opr-okta-side': {} })).state).toBe('unknown')
  })

  it('with a tracking id it is looked up by that id', () => {
    const r = one({ ...noTrackingId, access_tracking_id: 'trk-1' })
    expect(trackedRequests([r])).toEqual([{ resource_kind: 'individual_managed_saas_app_account', resource_id: 'trk-1' }])
  })
})

describe('C1 / H7: inactive policies, null names, deleted objects', () => {
  it('an inactive policy is marked, never effective, and never risky', () => {
    const r = one(resolved('s1', 'host-1', 'individual_server'), {}, { active: false })
    expect(r.inactiveOnly).toBe(true)
    expect(r.risky).toBe(false)
    expect(r.hint).toContain('inactive policy')
    expect(r.lines[0].inactive).toBe(true)
  })

  it('an active policy alongside an inactive one keeps the resource effective and risky', () => {
    const grants = rulesGrantedToGroupIds([
      policy('p1', 'Off', G, [rule('R', 'Servers', [resolved('s1', 'host-1', 'individual_server')])], { active: false }),
      policy('p2', 'On', G, [rule('R', 'Servers', [resolved('s1', 'host-1', 'individual_server')])]),
    ], new Set(['g1']))
    const [r] = aggregateResources(grants)
    expect(r.inactiveOnly).toBe(false)
    expect(r.risky).toBe(true)
    expect(r.lines.map(l => l.inactive)).toEqual([true, false])
  })

  it('only an inactive policy being risky does not make the resource risky', () => {
    const grants = rulesGrantedToGroupIds([
      policy('p1', 'Off', G, [rule('R', 'Servers', [resolved('s1', 'host-1', 'individual_server')])], { active: false }),
      policy('p2', 'On', G, [rule('R', 'Servers', [resolved('s1', 'host-1', 'individual_server')], { conditions: [{ condition_type: 'mfa', condition_value: {} }] })]),
    ], new Set(['g1']))
    expect(aggregateResources(grants)[0].risky).toBe(false)
  })

  it('a null name falls back to the id and does not crash the sort', () => {
    const grants = rulesGrantedToGroupIds([
      policy('p', 'P', G, [rule('R', 'Secrets', [
        { ...resolved('sec-1', 'x', 'secret'), name: null },
        resolved('sec-2', 'alpha', 'secret'),
      ])]),
    ], new Set(['g1']))
    const out = aggregateResources(grants)
    expect(out.map(r => r.name).sort()).toEqual(['alpha', 'sec-1'])
  })

  it('a missing object shows (deleted)', () => {
    const r = one({ ...resolved('sec-9', 'old-secret', 'secret'), missing: true })
    expect(r.name).toBe('old-secret (deleted)')
  })

  it('two same-named resources are told apart by a short id', () => {
    const grants = rulesGrantedToGroupIds([
      policy('p', 'P', G, [rule('R', 'Secrets', [resolved('aaaaaaaa-1111', 'db-password', 'secret'), resolved('bbbbbbbb-2222', 'db-password', 'secret')])]),
    ], new Set(['g1']))
    const hints = aggregateResources(grants).map(r => r.hint)
    expect(hints[0]).toContain('#aaaaaaaa')
    expect(hints[1]).toContain('#bbbbbbbb')
  })

  it('the shared fixtures still list the inactive policy as inactive when it applies', () => {
    expect(examplePolicies[2].active).toBe(false)
  })
})

describe('C3: server accounts', () => {
  const sa = (username?: string, unique = true) => ({
    ...resolved('srv-1', 'host-1 / ' + (username ?? ''), 'individual_server_account'),
    server_id: 'srv-1', server_name: 'host-1', ...(username ? { account_name: username, name_unique: unique } : {}),
  })

  it('is looked up by server and account name under a plain-identifier key', () => {
    const r = one(sa('root'))
    const [req] = trackedRequests([r])
    expect(req).toEqual({
      resource_kind: 'individual_server_account', resource_id: `srv-1-${fnvHex('root')}`, server_id: 'srv-1', account_name: 'root', name_unique: true,
    })
    expect(req.resource_id).toMatch(/^[A-Za-z0-9_-]{1,128}$/)
  })

  it('two accounts on one server are two lookups', () => {
    const grants = rulesGrantedToGroupIds([policy('p', 'P', G, [rule('R', 'Servers', [sa('root'), { ...sa('app'), id: 'srv-1b' }])])], new Set(['g1']))
    expect(new Set(trackedRequests(aggregateResources(grants)).map(q => q.resource_id)).size).toBe(2)
  })

  it('a server account row without a username keeps the plain server key', () => {
    expect(trackedRequests([one(sa())])).toEqual([{ resource_kind: 'individual_server_account', resource_id: 'srv-1' }])
  })

  it('shows used with the count and the event types counted', () => {
    const r = one(sa('root'))
    const key = trackedRequests([r])[0].resource_id
    const lu = lastUsedFor(r, ready({ [key]: { events: [ev('2026-10-05T00:00:00Z', { event_type: 'pam.server_account.password.reveal' })], uses: 4, window_days: 120, event_types: ['pam.server_account.password.reveal', 'pam.resource.checkout'] } }))
    expect(lu).toMatchObject({ state: 'used', at: '2026-10-05T00:00:00Z', uses: 4, windowDays: 120 })
    expect(describeEventTypes(['pam.server_account.password.reveal', 'pam.resource.checkout', 'pam.user_creds.issue'])).toBe('revealed password, checked out, issued server credentials')
  })
})

describe('H1 / M1: folders and relationship secrets', () => {
  it('an unresolved folder is Unknown with the reason; an empty folder is Not tracked as empty', () => {
    const unresolved = one(resolved('f-x', 'gone', 'secret_folder'))
    expect(lastUsedFor(unresolved, ready({}))).toEqual({ state: 'unknown', reason: UNRESOLVED_FOLDER_REASON })
    expect(trackingFor(unresolved).gap?.reason).toBe(UNRESOLVED_FOLDER_REASON)
    const empty = one({ ...resolved('f-1', 'empty', 'secret_folder'), child_secrets: [] })
    expect(lastUsedFor(empty, ready({}))).toEqual({ state: 'untracked', reason: EMPTY_FOLDER_REASON })
  })

  it('a secret granted through a relationship is tracked by its id', () => {
    const r = one({ ...resolved('sec-r', 'shared-secret', 'relationship_assignment:secret') })
    expect(trackedRequests([r])).toEqual([{ resource_kind: 'secret', resource_id: 'sec-r' }])
    expect(lastUsedFor(r, ready({ 'sec-r': { events: [ev('2026-10-02T00:00:00Z')] } })).state).toBe('used')
  })

  it('a relationship-granted folder is tracked through its secrets', () => {
    const r = one({ ...resolved('f-r', 'rel-folder', 'relationship_assignment:secret_folder'), child_secrets: [{ id: 'c1', name: 'a' }] })
    expect(trackedRequests([r])).toEqual([{ resource_kind: 'secret', resource_id: 'c1' }])
  })
})

describe('H2 / H4 / H5: selectors and shared accounts', () => {
  it('a selector row says any account, in the answer and its title text', () => {
    const r = rows([policy('p', 'P', G, [rule('R', 'Database accounts', [{ kind: 'condition', description: 'Database accounts in c' }], { resource_type: 'database_based_resource' })])])[0]
    expect(lastUsedFor(r, ready({ database_accounts: { events: [ev('2026-10-05T00:00:00Z')] } }))).toMatchObject({ state: 'used', anyAccount: true })
    expect(lastUsedFor(r, ready({ database_accounts: {} }))).toMatchObject({ state: 'never', anyAccount: true })
  })

  it('a shared account without an id of its own gets a plain key and still carries its name', () => {
    const r = one({ ...resolved('shared:My Account (x)', 'My Account (x)', 'individual_active_directory_account'), account_name: 'My Account (x)', name_unique: true })
    const [req] = trackedRequests([r])
    expect(req.resource_id).toMatch(/^[A-Za-z0-9_-]{1,128}$/)
    expect(req).toMatchObject({ account_name: 'My Account (x)', name_unique: true })
  })
})

describe('evidence text', () => {
  const info = (over: Partial<ResourceAccessInfo> = {}): ResourceAccessInfo => ({
    resource_kind: 'x', supported: true, events: [], source: 'archive+live', coverage_from: '2026-07-20T00:00:00.000Z',
    last_synced_at: '2026-10-18T06:00:00.000Z', ...over,
  })
  const now = Date.parse('2026-10-18T09:00:00Z')

  it('footer names source, coverage and last sync', () => {
    expect(evidenceFooter(info(), now)).toBe('Source: archive + live · covers 2026-07-20 to now · last synced 3 hours ago')
    expect(evidenceFooter(info({ source: 'live', last_synced_at: null }), now)).toBe('Source: live · covers 2026-07-20 to now')
  })

  it('chip appears only with a count', () => {
    expect(usesChip(12, 90)).toBe('12 uses · 90d')
    expect(usesChip(1, undefined)).toBe('1 use')
    expect(usesChip(0, 90)).toBeUndefined()
    expect(usesChip(undefined, 90)).toBeUndefined()
  })

  it('coverage note uses the narrowest window and reports a mixed source', () => {
    const note = coverageNote([info(), info({ source: 'live', coverage_from: '2026-07-22T00:00:00.000Z', archive_note: 'type_not_stored' })], now)!
    expect(note).toContain('a mix of archive + live and live')
    expect(note).toContain('covers 2026-07-22 to now')
    expect(note).toContain('does not hold this event type')
    expect(coverageNote([], now)).toBeUndefined()
    expect(coverageNote([info({ supported: false })], now)).toBeUndefined()
  })

  it('a used answer carries the newer-than-sync flag and the union of event types', () => {
    const r = one(resolved('sec-1', 's', 'secret'))
    const lu = lastUsedFor(r, ready({ 'sec-1': { events: [ev('2026-10-05T00:00:00Z')], uses: 2, newer_than_sync: true, event_types: ['pam.secret.reveal'] } }))
    expect(lu).toMatchObject({ state: 'used', uses: 2, newerThanSync: true, eventTypes: ['pam.secret.reveal'] })
  })
})
