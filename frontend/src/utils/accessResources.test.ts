import { act, renderHook } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { useGrantsExplorer } from '../components/explorer/useGrantsExplorer'
import { grantRows } from './exportSections'
import { examplePolicies, MFA, policy, resolved, rule } from '../test/accessFixtures'
import type { ResourceAccessInfo } from '../types'
import {
  aggregateResources, countLabel, ACTIVE_DIRECTORY_ACCOUNT_ANY_ID, DATABASE_ACCOUNT_ANY_ID, describeActions, lastUsedFor, sectionsByType, trackedRequests, trackTargets,
  type AccessLookup,
} from './accessResources'
import { rulesGrantedToGroupIds } from './policy'

const grants = rulesGrantedToGroupIds(examplePolicies, new Set(['g1', 'g2']))

describe('aggregateResources', () => {
  const resources = aggregateResources(grants)

  it('makes one row per resource, not per rule', () => {
    expect(resources.map(r => r.name)).toEqual([
      'lab-linux-example-01', 'lab-linux-example-02', 'crm-integration@example.test', 'crm-readonly@example.test', 'crm-svc@example.test',
    ])
  })

  it('keeps every contributing policy rule as a line and de-duplicates groups', () => {
    const merged = aggregateResources([...grants, ...rulesGrantedToGroupIds(examplePolicies, new Set(['g1']))])
    const crm = merged.find(r => r.name === 'crm-svc@example.test')!
    expect(crm.lines.length).toBe(1)
    expect(crm.viaNames).toEqual(['Example-All-Users', 'Example-Linux-Admins'])
    expect(crm.policyNames).toEqual(['Pull SaaS Policy'])
  })

  it('merges the same resource granted by two policies', () => {
    const twice = policy('pol4', 'Second Policy', [{ id: 'g2', name: 'Example-Linux-Admins' }], [
      rule('Again', 'Servers', [resolved('s1', 'lab-linux-example-01')]),
    ])
    const r = aggregateResources(rulesGrantedToGroupIds([...examplePolicies, twice], new Set(['g1', 'g2'])))
    const server = r.find(x => x.name === 'lab-linux-example-01')!
    expect(server.lines.map(l => l.policy.name)).toEqual(['Linux Servers Policy', 'Second Policy'])
    expect(server.policyNames.length).toBe(2)
  })

  it('flags a resource with no MFA or approval as risky, and one with MFA as not', () => {
    expect(resources.find(r => r.name === 'lab-linux-example-01')!.risky).toBe(false) // rule has MFA
    expect(resources.find(r => r.name === 'crm-svc@example.test')!.risky).toBe(true)
  })

  it('keeps unresolved selectors as their own rows', () => {
    const p = policy('pol5', 'Selector Policy', [{ id: 'g1', name: 'Example-All-Users' }], [
      rule('Labelled', 'Servers', [{ kind: 'condition', description: 'Servers labeled role=bastion' }]),
    ])
    const r = aggregateResources(rulesGrantedToGroupIds([p], new Set(['g1'])))
    expect(r[0].name).toBe('Servers labeled role=bastion')
    expect(r[0].hint).toBe('selector')
  })

  it('can limit a rule to some of its resolutions and says how many it left out', () => {
    const r = aggregateResources(grants, { includeResolution: res => res.id === 's1' })
    const server = r.find(x => x.name === 'lab-linux-example-01')!
    expect(server.lines[0].othersCount).toBe(1)
  })

  it('sections follow the rule resource type in first-seen order', () => {
    expect(sectionsByType(resources).map(s => `${s.title}:${s.resources.length}`)).toEqual(['Servers:2', 'Managed SaaS app accounts:3'])
  })
})

describe('describeActions', () => {
  it('uses plain words and falls back to a readable form of unknown types', () => {
    const r = rule('x', 'Servers', [], {
      privileges: [
        { privilege_type: 'reveal_password', flags: ['reveal_password'] },
        { privilege_type: 'principal_account_ssh', flags: ['admin_level_permissions', 'principal_account_ssh'] },
        { privilege_type: 'brand_new_thing', flags: [] },
        { privilege_type: 'secret', flags: ['list', 'secret_reveal'] },
      ],
    })
    expect(describeActions(r)).toEqual(['View the password', 'SSH as admin', 'Brand New Thing', 'List', 'View secrets'])
  })
})

describe('countLabel', () => {
  it('lower-cases and singularises at one', () => {
    expect(countLabel('Servers', 4)).toBe('servers')
    expect(countLabel('Servers', 1)).toBe('server')
    expect(countLabel('Active Directory accounts', 1)).toBe('active directory account')
  })
})

describe('last accessed', () => {
  const [folderRes] = aggregateResources(rulesGrantedToGroupIds([
    policy('pf', 'Folder Policy', [{ id: 'g1', name: 'G' }], [
      rule('Folder', 'Secrets', [{ ...resolved('f1', 'folder-one', 'secret_folder'), child_secrets: [{ id: 'c1', name: 'secret-a' }, { id: 'c2', name: 'secret-b' }] }]),
    ]),
  ], new Set(['g1'])))
  const [acct] = aggregateResources(rulesGrantedToGroupIds([
    policy('pa', 'Acct Policy', [{ id: 'g1', name: 'G' }], [
      rule('Acct', 'Managed SaaS app accounts', [{ ...resolved('a1', 'acct', 'individual_managed_saas_app_account'), access_tracking_id: 'track-1' }]),
    ]),
  ], new Set(['g1'])))
  const info = (over: Partial<ResourceAccessInfo>): ResourceAccessInfo => ({ resource_kind: 'x', supported: true, events: [], ...over })
  const ready = (entries: Record<string, ResourceAccessInfo>): AccessLookup => ({ status: 'ready', byId: new Map(Object.entries(entries)) })

  it('queries the tracking id of an account and the children of a folder', () => {
    expect(trackTargets(acct).map(t => t.id)).toEqual(['track-1'])
    expect(trackTargets(folderRes).map(t => t.id)).toEqual(['c1', 'c2'])
    expect(trackedRequests([acct, folderRes])).toEqual([
      { resource_kind: 'individual_managed_saas_app_account', resource_id: 'track-1' },
      { resource_kind: 'secret', resource_id: 'c1' }, { resource_kind: 'secret', resource_id: 'c2' },
    ])
  })

  it('reports used with the newest time across a folder, never, unknown and untracked', () => {
    const ev = (published: string) => ({ published, request_id: 'r', outcome: 'SUCCESS' })
    expect(lastUsedFor(folderRes, ready({ c1: info({ events: [ev('2026-10-01T00:00:00Z')] }), c2: info({ events: [ev('2026-10-05T00:00:00Z')] }) })))
      .toEqual({ state: 'used', at: '2026-10-05T00:00:00Z' })
    expect(lastUsedFor(acct, ready({ 'track-1': info({}) }))).toEqual({ state: 'never' })
    expect(lastUsedFor(acct, ready({ 'track-1': info({ complete: false }) }))).toEqual({ state: 'unknown' })
    expect(lastUsedFor(acct, ready({}))).toEqual({ state: 'unknown' })
    expect(lastUsedFor(acct, ready({ 'track-1': info({ supported: false }) }))).toEqual({ state: 'untracked' })
    expect(lastUsedFor(acct, { status: 'loading' })).toEqual({ state: 'loading' })
    expect(lastUsedFor(acct, undefined)).toEqual({ state: 'none' })
  })

  it('a resource kind without tracking is untracked when a lookup exists, none otherwise', () => {
    const [server] = aggregateResources(rulesGrantedToGroupIds([policy('ps', 'P', [{ id: 'g1', name: 'G' }], [rule('S', 'Servers', [resolved('s1', 'srv', 'individual_server')], { conditions: [MFA] })])], new Set(['g1'])))
    expect(lastUsedFor(server, { status: 'loading' })).toEqual({ state: 'untracked' })
    expect(lastUsedFor(server, undefined)).toEqual({ state: 'none' })
  })
})

describe('last accessed for database selector rules', () => {
  const dbRule = rule('Db', 'Database accounts', [{ kind: 'condition', description: 'Database accounts in example-conn where name contains app' }], { resource_type: 'database_based_resource' })
  const mk = (r = dbRule) => aggregateResources(rulesGrantedToGroupIds([policy('pd', 'Db Policy', [{ id: 'g1', name: 'G' }], [r])], new Set(['g1'])))
  const [db] = mk()
  const ev = (published: string, name = 'example-db-a') => ({ published, request_id: 'r', outcome: 'SUCCESS', account_name: name })
  const ready = (info: Partial<ResourceAccessInfo>): AccessLookup => ({
    status: 'ready', byId: new Map([[DATABASE_ACCOUNT_ANY_ID, { resource_kind: 'database_account', supported: true, events: [], ...info }]]),
  })

  it('targets and requests the single any-database-account lookup, once', () => {
    expect(trackTargets(db)).toEqual([expect.objectContaining({ id: DATABASE_ACCOUNT_ANY_ID, kind: 'account_selector' })])
    expect(trackedRequests([db, ...mk()])).toEqual([{ resource_kind: 'database_account', resource_id: DATABASE_ACCOUNT_ANY_ID }])
  })

  it('does not track a non-database selector', () => {
    const [labelled] = mk(rule('S', 'Servers', [{ kind: 'condition', description: 'Servers labeled role=x' }]))
    expect(trackTargets(labelled)).toEqual([])
    expect(lastUsedFor(labelled, { status: 'loading' })).toEqual({ state: 'untracked' })
  })

  it('uses the newest event overall, and has never / unknown / loading / error states', () => {
    expect(lastUsedFor(db, ready({ events: [ev('2026-10-05T00:00:00Z'), ev('2026-10-01T00:00:00Z', 'example-db-b')] }))).toEqual({ state: 'used', at: '2026-10-05T00:00:00Z', anyAccount: true })
    expect(lastUsedFor(db, ready({}))).toEqual({ state: 'never', anyAccount: true })
    expect(lastUsedFor(db, ready({ complete: false }))).toEqual({ state: 'unknown' })
    expect(lastUsedFor(db, { status: 'loading' })).toEqual({ state: 'loading' })
    expect(lastUsedFor(db, { status: 'error', message: 'x', onRetry: () => {} })).toEqual({ state: 'error' })
  })
})

describe('last accessed for Active Directory selector rules', () => {
  const adRule = rule('Ad', 'Active Directory accounts', [{ kind: 'condition', description: 'AD accounts in domain(s): example.test' }], { resource_type: 'active_directory_based_resource' })
  const mk = (r = adRule) => aggregateResources(rulesGrantedToGroupIds([policy('pa', 'Ad Policy', [{ id: 'g1', name: 'G' }], [r])], new Set(['g1'])))
  const [ad] = mk()
  const ready = (info: Partial<ResourceAccessInfo>): AccessLookup => ({
    status: 'ready', byId: new Map([[ACTIVE_DIRECTORY_ACCOUNT_ANY_ID, { resource_kind: 'active_directory_account', supported: true, events: [], ...info }]]),
  })

  it('targets and requests the Active Directory lookup, separate from databases', () => {
    expect(trackTargets(ad)).toEqual([expect.objectContaining({ id: ACTIVE_DIRECTORY_ACCOUNT_ANY_ID, kind: 'account_selector', label: expect.stringContaining('Active Directory account this user revealed') })])
    expect(trackedRequests([ad, ...mk()])).toEqual([{ resource_kind: 'active_directory_account', resource_id: ACTIVE_DIRECTORY_ACCOUNT_ANY_ID }])
  })

  it('reports used, never, unknown, loading and error', () => {
    const ev = { published: '2026-10-05T00:00:00Z', request_id: 'r', outcome: 'SUCCESS', account_name: 'example-ad-a' }
    expect(lastUsedFor(ad, ready({ events: [ev] }))).toEqual({ state: 'used', at: '2026-10-05T00:00:00Z', anyAccount: true })
    expect(lastUsedFor(ad, ready({}))).toEqual({ state: 'never', anyAccount: true })
    expect(lastUsedFor(ad, ready({ complete: false }))).toEqual({ state: 'unknown' })
    expect(lastUsedFor(ad, { status: 'loading' })).toEqual({ state: 'loading' })
    expect(lastUsedFor(ad, { status: 'error', message: 'x', onRetry: () => {} })).toEqual({ state: 'error' })
  })
})

describe('database selectors resolved to named accounts (5.44.5)', () => {
  const acct = (id: string, name: string, conn = 'example-conn-1') => ({
    ...resolved(id, name, 'individual_database_account'), access_tracking_id: id, sub_label: conn,
    via_selector: "Database accounts in example-conn-1 where name contains 'svc'",
  })
  const ruleA = rule('Rule A', 'Database accounts', [acct('a1', 'svc_app'), acct('a2', 'app_svc')], { resource_type: 'database_based_resource' })
  const ruleB = rule('Rule B', 'Database accounts', [acct('a1', 'svc_app')], { resource_type: 'database_based_resource' })
  const grantsDb = rulesGrantedToGroupIds([
    policy('p1', 'Policy One', [{ id: 'g1', name: 'G' }], [ruleA]),
    policy('p2', 'Policy Two', [{ id: 'g1', name: 'G' }], [ruleB]),
  ], new Set(['g1']))
  const rows = aggregateResources(grantsDb)

  it('shows one row per account named by the account, with the connection as sub-label', () => {
    expect(rows.map(r => r.name)).toEqual(['app_svc', 'svc_app'])
    expect(rows[1].hint).toContain('example-conn-1')
    expect(rows[1].selectors).toEqual(["Database accounts in example-conn-1 where name contains 'svc'"])
  })

  it('merges an account matched by two rules into one row with both grants', () => {
    const svc = rows.find(r => r.name === 'svc_app')!
    expect(svc.lines.map(l => l.policy.name)).toEqual(['Policy One', 'Policy Two'])
  })

  it('looks each account up by its own id, not the any-account selector id', () => {
    expect(trackedRequests(rows)).toEqual([
      { resource_kind: 'individual_database_account', resource_id: 'a2' },
      { resource_kind: 'individual_database_account', resource_id: 'a1' },
    ])
    const lookup: AccessLookup = { status: 'ready', byId: new Map([
      ['a1', { resource_kind: 'individual_database_account', supported: true, events: [{ published: '2026-10-05T00:00:00Z', request_id: 'r', outcome: 'SUCCESS' }] }],
      ['a2', { resource_kind: 'individual_database_account', supported: true, events: [], complete: true }],
    ]) }
    expect(lastUsedFor(rows.find(r => r.name === 'svc_app')!, lookup)).toEqual({ state: 'used', at: '2026-10-05T00:00:00Z' })
    expect(lastUsedFor(rows.find(r => r.name === 'app_svc')!, lookup)).toEqual({ state: 'never' })
  })

  it('counts and searches the named accounts, by account name and by rule text', () => {
    const { result } = renderHook(() => useGrantsExplorer({ resources: rows, lookup: undefined, resetKey: "u" }))
    expect(result.current.total).toBe(2)
    expect(result.current.visible.length).toBe(2)
    expect(result.current.countItems.find(c => /database/i.test(c.label))?.count).toBe(2)
    act(() => result.current.setQuery("svc_app"))
    expect(result.current.visible.map(v => v.resource.name)).toEqual(["svc_app"])
    act(() => result.current.setQuery("contains svc"))
    expect(result.current.visible.length).toBe(2)
  })

  it('exports the account names and keeps the rule selector in its own column', () => {
    const [row] = grantRows(grantsDb.slice(0, 1))
    expect(row['Applies To']).toContain('svc_app · example-conn-1')
    expect(row['Rule Selector']).toBe("Database accounts in example-conn-1 where name contains 'svc'")
  })
})

describe('last used by account name, Active Directory rows and named servers (5.44.6)', () => {
  const adAcct = (id: string, name: string) => ({
    ...resolved(id, name, 'individual_active_directory_account'), access_tracking_id: id, sub_label: 'example.test',
    via_selector: 'AD accounts in domain(s): example.test', account_name: name, name_unique: true,
  })
  const adRule = rule('Rule AD', 'Active Directory accounts', [adAcct('d1', 'svc_one')], { resource_type: 'active_directory_based_resource' })
  const adGrants = rulesGrantedToGroupIds([policy('p1', 'Policy One', [{ id: 'g1', name: 'G' }], [adRule])], new Set(['g1']))
  const adRows = aggregateResources(adGrants)

  it('headers an Active Directory row with the account name alone; the domain goes in the export and the opened row', () => {
    expect(adRows[0].name).toBe('svc_one')
    expect(adRows[0].hint).toBe('Example Project')
    const [row] = grantRows(adGrants)
    expect(row['Applies To']).toBe('svc_one — Example Project')
    expect(row['Connection or Domain']).toBe('example.test')
    expect(row['Rule Selector']).toBe('AD accounts in domain(s): example.test')
  })

  it('sends the account name and its uniqueness with each database / Active Directory request, nothing else', () => {
    expect(trackedRequests(adRows)).toEqual([
      { resource_kind: 'individual_active_directory_account', resource_id: 'd1', account_name: 'svc_one', name_unique: true },
    ])
    const server = aggregateResources(rulesGrantedToGroupIds([policy('p2', 'P2', [{ id: 'g1', name: 'G' }], [rule('S', 'Servers', [resolved('s1', 'example-web-01')])])], new Set(['g1'])))
    expect(trackedRequests(server)).toEqual([{ resource_kind: 'individual_server_account', resource_id: 's1' }])
  })

  it('never reports "never used" for an ambiguous name, and still reports a name-matched use', () => {
    const lookup = (info: object): AccessLookup => ({ status: 'ready', byId: new Map([['d1', { resource_kind: 'individual_active_directory_account', supported: true, events: [], complete: true, ...info }]]) })
    expect(lastUsedFor(adRows[0], lookup({ ambiguous: true }))).toEqual({ state: 'ambiguous' })
    expect(lastUsedFor(adRows[0], lookup({}))).toEqual({ state: 'never' })
    expect(lastUsedFor(adRows[0], lookup({ events: [{ published: '2026-10-05T00:00:00Z', request_id: 'r', outcome: 'SUCCESS', matched_by: 'name' }], ambiguous: true })))
      .toEqual({ state: 'used', at: '2026-10-05T00:00:00Z' })
    expect(lastUsedFor(adRows[0], lookup({ ambiguous: true, complete: false }))).toEqual({ state: 'unknown' })
  })

  it('shows servers by name, merged with the same server named another way, and keeps a selector row as a selector', () => {
    const named = { ...resolved('s1', 'example-web-01', 'individual_server'), via_selector: 'Servers labeled env=prod' }
    const grantsSrv = rulesGrantedToGroupIds([
      policy('p1', 'P1', [{ id: 'g1', name: 'G' }], [rule('By label', 'Servers', [named])]),
      policy('p2', 'P2', [{ id: 'g1', name: 'G' }], [rule('By id', 'Servers', [resolved('s1', 'example-web-01', 'individual_server'), { kind: 'condition', description: 'Servers labeled system.os_type=linux' }])]),
    ], new Set(['g1']))
    const rows = aggregateResources(grantsSrv)
    expect(rows.map(r => [r.name, r.hint])).toEqual([['example-web-01', 'Example Project'], ['Servers labeled system.os_type=linux', 'selector']])
    expect(rows[0].lines.length).toBe(2)
    expect(rows[0].selectors).toEqual(['Servers labeled env=prod'])
  })
})
