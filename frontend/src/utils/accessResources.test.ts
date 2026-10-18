import { describe, expect, it } from 'vitest'
import { examplePolicies, MFA, policy, resolved, rule } from '../test/accessFixtures'
import type { ResourceAccessInfo } from '../types'
import {
  aggregateResources, countLabel, describeActions, lastUsedFor, sectionsByType, trackedRequests, trackTargets,
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
