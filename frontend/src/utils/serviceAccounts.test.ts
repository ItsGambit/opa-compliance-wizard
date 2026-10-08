/** Covers the pure helpers behind the Service Accounts Dashboard (5.40.0):
 * filtering, option derivation, summary tiles, identity/scope lines and
 * the rotation summary string. */
import { describe, expect, it } from 'vitest'
import type { ServiceAccountReportRow } from '../types'
import {
  ALL,
  DEFAULT_SERVICE_ACCOUNT_FILTERS,
  countHiddenByScope,
  filterServiceAccountRows,
  rotationSummaryLine,
  serviceAccountFilterOptions,
  serviceAccountIdentityLine,
  serviceAccountScopeLine,
  summarizeServiceAccounts,
} from './serviceAccounts'

function row(overrides: Partial<ServiceAccountReportRow>): ServiceAccountReportRow {
  return {
    id: 'id',
    kind: 'saas',
    name: 'Example',
    username: null,
    app_name: null,
    okta_user_id: null,
    privileged_resource_id: null,
    resource_group_id: null,
    resource_group_name: null,
    project_id: null,
    project_name: null,
    status: 'active',
    sync_status: null,
    last_password_change_at: null,
    created: null,
    updated: [],
    assigned: [],
    deleted: null,
    reveals: [],
    checkouts: [],
    rotations: { total: 0, by_outcome: {}, first_at: null, last_at: null, recent: [] },
    ...overrides,
  }
}

const liveSaas = row({ id: 's1', kind: 'saas', username: 'svc@example.com', app_name: 'Example App',
  resource_group_id: 'rg1', resource_group_name: 'RG One', project_id: 'p1', project_name: 'Proj One' })
const liveOkta = row({ id: 'o1', kind: 'okta', username: 'svc-okta@example.com', okta_user_id: '00uEXAMPLE',
  resource_group_id: 'rg2', resource_group_name: 'RG Two', project_id: 'p2', project_name: 'Proj Two' })
const goneSaas = row({ id: 's2', kind: 'saas', status: 'deleted' })
const unknownOkta = row({ id: 'o2', kind: 'okta', status: 'unknown' })
const rows = [liveSaas, liveOkta, goneSaas, unknownOkta]

describe('filterServiceAccountRows', () => {
  it('returns everything with the default filters', () => {
    expect(filterServiceAccountRows(rows, DEFAULT_SERVICE_ACCOUNT_FILTERS)).toEqual(rows)
  })

  it('filters by kind and status independently and together', () => {
    expect(filterServiceAccountRows(rows, { ...DEFAULT_SERVICE_ACCOUNT_FILTERS, kind: 'okta' }).map(r => r.id)).toEqual(['o1', 'o2'])
    expect(filterServiceAccountRows(rows, { ...DEFAULT_SERVICE_ACCOUNT_FILTERS, status: 'deleted' }).map(r => r.id)).toEqual(['s2'])
    expect(filterServiceAccountRows(rows, { ...DEFAULT_SERVICE_ACCOUNT_FILTERS, kind: 'saas', status: 'active' }).map(r => r.id)).toEqual(['s1'])
  })

  it('a resource group or project filter hides rows with no live project (never guessed)', () => {
    expect(filterServiceAccountRows(rows, { ...DEFAULT_SERVICE_ACCOUNT_FILTERS, resourceGroupId: 'rg1' }).map(r => r.id)).toEqual(['s1'])
    expect(filterServiceAccountRows(rows, { ...DEFAULT_SERVICE_ACCOUNT_FILTERS, projectId: 'p2' }).map(r => r.id)).toEqual(['o1'])
    expect(filterServiceAccountRows(rows, { ...DEFAULT_SERVICE_ACCOUNT_FILTERS, resourceGroupId: 'rg1', projectId: 'p2' })).toEqual([])
  })
})

describe('countHiddenByScope', () => {
  it('is zero without a scope filter and counts only roster-less rows that pass the other filters', () => {
    expect(countHiddenByScope(rows, DEFAULT_SERVICE_ACCOUNT_FILTERS)).toBe(0)
    expect(countHiddenByScope(rows, { ...DEFAULT_SERVICE_ACCOUNT_FILTERS, resourceGroupId: 'rg1' })).toBe(2)
    expect(countHiddenByScope(rows, { ...DEFAULT_SERVICE_ACCOUNT_FILTERS, projectId: 'p1', kind: 'okta' })).toBe(1)
    expect(countHiddenByScope(rows, { ...DEFAULT_SERVICE_ACCOUNT_FILTERS, projectId: 'p1', status: 'active' })).toBe(0)
  })
})

describe('serviceAccountFilterOptions', () => {
  it('derives unique resource groups and projects from the rows, in walk order', () => {
    const opts = serviceAccountFilterOptions([...rows, liveSaas], ALL)
    expect(opts.resourceGroups).toEqual([{ value: 'rg1', label: 'RG One' }, { value: 'rg2', label: 'RG Two' }])
    expect(opts.projects).toEqual([{ value: 'p1', label: 'Proj One' }, { value: 'p2', label: 'Proj Two' }])
  })

  it('scopes projects to the chosen resource group', () => {
    expect(serviceAccountFilterOptions(rows, 'rg2').projects).toEqual([{ value: 'p2', label: 'Proj Two' }])
  })

  it('falls back to the id when a name is missing', () => {
    const opts = serviceAccountFilterOptions([row({ resource_group_id: 'rgX', project_id: 'pX' })], ALL)
    expect(opts.resourceGroups).toEqual([{ value: 'rgX', label: 'rgX' }])
    expect(opts.projects).toEqual([{ value: 'pX', label: 'pX' }])
  })
})

describe('summarizeServiceAccounts', () => {
  it('counts kinds and statuses over exactly the rows given', () => {
    expect(summarizeServiceAccounts(rows)).toEqual({ total: 4, saas: 2, okta: 2, active: 2, deleted: 1, unknown: 1 })
    expect(summarizeServiceAccounts([])).toEqual({ total: 0, saas: 0, okta: 0, active: 0, deleted: 0, unknown: 0 })
  })
})

describe('identity and scope lines', () => {
  it('shows username plus app for SaaS, username plus Okta user id for Okta', () => {
    expect(serviceAccountIdentityLine(liveSaas)).toBe('svc@example.com · Example App')
    expect(serviceAccountIdentityLine(liveOkta)).toBe('svc-okta@example.com · 00uEXAMPLE')
    expect(serviceAccountIdentityLine(goneSaas)).toBe('')
  })

  it('shows RG › Project only when known', () => {
    expect(serviceAccountScopeLine(liveSaas)).toBe('RG One › Proj One')
    expect(serviceAccountScopeLine(goneSaas)).toBe('')
    expect(serviceAccountScopeLine(row({ resource_group_name: 'Only RG' }))).toBe('Only RG')
  })
})

describe('rotationSummaryLine', () => {
  it('is empty for no rotations and a bare total when every rotation succeeded', () => {
    expect(rotationSummaryLine({ total: 0, by_outcome: {}, first_at: null, last_at: null, recent: [] })).toBe('')
    expect(rotationSummaryLine({ total: 3, by_outcome: { SUCCESS: 3 }, first_at: null, last_at: null, recent: [] })).toBe('3')
  })

  it('breaks down mixed outcomes with SUCCESS first, then the rest alphabetically', () => {
    expect(rotationSummaryLine({ total: 6, by_outcome: { FAILURE: 2, SUCCESS: 3, DEFERRED: 1 }, first_at: null, last_at: null, recent: [] }))
      .toBe('6 · 3 SUCCESS, 1 DEFERRED, 2 FAILURE')
    expect(rotationSummaryLine({ total: 2, by_outcome: { FAILURE: 2 }, first_at: null, last_at: null, recent: [] })).toBe('2 · 2 FAILURE')
  })
})
