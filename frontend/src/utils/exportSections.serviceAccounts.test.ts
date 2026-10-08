/** Covers serviceAccountsReportExportSections (5.40.0): every column the
 * Service Accounts Dashboard exports, the outcome suffix on non-success
 * entries, the scheduled/manual rotation marker, and the id fallback for
 * a nameless account. */
import { describe, expect, it } from 'vitest'
import type { ServiceAccountReportRow } from '../types'
import { serviceAccountsReportExportSections } from './exportSections'

const row: ServiceAccountReportRow = {
  id: 'aaaaaaaa-0000-4000-8000-000000000001',
  kind: 'saas',
  name: 'Example account',
  username: 'svc@example.com',
  app_name: 'Example App',
  okta_user_id: null,
  privileged_resource_id: 'opr-example',
  resource_group_id: 'rg1',
  resource_group_name: 'RG One',
  project_id: 'p1',
  project_name: 'Proj One',
  status: 'active',
  sync_status: 'SYNCED',
  last_password_change_at: null,
  created: { by: 'Alex Example', at: '2026-10-01T00:00:00.000Z', request_id: 'req-1', outcome: 'DEFERRED', outcome_reason: null },
  updated: [],
  assigned: [{ by: 'Dana Example', at: '2026-10-02T00:00:00.000Z', request_id: null, outcome: 'SUCCESS', outcome_reason: null }],
  deleted: null,
  reveals: [],
  checkouts: [{ by: 'Alex Example', at: '2026-10-03T00:00:00.000Z', request_id: 'req-3', outcome: 'SUCCESS', outcome_reason: null, expires_at: '2026-10-03T01:00:00.000Z' }],
  rotations: {
    total: 3,
    by_outcome: { SUCCESS: 2, FAILURE: 1 },
    first_at: '2026-09-01T00:00:00.000Z',
    last_at: '2026-10-04T00:00:00.000Z',
    recent: [
      { by: 'Okta System', at: '2026-10-04T00:00:00.000Z', request_id: null, outcome: 'FAILURE', outcome_reason: 'x', system_initiated: true },
      { by: 'Alex Example', at: '2026-10-03T12:00:00.000Z', request_id: null, outcome: 'SUCCESS', outcome_reason: null, system_initiated: false },
    ],
  },
}

describe('serviceAccountsReportExportSections', () => {
  it('exports one section with every column, marking non-success outcomes', () => {
    const [section] = serviceAccountsReportExportSections([row])
    expect(section.title).toBe('Service Accounts')
    const out = section.rows[0]
    expect(out.Account).toBe('Example account')
    expect(out.Type).toBe('SaaS app')
    expect(out['App / Okta User ID']).toBe('Example App')
    expect(out['Resource Group']).toBe('RG One')
    expect(out.Status).toBe('Active')
    expect(out['Sync Status (informational)']).toBe('SYNCED')
    expect(out.Created).toMatch(/^Alex Example — .* \(request req-1\) \[DEFERRED\]$/)
    expect(out['Assigned (most recent first)']).toMatch(/^Dana Example — /)
    expect(out['Checked Out (most recent first)']).toMatch(/\(request req-3\) until /)
    expect(out['Rotations (total)']).toBe('3')
    expect(out['Rotation Outcomes']).toBe('SUCCESS: 2, FAILURE: 1')
    expect(out['Recent Rotations (most recent first)']).toMatch(/\[FAILURE\] \(scheduled\); Alex Example — .* \(manual\)$/)
    expect(out.Deleted).toBe('')
    expect(out['Account ID']).toBe(row.id)
    expect(out['Privileged Resource ID']).toBe('opr-example')
  })

  it('falls back to the id for a nameless account and labels Okta accounts by their Okta user', () => {
    const [section] = serviceAccountsReportExportSections([
      { ...row, kind: 'okta', name: '', app_name: null, okta_user_id: '00uEXAMPLE', privileged_resource_id: null },
    ])
    expect(section.rows[0].Account).toBe(row.id)
    expect(section.rows[0].Type).toBe('Okta')
    expect(section.rows[0]['App / Okta User ID']).toBe('00uEXAMPLE')
    expect(section.rows[0]['Privileged Resource ID']).toBe('')
  })

  it('exports no rows for an empty report', () => {
    expect(serviceAccountsReportExportSections([])[0].rows).toEqual([])
  })
})
