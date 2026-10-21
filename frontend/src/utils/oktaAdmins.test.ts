import { describe, expect, it } from 'vitest'
import { adminRow, c1Card, okReport } from '../test/oktaFixtures'
import { diffSummary, evidenceText, itemLabel, oktaAdminsExportSections, oktaStateText, roleLabel, scopeText, statusText, crossCheckExportSections } from './oktaAdmins'
import { toCsv, toMarkdown } from './export'

describe('okta admin wording', () => {
  it('names roles, scopes and evidence plainly', () => {
    expect(roleLabel({ role_type: 'USER_ADMIN', role_label: null })).toBe('Group administrator')
    expect(roleLabel({ role_type: null, role_label: null })).toBe('Unknown role')
    expect(scopeText(adminRow())).toBe('Whole org')
    expect(scopeText(adminRow({ scope: 'groups', target_groups: ['Support', 'Ops'] }))).toBe('Groups: Support, Ops')
    expect(scopeText(adminRow({ scope: 'groups', target_groups: [] }))).toContain('All groups')
    expect(scopeText(adminRow({ scope: 'unscoped', role_type: 'CUSTOM', custom_role: 'Auditor', resource_set: 'All users' }))).toBe('Resource set: All users')
    expect(scopeText(adminRow({ status: 'removed' }))).toBe('—')
    expect(evidenceText(adminRow({ granted_evidence: 'predates_archive' }))).toBe('Before the archive began')
    expect(evidenceText(adminRow({ granted_evidence: 'none_in_archive' }))).toBe('No privilege event in the archive')
    expect(statusText(adminRow({ status: 'unknown' }))).toContain('unknown')
    expect(oktaStateText('ABSENT')).toBe('not found')
    expect(oktaStateText('PASSWORD_EXPIRED')).toBe('password expired')
    expect(oktaStateText(null)).toBe('unknown')
  })
  it('labels snapshot items and summarises diffs', () => {
    expect(itemLabel('user:00u1', { login: 'a@example.com' })).toBe('a@example.com')
    expect(itemLabel('custom_role:cr1', { label: 'Auditor' })).toBe('Auditor')
    expect(itemLabel('user:00u1', null)).toBe('user:00u1')
    expect(diffSummary({ kind: 'okta_admins', older: {} as never, newer: {} as never, added: [{ key: 'a', object: null }], removed: [], changed: [], unchanged: 3 })).toBe('1 added, 0 removed, 0 changed, 3 unchanged')
  })
})

describe('exports', () => {
  it('carry the basis, the rows and the separation-of-duties overlaps; formula-looking logins are neutralised', () => {
    const report = okReport()
    const sections = oktaAdminsExportSections(report, report.rows)
    expect(sections.map(s => s.title)).toEqual(['Okta Admins: report basis', 'Okta Admins', 'Okta admins who also hold an OPA admin role (candidates for review)'])
    expect(sections[0].rows[0]['Snapshot sha256']).toBe('a'.repeat(64))
    const csv = toCsv(sections)
    expect(csv).toContain("'=cmd|calc")  // neutralised, never a live formula
    expect(csv).not.toMatch(/(^|,)=cmd/m)
    expect(toMarkdown(sections)).toContain('## Okta Admins')
    expect(sections[1].rows.find(r => r.Login === 'sam@example.com')?.['Time-bound']).toBe('Yes')
  })
  it('export nothing for a refused or empty report', () => {
    expect(oktaAdminsExportSections(okReport({ state: 'refused' }), [])).toEqual([])
    expect(oktaAdminsExportSections(undefined, [])).toEqual([])
    expect(crossCheckExportSections(c1Card({ state: 'refused' }))).toEqual([])
  })
  it('omit the separation-of-duties section when the OPA roster was not loaded', () => {
    const report = okReport({ separation_of_duties: { state: 'not_loaded', overlaps: [], checked: 0 } })
    expect(oktaAdminsExportSections(report, report.rows).map(s => s.title)).not.toContain('Okta admins who also hold an OPA admin role (candidates for review)')
  })
  it('cross-check export lists the candidates with the basis', () => {
    const s = crossCheckExportSections(c1Card())
    expect(s[0].rows[0]['Inactive in Okta']).toBe('1')
    expect(s[1].rows.map(r => r.Flag)).toEqual(['Inactive in Okta', 'Not found in Okta'])
  })
})

import { itemLabel as label } from './oktaAdmins'
describe('itemLabel for the OPA access state (5.51.0)', () => {
  it('names a user, group or policy by the name the record holds', () => {
    expect(label('user:ou1', { name: 'alex@example.com', email: 'alex@example.com' })).toBe('alex@example.com')
    expect(label('user:ou2', { name: 'svc-key' })).toBe('svc-key')
    expect(label('group:g1', { name: 'PAM-Admins' })).toBe('PAM-Admins')
    expect(label('policy:p1', { name: 'Servers' })).toBe('Servers')
    expect(label('summary:counts', { counts: {} })).toBe('summary:counts')
  })
})
