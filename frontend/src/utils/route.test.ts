/** Covers the hash-route parser/builder behind in-app Back/Forward
 * (5.40.1): round-trips, defaults for partial or unknown hashes, and the
 * validation that keeps anything derived from the URL to known values. */
import { describe, expect, it } from 'vitest'
import { defaultRoute, parseRoute, routeToHash, sameRoute, type RouteVocabulary } from './route'

const vocab: RouteVocabulary = {
  tabs: ['reports', 'access', 'builder', 'audit_log'],
  reportsSubTabs: ['browse', 'secrets_access', 'service_accounts'],
  accessSubTabs: ['resource_groups', 'projects', 'resources'],
}

describe('parseRoute', () => {
  it('falls back to the default view for an empty, malformed or unknown hash', () => {
    const d = defaultRoute(vocab)
    for (const h of ['', '#', '#/', '#nothing', '#/nope', '#/reports/bogus/x', '#/%E0%A4%A']) {
      expect(parseRoute(h, vocab)).toEqual(d)
    }
  })

  it('parses every level of the reports tab', () => {
    expect(parseRoute('#/reports', vocab)).toEqual({ ...defaultRoute(vocab), tab: 'reports' })
    expect(parseRoute('#/reports/browse/mfa_enforcement', vocab).reportKey).toBe('mfa_enforcement')
    expect(parseRoute('#/reports/secrets_access', vocab).reportsSubTab).toBe('secrets_access')
    // A report key only belongs to the browse sub-tab; elsewhere it's ignored.
    expect(parseRoute('#/reports/service_accounts/mfa_enforcement', vocab).reportKey).toBeNull()
  })

  it('rejects a report key outside the allowed character set', () => {
    expect(parseRoute('#/reports/browse/<script>', vocab).reportKey).toBeNull()
    expect(parseRoute('#/reports/browse/a%20b', vocab).reportKey).toBeNull()
    expect(parseRoute(`#/reports/browse/${'x'.repeat(65)}`, vocab).reportKey).toBeNull()
  })

  it('parses access sub-tabs and plain tabs, ignoring unknown sub-tabs', () => {
    expect(parseRoute('#/access/projects', vocab).accessSubTab).toBe('projects')
    expect(parseRoute('#/access/bogus', vocab)).toEqual({ ...defaultRoute(vocab), tab: 'access' })
    expect(parseRoute('#/builder', vocab).tab).toBe('builder')
    expect(parseRoute('#/audit_log', vocab).tab).toBe('audit_log')
  })
})

describe('routeToHash', () => {
  it('round-trips every route shape', () => {
    const routes = [
      defaultRoute(vocab),
      { ...defaultRoute(vocab), reportKey: 'pam_secrets' },
      { ...defaultRoute(vocab), reportsSubTab: 'service_accounts' },
      { ...defaultRoute(vocab), tab: 'access', accessSubTab: 'resources' },
      { ...defaultRoute(vocab), tab: 'builder' },
    ]
    for (const r of routes) {
      const hash = routeToHash(r, vocab)
      expect(sameRoute(parseRoute(hash, vocab), r)).toBe(true)
    }
    expect(routeToHash({ ...defaultRoute(vocab), reportKey: 'pam_secrets' }, vocab)).toBe('#/reports/browse/pam_secrets')
  })

  it('drops a report key that does not belong to the browse sub-tab', () => {
    expect(routeToHash({ ...defaultRoute(vocab), reportsSubTab: 'secrets_access', reportKey: 'x' }, vocab)).toBe('#/reports/secrets_access')
  })
})
