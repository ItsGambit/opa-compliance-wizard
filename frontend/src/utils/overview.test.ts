import { describe, expect, it } from 'vitest'
import { overview } from '../test/oktaFixtures'
import { toCsv } from './export'
import { leadershipPdfHtml, overviewExportSections, signed, windowFigures, approx } from './overview'

describe('overview helpers', () => {
  it('computes shares and rates from summed counts, not averaged percentages', () => {
    const o = overview()
    if (o.signins_mfa.state !== 'ok') throw new Error('fixture')
    const f = windowFigures(o.signins_mfa.everyone.slice(-2))
    const a = o.signins_mfa.everyone.slice(-2)
    expect(f.signins).toBe(a[0].signins + a[1].signins)
    expect(f.share).toBeCloseTo((a[0].phishing_resistant + a[1].phishing_resistant) / (a[0].mfa_success + a[1].mfa_success - a[0].unclassified - a[1].unclassified), 6)
  })
  it('formats deltas and shares honestly', () => {
    expect(signed(null)).toBe('n/a'); expect(signed(0)).toBe('0'); expect(signed(5)).toBe('+5'); expect(signed(-3)).toBe('-3')
    expect(approx(null)).toBe('n/a'); expect(approx(0.684)).toBe('~68%')
  })
  it('the counts-only export holds the paragraph, counts and weekly figures and no names', () => {
    const csv = toCsv(overviewExportSections(overview(), 'prod-example'))
    expect(csv).toContain('State of privileged access')
    expect(csv).toContain('People with Okta admin roles,14')
    expect(csv).toContain('Sign-ins and MFA per week')
    expect(csv).not.toMatch(/@/)
  })
  it('says not available rather than zero when a figure has no source', () => {
    const o = overview({ tiles: { ...overview().tiles, opa_privileged: null, both: null } })
    expect(toCsv(overviewExportSections(o, 'e'))).toContain('Hold both (separation of duties),not available')
  })
  it('the leadership one-pager is light, sized, counts only and escapes text', () => {
    const o = overview({ paragraph: 'Bad <script>alert(1)</script> & text' })
    const html = leadershipPdfHtml(o, 'prod', 'Letter')
    expect(html).toContain('size:Letter')
    expect(html).toContain('Bad &lt;script&gt;alert(1)&lt;/script&gt; &amp; text')
    expect(html).not.toMatch(/<a /)
    expect(html).not.toMatch(/@example/)
    expect(leadershipPdfHtml(o, 'prod', 'A4')).toContain('size:A4')
  })
})
