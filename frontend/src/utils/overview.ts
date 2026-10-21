import type { InventorySeries, MfaWeek, Overview } from '../types'
import type { ExportSection } from './export'
import { formatDateTime } from './format'

// Wording, number formats, the counts-only export and the leadership one-pager for the Overview (5.50.0).
// Everything here is counts: no name or login is ever read from the Overview payload.

export const FACTOR_ROWS: { key: string; label: string; phishingResistant: boolean; note?: string }[] = [
  { key: 'fastpass', label: 'FastPass', phishingResistant: true },
  { key: 'passkey', label: 'Passkey or security key', phishingResistant: true },
  { key: 'smart_card', label: 'Smart card (PIV)', phishingResistant: true, note: 'log value unconfirmed' },
  { key: 'okta_verify_push', label: 'Okta Verify push', phishingResistant: false },
  { key: 'okta_verify_code', label: 'Okta Verify code', phishingResistant: false },
  { key: 'sms', label: 'SMS', phishingResistant: false },
  { key: 'voice', label: 'Voice (estimate)', phishingResistant: false },
  { key: 'email', label: 'Email', phishingResistant: false },
  { key: 'other_code', label: 'Other one-time code or token', phishingResistant: false },
  { key: 'security_question', label: 'Security question', phishingResistant: false },
  { key: 'other', label: 'Other (not recognised)', phishingResistant: false },
]

export const dayLabel = (iso: string) => {
  const d = new Date(iso.length === 10 ? iso + 'T00:00:00Z' : iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleDateString(undefined, { day: 'numeric', month: 'short', timeZone: 'UTC' })
}
export const weekReadout = (iso: string) => `Week of ${dayLabel(iso)}`
export const pct = (v: number | null | undefined, digits = 0) => (v == null ? 'n/a' : `${(v * 100).toFixed(digits)}%`)
export const approx = (v: number | null | undefined) => (v == null ? 'n/a' : `~${Math.round(v * 100)}%`)
export const signed = (v: number | null) => (v == null ? 'n/a' : v > 0 ? `+${v.toLocaleString()}` : v < 0 ? `-${Math.abs(v).toLocaleString()}` : '0')

export function sum(weeks: MfaWeek[], pick: (w: MfaWeek) => number): number {
  return weeks.reduce((a, w) => a + pick(w), 0)
}

/** The figures of a window: shares and rates recomputed from summed counts (never an average of weekly percentages). */
export function windowFigures(weeks: MfaWeek[]) {
  const mfa = sum(weeks, w => w.mfa_success)
  const unclassified = sum(weeks, w => w.unclassified)
  const classified = mfa - unclassified
  const pr = sum(weeks, w => w.phishing_resistant)
  const failed = sum(weeks, w => w.mfa_failed)
  return {
    signins: sum(weeks, w => w.signins), mfa, unclassified, pr,
    share: classified > 0 ? pr / classified : null,
    failureRate: failed + mfa > 0 ? failed / (failed + mfa) : null,
    smsVoice: sum(weeks, w => w.sms_voice),
    byClass: Object.fromEntries(FACTOR_ROWS.map(f => [f.key, sum(weeks, w => w.by_class[f.key] ?? 0)])) as Record<string, number>,
  }
}

export function lastNonNull<T>(values: (T | null)[]): T | null {
  for (let i = values.length - 1; i >= 0; i--) if (values[i] != null) return values[i]
  return null
}

/** The status of one inventory row's trend, for the sparkline and the table. */
export function seriesValues(s: InventorySeries): number[] {
  return s.points.map(p => p.count)
}

export function inventoryCsv(series: InventorySeries[]): ExportSection[] {
  return [{
    title: 'Inventory over time (counts per daily snapshot)',
    rows: series.map(s => ({
      Side: s.side === 'opa' ? 'OPA' : 'Okta', Type: s.label, Latest: String(s.latest), 'Latest snapshot': s.latest_at,
      '7 days': s.delta_7d == null ? 'n/a' : String(s.delta_7d), '30 days': s.delta_30d == null ? 'n/a' : String(s.delta_30d),
      'First seen': s.first_seen, 'Since first': String(s.latest - (s.points[0]?.count ?? s.latest)),
    })),
  }]
}

/** Counts-only export of the whole page (CSV / Markdown). Never contains a name. */
export function overviewExportSections(o: Overview, envName: string): ExportSection[] {
  const t = o.tiles
  const n = (v: number | null | undefined) => (v == null ? 'not available' : String(v))
  const sections: ExportSection[] = [
    { title: `Overview: ${envName}`, rows: [{ 'As of': o.as_of ?? 'latest', Generated: o.generated_at, 'Okta snapshot': o.sources.okta_snapshot.captured_at ?? 'none',
      'Archive newest event': o.sources.archive.newest ?? '', 'Archive days held': n(o.sources.archive.days_held), 'Chain intact': o.sources.chain?.valid == null ? 'not checked' : o.sources.chain.valid ? 'yes' : 'no',
      Note: 'Counts only. Lists of people are separate and audited.' }] },
    { title: 'State of privileged access', rows: [{ Statement: o.paragraph }] },
    { title: 'Counts', rows: [
      { Figure: 'People with Okta admin roles', Count: n(o.okta_admins.state === 'ok' ? t.okta_people : null) },
      { Figure: 'People with privileged OPA roles', Count: n(t.opa_privileged) },
      { Figure: 'Hold both (separation of duties)', Count: n(t.both) },
      { Figure: 'Left Okta, still in OPA (people)', Count: n(t.left_okta.people) },
      { Figure: 'Left Okta, still in OPA (service accounts)', Count: n(t.left_okta.accounts) },
      { Figure: 'OPA service accounts', Count: n(t.service.total) }, { Figure: 'OPA service users', Count: n(t.service.service_users) },
      { Figure: 'Evidence archive days held', Count: n(t.archive_days) },
    ] },
  ]
  if (o.signins_mfa.state === 'ok') {
    const rows = (weeks: MfaWeek[]) => weeks.map(w => ({
      Week: w.week, 'Successful sign-ins': String(w.signins), 'Successful MFA sign-ins': String(w.mfa_success), 'Phishing-resistant share': pct(w.phishing_resistant_share, 1),
      'SMS and voice': String(w.sms_voice), 'MFA failure rate': pct(w.mfa_failure_rate, 1),
    }))
    sections.push({ title: 'Sign-ins and MFA per week: everyone (estimate; factor from debugData.factor)', rows: rows(o.signins_mfa.everyone) })
    if (o.signins_mfa.privileged.length) sections.push({ title: 'Sign-ins and MFA per week: privileged people (counts)', rows: rows(o.signins_mfa.privileged) })
  }
  if (o.inventory.state === 'ok') sections.push(...inventoryCsv(o.inventory.series))
  return sections
}

const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')

/** The one-page leadership summary as a self-contained, always-light, counts-only HTML page sized for A4 or Letter. The
 * paragraph is the same sentence the screen shows. No names, no links. Printed (Save as PDF) from a new window. */
export function leadershipPdfHtml(o: Overview, envName: string, paper: 'A4' | 'Letter'): string {
  const t = o.tiles
  const tile = (label: string, value: string, sub: string) => `<div class="tile"><div class="tl">${esc(label)}</div><div class="tv">${esc(value)}</div><div class="ts">${esc(sub)}</div></div>`
  const nv = (v: number | null | undefined) => (v == null ? 'n/a' : String(v))
  const byRole = (m: Record<string, number>) => Object.entries(m).map(([k, v]) => `${v} ${k.replace(/_ADMIN$/, '').replace(/_/g, ' ').toLowerCase()}`).join(' · ')
  const mfa = o.signins_mfa.state === 'ok' ? windowFigures(o.signins_mfa.everyone) : null
  const priv = o.signins_mfa.state === 'ok' && o.signins_mfa.privileged.length ? windowFigures(o.signins_mfa.privileged) : null
  const cc = o.cross_checks.map(c => `<tr><td>${esc(c.id)}</td><td>${esc(c.title)}</td><td>${c.result.state === 'ok' ? esc(String((c.result.people ?? 0) + (c.result.accounts ?? 0))) : 'not readable'}</td></tr>`).join('')
  const inv = o.inventory.state === 'ok' ? o.inventory.series.filter(s => ['opa.servers', 'opa.secrets', 'opa.users_human', 'opa.groups', 'opa.policies', 'okta.users', 'okta.apps', 'okta.groups'].includes(s.key))
    .map(s => `<tr><td>${esc(s.side === 'opa' ? 'OPA' : 'Okta')} ${esc(s.label)}</td><td class="n">${s.latest.toLocaleString()}</td><td class="n">${esc(signed(s.delta_7d))}</td></tr>`).join('') : ''
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Privileged access: ${esc(envName)}</title><style>
@page{size:${paper};margin:14mm}@media screen{body{padding:14mm}}
*{box-sizing:border-box}body{font:11px/1.45 Inter,Arial,sans-serif;color:#1D2027;background:#fff;margin:0}
h1{font-size:18px;margin:0 0 2px}h2{font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;color:#5a6173;border-bottom:1px solid #E1E4E9;margin:12px 0 4px;padding-bottom:2px}
.k{color:#5a6173;font-size:10.5px}p{margin:4px 0}.tiles{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-top:6px}
.tile{border:1px solid #E1E4E9;border-radius:6px;padding:6px 8px}.tl{font-size:10px;color:#5a6173}.tv{font-size:20px;font-weight:600}.ts{font-size:9.5px;color:#5a6173}
table{width:100%;border-collapse:collapse;font-size:10.5px}td,th{text-align:left;padding:3px 4px;border-bottom:1px solid #ECEEF1}td.n{text-align:right}
</style></head><body>
<div class="k">Okta and OPA privileged access · ${esc(envName)} · as of ${esc(formatDateTime(o.as_of ?? o.generated_at))}</div>
<h1>State of privileged access</h1>
<p>${esc(o.paragraph)}</p>
<div class="tiles">
${tile('People with Okta admin roles', nv(o.okta_admins.state === 'ok' ? t.okta_people : null), byRole(t.okta_by_role))}
${tile('People with privileged OPA roles', nv(t.opa_privileged), byRole(t.opa_by_role))}
${tile('Hold both (to review)', nv(t.both), 'separation of duties')}
${tile('Left Okta, still in OPA', nv(t.left_okta.people), t.left_okta.accounts ? `+ ${t.left_okta.accounts} service account(s)` : 'cross-check C1')}
${tile('OPA service accounts', nv(t.service.total), `+ ${nv(t.service.service_users)} service users`)}
${tile('Evidence archive', nv(t.archive_days), 'days held (Okta keeps 90)')}
</div>
<h2>Cross-checks (candidates for review)</h2><table>${cc}</table>
${mfa ? `<h2>Okta sign-ins and MFA (estimate)</h2><p>${mfa.signins.toLocaleString()} successful sign-ins in the period. Phishing-resistant share of MFA sign-ins: ${approx(mfa.share)}${priv ? ` (privileged people ${approx(priv.share)})` : ''}. SMS and voice sign-ins: ${mfa.smsVoice.toLocaleString()}. MFA failure rate: ${approx(mfa.failureRate)}. The factor comes from a diagnostic field of the System Log that Okta does not promise to keep stable.</p>` : ''}
${inv ? `<h2>Inventory</h2><table><tr><th>Type</th><th class="n">Latest</th><th class="n">7 days</th></tr>${inv}</table>` : ''}
<h2>Evidence</h2><p>The evidence chain ${o.sources.chain?.valid ? `was verified intact (${o.sources.chain.manifest_count} manifests, 0 breaks)` : o.sources.chain?.valid === false ? 'check found a break' : 'was not checked'}. Counts only: no names or links in this page.</p>
<script>window.onload=function(){setTimeout(function(){window.print()},200)}</script>
</body></html>`
}
