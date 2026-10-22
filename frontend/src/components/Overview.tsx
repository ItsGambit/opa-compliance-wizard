import { useEffect, useMemo, useRef, useState } from 'react'
import * as Dialog from '@radix-ui/react-dialog'
import { useQueryClient } from '@tanstack/react-query'
import { ChevronDown, Copy, FileText, List, RefreshCw } from 'lucide-react'
import { startOktaCapture } from '../api/client'
import { useEnvironments, useOverview, usePeopleList, useReportDefs, useWhoami } from '../api/hooks'
import { useIntegrityCheck } from '../hooks/useIntegrityCheck'
import { useRefreshActions, useRefreshStatus } from '../hooks/useRefresh'
import { toast } from '../hooks/useToast'
import type { CrossCheckRow, InventorySeries, MfaWeek, Overview as OverviewData, SodOverlap } from '../types'
import { downloadTextFile, exportSections, toCsv } from '../utils/export'
import { formatDateTime, formatDateTimeZone } from '../utils/format'
import { activeRow, can, refreshReason } from '../utils/environmentRows'
import { ageText, completedWords, formatDayYear, formatTimeOnly, isActive, ordinal, requestedParts, scanFreshness, staleBadgeText } from '../utils/refresh'
import { exportAllReports } from '../utils/reportExports'
import {
  FACTOR_ROWS, approx, dayLabel, inventoryCsv, leadershipPdfHtml, overviewExportSections, pct, seriesValues, signed, weekReadout, windowFigures,
} from '../utils/overview'
import { oktaStateText } from '../utils/oktaAdmins'
import { canAdminFrom } from '../utils/whoami'
import { DialogCloseButton } from './DialogCloseButton'
import { ActionMenu } from './ActionMenu'
import { ExportButtons } from './ExportButtons'
import { RefreshControl } from './RefreshControl'
import { RefreshProgressCard } from './RefreshProgressCard'
import { Select } from './Select'
import { StatusBadge } from './StatusBadge'
import { Legend, Sparkline, TimeChart } from './TimeChart'

// The Overview (5.50.0): Okta and OPA privileged access on one page -- where each figure comes from and when,
// a paragraph written from the figures, six tiles, three trends, the cross-checks, sign-ins and MFA, inventory over
// time and evidence readiness. Counts only; the names behind a count open in a drawer (audited on the server).

const LATEST = '__latest__'
const PERIODS = [{ value: '13', label: 'Last 13 weeks' }, { value: '26', label: 'Last 26 weeks' }, { value: '52', label: 'Last 52 weeks' }]

function relative(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return 'never'
  const ms = now - new Date(iso).getTime()
  if (Number.isNaN(ms)) return iso
  const h = Math.floor(ms / 3_600_000)
  if (h < 1) return 'less than an hour ago'
  if (h < 48) return `${h} h ago`
  return `${Math.floor(h / 24)} days ago`
}

function SectionHead({ id, title, children, badge }: { id: string; title: string; children?: React.ReactNode; badge?: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-3 flex-wrap mb-2">
      <h2 id={id} className="text-sm font-semibold text-text flex items-center gap-2">{title}{badge}</h2>
      <div className="flex items-center gap-2 flex-wrap">{children}</div>
    </div>
  )
}

function Tile({ label, value, unit, sub, flag, na, onOpen, openLabel }: {
  label: string; value: string | number; unit?: string; sub?: React.ReactNode; flag?: boolean; na?: boolean; onOpen?: () => void; openLabel?: string
}) {
  // A figure that cannot be shown says so in plain text (the mockup's "na" tile), not in 28 px type.
  return (
    <li className={`card p-3.5 flex flex-col gap-1 min-h-[7.25rem] ${flag ? 'border-warn/55' : ''}`}>
      <span className="text-xs text-muted font-medium">{label}</span>
      {na ? (
        <span className="text-sm font-medium text-text-dim leading-snug">{value}</span>
      ) : (
        <span className="text-[1.75rem] font-semibold leading-tight text-text flex items-baseline gap-1.5 flex-wrap">
          {onOpen ? (
            <button type="button" onClick={onOpen} aria-label={openLabel ?? `Open the list: ${label}`} className="text-accent-text underline underline-offset-4 decoration-accent-text/40 inline-flex items-baseline gap-1">
              {value}<List size={13} aria-hidden="true" className="self-center" />
            </button>
          ) : value}
          {unit && <small className="text-xs font-normal text-muted">{unit}</small>}
        </span>
      )}
      {sub && <span className="text-[0.6875rem] text-muted leading-snug break-words">{sub}</span>}
    </li>
  )
}

function ChartCard({ title, subtitle, children, how }: { title: string; subtitle: string; children: React.ReactNode; how: string }) {
  return (
    <div className="card p-3">
      <h3 className="text-[0.8125rem] font-semibold text-text">{title}</h3>
      <p className="text-[0.6875rem] text-muted mb-2">{subtitle}</p>
      {children}
      <details className="mt-2"><summary className="text-xs text-muted cursor-pointer">How this is calculated</summary><p className="text-xs text-muted mt-1.5">{how}</p></details>
    </div>
  )
}

const OKTA_ROLE_NAMES: Record<string, string> = {
  SUPER_ADMIN: 'Super', ORG_ADMIN: 'Organization', APP_ADMIN: 'Application', USER_ADMIN: 'Group', READ_ONLY_ADMIN: 'Read-only', HELP_DESK_ADMIN: 'Help desk',
  MOBILE_ADMIN: 'Mobile', API_ACCESS_MANAGEMENT_ADMIN: 'API access', REPORT_ADMIN: 'Report', GROUP_MEMBERSHIP_ADMIN: 'Group membership', CUSTOM: 'Custom',
}
/** "3 Super · 2 Organization · ..." (the mockup's wording for Okta roles). */
const oktaRoleText = (m: Record<string, number>) =>
  Object.entries(m).map(([k, v]) => `${v} ${OKTA_ROLE_NAMES[k] ?? k.replace(/_ADMIN$/, '').replace(/_/g, ' ').toLowerCase().replace(/^./, c => c.toUpperCase())}`).join(' · ')
/** "3 pam_admin · 4 resource_admin" (OPA roles keep their names). */
const opaRoleText = (m: Record<string, number>) => Object.entries(m).map(([k, v]) => `${v} ${k}`).join(' · ')

/** The paragraph with its key figures in bold, as the approved mockup draws it. The text itself is the server's; only these three phrases are emphasised. */
const FIGURE_PHRASES = /(\d[\d,]* (?:people|person) (?:hold|holds) an Okta admin role|\d[\d,]* hold(?:s)? a privileged OPA role|\d[\d,]* (?:people|person) (?:hold|holds) both)/g
function BoldFigures({ text }: { text: string }) {
  return <>{text.split(FIGURE_PHRASES).map((part, i) => (i % 2 === 1 ? <strong key={i}>{part}</strong> : part))}</>
}

// ── People drawer ───────────────────────────────────────────────────────────────────────────────────────────────
type DrawerList = 'c1' | 'c5' | 'mfa_nonpr' | 'mfa_smsvoice'

function PeopleDrawer({ environment, list, asOf, onClose }: { environment: string; list: DrawerList | null; asOf?: string; onClose: () => void }) {
  const { data, isLoading, isError, error } = usePeopleList(environment, list, asOf)
  const title = list === 'c1' ? 'Left Okta, still holds OPA access' : list === 'c5' ? 'Okta admins who also hold an OPA admin role'
    : list === 'mfa_nonpr' ? 'Privileged people who used a non-phishing-resistant factor' : 'Privileged people who used SMS or voice, last 5 weeks'
  return (
    <Dialog.Root open={list != null} onOpenChange={o => { if (!o) onClose() }}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/55 z-40" />
        <Dialog.Content className="fixed right-0 top-0 h-full w-[min(46rem,100vw)] z-50 bg-bg-elevated border-l border-border shadow-[var(--shadow-xl)] p-5 overflow-y-auto flex flex-col gap-3">
          <div className="flex items-start justify-between gap-3">
            <Dialog.Title className="text-base font-semibold text-text">{title}</Dialog.Title>
            <DialogCloseButton />
          </div>
          <Dialog.Description className="text-xs text-muted">
            This list contains names. Opening it is recorded in the Audit Log. Candidates for review, not findings.
          </Dialog.Description>
          {isLoading && <span className="text-sm text-text-faint">Loading…</span>}
          {isError && ((error as { status?: number } | null)?.status === 403
            ? <div className="text-sm text-text-dim" role="status">Lists are available on the main sign-in. This sign-in shows the counts only.</div>
            : <div className="text-sm text-loss">Could not load the list: {(error as Error).message}</div>)}
          {data && data.state === 'refused' && <div className="text-sm text-loss" role="status">{data.message}</div>}
          {data && data.state !== 'refused' && data.people.length === 0 && <span className="text-sm text-text-dim">Nobody is on this list.</span>}
          {data && list === 'c1' && data.people.length > 0 && (
            <table className="w-full text-sm">
              <thead><tr className="text-left text-xs text-text-faint border-b border-border"><th className="py-1 pr-2 font-medium">Person or account</th><th className="py-1 pr-2 font-medium">Okta status</th><th className="py-1 font-medium">OPA access still effective</th></tr></thead>
              <tbody>
                {(data.people as (CrossCheckRow & { footprint?: { groups?: number; policies?: number; resources?: number } | null; okta_status_changed?: string | null })[]).map((r, i) => (
                  <tr key={`${r.opa_id}:${i}`} className="border-b border-border/50 align-top">
                    <td className="py-1.5 pr-2"><div className="text-text-dim">{r.name}{r.source === 'okta_ud_account' ? ' (Okta UD service account)' : ''}</div>{r.email && <div className="text-xs text-text-faint">{r.email}</div>}</td>
                    <td className="py-1.5 pr-2"><StatusBadge label={r.flag === 'absent' ? 'Not found in Okta' : oktaStateText(r.okta_state)} variant="deleted" />{r.flag === 'absent' && r.absent_text && <div className="text-xs text-text-faint">{r.absent_text}</div>}{r.okta_status_changed && <div className="text-xs text-text-faint">since {formatDateTime(r.okta_status_changed)}</div>}</td>
                    <td className="py-1.5 text-xs text-text-dim">{r.footprint ? [r.footprint.groups ? `${r.footprint.groups} group(s)` : null, r.footprint.policies ? `${r.footprint.policies} polic${r.footprint.policies === 1 ? 'y' : 'ies'}` : null, r.footprint.resources ? `${r.footprint.resources} resource(s)` : null].filter(Boolean).join(' → ') : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {data && list === 'c5' && data.people.length > 0 && (
            <table className="w-full text-sm">
              <thead><tr className="text-left text-xs text-text-faint border-b border-border"><th className="py-1 pr-2 font-medium">Person</th><th className="py-1 pr-2 font-medium">Okta roles</th><th className="py-1 font-medium">OPA roles</th></tr></thead>
              <tbody>
                {(data.people as SodOverlap[]).map(o => (
                  <tr key={`${o.okta_user_id}`} className="border-b border-border/50 align-top">
                    <td className="py-1.5 pr-2 text-text-dim">{o.login ?? o.okta_user_id}</td>
                    <td className="py-1.5 pr-2 text-text-dim">{o.okta_roles.join(', ')}</td>
                    <td className="py-1.5 font-mono text-xs">{o.opa_roles.join(', ')}<div className="text-text-faint">{Object.values(o.via_groups).flat().join(', ')}</div></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {data && (list === 'mfa_nonpr' || list === 'mfa_smsvoice') && data.people.length > 0 && (
            <table className="w-full text-sm">
              <thead><tr className="text-left text-xs text-text-faint border-b border-border"><th className="py-1 pr-2 font-medium">Person</th><th className="py-1 pr-2 font-medium text-right">Sign-ins</th><th className="py-1 pr-2 font-medium text-right">MFA sign-ins</th><th className="py-1 pr-2 font-medium text-right">Phishing-resistant share</th><th className="py-1 font-medium text-right">SMS or voice</th></tr></thead>
              <tbody>
                {(data.people as { actor_id: string; login: string | null; signins: number; mfa_success: number; phishing_resistant_share: number | null; sms_voice: number }[]).map(p => (
                  <tr key={p.actor_id} className="border-b border-border/50"><td className="py-1.5 pr-2 text-text-dim">{p.login ?? p.actor_id}</td><td className="py-1.5 pr-2 text-right tabular-nums">{p.signins}</td><td className="py-1.5 pr-2 text-right tabular-nums">{p.mfa_success}</td><td className="py-1.5 pr-2 text-right tabular-nums">{pct(p.phishing_resistant_share)}</td><td className="py-1.5 text-right tabular-nums">{p.sms_voice}</td></tr>
                ))}
              </tbody>
            </table>
          )}
          {data?.note && <p className="text-xs text-muted">{data.note}</p>}
          <p className="text-xs text-muted">The Okta Admins and Cross-checks pages hold the full detail. Exporting this list is not available from the Overview.</p>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}

// ── Sections ────────────────────────────────────────────────────────────────────────────────────────────────────
function ScanRow({ o }: { o: OverviewData }) {
  const m = o.sources.opa_model
  const now = Date.now()
  if (!m.built_at) {
    const sched = o.sources.refresh?.schedule
    return (
      <span>
        No OPA scan stored yet. Select <strong>Refresh</strong> to scan now{sched?.enabled ? `, or wait for the daily refresh at ${sched.run_time} UTC` : ''}.
      </span>
    )
  }
  const freshness = scanFreshness(m.built_at, now)
  const stale = staleBadgeText(m.built_at, now)
  return (
    <span>
      OPA scan {formatDateTimeZone(m.built_at)} ({ageText(m.built_at, now)}){' '}
      {stale ? <StatusBadge label={stale} variant={freshness === 'very_stale' ? 'error' : 'warn'} /> : <StatusBadge label="Current" variant="active" />}
      {m.modified_at && <>{' '}<StatusBadge label="Edited since the scan" variant="neutral" /></>}
      {m.principals_effective != null ? ` · ${m.principals_effective} principals with effective access, resolved through policies` : ''}
      {(m.warnings_count ?? 0) > 0 ? ` · ${m.warnings_count} section${m.warnings_count === 1 ? '' : 's'} the key cannot read` : ''} · stored in the local archive
    </span>
  )
}

function ScheduleRow({ o }: { o: OverviewData }) {
  const r = o.sources.refresh
  if (!r) return <span>—</span>
  const last = r.last_scheduled
  const parts = last ? (['opa', 'log', 'okta'] as const).filter(p => last.parts[p]) : []
  const ok = parts.filter(p => last!.parts[p]!.state === 'ok').length
  const lastText = last?.finished_at ? ` · last run ${formatDateTime(last.finished_at)} · ${completedWords(ok, parts.length)}` : ' · no scheduled run yet'
  return <span>{r.schedule.enabled ? `Daily at ${r.schedule.run_time} UTC${lastText}` : `The daily refresh is off${last?.finished_at ? lastText.replace(' · last run', ' · last scheduled run') : ''}. Turn it on in the environment's sync settings.`}</span>
}

function SourcesStrip({ o, environment, canRun, disabledReason, onRefresh }: {
  o: OverviewData; environment: string; canRun: boolean; disabledReason: string; onRefresh: (parts?: ('opa' | 'okta' | 'log')[]) => void
}) {
  const s = o.sources
  const qc = useQueryClient()
  const integrity = useIntegrityCheck(environment)
  const { data: refresh } = useRefreshStatus(environment)
  const running = refresh?.status === 'running'
  const buildSignins = async () => {
    try { await startOktaCapture(environment, 'mfa_aggregates'); await qc.invalidateQueries({ queryKey: ['overview', environment] }) }
    catch (e) { toast({ title: 'Could not build the sign-in figures', description: (e as Error).message, variant: 'error' }) }
  }
  const chain = integrity.state.phase === 'done' ? integrity.state.result : null
  return (
    <section aria-label="Where the figures come from" className="card p-4 flex flex-col gap-3">
      <div className="grid gap-x-5 gap-y-3 text-xs text-text-dim sm:grid-cols-2 lg:grid-cols-3">
        <div className="flex flex-col gap-0.5">
          <span className="section-label">OPA access model (who can reach what)</span>
          <ScanRow o={o} />
        </div>
        <div className="flex flex-col gap-0.5">
          <span className="section-label">Okta configuration (who holds which role)</span>
          {s.okta_snapshot.captured_at ? (() => {
            const when = formatDateTimeZone(s.okta_snapshot.captured_at)
            const which = s.okta_snapshot.index ? ` (${ordinal(s.okta_snapshot.index)} daily snapshot${s.okta_snapshot.first_at ? `, daily since ${formatDayYear(s.okta_snapshot.first_at)}` : ''})` : ''
            // A refused newest capture is said here, not hidden: the figures use the last readable snapshot.
            return s.okta_snapshot.newest_attempt_status === 'refused'
              ? <span>Last readable snapshot {when}{which} · <strong>the newest capture was refused by Okta</strong> <StatusBadge label="Refused" variant="error" /></span>
              : <span>Okta configuration snapshot {when}{which} · sealed into the evidence chain <StatusBadge label="Chained" variant="active" /></span>
          })() : <span>No readable snapshot yet{s.okta_snapshot.newest_attempt_status === 'refused' ? ': Okta refused the last capture' : ''}.</span>}
        </div>
        <div className="flex flex-col gap-0.5">
          <span className="section-label">System Log archive (what happened)</span>
          {s.archive.has_archive ? (
            <span>
              {s.archive.days_held} days held{s.archive.oldest ? `, ${formatDayYear(s.archive.oldest)} to ${formatDateTimeZone(s.archive.newest)}` : ''} (Okta keeps 90) · {s.archive.events?.toLocaleString()} events · last sync {formatDateTime(s.archive.last_sync_completed_at)} ({relative(s.archive.last_sync_completed_at)}){' '}
              {s.archive.last_sync_status === 'error' ? <StatusBadge label="Sync failed" variant="error" /> : <StatusBadge label="Current" variant="active" />}
            </span>
          ) : <span>No archive yet: select <strong>Refresh</strong> to read the System Log.</span>}
        </div>
        <div className="flex flex-col gap-0.5">
          <span className="section-label">Evidence chain</span>
          <span>
            {(chain ?? s.chain) ? <>{chain ? 'Verified now' : `Verified ${formatDateTimeZone(o.generated_at)}`} · {(chain ?? s.chain)!.manifest_count} manifests (syncs and snapshots), {(chain ?? s.chain)!.valid ? '0 breaks' : 'a break was found'}{(chain ?? s.chain)!.head_hash ? ` · head ${(chain ?? s.chain)!.head_hash!.slice(0, 8)}…` : ''}{' '}
              <StatusBadge label={(chain ?? s.chain)!.valid ? 'Intact' : 'Broken'} variant={(chain ?? s.chain)!.valid ? 'active' : 'error'} /></> : 'Not checked yet.'}
          </span>
        </div>
        <div className="flex flex-col gap-0.5">
          <span className="section-label">Okta org</span>
          <span>{s.okta_org.users != null ? `${s.okta_org.users.toLocaleString()} users${s.okta_org.host ? ` in ${s.okta_org.host}` : ''} (informational)` : 'No count yet'}</span>
        </div>
        <div className="flex flex-col gap-0.5">
          <span className="section-label">Scheduled refresh</span>
          <ScheduleRow o={o} />
        </div>
      </div>
      <div className="flex items-start gap-3 flex-wrap">
        <RefreshControl
          running={running}
          disabledReason={canRun ? '' : disabledReason}
          onRefresh={onRefresh}
          extras={[
            { key: 'verify', label: integrity.state.phase === 'checking' ? 'Verifying…' : 'Verify the chain', hint: 'no reads', disabled: integrity.state.phase === 'checking', onSelect: () => integrity.run(true) },
            ...(o.signins_mfa.state === 'not_built' ? [{ key: 'signins', label: 'Build sign-in figures from the archive', onSelect: () => void buildSignins() }] : []),
          ]}
        />
        <span className="text-xs text-muted self-center">
          {running
            ? `Started by ${refresh?.started_by ?? 'you'} at ${formatTimeOnly(refresh?.started_at)}. A second click attaches to this run; nothing is started twice.`
            : 'Refresh reads OPA and Okta again and syncs the System Log. Each part is logged in the Audit Log. Reads only; nothing is written to OPA or Okta.'}
        </span>
      </div>
    </section>
  )
}

function Trends({ o }: { o: OverviewData }) {
  const okta = o.trends.admin_holders.okta
  const opa = o.trends.admin_holders.opa
  const labels = Array.from(new Set([...okta.map(p => p.t), ...opa.map(p => p.t)])).sort()
  const at = (pts: { t: string; count: number }[]) => labels.map(t => pts.find(p => p.t === t)?.count ?? null)
  const weeks = o.trends.privilege_events.map(w => w.week)
  const req = o.trends.access_requests
  return (
    <div className="grid gap-3 lg:grid-cols-3">
      <ChartCard title="Admin role holders per snapshot" subtitle={`Okta and OPA, ${labels.length} daily snapshot${labels.length === 1 ? '' : 's'}${o.sources.okta_snapshot.first_at ? ` since ${dayLabel(o.sources.okta_snapshot.first_at)}` : ''}`}
        how="One point per daily Okta configuration snapshot: people with at least one Okta admin role assignment (from the sealed snapshot) and people in an OPA group that carries an admin role (from the access model read at the same time). The line begins when snapshots began; earlier counts are not reconstructed from events.">
        {labels.length === 0 ? <p className="text-xs text-text-faint">No snapshots yet.</p> : (<>
          <Legend items={[{ name: 'Okta admin roles', color: 'var(--color-s1)' }, { name: 'OPA privileged roles', color: 'var(--color-s2)', dashed: true }]} />
          <TimeChart title="People holding admin roles, per daily snapshot" kind="line" labels={labels} axisLabel={dayLabel} readoutLabel={l => formatDateTime(l)}
            series={[{ name: 'Okta admin roles', color: 'var(--color-s1)', values: at(okta) }, { name: 'OPA privileged roles', color: 'var(--color-s2)', values: at(opa), dashed: true }]} />
        </>)}
      </ChartCard>
      <ChartCard title="Okta admin privilege grants and revokes" subtitle="Per week, last 13 weeks, from the archive"
        how={`Successful user.account.privilege.grant and user.account.privilege.revoke events in the archive, counted by the week they were published. OPA role changes arrive as group-role edits and are not counted here.${o.trends.revokes_archived ? '' : ' Revoke events are archived only with the "all events" ingestion scope, so revokes read zero here until that scope is used.'}`}>
        <Legend items={[{ name: 'Granted', color: 'var(--color-s1)' }, { name: 'Revoked', color: 'var(--color-s2)' }]} />
        <TimeChart title="Okta admin privilege grants and revokes per week" kind="bar" stacked labels={weeks} axisLabel={dayLabel} readoutLabel={weekReadout}
          series={[{ name: 'Granted', color: 'var(--color-s1)', values: o.trends.privilege_events.map(w => w.granted) }, { name: 'Revoked', color: 'var(--color-s2)', values: o.trends.privilege_events.map(w => w.revoked) }]} />
      </ChartCard>
      <ChartCard title="OPA access requests per week" subtitle="Per week, last 13 weeks, from the archive"
        how="OPA access-request events in the archive (access.request.create, .resolve and .expire), counted by the week published. Okta's log does not record whether a request was approved or denied, so this chart does not claim an outcome: it shows requests created, resolved and expired.">
        <Legend items={[{ name: 'Created', color: 'var(--color-s1)' }, { name: 'Resolved', color: 'var(--color-s3)' }, { name: 'Expired', color: 'var(--color-s2)' }]} />
        <TimeChart title="OPA access requests per week" kind="bar" labels={req.map(w => w.week)} axisLabel={dayLabel} readoutLabel={weekReadout}
          series={[{ name: 'Created', color: 'var(--color-s1)', values: req.map(w => w.created) }, { name: 'Resolved', color: 'var(--color-s3)', values: req.map(w => w.resolved) }, { name: 'Expired', color: 'var(--color-s2)', values: req.map(w => w.expired) }]} />
      </ChartCard>
    </div>
  )
}

function CrossChecks({ o, onOpen }: { o: OverviewData; onOpen?: (l: 'c1' | 'c5') => void }) {
  return (
    <section aria-labelledby="ov-xc" className="card p-4">
      <SectionHead id="ov-xc" title="Cross-checks" badge={<span className="text-xs font-normal text-muted">{o.cross_checks.length} rules, version 1</span>} />
      <p className="text-xs text-muted mb-3">Each rule states what it used and when. Results are recomputed from sealed inputs and exported with their snapshot ids.</p>
      <div className="flex flex-col gap-2.5">
        {o.cross_checks.map(c => {
          const n = (c.result.people ?? 0) + (c.result.accounts ?? 0)
          const ok = c.result.state === 'ok'
          return (
            <div key={c.id} className="grid gap-3 rounded-lg border border-border-sub bg-bg-elevated p-3 sm:grid-cols-[4rem_1fr_auto]">
              <span className="font-mono text-xs text-muted pt-0.5">{c.id}</span>
              <div>
                <div className="font-semibold text-[0.8125rem] text-text">{c.title}</div>
                <div className="text-xs text-muted mt-0.5">{c.statement}</div>
                <div className="text-[0.6875rem] text-muted mt-1.5 flex gap-x-4 flex-wrap">
                  {c.inputs.okta_snapshot && <span>Okta snapshot {formatDateTime(c.inputs.okta_snapshot.captured_at)}</span>}
                  <span>OPA scan {c.inputs.opa_roster_loaded ? 'stored' : 'not stored yet'}</span>
                </div>
                {!ok && c.message && <div className="text-xs text-loss mt-1" role="status">{c.message}</div>}
              </div>
              <div className="flex flex-col items-end gap-1 min-w-28">
                {ok ? (
                  <>
                    {n > 0 && onOpen ? <button type="button" onClick={() => onOpen(c.id === 'C1' ? 'c1' : 'c5')} aria-label={`Open the list: ${c.title}, ${n}`} className="text-[1.375rem] font-semibold text-accent-text underline underline-offset-2">{n}</button> : <span className="text-[1.375rem] font-semibold text-text">0</span>}
                    <StatusBadge label={n === 0 ? 'Clear' : 'Review'} variant={n === 0 ? 'active' : 'error'} />
                    <span className="text-xs text-muted">{n === 0 ? 'none' : c.id === 'C1' ? `${c.result.people ?? 0} people, ${c.result.accounts ?? 0} service account(s)` : `${n} ${n === 1 ? 'person' : 'people'}`}</span>
                  </>
                ) : <StatusBadge label={c.result.state === 'refused' ? 'Not readable' : c.result.state === 'never_run' || c.result.state === 'never_captured' ? 'Not run yet' : 'Unknown'} variant="unknown" />}
              </div>
            </div>
          )
        })}
      </div>
    </section>
  )
}

function SignIns({ o, environment, onOpen }: { o: OverviewData; environment: string; onOpen?: (l: DrawerList) => void }) {
  const [period, setPeriod] = useState('13')
  const s = o.signins_mfa
  const qc = useQueryClient()
  const [starting, setStarting] = useState(false)
  if (s.state === 'not_built') {
    return (
      <section aria-labelledby="ov-mfa" className="card p-4">
        <SectionHead id="ov-mfa" title="Okta sign-ins and MFA" badge={<StatusBadge label="Estimate" variant="unknown" />} />
        <p className="text-sm text-text-dim">{s.message}</p>
        <button type="button" className="btn-secondary mt-2" disabled={starting} onClick={async () => { setStarting(true); try { await startOktaCapture(environment, 'mfa_aggregates'); await qc.invalidateQueries({ queryKey: ['overview', environment] }) } finally { setStarting(false) } }}>
          <RefreshCw size={13} aria-hidden="true" className={starting ? 'animate-spin' : ''} /> Build from the archive
        </button>
      </section>
    )
  }
  const n = Number(period)
  const every = s.everyone.slice(-n)
  const priv = s.privileged.slice(-n)
  const labels = every.map(w => w.week)
  const ev = windowFigures(every)
  const pv = priv.length ? windowFigures(priv) : null
  const thisWeek = every[every.length - 1]
  const privThis = priv[priv.length - 1]
  const first = every.find(w => w.phishing_resistant_share != null)
  const series = (weeks: MfaWeek[], pick: (w: MfaWeek) => number | null, scale = 1) => weeks.map(w => { const v = pick(w); return v == null ? null : v * scale })
  const exportBits = overviewExportSections(o, 'Overview').filter(x => x.title.startsWith('Sign-ins'))
  return (
    <section aria-labelledby="ov-mfa" className="card p-4 flex flex-col gap-3">
      <SectionHead id="ov-mfa" title="Okta sign-ins and MFA" badge={<StatusBadge label="Estimate" variant="unknown" />}>
        <Select ariaLabel="Period" value={period} onValueChange={setPeriod} placeholder="Period" options={PERIODS} />
        <ExportButtons sections={exportBits} filenameBase="opa-signins-mfa-counts" />
      </SectionHead>
      <p className="text-xs text-muted">From the System Log archive (complete through {formatDateTime(o.sources.archive.newest)}). Privileged people here means {s.privileged_cohort && s.people.privileged_total != null ? `${s.people.privileged_total} people: ${s.privileged_cohort.okta_admins} Okta admin role holders plus the OPA privileged users` : 'nobody yet'}, matched to sign-in events by login or Okta user id. The factor used at sign-in comes from a diagnostic field of the log (debugData.factor) that Okta does not promise to keep stable, so every figure that depends on it is an estimate. Same definitions as the FastPass Deployment Tool.</p>
      {s.privileged_message && <p className="text-xs text-warn">{s.privileged_message}</p>}
      <ul className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5 list-none p-0 m-0">
        <Tile label={`Successful sign-ins, ${n} weeks`} value={ev.signins.toLocaleString()} sub={`${pv ? `${pv.signins.toLocaleString()} by privileged people · ` : ''}${thisWeek ? `${thisWeek.password_only_derived.toLocaleString()} derived password-only this week` : ''}`} />
        <Tile label="Phishing-resistant share, this week" value={approx(thisWeek?.phishing_resistant_share)} sub={`everyone${privThis ? `; privileged people ${approx(privThis.phishing_resistant_share)}` : ''}${first && first !== thisWeek ? ` · ${pct(first.phishing_resistant_share)} at the start` : ''}`} />
        <Tile label="Privileged people who used a non-phishing-resistant factor" value={s.people.privileged_non_pr ?? 'n/a'} flag={(s.people.privileged_non_pr ?? 0) > 0}
          onOpen={onOpen && (s.people.privileged_non_pr ?? 0) > 0 ? () => onOpen('mfa_nonpr') : undefined} sub={s.people.privileged_total != null ? `of ${s.people.privileged_total} privileged people, in the period · push, code, SMS or email` : 'no privileged people known yet'} />
        <Tile label="People using SMS or voice, last 30 days" value={s.people.everyone_sms_voice_30d} flag={(s.people.privileged_sms_voice_30d ?? 0) > 0}
          onOpen={onOpen && (s.people.privileged_sms_voice_30d ?? 0) > 0 ? () => onOpen('mfa_smsvoice') : undefined} sub={s.people.privileged_sms_voice_30d != null ? `${s.people.privileged_sms_voice_30d} of them privileged (the list shows those)` : 'privileged people not known yet'} />
        <Tile label="MFA failure rate, this week" value={approx(thisWeek?.mfa_failure_rate)} sub={`${privThis ? `privileged people ${approx(privThis.mfa_failure_rate)} · ` : ''}rate only, no reasons`} />
      </ul>
      <div className="grid gap-3 md:grid-cols-2">
        <ChartCard title="Successful sign-ins per week" subtitle="Everyone · user.session.start with outcome SUCCESS" how="Successful user.session.start events in the archive by the week published: the same rows as the Session Activity report.">
          <TimeChart title="Successful sign-ins per week" kind="bar" labels={labels} axisLabel={dayLabel} readoutLabel={weekReadout} series={[{ name: 'Sign-ins', color: 'var(--color-s1)', values: every.map(w => w.signins) }]} />
        </ChartCard>
        <ChartCard title="Phishing-resistant share of MFA sign-ins per week" subtitle="FastPass, passkey or security key, smart card ÷ all successful MFA sign-ins that named a factor" how="For each week, successful multi-factor sign-ins (user.authentication.auth_via_mfa) whose factor was FastPass, a passkey or security key, or a smart card, divided by all successful multi-factor sign-ins that named a factor. Sign-ins with no factor named are left out of both numbers.">
          <Legend items={[{ name: 'Everyone', color: 'var(--color-s1)' }, { name: 'Privileged people', color: 'var(--color-s2)', dashed: true }]} />
          <TimeChart title="Phishing-resistant share per week" kind="line" labels={labels} axisLabel={dayLabel} readoutLabel={weekReadout} yMax={100} format={v => `${Math.round(v)}%`}
            series={[{ name: 'Everyone', color: 'var(--color-s1)', values: series(every, w => w.phishing_resistant_share, 100) }, ...(priv.length ? [{ name: 'Privileged people', color: 'var(--color-s2)', dashed: true, values: series(priv, w => w.phishing_resistant_share, 100) }] : [])]} />
        </ChartCard>
        <ChartCard title="SMS and voice sign-ins per week" subtitle="Successful MFA sign-ins that named SMS or a voice call" how="Successful multi-factor sign-ins that named SMS or a voice call. Voice is matched on the factor name (CALL or VOICE), which Okta does not document, so it is an estimate.">
          <Legend items={[{ name: 'SMS', color: 'var(--color-s1)' }, { name: 'Voice (estimate)', color: 'var(--color-s2)', dashed: true }]} />
          <TimeChart title="SMS and voice sign-ins per week" kind="line" labels={labels} axisLabel={dayLabel} readoutLabel={weekReadout}
            series={[{ name: 'SMS', color: 'var(--color-s1)', values: every.map(w => w.by_class.sms ?? 0) }, { name: 'Voice (estimate)', color: 'var(--color-s2)', dashed: true, values: every.map(w => w.by_class.voice ?? 0) }]} />
        </ChartCard>
        <ChartCard title="MFA failure rate per week" subtitle="FAILURE, ABANDONED, UNANSWERED or DENY ÷ those plus successes" how="Attempts whose outcome was FAILURE, ABANDONED, UNANSWERED or DENY, divided by those plus the successful ones, per week. The reason for a failure is never shown.">
          <Legend items={[{ name: 'Everyone', color: 'var(--color-s1)' }, { name: 'Privileged people', color: 'var(--color-s2)', dashed: true }]} />
          <TimeChart title="MFA failure rate per week" kind="line" labels={labels} axisLabel={dayLabel} readoutLabel={weekReadout} format={v => `${Math.round(v)}%`}
            series={[{ name: 'Everyone', color: 'var(--color-s1)', values: series(every, w => w.mfa_failure_rate, 100) }, ...(priv.length ? [{ name: 'Privileged people', color: 'var(--color-s2)', dashed: true, values: series(priv, w => w.mfa_failure_rate, 100) }] : [])]} />
        </ChartCard>
      </div>
      <div>
        <h3 className="lbl text-xs font-semibold uppercase tracking-wide text-muted">Successful MFA sign-ins by factor, {n} weeks</h3>
        <p className="text-xs text-muted mb-1">Sign-ins, not people, except the last column (distinct people).</p>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead><tr className="text-left text-text-faint border-b border-border"><th className="py-1 pr-2 font-medium">Factor at sign-in</th><th className="py-1 pr-2 font-medium">Phishing-resistant</th><th className="py-1 pr-2 font-medium text-right">Everyone</th><th className="py-1 pr-2 font-medium text-right">Share</th><th className="py-1 pr-2 font-medium text-right">Privileged</th><th className="py-1 pr-2 font-medium text-right">Share</th><th className="py-1 font-medium text-right">Privileged people</th></tr></thead>
            <tbody>
              {FACTOR_ROWS.filter(f => (ev.byClass[f.key] ?? 0) > 0 || ['fastpass', 'passkey', 'smart_card', 'sms', 'voice'].includes(f.key)).map(f => {
                const classified = ev.mfa - ev.unclassified
                const pClassified = pv ? pv.mfa - pv.unclassified : 0
                return (
                  <tr key={f.key} className="border-b border-border-sub">
                    <td className="py-1 pr-2 text-text-dim">{f.label}{f.note && <span className="text-text-faint"> · {f.note}</span>}</td>
                    <td className={`py-1 pr-2 ${f.phishingResistant ? 'text-win font-semibold' : 'text-text-dim'}`}>{f.phishingResistant ? 'Yes' : 'No'}</td>
                    <td className="py-1 pr-2 text-right tabular-nums">{ev.byClass[f.key].toLocaleString()}</td>
                    <td className="py-1 pr-2 text-right tabular-nums">{classified > 0 ? pctSmall(ev.byClass[f.key] / classified) : 'n/a'}</td>
                    <td className="py-1 pr-2 text-right tabular-nums">{pv ? pv.byClass[f.key].toLocaleString() : 'n/a'}</td>
                    <td className="py-1 pr-2 text-right tabular-nums">{pv && pClassified > 0 ? pctSmall(pv.byClass[f.key] / pClassified) : 'n/a'}</td>
                    <td className="py-1 text-right tabular-nums">{s.people.privileged_by_class ? s.people.privileged_by_class[f.key] ?? 0 : 'n/a'}</td>
                  </tr>
                )
              })}
              <tr><td className="py-1 pr-2 text-text-dim">No factor named (left out of the shares)</td><td /><td className="py-1 pr-2 text-right tabular-nums">{ev.unclassified.toLocaleString()}</td><td /><td className="py-1 pr-2 text-right tabular-nums">{pv ? pv.unclassified.toLocaleString() : 'n/a'}</td><td /><td /></tr>
            </tbody>
          </table>
        </div>
        <details className="mt-2"><summary className="text-xs text-muted cursor-pointer">How this is calculated</summary>
          <p className="text-xs text-muted mt-1.5">{s.notes.join(' ')} The factor class map is the FastPass Deployment Tool's (SIGNED_NONCE FastPass; FIDO_WEBAUTHN passkey or security key; SMART_CARD, PIV or CERTIFICATE smart card; OKTA_VERIFY_PUSH; OKTA_SOFT_TOKEN or TOTP code; SMS; CALL or VOICE voice; EMAIL; PASSWORD_AS_FACTOR no factor). Phishing-resistant: FastPass, passkey, smart card. Events imported from a CSV file carry no factor and count as "no factor named". Enrollment figures are not shown: this tool does not read the Factors API.</p></details>
      </div>
    </section>
  )
}

const pctSmall = (v: number) => (v > 0 && v < 0.01 ? '<1%' : `${Math.round(v * 100)}%`)

function Inventory({ o }: { o: OverviewData }) {
  const series = o.inventory.series
  const [selected, setSelected] = useState('opa.servers')
  const current = series.find(s => s.key === selected) ?? series[0]
  if (o.inventory.state !== 'ok' || !current) {
    return (
      <section aria-labelledby="ov-inv" className="card p-4">
        <SectionHead id="ov-inv" title="Inventory over time" />
        <p className="text-sm text-text-dim">No inventory snapshot yet. Select <strong>Refresh</strong> to take one.</p>
      </section>
    )
  }
  const options = series.map(s => ({ value: s.key, label: `${s.label} (${s.side === 'opa' ? 'OPA' : 'Okta'})` }))
  // An Okta count stops at 50,000 (Okta has no count endpoint): say so where the number is shown, not only below.
  const capped = new Set(o.inventory.problems.filter(p => p.state === 'capped').map(p => p.series))
  const sideTable = (side: 'opa' | 'okta', heading: string, sub: string) => (
    <div className="min-w-0">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted">{heading}</h3>
      <p className="text-[0.6875rem] text-muted mb-1">{sub}</p>
      <table className="w-full text-xs">
        <thead><tr className="text-left text-text-faint border-b border-border"><th className="py-1 pr-1 font-medium">Type</th><th className="py-1 pr-1 font-medium text-right">Latest</th><th className="py-1 pr-1 font-medium text-right">7 d</th><th className="py-1 pr-1 font-medium text-right">30 d</th><th className="py-1 pr-1 font-medium text-right">Since first</th><th className="py-1 font-medium">Trend</th></tr></thead>
        <tbody>
          {series.filter(s => s.side === side).map((s: InventorySeries) => (
            <tr key={s.key} className={`border-b border-border-sub ${s.key === current.key ? 'bg-accent-dim' : ''}`}>
              <th scope="row" className="py-0.5 pr-1 text-left font-normal">
                <button type="button" onClick={() => setSelected(s.key)} aria-pressed={s.key === current.key} className="text-left text-text-dim hover:text-text w-full py-1">{s.label}</button>
              </th>
              <td className="py-1 pr-1 text-right tabular-nums text-text" title={capped.has(s.key) ? 'Lower bound: counting stopped at 50,000' : undefined}>{capped.has(s.key) ? '≥ ' : ''}{s.latest.toLocaleString()}{capped.has(s.key) && <span className="sr-only"> (lower bound, stopped at 50,000)</span>}</td>
              <td className="py-1 pr-1 text-right tabular-nums">{signed(s.delta_7d)}</td>
              <td className="py-1 pr-1 text-right tabular-nums text-text-faint">{signed(s.delta_30d)}</td>
              <td className="py-1 pr-1 text-right tabular-nums">{signed(s.latest - (s.points[0]?.count ?? s.latest))}</td>
              <td className="py-1"><Sparkline values={seriesValues(s)} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
  return (
    <section aria-labelledby="ov-inv" className="card p-4 flex flex-col gap-3">
      <SectionHead id="ov-inv" title="Inventory over time" badge={o.sources.okta_snapshot.days_old && o.sources.okta_snapshot.days_old >= 2 ? <StatusBadge label={`latest snapshot ${o.sources.okta_snapshot.days_old} days old`} variant="unknown" /> : undefined}>
        <Select ariaLabel="Chart" value={current.key} onValueChange={setSelected} placeholder="Chart" options={options} />
        <ExportButtons sections={inventoryCsv(series)} filenameBase="opa-inventory-counts" />
      </SectionHead>
      <p className="text-xs text-muted">Counts per daily snapshot, since the first snapshot on {dayLabel(series.reduce((a, s) => (s.first_seen < a ? s.first_seen : a), series[0].first_seen))} ({o.inventory.snapshots} so far). 30-day change appears once a snapshot at least 30 days older than the latest exists.</p>
      <ChartCard title={`${current.label} (${current.side === 'opa' ? 'OPA' : 'Okta'}), per daily snapshot`} subtitle="Click a row to chart it. One series at a time: the counts differ by orders of magnitude, so a shared axis would flatten the small ones." how="Counts only, from the daily snapshot sealed into the evidence chain; a series whose read was refused is absent from that day's snapshot and shows a gap, never zero.">
        <TimeChart title={`${current.label} per daily snapshot`} kind="line" width={880} height={190} labels={current.points.map(p => p.t)} axisLabel={dayLabel} readoutLabel={l => formatDateTime(l)} series={[{ name: current.label, color: 'var(--color-s1)', values: current.points.map(p => p.count) }]} />
      </ChartCard>
      <div className="grid gap-4 lg:grid-cols-[1.2fr_1fr]">
        {sideTable('opa', 'OPA', 'From the same access-model run the snapshot seals; counts only')}
        {sideTable('okta', 'Okta', 'Read-only; apps and policies are new reads in 5.50.0')}
      </div>
      {o.inventory.problems.length > 0 && <p className="text-xs text-warn" role="status">{o.inventory.problems.some(p => p.state !== 'capped') && <>Some series could not be read in the latest snapshot: {o.inventory.problems.filter(p => p.state !== 'capped').map(p => `${p.series} (${p.state})`).join(', ')}. </>}{capped.size > 0 && <>{[...capped].map(k => series.find(s => s.key === k)?.label ?? k).join(', ')}: a lower bound, counting stopped at 50,000.</>}</p>}
      <p className="text-xs text-muted">Definitions: group memberships are user-to-group links across all OPA groups; policy grants are security-policy rules resolved to a specific resource (the Access Explorer's resolutions); assignments are OPA relationship assignments. Okta users and devices are informational. Kubernetes and cloud-infrastructure resources are not part of the product's model.</p>
    </section>
  )
}

function EvidenceReadiness({ o, environment, onOpenReports }: { o: OverviewData; environment: string; onOpenReports: () => void }) {
  const { data: defs } = useReportDefs(environment)
  const [busy, setBusy] = useState(false)
  const exportAll = async () => {
    if (!defs) return
    setBusy(true)
    try {
      const { sections, failed } = await exportAllReports(defs, environment)
      if (failed.length) { toast({ title: 'Some reports could not be exported', description: failed.map(f => f.def.label).join(', '), variant: 'error' }); return }
      downloadTextFile('opa-all-reports.csv', toCsv(sections.map(s => s.section)), 'text/csv')
    } finally { setBusy(false) }
  }
  return (
    <section aria-labelledby="ov-ev" className="card p-4 flex flex-col gap-3">
      <SectionHead id="ov-ev" title="Evidence readiness"><button type="button" className="btn-primary" disabled={busy || !defs} onClick={exportAll}>Export all reports</button></SectionHead>
      <div className="grid gap-4 lg:grid-cols-[1.4fr_1fr]">
        <table className="w-full text-xs">
          <thead><tr className="text-left text-text-faint border-b border-border"><th className="py-1 pr-2 font-medium">Reports</th><th className="py-1 pr-2 font-medium">Built from</th><th className="py-1 pr-2 font-medium">Current through</th><th className="py-1"><span className="sr-only">Open</span></th></tr></thead>
          <tbody>
            {o.evidence_readiness.map(r => (
              <tr key={r.group} className="border-b border-border-sub align-top">
                <td className="py-1.5 pr-2"><div className="text-text font-medium">{r.group}{r.reports.length > 1 ? ` · ${r.reports.length} reports` : ''}</div><div className="text-text-faint">{r.reports.join(', ')}</div></td>
                <td className="py-1.5 pr-2 text-text-dim">{r.built_from}</td>
                <td className="py-1.5 pr-2 text-text-dim">{formatDateTime(r.current_through)}</td>
                <td className="py-1.5"><button type="button" className="text-accent-text underline underline-offset-2" onClick={onOpenReports}>Open</button></td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="text-xs text-text-dim">
          <div className="section-label mb-1">What the pack contains</div>
          <ul className="list-disc pl-4 flex flex-col gap-1">
            <li>Every report as CSV for the date range you set on the report, formulas neutralised.</li>
            <li>Each Okta configuration snapshot can be exported as JSON with its sha256 from the Okta Admins page.</li>
            <li>A methodology note per report is in each report's "How this is calculated".</li>
            <li>Counts only by default. Lists of people are separate and audited.</li>
          </ul>
        </div>
      </div>
    </section>
  )
}

// ── Page ────────────────────────────────────────────────────────────────────────────────────────────────────────
interface OverviewPageProps {
  onOpenReports: () => void
  /** Where the count links go (administrators only: those pages hold names). */
  onOpenOktaAdmins?: () => void
  onOpenAccessUsers?: () => void
  onOpenServiceAccounts?: () => void
  onOpenEnvironments?: () => void
}

export function OverviewPage({ onOpenReports, onOpenOktaAdmins, onOpenAccessUsers, onOpenServiceAccounts, onOpenEnvironments }: OverviewPageProps) {
  const { data: environments } = useEnvironments()
  const { data: whoami } = useWhoami()
  const canAdmin = canAdminFrom(whoami)  // 5.51.0: an archive viewer sees the counts; the lists of names are administrators-only
  const environment = environments?.active ?? undefined
  const [asOf, setAsOf] = useState<string>(LATEST)
  const [drawer, setDrawer] = useState<DrawerList | null>(null)
  const [paper, setPaper] = useState<'A4' | 'Letter'>('A4')
  const [copied, setCopied] = useState(false)
  const effectiveAsOf = asOf === LATEST ? undefined : asOf
  const { data: o, isLoading, isError, error, refetch } = useOverview(environment, effectiveAsOf)
  // 5.51.0: one Refresh (the OPA scan, the Okta scan and the System Log sync). The page reloads itself as each part ends.
  const { data: refresh } = useRefreshStatus(environment)
  const { start, stop } = useRefreshActions(environment)
  const row = activeRow(environments)
  const canRun = !row || (can(row, 'sync_now') && can(row, 'live_read'))
  const endedSignature = refresh && refresh.status !== 'idle' ? `${refresh.job_id}:${requestedParts(refresh).filter(p => !isActive(refresh.parts[p].state)).length}` : ''
  const lastSignature = useRef(endedSignature)
  useEffect(() => {
    if (endedSignature === lastSignature.current) return
    lastSignature.current = endedSignature
    if (endedSignature) void refetch()
  }, [endedSignature, refetch])
  const exportBits = useMemo(() => (o && environment ? overviewExportSections(o, environment) : []), [o, environment])
  const asOfOptions = useMemo(
    () => [{ value: LATEST, label: o?.sources.okta_snapshot.captured_at ? `Latest · ${formatDateTime(o.sources.okta_snapshot.captured_at)}` : 'Latest' },
      ...(o?.snapshot_dates ?? []).filter(s => s.status === 'ok').map(s => ({ value: s.captured_at, label: formatDateTime(s.captured_at) }))],
    [o],
  )

  const printPdf = () => {
    if (!o || !environment) return
    const w = window.open('', '_blank')
    if (!w) { toast({ title: 'The browser blocked the new window', description: 'Allow pop-ups for this page and try again.', variant: 'error' }); return }
    w.document.open()
    w.document.write(leadershipPdfHtml(o, environment, paper))
    w.document.close()
  }
  const copy = async () => {
    if (!o) return
    try { await navigator.clipboard.writeText(o.paragraph); setCopied(true); setTimeout(() => setCopied(false), 1500) } catch { toast({ title: 'Could not copy', variant: 'error' }) }
  }

  if (!environment) return <div className="card p-3 text-sm text-loss">No active environment configured. Use the Environments control in the sidebar to set one up.</div>
  if (isLoading) return <span className="text-sm text-text-faint">Loading…</span>
  if (isError || !o) {
    const status = (error as { status?: number } | null)?.status
    return <div className="card p-3 text-sm text-loss">{status === 403 ? 'The Overview needs administrator access, or the View archive and Live read permissions on this environment. Ask its owner or an administrator.' : `Could not load the Overview: ${(error as Error | null)?.message ?? 'unknown error'}`}</div>
  }
  const t = o.tiles
  const left = t.left_okta
  const leftN = (left.people ?? 0) + (left.accounts ?? 0)
  return (
    <div className="flex flex-col gap-4">
      {o.attention.length > 0 && (
        <div className="card p-3 border-warn/40 text-xs text-warn flex flex-col gap-1" role="status">
          {o.attention.map(a => <div key={a.kind}>{a.text} Figures below are as of {formatDateTime(o.sources.archive.newest ?? o.sources.okta_snapshot.captured_at)}.</div>)}
        </div>
      )}
      {o.as_of && <div className="card p-2.5 text-xs text-text-dim" role="status">You are viewing {formatDateTime(o.as_of)}. Tiles, the paragraph and the cross-checks are read from the sealed snapshot of that time and the archive up to then; the charts keep their window.</div>}

      {/* One row, as in the approved mockup: Environment, As of, Export…, PDF for leadership. */}
      <div className="flex flex-wrap items-center gap-3">
        <button type="button" className="text-input inline-flex items-center gap-1.5 !py-1.5 !px-2.5 min-h-[2.125rem]" onClick={onOpenEnvironments} disabled={!onOpenEnvironments}
          aria-label={`Environment: ${environment}. Open Environments`}>
          <span className="text-muted text-xs">Environment</span> {environment}<ChevronDown size={13} aria-hidden="true" className="text-muted" />
        </button>
        <label className="inline-flex items-center gap-1.5 text-xs text-muted">As of <Select ariaLabel="As of" value={asOf} onValueChange={setAsOf} placeholder="As of" options={asOfOptions} /></label>
        <ActionMenu label="Export…" menuLabel="Export" items={[
          { key: 'csv', label: 'Counts as CSV', disabled: exportBits.length === 0, onSelect: () => exportSections(exportBits, 'csv', 'opa-overview-counts') },
          { key: 'md', label: 'Counts as Markdown', disabled: exportBits.length === 0, onSelect: () => exportSections(exportBits, 'md', 'opa-overview-counts') },
          { key: 'a4', label: 'Paper size: A4', kind: 'radio', checked: paper === 'A4', separated: true, onSelect: () => setPaper('A4') },
          { key: 'letter', label: 'Paper size: Letter', kind: 'radio', checked: paper === 'Letter', onSelect: () => setPaper('Letter') },
        ]} />
        <button type="button" className="btn-primary" onClick={printPdf}><FileText size={13} aria-hidden="true" /> PDF for leadership</button>
      </div>

      <SourcesStrip o={o} environment={environment} canRun={canRun} disabledReason={row ? refreshReason(row) : ''} onRefresh={parts => void start(parts)} />
      {refresh && refresh.status !== 'idle' && <RefreshProgressCard status={refresh} environment={environment} canRun={canRun} onRetry={part => void start([part])} onStop={() => void stop()} />}

      <section aria-labelledby="ov-state" className="card p-4">
        <div className="flex items-start justify-between gap-3 flex-wrap mb-2.5">
          <h2 id="ov-state" className="text-sm font-semibold text-text">State of privileged access</h2>
          <p className="text-xs text-muted m-0 text-right">Written from the figures below as of {formatDateTime(o.as_of ?? o.generated_at)}. The same paragraph opens the PDF one-pager.</p>
        </div>
        <p className="text-sm leading-relaxed text-text m-0 max-w-[110ch]"><BoldFigures text={o.paragraph} /></p>
        <button type="button" onClick={copy} className="mt-2 text-xs text-accent-text underline underline-offset-2 inline-flex items-center gap-1"><Copy size={12} aria-hidden="true" /> {copied ? 'Copied' : 'Copy paragraph'}</button>
      </section>

      <ul className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 list-none p-0 m-0" aria-label="Key figures">
        {o.okta_admins.state === 'ok' ? (
          <Tile label="People with Okta admin roles" value={t.okta_people} onOpen={canAdmin && onOpenOktaAdmins && t.okta_people > 0 ? onOpenOktaAdmins : undefined} openLabel="Open the Okta Admins report"
            sub={`${oktaRoleText(t.okta_by_role)} (a person can hold several) · as of ${formatDayYear(o.sources.okta_snapshot.captured_at)}`} />
        ) : o.okta_admins.state === 'refused' ? (
          <Tile na label="People with Okta admin roles" value="Not readable with this token"
            sub={`${o.sources.okta_snapshot.newest_attempt_error_code ? `Okta error ${o.sources.okta_snapshot.newest_attempt_error_code} on today's refresh.` : 'Okta refused the read.'} Needs okta.iam.read.${o.sources.okta_snapshot.captured_at ? ` The last readable snapshot (${dayLabel(o.sources.okta_snapshot.captured_at)}) is used by the As-of picker.` : ''}`} />
        ) : (
          <Tile na label="People with Okta admin roles" value="Not captured yet" sub={o.okta_admins.message ?? 'No snapshot yet. Select Refresh to read Okta.'} />
        )}
        {t.opa_privileged != null ? (
          <Tile label="People with privileged OPA roles" value={t.opa_privileged} onOpen={canAdmin && onOpenAccessUsers && t.opa_privileged > 0 ? onOpenAccessUsers : undefined} openLabel="Open Access Explorer, Users"
            sub={`${opaRoleText(t.opa_by_role)} · via group roles${o.sources.opa_model.built_at ? ` · OPA scan ${formatDateTime(o.sources.opa_model.built_at)}` : ''}`} />
        ) : (
          <Tile na label="People with privileged OPA roles" value="No OPA scan stored yet" sub="Select Refresh to scan now." />
        )}
        {t.both != null ? (
          <Tile label="Hold both (separation of duties)" value={t.both} unit={t.both > 0 ? 'to review' : 'none'} flag={t.both > 0} onOpen={canAdmin && t.both > 0 ? () => setDrawer('c5') : undefined}
            sub={`Okta Super, Org or App admin who is also an OPA admin · from the Okta Admins report${canAdmin || t.both === 0 ? '' : ' · list: administrators only'}`} />
        ) : o.okta_admins.state === 'refused' ? (
          <Tile na label="Hold both (separation of duties)" value="Needs admin roles" sub="Not computed while role assignments cannot be read." />
        ) : (
          <Tile na label="Hold both (separation of duties)" value="Needs an OPA scan" sub="Needs the Okta admin list and an OPA scan." />
        )}
        {left.state === 'ok' && left.effective_known ? (
          <Tile label="Left Okta, still in OPA" value={leftN} unit={leftN === 0 ? 'none' : undefined} flag={leftN > 0} onOpen={canAdmin && leftN > 0 ? () => setDrawer('c1') : undefined}
            sub={`Deprovisioned or suspended in Okta, OPA access still effective · cross-check C1${o.lifecycle_c1?.snapshot?.captured_at ? ` · Okta status read ${formatDateTime(o.lifecycle_c1.snapshot.captured_at)}` : ''}${canAdmin || leftN === 0 ? '' : ' · list: administrators only'}`} />
        ) : left.state === 'refused' ? (
          <Tile na label="Left Okta, still in OPA" value="Not readable with this token" sub="Okta refused the user lookup. Cross-check C1." />
        ) : left.state === 'never_run' ? (
          <Tile na label="Left Okta, still in OPA" value="Not run yet" sub="Run the lookup on the Cross-checks page, or select Refresh." />
        ) : (
          <Tile na label="Left Okta, still in OPA" value="Not available" sub="Cross-check C1 needs an OPA scan and the Okta lookup." />
        )}
        {t.service.total != null ? (
          <Tile label="OPA service accounts and service users" value={t.service.total} unit={`+ ${t.service.service_users} service users`} onOpen={canAdmin && onOpenServiceAccounts && t.service.total > 0 ? onOpenServiceAccounts : undefined} openLabel="Open the Service Accounts dashboard"
            sub={`${t.service.saas} SaaS · ${t.service.okta_ud} Okta Universal Directory · ${t.service.service_users} OPA service users with API keys`} />
        ) : (
          <Tile na label="OPA service accounts and service users" value="No OPA scan stored yet" sub="Select Refresh to scan now." />
        )}
        <Tile label="Evidence archive" value={t.archive_days != null ? `${t.archive_days}` : 'n/a'} unit="days held"
          sub={<>Okta keeps 90 · {o.sources.archive.last_sync_status === 'error' ? 'last sync failed' : `last sync ${relative(o.sources.archive.last_sync_completed_at)}`} · chain {o.sources.chain ? <StatusBadge label={o.sources.chain.valid ? 'intact' : 'broken'} variant={o.sources.chain.valid ? 'active' : 'error'} /> : 'not checked'}</>} />
      </ul>

      <Trends o={o} />
      <CrossChecks o={o} onOpen={canAdmin ? setDrawer : undefined} />
      <SignIns o={o} environment={environment} onOpen={canAdmin ? setDrawer : undefined} />
      <Inventory o={o} />
      <EvidenceReadiness o={o} environment={environment} onOpenReports={onOpenReports} />
      <PeopleDrawer environment={environment} list={drawer} asOf={effectiveAsOf} onClose={() => setDrawer(null)} />
    </div>
  )
}

