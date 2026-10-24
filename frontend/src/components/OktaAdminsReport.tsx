import { useMemo, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { Camera, Download, RefreshCw, Search } from 'lucide-react'
import { fetchConfigSnapshotExport, logOktaAdminsExport, startOktaCapture } from '../api/client'
import { useConfigSnapshotDiff, useConfigSnapshots, useEnvironments, useOktaAdminsReport } from '../api/hooks'
import { toast } from '../hooks/useToast'
import type { ApiErrorBody, OktaAdminRow, SodOverlap } from '../types'
import { downloadTextFile } from '../utils/export'
import { formatDateTime, formatDateTimeZone } from '../utils/format'
import { HighlightedText, useFuzzyFilter } from '../utils/fuzzySearch'
import {
  OKTA_ROLE_LABELS, diffSummary, evidenceText, itemLabel, oktaAdminsExportSections, personName, roleLabel, scopeText,
  snapshotLine, statusText,
} from '../utils/oktaAdmins'
import { ExportButtons } from './ExportButtons'
import { Select } from './Select'
import { StatusBadge } from './StatusBadge'

// The Okta Admins report (5.50.0). Read from a stored, hash-chained snapshot of Okta, never from a live
// call, so "as of the audit date" and "now" are the same screen. A refused Okta read is shown as what it
// is -- the server sends the exact sentence -- and never as an empty list.

const ALL = '__all__'
const FUZZY_KEYS = ['login', 'name', 'email', 'okta_user_id', 'role_label', 'role_type', 'custom_role']
const STATUS_OPTIONS = [
  { value: ALL, label: 'All statuses' },
  { value: 'active', label: 'Active' },
  { value: 'removed', label: 'Removed' },
  { value: 'unknown', label: 'Unknown' },
]

function SummaryTile({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="card px-3 py-2 min-w-24">
      <div className="text-lg font-bold text-text leading-tight">{value}</div>
      <div className="text-[0.625rem] text-text-faint uppercase tracking-wide">{label}</div>
    </div>
  )
}

function Banner({ children, tone = 'loss' }: { children: React.ReactNode; tone?: 'loss' | 'warn' | 'neutral' }) {
  const cls = tone === 'loss' ? 'text-loss' : tone === 'warn' ? 'text-warn border-warn/40' : 'text-text-dim'
  return <div className={`card p-3 text-sm ${cls}`} role="status">{children}</div>
}

function SodCard({ overlaps, state }: { overlaps: SodOverlap[]; state: string }) {
  if (state === 'not_loaded') return null
  return (
    <section className="card p-3 flex flex-col gap-2" aria-label="Separation of duties">
      <h2 className="text-sm font-semibold text-text">Okta admins who also hold an OPA admin role</h2>
      <p className="text-xs text-text-faint">
        Matched by login or e-mail between the two products. Candidates for review, not findings: whether the combination is
        acceptable is the customer's call.
      </p>
      {overlaps.length === 0 ? (
        <span className="text-xs text-text-dim">No Okta admin in this snapshot also holds an OPA admin role.</span>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-text-faint border-b border-border">
                <th className="px-2 py-1 font-medium">Person</th>
                <th className="px-2 py-1 font-medium">Okta roles</th>
                <th className="px-2 py-1 font-medium">OPA roles</th>
                <th className="px-2 py-1 font-medium">Through OPA groups</th>
              </tr>
            </thead>
            <tbody>
              {overlaps.map(o => (
                <tr key={`${o.okta_user_id}:${o.opa_user_id}`} className="border-b border-border/50 align-top">
                  <td className="px-2 py-1 text-text-dim">{o.login ?? o.okta_user_id}</td>
                  <td className="px-2 py-1">{o.okta_roles.map(t => OKTA_ROLE_LABELS[t] ?? t).join(', ')}</td>
                  <td className="px-2 py-1 font-mono text-xs">{o.opa_roles.join(', ')}</td>
                  <td className="px-2 py-1 text-text-faint">{Object.values(o.via_groups).flat().join(', ') || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

function AdminsTable({ results }: { results: { item: OktaAdminRow; matches: { key: string; indices: [number, number][] }[] }[] }) {
  return (
    <div className="card p-0 overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-xs text-text-faint border-b border-border">
            <th className="px-3 py-1.5 font-medium">Person</th>
            <th className="px-3 py-1.5 font-medium">Role</th>
            <th className="px-3 py-1.5 font-medium">Scope</th>
            <th className="px-3 py-1.5 font-medium">Access</th>
            <th className="px-3 py-1.5 font-medium">Evidence in the archive</th>
            <th className="px-3 py-1.5 font-medium">Status</th>
          </tr>
        </thead>
        <tbody>
          {results.map(({ item: row, matches }, i) => {
            const nameMatch = matches.find(m => m.key === 'login' || m.key === 'name')
            return (
              <tr key={`${row.okta_user_id}:${row.role_assignment_id}:${row.status}:${i}`} className="border-b border-border/50 align-top">
                <td className="px-3 py-1.5">
                  <div className="text-text-dim"><HighlightedText text={personName(row)} indices={nameMatch?.indices} /></div>
                  {row.login && row.name && <div className="text-xs text-text-faint">{row.login}</div>}
                  {row.user_status && <div className="text-[0.6875rem] text-text-faint">Okta user {row.user_status.toLowerCase().replace(/_/g, ' ')}</div>}
                </td>
                <td className="px-3 py-1.5">
                  <div className="text-text-dim">{row.role_type ? roleLabel(row) : '—'}</div>
                  {row.role_type === 'CUSTOM' && row.custom_role && (
                    <div className="text-xs text-text-faint" title={(row.custom_role_permissions ?? []).join(', ')}>
                      {row.custom_role}{row.custom_role_permissions ? ` · ${row.custom_role_permissions.length} permission${row.custom_role_permissions.length === 1 ? '' : 's'}` : ''}
                    </div>
                  )}
                </td>
                <td className="px-3 py-1.5 text-text-dim">{scopeText(row)}</td>
                <td className="px-3 py-1.5 text-text-dim">
                  {row.status !== 'active' ? '—' : row.time_bound ? <>Time-bound until {formatDateTime(row.expires)}</> : 'Standing'}
                  {row.status === 'active' && <div className="text-xs text-text-faint">{row.assignment_type ? `${row.assignment_type.toLowerCase()} assignment` : 'assigned'}{row.assigned_at ? `, ${formatDateTime(row.assigned_at)}` : ''}</div>}
                </td>
                <td className="px-3 py-1.5 text-xs text-text-dim">{evidenceText(row)}</td>
                <td className="px-3 py-1.5">
                  <StatusBadge label={statusText(row)} variant={row.status === 'active' ? 'active' : row.status === 'removed' ? 'deleted' : 'unknown'} />
                  {row.removed_between && (
                    <div className="text-[0.6875rem] text-text-faint mt-0.5">between {formatDateTime(row.removed_between[0])} and {formatDateTime(row.removed_between[1])}</div>
                  )}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

interface HistoryKind { kind: string; title: string; blurb: string; file: string; readLabel: string; refusedLabel: string }
const ADMINS_HISTORY: HistoryKind = {
  kind: 'okta_admins', title: 'Snapshot history', file: 'opa-okta-admins-snapshot', readLabel: 'read', refusedLabel: 'refused by Okta',
  blurb: 'Every capture is stored and sealed into the same hash chain as the archived log, and is never deleted by retention. The Integrity check (deep) verifies them. A refused or failed capture is recorded too.',
}
// 5.51.0: one sealed record of who could reach what in OPA per day, taken from the scan the refresh just read.
const ACCESS_STATE_HISTORY: HistoryKind = {
  kind: 'opa_access_state', title: 'Daily OPA access state', file: 'opa-access-state-snapshot', readLabel: 'sealed', refusedLabel: 'not recorded',
  blurb: 'Once a day the refresh seals who could reach what in OPA (users, groups, and the resources each policy resolves to, by id) into the same chain, from the scan it just read. Names and e-mails are in the records; resource names are not. Never deleted by retention. Opening, comparing or exporting one needs the Live read permission.',
}

function SnapshotHistory({ environment, active, history = ADMINS_HISTORY }: { environment: string; active: number | null; history?: HistoryKind }) {
  const { data: snapshots, isLoading } = useConfigSnapshots(environment, history.kind)
  const [older, setOlder] = useState<string>(ALL)
  const [newer, setNewer] = useState<string>(ALL)
  const [busy, setBusy] = useState<number | null>(null)
  const options = useMemo(
    () => [{ value: ALL, label: 'Choose a snapshot' }, ...(snapshots ?? []).filter(s => s.status === 'ok')
      .map(s => ({ value: String(s.snapshot_id), label: `${formatDateTime(s.captured_at)} (#${s.snapshot_id})` }))],
    [snapshots],
  )
  const olderId = older === ALL ? null : Number(older)
  const newerId = newer === ALL ? null : Number(newer)
  const { data: diff, isError, error, isFetching } = useConfigSnapshotDiff(environment, olderId, newerId)

  const download = async (id: number) => {
    setBusy(id)
    try {
      const body = await fetchConfigSnapshotExport(environment, id)
      downloadTextFile(`${history.file}-${id}.json`, JSON.stringify(body, null, 2), 'application/json')
    } catch (e) {
      toast({ title: 'Could not export the snapshot', description: (e as Error).message, variant: 'error' })
    } finally {
      setBusy(null)
    }
  }

  return (
    <section className="card p-3 flex flex-col gap-3" aria-label={history.title}>
      <div>
        <h2 className="text-sm font-semibold text-text">{history.title}</h2>
        <p className="text-xs text-text-faint">{history.blurb}</p>
      </div>
      {isLoading && <span className="text-xs text-text-faint">Loading…</span>}
      {snapshots && snapshots.length === 0 && <span className="text-xs text-text-faint">{history.kind === 'opa_access_state' ? 'None yet: the first is sealed by the next refresh that reads OPA.' : 'No captures yet.'}</span>}
      {snapshots && snapshots.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-text-faint border-b border-border">
                <th className="px-2 py-1 font-medium">Captured</th>
                <th className="px-2 py-1 font-medium">Result</th>
                <th className="px-2 py-1 font-medium">Objects</th>
                <th className="px-2 py-1 font-medium">SHA-256</th>
                <th className="px-2 py-1 font-medium"><span className="sr-only">Export</span></th>
              </tr>
            </thead>
            <tbody>
              {snapshots.map(s => (
                <tr key={s.snapshot_id} className={`border-b border-border/50 ${s.snapshot_id === active ? 'bg-accent-dim/40' : ''}`}>
                  <td className="px-2 py-1 whitespace-nowrap">{formatDateTime(s.captured_at)}{s.snapshot_id === active && <span className="text-xs text-text-faint"> · shown</span>}</td>
                  <td className="px-2 py-1">
                    <StatusBadge label={s.status === 'ok' ? history.readLabel : s.status === 'refused' ? history.refusedLabel : 'failed'} variant={s.status === 'ok' ? 'active' : 'error'} />
                  </td>
                  <td className="px-2 py-1">{s.item_count}</td>
                  <td className="px-2 py-1 font-mono text-xs text-text-faint" title={s.sha256}>{s.sha256.slice(0, 16)}…</td>
                  <td className="px-2 py-1 text-right">
                    <button type="button" className="btn-secondary !px-2 text-xs" disabled={busy === s.snapshot_id} onClick={() => download(s.snapshot_id)}
                      aria-label={`Export snapshot ${s.snapshot_id} as JSON`} title="Export this snapshot as JSON, with its hashes and chain link">
                      <Download size={12} aria-hidden="true" /> JSON
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {snapshots && snapshots.filter(s => s.status === 'ok').length >= 2 && (
        <div className="flex flex-col gap-2">
          <div className="flex flex-wrap items-end gap-3">
            <div className="flex flex-col gap-1">
              <span className="section-label">Compare</span>
              <Select ariaLabel="Older snapshot" value={older} onValueChange={setOlder} placeholder="Older" options={options} />
            </div>
            <div className="flex flex-col gap-1">
              <span className="section-label">with</span>
              <Select ariaLabel="Newer snapshot" value={newer} onValueChange={setNewer} placeholder="Newer" options={options} />
            </div>
          </div>
          {olderId != null && newerId != null && olderId === newerId && <span className="text-xs text-text-faint">Choose two different snapshots.</span>}
          {isFetching && <span className="text-xs text-text-faint">Comparing…</span>}
          {isError && <span className="text-xs text-loss">{(error as Error & { body?: ApiErrorBody }).message}</span>}
          {diff && (
            <div className="text-sm flex flex-col gap-1.5" aria-live="polite">
              <div className="text-text-dim">{diffSummary(diff)} (between {formatDateTime(diff.older.captured_at)} and {formatDateTime(diff.newer.captured_at)})</div>
              {diff.added.length > 0 && <div><span className="text-win font-medium">Added:</span> {diff.added.map(a => itemLabel(a.key, a.object)).join(', ')}</div>}
              {diff.removed.length > 0 && <div><span className="text-loss font-medium">Removed:</span> {diff.removed.map(a => itemLabel(a.key, a.object)).join(', ')}</div>}
              {diff.changed.length > 0 && (
                <div><span className="text-warn font-medium">Changed:</span>{' '}
                  {diff.changed.map(c => `${itemLabel(c.key, c.after ?? c.before)} (${c.fields.join(', ') || 'details'})`).join('; ')}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </section>
  )
}

export function OktaAdminsReport() {
  const { data: environments } = useEnvironments()
  const environment = environments?.active ?? undefined
  const queryClient = useQueryClient()
  const [asOf, setAsOf] = useState<string>(ALL)
  const [statusFilter, setStatusFilter] = useState<string>(ALL)
  const [roleFilter, setRoleFilter] = useState<string>(ALL)
  const [query, setQuery] = useState('')
  const [starting, setStarting] = useState(false)
  const { data: snapshotList } = useConfigSnapshots(environment, 'okta_admins')
  const { data: report, isLoading, isError, error, refetch, isFetching } = useOktaAdminsReport(environment, asOf === ALL ? undefined : asOf)
  const capturing = starting || report?.capture?.status === 'running'

  const allRows = useMemo(() => report?.rows ?? [], [report])
  const roleOptions = useMemo(() => {
    const types = Array.from(new Set(allRows.map(r => r.role_type).filter((t): t is string => !!t))).sort()
    return [{ value: ALL, label: 'All roles' }, ...types.map(t => ({ value: t, label: OKTA_ROLE_LABELS[t] ?? t }))]
  }, [allRows])
  const structured = useMemo(
    () => allRows.filter(r => (statusFilter === ALL || r.status === statusFilter) && (roleFilter === ALL || r.role_type === roleFilter)),
    [allRows, statusFilter, roleFilter],
  )
  const results = useFuzzyFilter(structured, query, FUZZY_KEYS)
  const visible = useMemo(() => results.map(r => r.item), [results])
  const sections = useMemo(() => oktaAdminsExportSections(report, visible), [report, visible])
  const asOfOptions = useMemo(
    () => [{ value: ALL, label: 'Latest snapshot' },
      ...(snapshotList ?? []).filter(s => s.status === 'ok').map(s => ({ value: s.captured_at, label: formatDateTime(s.captured_at) }))],
    [snapshotList],
  )

  const capture = async () => {
    if (!environment) return
    setStarting(true)
    try {
      const r = await startOktaCapture(environment, 'okta_admins')
      toast({
        title: r.started ? 'Reading Okta' : `A capture is already running${r.started_at ? ` (started ${formatDateTimeZone(r.started_at)})` : ''}`,
        description: 'The report updates when it finishes.', variant: 'success',
      })
      await queryClient.invalidateQueries({ queryKey: ['okta_admins_report', environment] })
      await queryClient.invalidateQueries({ queryKey: ['config_snapshots', environment] })
    } catch (e) {
      toast({ title: 'Could not start the capture', description: (e as Error).message, variant: 'error' })
    } finally {
      setStarting(false)
    }
  }

  const noEnvironment = isError && !!(error as Error & { body?: ApiErrorBody })?.body?.error?.includes('No active environment')

  return (
    <div className="flex flex-col gap-4">
      <div className="card p-3 flex flex-wrap items-end justify-between gap-4">
        <div className="flex flex-wrap items-end gap-4">
          <div className="flex flex-col gap-1">
            <span className="section-label">As of</span>
            <Select ariaLabel="As of" value={asOf} onValueChange={setAsOf} placeholder="As of" options={asOfOptions} />
          </div>
          <div className="flex flex-col gap-1">
            <span className="section-label">Status</span>
            <Select ariaLabel="Status" value={statusFilter} onValueChange={setStatusFilter} placeholder="Status" options={STATUS_OPTIONS} />
          </div>
          <div className="flex flex-col gap-1">
            <span className="section-label">Role</span>
            <Select ariaLabel="Role" value={roleFilter} onValueChange={setRoleFilter} placeholder="Role" options={roleOptions} />
          </div>
          <div className="flex flex-col gap-1">
            <span className="section-label">Search</span>
            <div className="relative">
              <Search size={13} aria-hidden="true" className="absolute left-2 top-1/2 -translate-y-1/2 text-text-faint" />
              <input type="text" aria-label="Search admins" value={query} onChange={e => setQuery(e.target.value)}
                placeholder="Name, login, role…" className="text-input pl-7 min-w-56" />
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button type="button" className="btn-secondary" disabled={capturing || !environment} onClick={capture}
            title="Read the admin list from Okta now and store it as a new snapshot">
            <Camera size={13} className={capturing ? 'animate-pulse' : ''} aria-hidden="true" /> {capturing ? 'Reading Okta…' : 'Capture now'}
          </button>
          <button type="button" className="btn-secondary" disabled={isFetching} onClick={() => refetch()} title="Re-read the stored snapshot">
            <RefreshCw size={13} className={isFetching ? 'animate-spin' : ''} aria-hidden="true" /> Refresh
          </button>
          <ExportButtons sections={sections} filenameBase="opa-okta-admins"
            onExport={format => { if (environment) void logOktaAdminsExport(environment, format, asOf === ALL ? undefined : asOf).catch(() => undefined) }} />
        </div>
      </div>

      {isLoading && <span className="text-sm text-text-faint">Loading…</span>}
      {noEnvironment && <Banner>No active environment configured. Use the Environments control in the sidebar to set one up.</Banner>}
      {isError && !noEnvironment && <Banner>Could not load the Okta Admins report: {(error as Error).message}</Banner>}
      {report?.capture?.status === 'error' && report.capture.error && <Banner>The last capture failed: {report.capture.error}</Banner>}

      {report && report.state === 'never_captured' && (
        <Banner tone="neutral">
          {report.message} Press <span className="font-medium">Capture now</span>; after that, a capture is also taken after each sync (at most every
          six hours). The token needs an admin that can view roles and admin assignments.
        </Banner>
      )}
      {report && report.state === 'refused' && <Banner>{report.message}</Banner>}
      {report && report.state === 'error' && <Banner>{report.message}</Banner>}
      {report && report.state === 'no_snapshot_for_date' && <Banner tone="warn">{report.message}</Banner>}

      {report && report.state === 'ok' && (
        <>
          {report.message && <Banner tone="warn">{report.message} The data below is the last successful snapshot ({formatDateTime(report.as_of_snapshot?.captured_at)}).</Banner>}
          <div className="flex flex-wrap gap-2">
            <SummaryTile label="Admins" value={report.summary.admins ?? 0} />
            <SummaryTile label="Assignments" value={report.summary.assignments ?? 0} />
            <SummaryTile label="Time-bound" value={report.summary.time_bound ?? 0} />
            <SummaryTile label="Removed" value={report.summary.removed ?? 0} />
            <SummaryTile label="Unknown" value={report.summary.unknown ?? 0} />
            <SummaryTile label="Also OPA admin" value={report.separation_of_duties.state === 'not_loaded' ? '—' : report.summary.sod_overlaps ?? 0} />
          </div>
          <p className="text-xs text-text-faint">
            Snapshot {snapshotLine(report.as_of_snapshot)}
            {report.previous_snapshot ? `; compared with ${formatDateTime(report.previous_snapshot.captured_at)}` : '; no earlier snapshot to compare with'}.
            “Removed” means in the earlier snapshot and not in this one; “unknown” means a privilege event in the archive names someone who is in no
            snapshot. Tiles and exports reflect the filters and search above.
          </p>
          {report.notes.map(n => <p key={n} className="text-xs text-text-faint">{n}</p>)}
          <SodCard overlaps={report.separation_of_duties.overlaps} state={report.separation_of_duties.state} />
          {allRows.length === 0 ? (
            <span className="text-xs text-text-faint">No users with a direct Okta admin role assignment in this snapshot.</span>
          ) : structured.length === 0 ? (
            <span className="text-xs text-text-faint">No rows match the current filters.</span>
          ) : results.length === 0 ? (
            <span className="text-xs text-text-faint">No rows match “{query}”.</span>
          ) : (
            <AdminsTable results={results} />
          )}
          {(report.custom_roles.length > 0 || report.resource_sets.length > 0) && (
            <details className="card p-3 text-sm">
              <summary className="cursor-pointer text-text-dim font-medium">Custom roles ({report.custom_roles.length}) and resource sets ({report.resource_sets.length}) defined in Okta</summary>
              <div className="mt-2 flex flex-col gap-1 text-xs">
                {report.custom_roles.map(c => (
                  <div key={c.id}><span className="text-text-dim">{c.label ?? c.id}</span> <span className="text-text-faint">— {c.permissions ? c.permissions.join(', ') || 'no permissions' : 'permissions not read'}</span></div>
                ))}
                {report.resource_sets.map(r => (
                  <div key={r.id}><span className="text-text-dim">{r.label ?? r.id}</span> <span className="text-text-faint">— resource set{r.description ? `: ${r.description}` : ''}</span></div>
                ))}
              </div>
            </details>
          )}
        </>
      )}

      {environment && <SnapshotHistory environment={environment} active={report?.as_of_snapshot?.snapshot_id ?? null} />}
      {environment && <SnapshotHistory environment={environment} active={null} history={ACCESS_STATE_HISTORY} />}
    </div>
  )
}
