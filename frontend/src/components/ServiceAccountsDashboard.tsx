import { useMemo, useState } from 'react'
import { RefreshCw, Search } from 'lucide-react'
import { useEnvironments, useServiceAccountsReport } from '../api/hooks'
import type { ApiErrorBody, SecretsAccessStatus, ServiceAccountCheckoutEntry, ServiceAccountKind, ServiceAccountReportRow, ServiceAccountRotationEntry } from '../types'
import { formatDateTime } from '../utils/format'
import { serviceAccountsReportExportSections } from '../utils/exportSections'
import { HighlightedText, useFuzzyFilter } from '../utils/fuzzySearch'
import {
  ALL,
  DEFAULT_SERVICE_ACCOUNT_FILTERS,
  SERVICE_ACCOUNT_KIND_LABEL,
  countHiddenByScope,
  filterServiceAccountRows,
  rotationSummaryLine,
  serviceAccountFilterOptions,
  serviceAccountIdentityLine,
  serviceAccountScopeLine,
  summarizeServiceAccounts,
  type ServiceAccountFilters,
} from '../utils/serviceAccounts'
import { statusLabel, statusVariant } from '../utils/accessStatus'
import { AuditCell, AuditHistoryCell } from './AuditCells'
import { ExportButtons } from './ExportButtons'
import { ResourceHistoryPanel } from './ResourceHistoryPanel'
import { Select } from './Select'
import { StatusBadge } from './StatusBadge'

// The SaaS / Okta service-account counterpart of SecretsAccessDashboard
// (5.40.0): one combined view with a type filter rather than two pages --
// both families share the same event family, the same id space and the
// same columns (see create_secret_folders.py's
// build_service_accounts_report_from_archive); only the identity sub-line
// differs. Tenant-wide rather than per-project, because a since-deleted
// account's project is not knowable (events carry no project co-target),
// so "deleted" is only honest against the whole tenant's roster.

const KIND_OPTIONS = [
  { value: ALL, label: 'All types' },
  { value: 'saas', label: 'SaaS app accounts' },
  { value: 'okta', label: 'Okta service accounts' },
]

const STATUS_OPTIONS = [
  { value: ALL, label: 'All statuses' },
  { value: 'active', label: 'Active' },
  { value: 'deleted', label: 'Deleted' },
  { value: 'unknown', label: 'Unknown' },
]

// Module-level so useFuzzyFilter's memoized Fuse index keys off a stable
// array identity (see that hook's own comment).
const FUZZY_KEYS = ['name', 'username', 'app_name', 'okta_user_id', 'project_name', 'resource_group_name']

const UNKNOWN_HINT = 'not in live roster, no delete event'

function SummaryTile({ label, value }: { label: string; value: number }) {
  return (
    <div className="card px-3 py-2 min-w-24">
      <div className="text-lg font-bold text-text leading-tight">{value}</div>
      <div className="text-[0.625rem] text-text-faint uppercase tracking-wide">{label}</div>
    </div>
  )
}

function CheckoutEntry({ entry }: { entry: ServiceAccountCheckoutEntry }) {
  return (
    <span>
      <AuditCell entry={entry} />
      {entry.expires_at && <span className="text-text-faint"> · until {formatDateTime(entry.expires_at)}</span>}
    </span>
  )
}

function RotationEntry({ entry }: { entry: ServiceAccountRotationEntry }) {
  return (
    <span>
      <AuditCell entry={entry} />
      {entry.system_initiated != null && (
        <span className="text-text-faint"> · {entry.system_initiated ? 'scheduled' : 'manual'}</span>
      )}
    </span>
  )
}

function RotationsCell({ row }: { row: ServiceAccountReportRow }) {
  const rot = row.rotations
  if (rot.total === 0) return <span className="text-text-faint">—</span>
  return (
    <span className="inline-flex flex-col gap-0.5">
      <span className="text-text-dim" title="Total rotations recorded in the archive, by outcome">{rotationSummaryLine(rot)}</span>
      <span className="text-xs text-text-faint">last {formatDateTime(rot.last_at)}</span>
      <AuditHistoryCell entries={rot.recent} renderEntry={entry => <RotationEntry entry={entry} />} />
    </span>
  )
}

function AccountsTable({
  results,
  selectedId,
  onSelect,
}: {
  results: { item: ServiceAccountReportRow; matches: { key: string; indices: [number, number][] }[] }[]
  selectedId: string | null
  onSelect: (row: ServiceAccountReportRow) => void
}) {
  return (
    <div className="card p-0 overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-xs text-text-faint border-b border-border">
            <th className="px-3 py-1.5 font-medium">Account</th>
            <th className="px-3 py-1.5 font-medium">Type</th>
            <th className="px-3 py-1.5 font-medium">Status</th>
            <th className="px-3 py-1.5 font-medium">Created</th>
            <th className="px-3 py-1.5 font-medium">Assigned / Updated</th>
            <th className="px-3 py-1.5 font-medium">Retrieved</th>
            <th className="px-3 py-1.5 font-medium">Checked out</th>
            <th className="px-3 py-1.5 font-medium">Rotations</th>
            <th className="px-3 py-1.5 font-medium">Deleted</th>
          </tr>
        </thead>
        <tbody>
          {results.map(({ item: row, matches }) => {
            const nameMatch = matches.find(m => m.key === 'name')
            return (
              <tr
                key={row.id}
                onClick={() => onSelect(row)}
                title="Show this account's archived events (date range and filters apply)"
                className={`border-b border-border/50 align-top cursor-pointer hover:bg-bg-hover ${row.id === selectedId ? 'bg-accent-dim/40' : ''}`}
              >
                <td className="px-3 py-1.5">
                  <div className="text-text-dim"><HighlightedText text={row.name || row.id} indices={nameMatch?.indices} /></div>
                  {serviceAccountIdentityLine(row) && <div className="text-xs text-text-faint">{serviceAccountIdentityLine(row)}</div>}
                  <div className="text-xs text-text-faint">
                    {serviceAccountScopeLine(row) || <span title="No longer in the live roster -- its project is not knowable from the archive">— (not in live roster)</span>}
                  </div>
                  {/* Informational only: a freshly registered SaaS account can
                      legitimately sit NOT_SYNCED (see docs/api-notes.md), so
                      sync state is shown as context, never as a finding. */}
                  {(row.sync_status || row.last_password_change_at) && (
                    <div className="text-[0.6875rem] text-text-faint" title="Informational: OPA's live sync state for this account, not a compliance finding">
                      {row.sync_status && <>sync {row.sync_status.toLowerCase()}</>}
                      {row.sync_status && row.last_password_change_at && ' · '}
                      {row.last_password_change_at && <>password changed {formatDateTime(row.last_password_change_at)}</>}
                    </div>
                  )}
                </td>
                <td className="px-3 py-1.5 text-text-dim whitespace-nowrap">{SERVICE_ACCOUNT_KIND_LABEL[row.kind]}</td>
                <td className="px-3 py-1.5">
                  <StatusBadge label={statusLabel(row.status, UNKNOWN_HINT)} variant={statusVariant(row.status)} />
                </td>
                <td className="px-3 py-1.5"><AuditCell entry={row.created} /></td>
                <td className="px-3 py-1.5">
                  <AuditHistoryCell entries={[...row.assigned, ...row.updated].sort((a, b) => (b.at ?? '').localeCompare(a.at ?? ''))} />
                </td>
                <td className="px-3 py-1.5"><AuditHistoryCell entries={row.reveals} /></td>
                <td className="px-3 py-1.5">
                  <AuditHistoryCell entries={row.checkouts} renderEntry={entry => <CheckoutEntry entry={entry} />} />
                </td>
                <td className="px-3 py-1.5"><RotationsCell row={row} /></td>
                <td className="px-3 py-1.5"><AuditCell entry={row.deleted} /></td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

export function ServiceAccountsDashboard() {
  const { data: environments } = useEnvironments()
  const activeEnv = environments?.active ?? undefined
  const { data: report, isLoading, isError, error, refetch, isFetching } = useServiceAccountsReport(activeEnv)
  const [filters, setFilters] = useState<ServiceAccountFilters>(DEFAULT_SERVICE_ACCOUNT_FILTERS)
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState<{ id: string; label: string } | null>(null)

  const allRows = useMemo(() => report?.accounts ?? [], [report])
  const structuredRows = useMemo(() => filterServiceAccountRows(allRows, filters), [allRows, filters])
  // The fuzzy search is the LAST filter, applied here (not inside the
  // table) so the summary tiles and the export agree with exactly what
  // the table shows.
  const results = useFuzzyFilter(structuredRows, query, FUZZY_KEYS)
  const visibleRows = useMemo(() => results.map(r => r.item), [results])
  const summary = useMemo(() => summarizeServiceAccounts(visibleRows), [visibleRows])
  const exportSections = useMemo(() => serviceAccountsReportExportSections(visibleRows), [visibleRows])
  const options = useMemo(() => serviceAccountFilterOptions(allRows, filters.resourceGroupId), [allRows, filters.resourceGroupId])
  const resourceGroupOptions = useMemo(() => [{ value: ALL, label: 'All resource groups' }, ...options.resourceGroups], [options.resourceGroups])
  const projectOptions = useMemo(() => [{ value: ALL, label: 'All projects' }, ...options.projects], [options.projects])
  const hiddenByScope = useMemo(() => countHiddenByScope(allRows, filters), [allRows, filters])

  const errorBody = (error as (Error & { body?: ApiErrorBody & { reason?: string } }) | undefined)?.body
  const notSynced = isError && errorBody?.reason === 'not_synced'
  const noEnvironment = isError && !!errorBody?.error?.includes('No active environment')

  const setFilter = <K extends keyof ServiceAccountFilters>(key: K, value: ServiceAccountFilters[K]) => {
    setSelected(null)
    setFilters(prev => {
      const next = { ...prev, [key]: value }
      // A project belongs to one resource group -- changing the group
      // resets the project so a stale (out-of-scope) project can't hide
      // every row.
      if (key === 'resourceGroupId') next.projectId = ALL
      return next
    })
  }

  const setSearch = (value: string) => {
    setSelected(null) // the selected row may no longer be on screen
    setQuery(value)
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="card p-3 flex flex-wrap items-end justify-between gap-4">
        <div className="flex flex-wrap items-end gap-4">
          <div className="flex flex-col gap-1">
            <span className="section-label">Type</span>
            <Select value={filters.kind} onValueChange={v => setFilter('kind', v as typeof ALL | ServiceAccountKind)} placeholder="Type" options={KIND_OPTIONS} />
          </div>
          <div className="flex flex-col gap-1">
            <span className="section-label">Status</span>
            <Select value={filters.status} onValueChange={v => setFilter('status', v as typeof ALL | SecretsAccessStatus)} placeholder="Status" options={STATUS_OPTIONS} />
          </div>
          <div className="flex flex-col gap-1">
            <span className="section-label">Resource group</span>
            <Select
              value={filters.resourceGroupId}
              onValueChange={v => setFilter('resourceGroupId', v)}
              placeholder="Resource group"
              disabled={!report}
              options={resourceGroupOptions}
            />
          </div>
          <div className="flex flex-col gap-1">
            <span className="section-label">Project</span>
            <Select
              value={filters.projectId}
              onValueChange={v => setFilter('projectId', v)}
              placeholder="Project"
              disabled={!report}
              options={projectOptions}
            />
          </div>
          <div className="flex flex-col gap-1">
            <span className="section-label">Search</span>
            <div className="relative">
              <Search size={13} className="absolute left-2 top-1/2 -translate-y-1/2 text-text-faint" />
              <input
                type="text"
                value={query}
                onChange={e => setSearch(e.target.value)}
                placeholder="Name, username, app, project…"
                className="text-input pl-7 min-w-56"
              />
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            className="btn-secondary"
            disabled={isFetching}
            onClick={() => refetch()}
            title="Re-walk every resource group/project for the live roster and re-read the archive"
          >
            <RefreshCw size={13} className={isFetching ? 'animate-spin' : ''} /> Refresh
          </button>
          <ExportButtons sections={exportSections} filenameBase="opa-service-accounts" />
        </div>
      </div>

      {isLoading && (
        <span className="text-sm text-text-faint">
          Walking every resource group and project for SaaS and Okta service accounts, then merging the archive… (a large
          tenant with many projects can take a while — this is one call per project per account type)
        </span>
      )}

      {notSynced && (
        <div className="card p-3 text-sm text-loss">
          This environment has not completed a compliance sync yet. Run <span className="font-medium">Sync now</span> in the
          footer first — the Service Accounts report is sourced from the compliance archive, so there is nothing to show
          until one has run.
        </div>
      )}

      {noEnvironment && (
        <div className="card p-3 text-sm text-loss">No active environment configured. Use the Environments control in the sidebar to set one up.</div>
      )}

      {isError && !notSynced && !noEnvironment && (
        <div className="card p-3 text-sm text-loss">Could not load the service accounts report: {(error as Error).message}</div>
      )}

      {report && (
        <>
          {report.truncated && (
            <div className="card p-2.5 text-xs text-loss">
              The archive holds {report.event_total.toLocaleString()} lifecycle / reveal / checkout events for service accounts, but
              only the newest portion fit the server-side load cap — the oldest creates and deletes may be missing, so an
              "unknown" status below may really be older history that was cut off.
            </div>
          )}

          <div className="flex flex-wrap gap-2">
            <SummaryTile label="Accounts" value={summary.total} />
            <SummaryTile label="SaaS app" value={summary.saas} />
            <SummaryTile label="Okta" value={summary.okta} />
            <SummaryTile label="Active" value={summary.active} />
            <SummaryTile label="Deleted" value={summary.deleted} />
            <SummaryTile label="Unknown" value={summary.unknown} />
          </div>

          <p className="text-xs text-text-faint">
            Live roster from {report.walked.projects} project{report.walked.projects === 1 ? '' : 's'} across{' '}
            {report.walked.resource_groups} resource group{report.walked.resource_groups === 1 ? '' : 's'}, merged with locally-preserved
            history back to {formatDateTime(report.oldest_captured_at)} — beyond that (or for anything not yet captured before
            compliance sync was turned on), an account with no history shown may simply predate local capture, not necessarily be
            untouched. "Unknown" means the account is no longer in the live roster and the archive holds no successful delete event
            for it — never inferred. Tiles and export reflect the filters and search above.
            {report.excluded.other_account_types > 0 && (
              <> Database, Active Directory and server accounts ({report.excluded.other_account_types}) share the same event types and
              are deliberately left out of this report — see the Resources tab for their live inventory.</>
            )}
            {report.excluded.unclassified > 0 && (
              <> {report.excluded.unclassified} account id{report.excluded.unclassified === 1 ? '' : 's'} in the archive carried no
              recognisable account-family marker and {report.excluded.unclassified === 1 ? 'was' : 'were'} not guessed into either type.</>
            )}
            {report.warnings.conflicting_family_markers > 0 && (
              <> {report.warnings.conflicting_family_markers} account{report.warnings.conflicting_family_markers === 1 ? '' : 's'} had
              conflicting account-family markers across {report.warnings.conflicting_family_markers === 1 ? 'its' : 'their'} events (the
              live roster's type was used where available; see the server log).</>
            )}
            {hiddenByScope > 0 && (
              <> {hiddenByScope} account{hiddenByScope === 1 ? '' : 's'} no longer in the live roster {hiddenByScope === 1 ? 'is' : 'are'} hidden
              by the resource group / project filter — a deleted account's project is not knowable from the archive.</>
            )}
          </p>

          {allRows.length === 0 ? (
            <span className="text-xs text-text-faint">No SaaS app or Okta service accounts found in the live roster or the archive.</span>
          ) : structuredRows.length === 0 ? (
            <span className="text-xs text-text-faint">No service accounts match the current filters.</span>
          ) : results.length === 0 ? (
            <span className="text-xs text-text-faint">No service accounts match "{query}".</span>
          ) : (
            <AccountsTable
              results={results}
              selectedId={selected?.id ?? null}
              onSelect={row => setSelected(prev => (prev?.id === row.id ? null : { id: row.id, label: row.name || row.id }))}
            />
          )}

          {selected && (
            <ResourceHistoryPanel
              resourceId={selected.id}
              resourceLabel={selected.label}
              matchByName={false}
              onClose={() => setSelected(null)}
            />
          )}
        </>
      )}
    </div>
  )
}
