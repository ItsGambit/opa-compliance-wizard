import { useEffect, useMemo, useState } from 'react'
import { X } from 'lucide-react'
import type { ComplianceReportRow } from '../types'
import { formatDateTime } from '../utils/format'
import { HighlightedText, useFuzzyFilter } from '../utils/fuzzySearch'

// resource_type_detail comes from Okta's own debugContext.debugData.resourceType
// (confirmed live 2026-09-30 -- real values seen: PAM_DATABASE_ACCOUNT,
// SERVER_ACCOUNT) -- more specific than the generic target-derived
// resource_type (e.g. "Service Account"), which alone can't distinguish a
// database account checkout from a server account checkout. Shown in
// preference to resource_type when present, falling back otherwise.
const RESOURCE_TYPE_DETAIL_LABEL: Record<string, string> = {
  PAM_DATABASE_ACCOUNT: 'Database Account',
  SERVER_ACCOUNT: 'Server Account',
  // confirmed live 2026-09-30 via a real tenant's pam.resource.checkout
  // event for a Salesforce account -- not seen during initial probing,
  // found via this session's own Playwright verification pass instead.
  MANAGED_SAAS_APP_SERVICE_ACCOUNT: 'SaaS Service Account',
  // confirmed live 2026-10-01 against a 50-event real sample of
  // user.authentication.auth_via_mfa (see audit_store._resource_fields):
  // the real `factor` values seen were SIGNED_NONCE (36), OKTA_VERIFY_PUSH
  // (13), PASSWORD_AS_FACTOR (1), and one lowercase `signed_nonce` (1) --
  // Okta's own data is case-inconsistent for the same factor, so both
  // cases are mapped to the same label rather than showing two distinct
  // rows for what's really one factor type.
  SIGNED_NONCE: 'Okta Verify (FastPass)',
  signed_nonce: 'Okta Verify (FastPass)',
  OKTA_VERIFY_PUSH: 'Okta Verify (Push)',
  PASSWORD_AS_FACTOR: 'Password',
}

function resourceTypeLabel(row: { resource_type: string; resource_type_detail: string }): string {
  if (row.resource_type_detail) {
    return RESOURCE_TYPE_DETAIL_LABEL[row.resource_type_detail] ?? row.resource_type_detail
  }
  return row.resource_type
}

// Email + Okta resource ID, shown together under the resource's display
// name -- a display name alone isn't a unique identifier (two real users/
// resources in the same tenant can share one), which matters most for
// exactly the reports where "prove who was specifically affected" is the
// point (Provisioning & De-provisioning, Role/Group Changes, Admin
// Privilege Grants). "unknown" is a real Okta-emitted placeholder value
// (e.g. on a UserGroup target), not a real identifier -- excluded.
function resourceIdentifierLine(row: { resource: string; resource_id: string; resource_alternate_id: string }): string {
  const parts: string[] = []
  if (row.resource_alternate_id && row.resource_alternate_id !== 'unknown' && row.resource_alternate_id !== row.resource) {
    parts.push(row.resource_alternate_id)
  }
  // Many resource types have no separate "alternate id"/email at all -- the
  // API just repeats the same id in both fields (confirmed live 2026-09-30,
  // e.g. a Service Account target) -- showing it twice is noise, not a real
  // second identifier, so it's only added here when actually distinct.
  if (row.resource_id && row.resource_id !== row.resource_alternate_id) parts.push(row.resource_id)
  return parts.join(' · ')
}

// "Who did this and from where" together -- client IP/location from
// Okta's own client.ipAddress/geographicalContext (see audit_store.py's
// _four_field_row). Empty for most non-auth event types (e.g. a
// system-triggered PAM credential rotation has no originating client at
// all) -- omitted entirely rather than shown as an empty "from: " line.
function clientLocationLine(row: { client_ip: string; client_geo: string }): string {
  const parts: string[] = []
  if (row.client_ip) parts.push(row.client_ip)
  if (row.client_geo) parts.push(row.client_geo)
  return parts.join(' · ')
}

function outcomeVariant(outcome: string): string {
  const o = outcome.toUpperCase()
  if (o === 'SUCCESS' || o === 'ALLOW') return 'bg-win/10 text-win'
  if (o === 'DENY' || o === 'FAILURE') return 'bg-loss/10 text-loss'
  return 'bg-warn/10 text-warn'
}

interface Props {
  rows: ComplianceReportRow[]
  isLoading: boolean
  emptyMessage: string
  /** Lets a caller (e.g. ComplianceReportDetail) read the currently
   * filtered set back out, e.g. for ExportButtons -- "export what's on
   * screen", same convention this table already established. */
  onFilteredRowsChange?: (rows: ComplianceReportRow[]) => void
  /** UI-03/DATA-07 (external review, 2026-10-05): the real, uncapped
   * count for the current filters (ComplianceReportResponse/
   * ResourceHistoryResponse's own `total`) and whether `rows` is a
   * partial result (`truncated`). Both callers of this table pass these
   * straight through from the API response -- a report/history view used
   * to present a server-side-capped `rows` as if it were the complete
   * evidence window, with nothing on screen saying otherwise. Omit both
   * (or pass truncated=false) when the caller has no such concept. */
  total?: number
  truncated?: boolean
}

/** The filterable report-rows table -- extracted out of
 * ComplianceReportDetail (2026-09-30) so the Resources tab's per-resource
 * history drill-down can render the exact same table/filter/highlight
 * behavior against a DIFFERENT data source (resource_history instead of
 * run_report) without duplicating this whole block. Owns its own filter
 * state internally (User/Action/Affected-Resource fuzzy text filters +
 * Outcome dropdown, same as before this extraction) -- callers only see
 * the rendered table plus, optionally, the filtered rows via
 * onFilteredRowsChange. */
export function ReportRowsTable({ rows, isLoading, emptyMessage, onFilteredRowsChange, total, truncated }: Props) {
  const [userFilter, setUserFilter] = useState('')
  const [actionFilter, setActionFilter] = useState('')
  const [resourceFilter, setResourceFilter] = useState('')
  const [outcomeFilter, setOutcomeFilter] = useState('')

  const outcomeOptions = useMemo(
    () => [...new Set(rows.map(r => r.outcome).filter(Boolean))].sort(),
    [rows]
  )

  // Three independent fuzzy passes over the FULL row set (not progressively
  // narrowed) -- each column's filter is its own question ("does this row's
  // user match?"), so the three results are intersected by uuid below
  // rather than one filter narrowing what the next one can even see. A
  // blank query short-circuits to "every row, no matches" (see
  // useFuzzyFilter), so an unused filter box is a true no-op here.
  const userResults = useFuzzyFilter(rows, userFilter, ['user', 'actor_alternate_id'])
  const actionResults = useFuzzyFilter(rows, actionFilter, ['action'])
  const resourceResults = useFuzzyFilter(rows, resourceFilter, ['resource', 'resource_alternate_id', 'resource_id'])

  const userMatchByUuid = useMemo(() => new Map(userResults.map(r => [r.item.uuid, r.matches])), [userResults])
  const actionMatchByUuid = useMemo(() => new Map(actionResults.map(r => [r.item.uuid, r.matches])), [actionResults])
  const resourceMatchByUuid = useMemo(() => new Map(resourceResults.map(r => [r.item.uuid, r.matches])), [resourceResults])

  const filteredRows = useMemo(() => {
    const userUuids = new Set(userResults.map(r => r.item.uuid))
    const actionUuids = new Set(actionResults.map(r => r.item.uuid))
    const resourceUuids = new Set(resourceResults.map(r => r.item.uuid))
    return rows.filter((row: ComplianceReportRow) => {
      if (!userUuids.has(row.uuid)) return false
      if (!actionUuids.has(row.uuid)) return false
      if (!resourceUuids.has(row.uuid)) return false
      if (outcomeFilter && row.outcome !== outcomeFilter) return false
      return true
    })
  }, [rows, userResults, actionResults, resourceResults, outcomeFilter])

  // Reported back up to the caller (e.g. ComplianceReportDetail's
  // ExportButtons) in an effect, not inline during the render above --
  // calling a parent's setState mid-render is a React anti-pattern (it
  // works today but isn't a supported pattern going forward).
  useEffect(() => {
    onFilteredRowsChange?.(filteredRows)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filteredRows])

  const hasActiveFilter = !!(userFilter || actionFilter || resourceFilter || outcomeFilter)
  const clearFilters = () => {
    setUserFilter('')
    setActionFilter('')
    setResourceFilter('')
    setOutcomeFilter('')
  }

  return (
    <div className="card p-0 overflow-x-auto">
      {truncated && !isLoading && (
        <div className="px-3 py-2 text-[0.6875rem] text-warn bg-warn/10 border-b border-border">
          Showing the newest {rows.length.toLocaleString()} of {(total ?? rows.length).toLocaleString()} events in
          this date range. Narrow the date range or export in smaller windows to see the rest.
        </div>
      )}
      {isLoading ? (
        <div className="p-4 text-sm text-text-faint">Loading…</div>
      ) : rows.length === 0 ? (
        <div className="p-4 text-sm text-text-faint">{emptyMessage}</div>
      ) : (
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-border">
              <th className="text-left font-semibold text-text-faint uppercase text-[0.625rem] tracking-wide px-3 py-2">User</th>
              <th className="text-left font-semibold text-text-faint uppercase text-[0.625rem] tracking-wide px-3 py-2">Action</th>
              <th className="text-left font-semibold text-text-faint uppercase text-[0.625rem] tracking-wide px-3 py-2">Timestamp</th>
              <th className="text-left font-semibold text-text-faint uppercase text-[0.625rem] tracking-wide px-3 py-2">Affected Resource</th>
              <th className="text-left font-semibold text-text-faint uppercase text-[0.625rem] tracking-wide px-3 py-2">
                <div className="flex items-center justify-between gap-2">
                  Outcome
                  {hasActiveFilter && (
                    <button
                      type="button"
                      onClick={clearFilters}
                      title="Clear all filters"
                      className="text-text-faint hover:text-text-dim normal-case font-normal"
                    >
                      <X size={11} />
                    </button>
                  )}
                </div>
              </th>
            </tr>
            <tr className="border-b border-border bg-bg-hover/50">
              <th className="px-3 py-1.5">
                <input
                  type="text" placeholder="Filter…" value={userFilter} onChange={e => setUserFilter(e.target.value)}
                  className="text-input w-full !py-1 text-[0.6875rem] font-normal normal-case"
                />
              </th>
              <th className="px-3 py-1.5">
                <input
                  type="text" placeholder="Filter…" value={actionFilter} onChange={e => setActionFilter(e.target.value)}
                  className="text-input w-full !py-1 text-[0.6875rem] font-normal normal-case"
                />
              </th>
              <th className="px-3 py-1.5" />
              <th className="px-3 py-1.5">
                <input
                  type="text" placeholder="Filter…" value={resourceFilter} onChange={e => setResourceFilter(e.target.value)}
                  className="text-input w-full !py-1 text-[0.6875rem] font-normal normal-case"
                />
              </th>
              <th className="px-3 py-1.5">
                <select
                  value={outcomeFilter} onChange={e => setOutcomeFilter(e.target.value)}
                  className="text-input w-full !py-1 text-[0.6875rem] font-normal normal-case"
                >
                  <option value="">All</option>
                  {outcomeOptions.map(o => (
                    <option key={o} value={o}>{o}</option>
                  ))}
                </select>
              </th>
            </tr>
          </thead>
          <tbody>
            {filteredRows.length === 0 && (
              <tr>
                <td colSpan={5} className="px-3 py-4 text-center text-text-faint">
                  No rows match the current filters.
                </td>
              </tr>
            )}
            {filteredRows.map(row => {
              const userMatches = userMatchByUuid.get(row.uuid) ?? []
              const actionMatches = actionMatchByUuid.get(row.uuid) ?? []
              const resourceMatches = resourceMatchByUuid.get(row.uuid) ?? []
              const userMatch = userMatches.find(m => m.key === 'user')
              const altIdMatch = userMatches.find(m => m.key === 'actor_alternate_id')
              const actionMatch = actionMatches.find(m => m.key === 'action')
              const resourceMatch = resourceMatches.find(m => m.key === 'resource')
              return (
                <tr key={row.uuid} className="border-b border-border-sub hover:bg-bg-hover">
                  <td className="px-3 py-2 text-text-dim">
                    <HighlightedText text={row.user} indices={userMatch?.indices} />
                    {row.actor_alternate_id && row.actor_alternate_id !== row.user && (
                      <div className="text-text-faint text-[0.6875rem]">
                        <HighlightedText text={row.actor_alternate_id} indices={altIdMatch?.indices} />
                      </div>
                    )}
                    {clientLocationLine(row) && (
                      <div className="text-text-faint text-[0.6875rem]" title="Client IP / location">
                        {clientLocationLine(row)}
                      </div>
                    )}
                  </td>
                  <td className="px-3 py-2 text-text-dim">
                    <HighlightedText text={row.action} indices={actionMatch?.indices} />
                  </td>
                  <td className="px-3 py-2 text-text-faint whitespace-nowrap">
                    {formatDateTime(row.timestamp)}
                    {row.request_id && (
                      <div className="text-[0.6875rem]" title="Okta request/transaction ID">
                        <code className="text-[0.625rem]">{row.request_id}</code>
                      </div>
                    )}
                  </td>
                  <td className="px-3 py-2 text-text-dim">
                    {row.resource ? <HighlightedText text={row.resource} indices={resourceMatch?.indices} /> : <span className="text-text-faint">—</span>}
                    {resourceTypeLabel(row) && <span className="text-text-faint text-[0.6875rem]"> ({resourceTypeLabel(row)})</span>}
                    {/* Display name alone isn't a unique identifier -- two people/resources can share
                        one. Email + Okta ID disambiguate; "unknown" is a real Okta-emitted placeholder
                        value (e.g. on a UserGroup target), not a real identifier, so it's excluded
                        rather than shown as if it were. */}
                    {(resourceIdentifierLine(row)) && (
                      <div className="text-text-faint text-[0.6875rem]" title="Email / Okta resource ID">
                        {resourceIdentifierLine(row)}
                      </div>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    {row.outcome ? (
                      <span className={`inline-block px-1.5 py-0.5 rounded text-[0.6875rem] font-medium ${outcomeVariant(row.outcome)}`}>
                        {row.outcome}
                      </span>
                    ) : (
                      <span className="text-text-faint">—</span>
                    )}
                    {row.outcome_reason && (
                      <div className="text-text-faint text-[0.6875rem]" title="Why">
                        {row.outcome_reason}
                      </div>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      )}
    </div>
  )
}
