import { useEffect, useMemo, useState } from 'react'
import { Search } from 'lucide-react'
import { useEnvironments, useResourceHistory } from '../api/hooks'
import type {
  AccessActiveDirectoryAccount,
  AccessActiveDirectoryConnection,
  AccessDatabaseAccount,
  AccessDatabaseConnection,
  AccessGateway,
  AccessModel,
  AccessOktaAccount,
  AccessSaasAccount,
  AccessSaasAppConnection,
  AccessServer,
  AccessWorkloadConnection,
  AccessWorkloadRole,
} from '../types'
import type { ExportSection } from '../utils/export'
import { complianceReportExportSections } from '../utils/exportSections'
import { HighlightedText, useFuzzyFilter } from '../utils/fuzzySearch'
import { ExportButtons } from './ExportButtons'
import { ReportRowsTable } from './ReportRowsTable'
import { Select } from './Select'

// Every kind here is live-verified (2026-09-30) against a real tenant --
// see the "splendid-floating-moth" plan for the exact API paths. Windows/
// Linux/Gateway-as-server are three VIEWS over the same servers[] list
// (split client-side below), not three separate API calls -- a gateway
// server is identified by hostname matching a real Gateway resource's
// name (see gatewayHostnames below; EVERY OPA-managed server has
// "broker" in services[], confirmed live, so that field can't
// distinguish a gateway from a regular server -- an earlier version of
// this file wrongly assumed it could). The standalone "Gateways" kind
// further down is the actual gateway CONFIG resource (access_address/
// infrastructure_orchestrator), a different thing from the server
// object hosting it.
const RESOURCE_KINDS = [
  { value: 'windows_servers', label: 'Windows Servers' },
  { value: 'linux_servers', label: 'Linux Servers' },
  { value: 'gateway_servers', label: 'Gateway Servers' },
  { value: 'okta_accounts', label: 'Okta Service Accounts' },
  { value: 'saas_accounts', label: 'SaaS Service Accounts' },
  { value: 'active_directory_accounts', label: 'Active Directory Accounts' },
  { value: 'database_accounts', label: 'Database Accounts' },
  { value: 'workload_roles', label: 'Workload Roles' },
  { value: 'workload_connections', label: 'Workload Connections' },
  { value: 'gateways', label: 'Gateways' },
  { value: 'database_connections', label: 'Database Connections' },
  { value: 'saas_app_connections', label: 'SaaS App Connections' },
  { value: 'active_directory_connections', label: 'Active Directory Connections' },
]

interface Props {
  model: AccessModel
}

/** One resource row -- `id` is the real resource id (the join key back
 * into compliance report rows, see audit_store.resource_history), `label`
 * is what's shown in the drill-down panel's header once clicked, `cells`
 * are the display columns, and `exportRow` is the flat record ExportButtons
 * wants. Not every kind has a stable, joinable id (the "connections" family
 * are integration configs this session confirmed have no compliance-report
 * target of their own -- see the plan's real-events sample -- so those
 * rows render but aren't clickable, `id` is null). */
interface ResourceRow {
  id: string | null
  label: string
  cells: (string | number)[]
  exportRow: Record<string, string>
}

function buildRows(kind: string, model: AccessModel, windowsServers: AccessServer[], linuxServers: AccessServer[], gatewayServers: AccessServer[]):
  { headers: string[]; rows: ResourceRow[] } {
  switch (kind) {
    case 'windows_servers':
    case 'linux_servers':
    case 'gateway_servers': {
      const list: AccessServer[] = kind === 'windows_servers' ? windowsServers : kind === 'linux_servers' ? linuxServers : gatewayServers
      return {
        headers: ['Hostname', 'OS', 'Access Address', 'State', 'Resource Group', 'Project'],
        rows: list.map(s => ({
          id: s.id,
          label: s.hostname,
          cells: [s.hostname, s.os, s.access_address ?? '', s.state, s.resource_group_name, s.project_name],
          exportRow: {
            Hostname: s.hostname, OS: s.os, 'Access Address': s.access_address ?? '',
            State: s.state, 'Resource Group': s.resource_group_name, Project: s.project_name,
          },
        })),
      }
    }
    case 'okta_accounts': {
      // Real bug fixed 2026-09-30: this used to read a.account_name,
      // which doesn't exist on the real API object -- confirmed live the
      // real fields are `name` (human label, e.g. "McKinsey Okta SA") and
      // `username` (the login identity, e.g. "mcksa@atko.email"), so
      // every row was silently falling through to the raw id.
      const list: AccessOktaAccount[] = model.okta_accounts
      return {
        headers: ['Account', 'Username', 'Resource Group', 'Project'],
        rows: list.map(a => {
          const label = String(a.name ?? a.username ?? a.id)
          return {
            id: a.id,
            label,
            cells: [label, a.username ?? '', a.resource_group_name, a.project_name],
            exportRow: { Account: label, Username: a.username ?? '', 'Resource Group': a.resource_group_name, Project: a.project_name },
          }
        }),
      }
    }
    case 'saas_accounts': {
      // Same real bug/fix as okta_accounts above -- same field names confirmed live.
      const list: AccessSaasAccount[] = model.saas_accounts
      return {
        headers: ['Account', 'Username', 'Resource Group', 'Project'],
        rows: list.map(a => {
          const label = String(a.name ?? a.username ?? a.id)
          return {
            id: a.id,
            label,
            cells: [label, a.username ?? '', a.resource_group_name, a.project_name],
            exportRow: { Account: label, Username: a.username ?? '', 'Resource Group': a.resource_group_name, Project: a.project_name },
          }
        }),
      }
    }
    case 'active_directory_accounts': {
      const list: AccessActiveDirectoryAccount[] = model.active_directory_accounts
      return {
        headers: ['Account', 'Domain', 'Status', 'Resource Group', 'Project'],
        rows: list.map(a => ({
          id: a.id,
          label: a.account_name,
          cells: [a.account_name, a.domain?.name ?? '', a.account_status_detail ?? '', a.resource_group_name, a.project_name],
          exportRow: {
            Account: a.account_name, Domain: a.domain?.name ?? '', Status: a.account_status_detail ?? '',
            'Resource Group': a.resource_group_name, Project: a.project_name,
          },
        })),
      }
    }
    case 'database_accounts': {
      const list: AccessDatabaseAccount[] = model.database_accounts
      return {
        headers: ['Account', 'DB Connection', 'Status', 'Resource Group', 'Project'],
        rows: list.map(a => ({
          id: a.id,
          label: a.account_name,
          cells: [a.account_name, a.database_connection?.name ?? '', a.account_status_detail ?? '', a.resource_group_name, a.project_name],
          exportRow: {
            Account: a.account_name, 'DB Connection': a.database_connection?.name ?? '', Status: a.account_status_detail ?? '',
            'Resource Group': a.resource_group_name, Project: a.project_name,
          },
        })),
      }
    }
    case 'workload_roles': {
      const list: AccessWorkloadRole[] = model.workload_roles
      return {
        headers: ['Name', 'Description', 'Linux Username'],
        rows: list.map(r => ({
          id: r.id,
          label: r.name,
          cells: [r.name, r.description ?? '', r.linux_server_username ?? ''],
          exportRow: { Name: r.name, Description: r.description ?? '', 'Linux Username': r.linux_server_username ?? '' },
        })),
      }
    }
    case 'workload_connections': {
      const list: AccessWorkloadConnection[] = model.workload_connections
      return {
        headers: ['Name', 'Type', 'Status'],
        rows: list.map(c => ({
          id: c.id,
          label: c.name,
          cells: [c.name, c.type, c.status ?? ''],
          exportRow: { Name: c.name, Type: c.type, Status: c.status ?? '' },
        })),
      }
    }
    case 'gateways': {
      const list: AccessGateway[] = model.gateways
      return {
        headers: ['Name', 'Access Address', 'Cloud Provider', 'Last Seen'],
        rows: list.map(g => ({
          id: g.id,
          label: g.name,
          cells: [g.name, g.access_address ?? '', g.cloud_provider ?? '', g.last_seen ?? ''],
          exportRow: {
            Name: g.name, 'Access Address': g.access_address ?? '', 'Cloud Provider': g.cloud_provider ?? '', 'Last Seen': g.last_seen ?? '',
          },
        })),
      }
    }
    case 'database_connections': {
      const list: AccessDatabaseConnection[] = model.database_connections
      return {
        headers: ['Name', 'Auth Type', 'Status', 'Discovered Accounts'],
        // Confirmed live 2026-09-30 (see the plan's real-events sample):
        // this session found no compliance-report target that resolves to
        // a database CONNECTION's own id (only the accounts discovered
        // through it show up as report targets) -- id is null, so these
        // rows render but aren't clickable into a history drill-down.
        rows: list.map(c => ({
          id: null,
          label: c.name,
          cells: [c.name, c.auth_type ?? '', c.status ?? '', c.discovered_accounts_count ?? ''],
          exportRow: {
            Name: c.name, 'Auth Type': c.auth_type ?? '', Status: c.status ?? '',
            'Discovered Accounts': String(c.discovered_accounts_count ?? ''),
          },
        })),
      }
    }
    case 'saas_app_connections': {
      const list: AccessSaasAppConnection[] = model.saas_app_connections
      return {
        headers: ['App', 'Global App Name'],
        rows: list.map(c => ({
          id: null, // same reasoning as database_connections above
          label: c.app_instance_name,
          cells: [c.app_instance_name, c.global_app_name ?? ''],
          exportRow: { App: c.app_instance_name, 'Global App Name': c.global_app_name ?? '' },
        })),
      }
    }
    case 'active_directory_connections': {
      const list: AccessActiveDirectoryConnection[] = model.active_directory_connections
      return {
        headers: ['Domain', 'Status'],
        rows: list.map(c => ({
          id: c.id,
          label: c.domain,
          cells: [c.domain, c.status ?? ''],
          exportRow: { Domain: c.domain, Status: c.status ?? '' },
        })),
      }
    }
    default:
      return { headers: [], rows: [] }
  }
}

function ResourceTable({
  headers,
  rows,
  query,
  selectedId,
  onSelect,
}: {
  headers: string[]
  rows: ResourceRow[]
  query: string
  selectedId: string | null
  onSelect: (row: ResourceRow) => void
}) {
  const results = useFuzzyFilter(rows, query, ['label', 'cells'])

  if (rows.length === 0) {
    return <span className="text-xs text-text-faint">No resources of this kind found.</span>
  }
  if (results.length === 0) {
    return <span className="text-xs text-text-faint">No resources match "{query}".</span>
  }
  return (
    <div className="card p-0 overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-border">
            {headers.map(h => (
              <th key={h} className="text-left font-semibold text-text-faint uppercase text-[0.625rem] tracking-wide px-3 py-2 whitespace-nowrap">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {results.map(({ item: row, matches }, i) => {
            const labelMatch = matches.find(m => m.key === 'label')
            const clickable = row.id !== null
            return (
              <tr
                key={row.id ?? i}
                onClick={clickable ? () => onSelect(row) : undefined}
                title={clickable ? 'View access history for this resource' : 'No compliance-report history available for this resource kind'}
                className={`border-b border-border-sub hover:bg-bg-hover ${clickable ? 'cursor-pointer' : ''} ${
                  row.id === selectedId ? 'bg-accent-dim/40' : ''
                }`}
              >
                {row.cells.map((cell, j) => (
                  <td key={j} className="px-3 py-2 text-text-dim whitespace-nowrap">
                    {cell === '' || cell == null ? (
                      <span className="text-text-faint">—</span>
                    ) : j === 0 ? (
                      <HighlightedText text={String(cell)} indices={labelMatch?.indices} />
                    ) : (
                      cell
                    )}
                  </td>
                ))}
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

/** The per-resource compliance-report history drill-down -- clicking a row
 * above shows every report row (across EVERY report, not one) where this
 * resource appears as ANY target on the event, matched by id AND/OR its
 * exact display name (resourceLabel, passed through as resourceName --
 * needed for database/AD accounts, which have no log-side id at all --
 * see audit_store.resource_history's docstring for the full live-verified
 * explanation). */
function ResourceHistoryPanel({ resourceId, resourceLabel, onClose }: { resourceId: string; resourceLabel: string; onClose: () => void }) {
  const { data: environments } = useEnvironments()
  const activeEnv = environments?.active
  const today = new Date().toISOString().slice(0, 10)
  const ninetyDaysAgo = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10)
  const [from, setFrom] = useState(ninetyDaysAgo)
  const [to, setTo] = useState(today)

  // No per-view Refresh here -- every resource's history reads the SAME
  // shared audit_store.db archive as every ordinary report, so pulling
  // fresh Okta data is one global action (the Footer's "Sync now"), not
  // something duplicated per screen. This query auto-refetches when that
  // global sync completes, via queryClient.invalidateQueries on the
  // ['resource_history'] key prefix (see Footer.tsx).
  const { data, isLoading } = useResourceHistory(resourceId, activeEnv, from, to, resourceLabel)
  const rows = data?.rows ?? []
  const [filteredRows, setFilteredRows] = useState(rows)

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-text">Access history — {resourceLabel}</h3>
        <div className="flex items-center gap-2">
          <ExportButtons
            sections={complianceReportExportSections(`History: ${resourceLabel}`, filteredRows)}
            filenameBase={`opa-resource-history-${resourceLabel}`}
          />
          <button type="button" className="btn-secondary text-xs" onClick={onClose}>
            Close
          </button>
        </div>
      </div>

      <div className="card p-3 flex items-end gap-3">
        <div className="field">
          <label className="section-label block mb-1">From</label>
          <input type="date" className="text-input" value={from} onChange={e => setFrom(e.target.value)} />
        </div>
        <div className="field">
          <label className="section-label block mb-1">To</label>
          <input type="date" className="text-input" value={to} onChange={e => setTo(e.target.value)} />
        </div>
      </div>

      <ReportRowsTable
        rows={rows}
        isLoading={isLoading}
        emptyMessage="No compliance-report activity found for this resource in this date range."
        onFilteredRowsChange={setFilteredRows}
      />
    </div>
  )
}

export function ResourcesTab({ model }: Props) {
  const [kind, setKind] = useState(RESOURCE_KINDS[0].value)
  const [query, setQuery] = useState('')
  // { id, label } rather than a bare string -- this is the seam for the
  // user's stated future request ("ability to select more than one
  // resource... feature request later"): swapping this to an array and
  // rendering N history panels is a follow-up, not built now, but this
  // shape doesn't need re-architecting to get there.
  const [selected, setSelected] = useState<{ id: string; label: string } | null>(null)

  // Changing kind (or the search query narrowing away the selected row)
  // clears the open history panel -- it was scoped to a resource that may
  // no longer even be visible.
  useEffect(() => {
    setSelected(null)
  }, [kind])

  // Real bug found and fixed 2026-09-30: EVERY OPA-managed server has
  // "broker" in services[] (confirmed live -- it's the always-present
  // client/connectivity agent, not a gateway-specific marker), so the
  // original "services includes broker" gateway check matched every
  // Linux server, showing zero real Linux servers and every Linux
  // server misfiled as a gateway. The real signal (confirmed live by
  // comparing model.gateways against model.servers) is that a gateway
  // server's hostname exactly matches a real Gateway resource's name --
  // gatewayHostnames below is that set.
  const gatewayHostnames = useMemo(() => new Set(model.gateways.map(g => g.name)), [model.gateways])
  const windowsServers = useMemo(() => model.servers.filter(s => s.os_type === 'windows'), [model.servers])
  const linuxServers = useMemo(
    () => model.servers.filter(s => s.os_type === 'linux' && !gatewayHostnames.has(s.hostname)),
    [model.servers, gatewayHostnames]
  )
  const gatewayServers = useMemo(() => model.servers.filter(s => gatewayHostnames.has(s.hostname)), [model.servers, gatewayHostnames])

  const { headers, rows } = useMemo(
    () => buildRows(kind, model, windowsServers, linuxServers, gatewayServers),
    [kind, model, windowsServers, linuxServers, gatewayServers]
  )

  const kindLabel = RESOURCE_KINDS.find(k => k.value === kind)?.label ?? kind
  const exportSections: ExportSection[] = [{ title: kindLabel, rows: rows.map(r => r.exportRow) }]

  return (
    <div className="flex flex-col gap-4">
      <div className="card p-3 flex flex-wrap items-end justify-between gap-4">
        <div className="flex flex-wrap items-end gap-3">
          <div className="flex flex-col gap-1">
            <span className="section-label">Resource kind</span>
            <Select value={kind} onValueChange={setKind} placeholder="Select a resource kind" options={RESOURCE_KINDS} />
          </div>
          <div className="flex flex-col gap-1">
            <span className="section-label">Search</span>
            <div className="flex items-center gap-1.5 text-input min-w-56">
              <Search size={13} className="text-text-faint shrink-0" />
              <input
                type="text"
                placeholder={`Search ${kindLabel.toLowerCase()}…`}
                value={query}
                onChange={e => setQuery(e.target.value)}
                className="flex-1 bg-transparent outline-none placeholder:text-text-faint"
              />
            </div>
          </div>
        </div>
        <ExportButtons sections={exportSections} filenameBase={`opa-resources-${kind}`} />
      </div>

      <div className="flex items-center justify-between">
        <span className="section-label">{kindLabel} ({rows.length})</span>
      </div>

      <ResourceTable
        headers={headers}
        rows={rows}
        query={query}
        selectedId={selected?.id ?? null}
        onSelect={row => row.id && setSelected({ id: row.id, label: row.label })}
      />

      {selected && (
        <ResourceHistoryPanel resourceId={selected.id} resourceLabel={selected.label} onClose={() => setSelected(null)} />
      )}
    </div>
  )
}
