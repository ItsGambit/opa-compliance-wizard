import { useMemo, useState } from 'react'
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
import { ExportButtons } from './ExportButtons'
import { Select } from './Select'

// Every kind here is live-verified (2026-09-30) against a real tenant --
// see the "splendid-floating-moth" plan for the exact API paths. Windows/
// Linux/Gateway-as-server are three VIEWS over the same servers[] list
// (split client-side below), not three separate API calls -- a gateway is
// a server whose services[] includes "broker"; the standalone
// "Gateways" kind further down is the actual gateway CONFIG resource
// (access_address/infrastructure_orchestrator), a different thing from
// the server object hosting it.
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

function Table({ headers, rows }: { headers: string[]; rows: (string | number)[][] }) {
  if (rows.length === 0) {
    return <span className="text-xs text-text-faint">No resources of this kind found.</span>
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
          {rows.map((row, i) => (
            <tr key={i} className="border-b border-border-sub hover:bg-bg-hover">
              {row.map((cell, j) => (
                <td key={j} className="px-3 py-2 text-text-dim whitespace-nowrap">
                  {cell === '' || cell == null ? <span className="text-text-faint">—</span> : cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function ResourcesTab({ model }: Props) {
  const [kind, setKind] = useState(RESOURCE_KINDS[0].value)

  const windowsServers = useMemo(() => model.servers.filter(s => s.os_type === 'windows'), [model.servers])
  const linuxServers = useMemo(
    () => model.servers.filter(s => s.os_type === 'linux' && !(s.services ?? []).includes('broker')),
    [model.servers]
  )
  const gatewayServers = useMemo(() => model.servers.filter(s => (s.services ?? []).includes('broker')), [model.servers])

  const { headers, rows, exportRows }: { headers: string[]; rows: (string | number)[][]; exportRows: Record<string, string>[] } =
    useMemo(() => {
      switch (kind) {
        case 'windows_servers':
        case 'linux_servers':
        case 'gateway_servers': {
          const list: AccessServer[] =
            kind === 'windows_servers' ? windowsServers : kind === 'linux_servers' ? linuxServers : gatewayServers
          return {
            headers: ['Hostname', 'OS', 'Access Address', 'State', 'Resource Group', 'Project'],
            rows: list.map(s => [s.hostname, s.os, s.access_address ?? '', s.state, s.resource_group_name, s.project_name]),
            exportRows: list.map(s => ({
              Hostname: s.hostname, OS: s.os, 'Access Address': s.access_address ?? '',
              State: s.state, 'Resource Group': s.resource_group_name, Project: s.project_name,
            })),
          }
        }
        case 'okta_accounts': {
          const list: AccessOktaAccount[] = model.okta_accounts
          return {
            headers: ['Account', 'Resource Group', 'Project'],
            rows: list.map(a => [String(a.account_name ?? a.id), a.resource_group_name, a.project_name]),
            exportRows: list.map(a => ({
              Account: String(a.account_name ?? a.id), 'Resource Group': a.resource_group_name, Project: a.project_name,
            })),
          }
        }
        case 'saas_accounts': {
          const list: AccessSaasAccount[] = model.saas_accounts
          return {
            headers: ['Account', 'Resource Group', 'Project'],
            rows: list.map(a => [String(a.account_name ?? a.id), a.resource_group_name, a.project_name]),
            exportRows: list.map(a => ({
              Account: String(a.account_name ?? a.id), 'Resource Group': a.resource_group_name, Project: a.project_name,
            })),
          }
        }
        case 'active_directory_accounts': {
          const list: AccessActiveDirectoryAccount[] = model.active_directory_accounts
          return {
            headers: ['Account', 'Domain', 'Status', 'Resource Group', 'Project'],
            rows: list.map(a => [a.account_name, a.domain?.name ?? '', a.account_status_detail ?? '', a.resource_group_name, a.project_name]),
            exportRows: list.map(a => ({
              Account: a.account_name, Domain: a.domain?.name ?? '', Status: a.account_status_detail ?? '',
              'Resource Group': a.resource_group_name, Project: a.project_name,
            })),
          }
        }
        case 'database_accounts': {
          const list: AccessDatabaseAccount[] = model.database_accounts
          return {
            headers: ['Account', 'DB Connection', 'Status', 'Resource Group', 'Project'],
            rows: list.map(a => [a.account_name, a.database_connection?.name ?? '', a.account_status_detail ?? '', a.resource_group_name, a.project_name]),
            exportRows: list.map(a => ({
              Account: a.account_name, 'DB Connection': a.database_connection?.name ?? '', Status: a.account_status_detail ?? '',
              'Resource Group': a.resource_group_name, Project: a.project_name,
            })),
          }
        }
        case 'workload_roles': {
          const list: AccessWorkloadRole[] = model.workload_roles
          return {
            headers: ['Name', 'Description', 'Linux Username'],
            rows: list.map(r => [r.name, r.description ?? '', r.linux_server_username ?? '']),
            exportRows: list.map(r => ({ Name: r.name, Description: r.description ?? '', 'Linux Username': r.linux_server_username ?? '' })),
          }
        }
        case 'workload_connections': {
          const list: AccessWorkloadConnection[] = model.workload_connections
          return {
            headers: ['Name', 'Type', 'Status'],
            rows: list.map(c => [c.name, c.type, c.status ?? '']),
            exportRows: list.map(c => ({ Name: c.name, Type: c.type, Status: c.status ?? '' })),
          }
        }
        case 'gateways': {
          const list: AccessGateway[] = model.gateways
          return {
            headers: ['Name', 'Access Address', 'Cloud Provider', 'Last Seen'],
            rows: list.map(g => [g.name, g.access_address ?? '', g.cloud_provider ?? '', g.last_seen ?? '']),
            exportRows: list.map(g => ({
              Name: g.name, 'Access Address': g.access_address ?? '', 'Cloud Provider': g.cloud_provider ?? '', 'Last Seen': g.last_seen ?? '',
            })),
          }
        }
        case 'database_connections': {
          const list: AccessDatabaseConnection[] = model.database_connections
          return {
            headers: ['Name', 'Auth Type', 'Status', 'Discovered Accounts'],
            rows: list.map(c => [c.name, c.auth_type ?? '', c.status ?? '', c.discovered_accounts_count ?? '']),
            exportRows: list.map(c => ({
              Name: c.name, 'Auth Type': c.auth_type ?? '', Status: c.status ?? '',
              'Discovered Accounts': String(c.discovered_accounts_count ?? ''),
            })),
          }
        }
        case 'saas_app_connections': {
          const list: AccessSaasAppConnection[] = model.saas_app_connections
          return {
            headers: ['App', 'Global App Name'],
            rows: list.map(c => [c.app_instance_name, c.global_app_name ?? '']),
            exportRows: list.map(c => ({ App: c.app_instance_name, 'Global App Name': c.global_app_name ?? '' })),
          }
        }
        case 'active_directory_connections': {
          const list: AccessActiveDirectoryConnection[] = model.active_directory_connections
          return {
            headers: ['Domain', 'Status'],
            rows: list.map(c => [c.domain, c.status ?? '']),
            exportRows: list.map(c => ({ Domain: c.domain, Status: c.status ?? '' })),
          }
        }
        default:
          return { headers: [], rows: [], exportRows: [] }
      }
    }, [kind, model, windowsServers, linuxServers, gatewayServers])

  const kindLabel = RESOURCE_KINDS.find(k => k.value === kind)?.label ?? kind
  const exportSections: ExportSection[] = [{ title: kindLabel, rows: exportRows }]

  return (
    <div className="flex flex-col gap-4">
      <div className="card p-3 flex flex-wrap items-end justify-between gap-4">
        <div className="flex flex-col gap-1">
          <span className="section-label">Resource kind</span>
          <Select value={kind} onValueChange={setKind} placeholder="Select a resource kind" options={RESOURCE_KINDS} />
        </div>
        <ExportButtons sections={exportSections} filenameBase={`opa-resources-${kind}`} />
      </div>

      <div className="flex items-center justify-between">
        <span className="section-label">{kindLabel} ({rows.length})</span>
      </div>

      <Table headers={headers} rows={rows} />
    </div>
  )
}
