import { useMemo, useState } from 'react'
import { AdConnectionRulesPanel } from './AdConnectionRulesPanel'
import type {
  AccessActiveDirectoryAccount,
  AccessActiveDirectoryConnection,
  AccessClient,
  AccessDatabaseAccount,
  AccessDatabaseConnection,
  AccessDevice,
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
import { HighlightedText, useFuzzyFilter } from '../utils/fuzzySearch'
import { DetailGrid, DetailSection } from './explorer/DetailBlocks'
import { ExplorerLayout } from './explorer/ExplorerLayout'
import { useExplorerLayout } from './explorer/explorerContext'
import type { ExplorerRowData } from './explorer/ExplorerRows'
import { ExplorerToolbar } from './explorer/ExplorerToolbar'
import { CountList, RailField } from './explorer/RailParts'
import { withCountEntries } from './explorer/countEntries'
import { RowSections } from './explorer/RowSections'
import { useSectionState } from './explorer/useSectionState'
import { ExportButtons } from './ExportButtons'
import { ResourceHistoryPanel } from './ResourceHistoryPanel'
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
  { value: 'clients', label: 'Enrolled Clients' },
  { value: 'devices', label: 'Okta-Managed Devices' },
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
    case 'clients': {
      // id is the real OPA client id, which IS the resource id on
      // pam.client.enroll's own target[] (confirmed live via a real
      // 90-day CSV export) -- clickable into the same compliance-report
      // history drill-down as every other id-bearing resource kind here.
      const list: AccessClient[] = model.clients
      return {
        headers: ['Hostname', 'User', 'OS', 'Encrypted', 'State'],
        rows: list.map(c => ({
          id: c.id,
          label: c.hostname,
          cells: [c.hostname, c.user_name, c.os, c.encrypted ? 'Yes' : 'No', c.state],
          exportRow: {
            Hostname: c.hostname, User: c.user_name, OS: c.os,
            Encrypted: c.encrypted ? 'Yes' : 'No', State: c.state,
          },
        })),
      }
    }
    case 'devices': {
      // id is the real Okta device id, which IS the resource id on
      // device.enrollment.create/.lifecycle.activate/.user.add's own
      // target[] (confirmed live) -- clickable into the compliance-report
      // history drill-down like every other id-bearing kind here. Only
      // populated when the active environment has Okta credentials
      // configured; empty (not an error) otherwise.
      const list: AccessDevice[] = model.devices
      return {
        headers: ['Name', 'User(s)', 'Platform', 'OS Version', 'Status', 'Disk Encryption', 'Authenticators'],
        rows: list.map(d => {
          const authNames = d.authenticator_enrollments.map(a => a.name).join(', ')
          // A device can genuinely have multiple associated users (shared/
          // kiosk-style device) -- confirmed live 2026-10-02, see
          // OktaClient.get_device_users' docstring -- so this joins the
          // whole list, same pattern as the Authenticators column above.
          const userNames = d.users.join(', ')
          return {
            id: d.id,
            label: d.profile.displayName ?? d.id,
            cells: [
              d.profile.displayName ?? '', userNames, d.profile.platform ?? '', d.profile.osVersion ?? '',
              d.status, d.profile.diskEncryptionType ?? '', authNames,
            ],
            exportRow: {
              Name: d.profile.displayName ?? '', 'User(s)': userNames, Platform: d.profile.platform ?? '',
              'OS Version': d.profile.osVersion ?? '', Status: d.status,
              'Disk Encryption': d.profile.diskEncryptionType ?? '', Authenticators: authNames,
            },
          }
        }),
      }
    }
    case 'okta_accounts': {
      // Real bug fixed 2026-09-30: this used to read a.account_name,
      // which doesn't exist on the real API object -- confirmed live the
      // real fields are `name` (human label, e.g. "Example Okta SA") and
      // `username` (the login identity, e.g. "svc@example.com"), so
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

const WHERE_HEADERS = ['Resource Group', 'Project']
const STATE_HEADERS = ['State', 'Status']

/** Splits a kind's columns into the row's four calm cells without losing
 * any: name = first column, "where" = resource group / project, "state" =
 * state / status, summary = every other column. The expanded row lists ALL
 * columns again, labelled. */
function summarize(headers: string[], cells: (string | number)[]) {
  const text = (i: number) => (cells[i] === '' || cells[i] == null ? '' : String(cells[i]))
  const where: string[] = []
  const summary: string[] = []
  let state = ''
  headers.forEach((h, i) => {
    if (i === 0) return
    if (WHERE_HEADERS.includes(h)) { if (text(i)) where.push(text(i)) }
    else if (STATE_HEADERS.includes(h)) state = text(i)
    else if (text(i)) summary.push(text(i))
  })
  return { summary: summary.join(' · '), where: where.join(' / '), state }
}

/** The expanded row: every column of the kind, labelled, then the access
 * history (or, for an AD connection, its discovery configuration). The
 * panels' Close button closes the row. */
function ResourceDetail({ headers, row, isAdConnection }: { headers: string[]; row: ResourceRow; isAdConnection: boolean }) {
  const { setOpenRowId } = useExplorerLayout()
  const close = () => setOpenRowId(null)
  return (
    <div className="flex flex-col gap-4">
      <DetailGrid>
        {headers.map((h, j) => (
          <DetailSection key={h} title={h}>
            <p className={row.cells[j] === '' || row.cells[j] == null ? 'xp-mute' : undefined}>
              {row.cells[j] === '' || row.cells[j] == null ? '—' : String(row.cells[j])}
            </p>
          </DetailSection>
        ))}
      </DetailGrid>
      {row.id === null && <p className="xp-note">No compliance-report history is available for this resource kind.</p>}
      {row.id !== null && !isAdConnection && <ResourceHistoryPanel resourceId={row.id} resourceLabel={row.label} onClose={close} />}
      {row.id !== null && isAdConnection && <AdConnectionRulesPanel connectionId={row.id} connectionLabel={row.label} onClose={close} />}
    </div>
  )
}

export function ResourcesTab({ model }: Props) {
  const [kind, setKind] = useState(RESOURCE_KINDS[0].value)
  const [query, setQuery] = useState('')

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

  // How many of each kind there are: the quick view switches kind.
  const kindCounts = useMemo(
    () => RESOURCE_KINDS.map(k => ({ ...k, count: buildRows(k.value, model, windowsServers, linuxServers, gatewayServers).rows.length })),
    [model, windowsServers, linuxServers, gatewayServers]
  )

  const kindLabel = RESOURCE_KINDS.find(k => k.value === kind)?.label ?? kind
  const exportSections: ExportSection[] = useMemo(() => [{ title: kindLabel, rows: rows.map(r => r.exportRow) }], [kindLabel, rows])

  const results = useFuzzyFilter(rows, query, ['label', 'cells'])
  const isAdConnection = kind === 'active_directory_connections'

  const explorerRows: ExplorerRowData[] = results.map(({ item: row, matches }, i) => {
    const parts = summarize(headers, row.cells)
    const labelMatch = matches.find(m => m.key === 'label')
    return {
      id: `${kind}:${row.id ?? `n${i}`}`,
      label: row.label,
      name: <HighlightedText text={String(row.cells[0] ?? row.label)} indices={labelMatch?.indices} />,
      can: parts.summary,
      via: parts.where,
      used: parts.state,
      detail: () => <ResourceDetail headers={headers} row={row} isAdConnection={isAdConnection} />,
    }
  })
  const sections = [{ id: kind, title: kindLabel, rows: explorerRows }]
  const state = useSectionState(explorerRows.length > 0 ? [kind] : [], { resetKey: kind, autoOpenKey: query.trim() })

  const rail = (
    <>
      <RailField label="Resource kind">
        <Select ariaLabel="Resource kind" value={kind} onValueChange={k => { setKind(k); setQuery('') }} placeholder="Select a resource kind" options={RESOURCE_KINDS} />
      </RailField>
      <CountList
        items={kindCounts.filter(k => k.count > 0).map(k => {
          const item = { id: k.value, label: k.label.toLowerCase(), count: k.count }
          // Only the kind on screen has rows to list; the others switch kind.
          return k.value === kind ? withCountEntries([item], sections)[0] : item
        })}
        onSelect={id => { setKind(id); setQuery('') }}
      />
      <div className="xp-rail-actions">
        <ExportButtons sections={exportSections} filenameBase={`opa-resources-${kind}`} />
      </div>
    </>
  )

  return (
    <ExplorerLayout rail={rail} railLabel="Resource kind and quick view">
      <ExplorerToolbar
        query={query}
        onQueryChange={setQuery}
        label={`Search ${kindLabel.toLowerCase()}`}
        placeholder={`Search ${kindLabel.toLowerCase()}…`}
        sections={state}
      />
      {rows.length === 0 && <p className="xp-note">No resources of this kind found.</p>}
      {rows.length > 0 && results.length === 0 && <p className="xp-note">No resources match "{query}".</p>}
      <RowSections sections={sections} state={state} />
    </ExplorerLayout>
  )
}
