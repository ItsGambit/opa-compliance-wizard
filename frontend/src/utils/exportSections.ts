import type {
  AccessModel,
  AccessPolicy,
  AccessProject,
  AuditEntry,
  ComplianceReportRow,
  FolderAccessRow,
  PolicyRule,
  RevealEntry,
  SecretAccessRow,
} from '../types'
import type { ExportSection } from './export'
import { cellValue, formatDateTime, labelize } from './format'
import type { GrantedRule } from './policy'
import { describeCondition } from './policy'

function grantRow(policy: AccessPolicy, rule: PolicyRule): Record<string, string> {
  return {
    Policy: policy.name,
    'Policy Active': policy.active ? 'Yes' : 'No',
    'Resource Group': policy.resource_group?.name ?? 'Team-wide',
    Rule: rule.name,
    'Resource Type': rule.resource_type_label,
    'Applies To': rule.resolutions
      .map(r =>
        r.kind === 'resolved'
          ? `${r.name}${r.project_name ? ` — ${r.project_name}` : ' (project unknown)'}`
          : r.description
      )
      .join('; '),
    Privileges: rule.privileges
      .map(p => (p.flags.length ? `${p.privilege_type}: ${p.flags.join(',')}` : p.privilege_type))
      .join('; '),
    Conditions: rule.conditions.map(c => describeCondition(c)).join('; '),
  }
}

export function grantRows(grants: GrantedRule[]): Record<string, string>[] {
  return grants.map(({ policy, rule }) => grantRow(policy, rule))
}

/** One row per field — for exporting a single project's detail (matches
 * the Projects tab's KeyValueGrid). */
export function projectFieldRows(project: AccessProject): Record<string, string>[] {
  return Object.entries(project).map(([key, value]) => ({ Field: labelize(key), Value: cellValue(value) }))
}

/** One row per project, columns = union of fields across all of them —
 * for the global export, where a wide table reads better than melting
 * every field into its own row per project. */
export function projectSummaryRows(projects: AccessProject[]): Record<string, string>[] {
  const columns: string[] = []
  for (const p of projects) {
    for (const key of Object.keys(p)) if (!columns.includes(key)) columns.push(key)
  }
  return projects.map(p => {
    const row: Record<string, string> = {}
    for (const key of columns) row[labelize(key)] = cellValue(p[key])
    return row
  })
}

export function policySummaryRows(policies: AccessPolicy[]): Record<string, string>[] {
  return policies.map(p => ({
    Policy: p.name,
    Active: p.active ? 'Yes' : 'No',
    'Resource Group': p.resource_group?.name ?? 'Team-wide',
    'Rule Count': String(p.rules.length),
    'Principal Groups': p.principals.user_groups.map(g => g.name).join(', '),
  }))
}

/** One row per (relationship, assignment) pair -- flattens the relationship
 * -> assignment -> policy chain the Relationships tab browses interactively. */
export function relationshipAssignmentRows(model: AccessModel): Record<string, string>[] {
  const rows: Record<string, string>[] = []
  for (const relationship of model.relationships) {
    const assignments = model.assignments.filter(a =>
      a.relationship_assignments.some(ra => ra.relationship.id === relationship.id)
    )
    if (assignments.length === 0) {
      rows.push({ Relationship: relationship.name, Assignment: '', Principals: '', 'Resolved Resources': '', 'Policies Using This': '' })
      continue
    }
    for (const assignment of assignments) {
      const principals = assignment.relationship_assignments
        .filter(ra => ra.relationship.id === relationship.id)
        .map(ra => ra.principal?.name)
        .filter((v): v is string => !!v)
      const relIds = new Set(assignment.relationship_assignments.map(ra => ra.relationship.id))
      const policiesUsing = model.policies.filter(p => p.relationship_ids.some(id => relIds.has(id)))
      rows.push({
        Relationship: relationship.name,
        Assignment: assignment.name,
        Principals: [...new Set(principals)].join(', '),
        'Resolved Resources': assignment.resolved_resources.map(r => (r.kind === 'resolved' ? r.name : r.description)).join(', '),
        'Policies Using This': policiesUsing.map(p => p.name).join(', '),
      })
    }
  }
  return rows
}

/** The "export everything" report — one section per category, covering
 * the whole access model regardless of what's currently selected on
 * screen. */
export function accessModelExportSections(model: AccessModel): ExportSection[] {
  return [
    {
      title: 'Resource Groups',
      rows: model.resource_groups.map(rg => ({
        'Resource Group': rg.name,
        Description: rg.description ?? '',
        'Delegated Admin Groups': (rg.delegated_resource_admin_groups ?? []).map(g => g.name).join(', '),
      })),
    },
    { title: 'Projects', rows: projectSummaryRows(model.projects) },
    { title: 'Policies', rows: policySummaryRows(model.policies) },
    { title: 'Policy Rules', rows: model.policies.flatMap(p => p.rules.map(r => grantRow(p, r))) },
    {
      title: 'Users',
      rows: model.users.map(u => ({
        User: u.details?.full_name || u.name,
        Email: u.details?.email ?? '',
        Status: u.status ?? '',
        Groups: u.groups.map(g => g.name).join(', '),
      })),
    },
    {
      title: 'Groups',
      rows: model.groups.map(g => ({ Group: g.name, Roles: g.roles.join(', ') })),
    },
    { title: 'Relationships & Assignments', rows: relationshipAssignmentRows(model) },
    {
      title: 'Enrolled Clients',
      rows: model.clients.map(c => ({
        Hostname: c.hostname, User: c.user_name, OS: c.os,
        Encrypted: c.encrypted ? 'Yes' : 'No', State: c.state,
      })),
    },
    {
      title: 'Okta-Managed Devices',
      rows: model.devices.map(d => ({
        Name: d.profile.displayName ?? '', Platform: d.profile.platform ?? '',
        'OS Version': d.profile.osVersion ?? '', Status: d.status,
        'Disk Encryption': d.profile.diskEncryptionType ?? '',
        Authenticators: d.authenticator_enrollments.map(a => a.name).join(', '),
      })),
    },
  ]
}

// ── Secrets Access Dashboard ──────────────────────────────────────────────

function auditCell(entry: AuditEntry | null | undefined): string {
  if (!entry) return ''
  const base = `${entry.by ?? 'unknown'} — ${formatDateTime(entry.at)}`
  // Fixes a real, independently-confirmed existing gap: reveals already
  // carried request_id before created/updated/deleted did, but this
  // function silently dropped it for every entry type, reveals included.
  return entry.request_id ? `${base} (request ${entry.request_id})` : base
}

function auditHistoryCell(entries: AuditEntry[]): string {
  return entries.map(e => auditCell(e)).join('; ')
}

function revealsCell(reveals: RevealEntry[]): string {
  return reveals.map(r => auditCell(r)).join('; ')
}

function secretAccessRow(row: SecretAccessRow): Record<string, string> {
  return {
    Secret: row.name,
    Path: row.path,
    Status: labelize(row.status),
    Created: auditCell(row.created),
    'Updated (most recent first)': auditHistoryCell(row.updated),
    Deleted: auditCell(row.deleted),
    'Retrieved (most recent first)': revealsCell(row.reveals),
  }
}

function folderAccessRow(row: FolderAccessRow): Record<string, string> {
  return {
    Folder: row.name,
    Path: row.path,
    Status: labelize(row.status),
    Created: auditCell(row.created),
    'Updated (most recent first)': auditHistoryCell(row.updated),
    Deleted: auditCell(row.deleted),
  }
}

export function secretsAccessReportExportSections(secrets: SecretAccessRow[], folders: FolderAccessRow[]): ExportSection[] {
  return [
    { title: 'Secrets', rows: secrets.map(secretAccessRow) },
    { title: 'Folders', rows: folders.map(folderAccessRow) },
  ]
}

// ── Compliance Reports ─────────────────────────────────────────────────────

/** The "four-field standard" the audit-requirements guide calls for on
 * every exported row: User, Action, Timestamp, Affected Resource. */
export function complianceReportRow(row: ComplianceReportRow): Record<string, string> {
  return {
    User: row.user,
    'User Email/ID': row.actor_alternate_id || '',
    'Client IP': row.client_ip || '',
    'Client Location': row.client_geo || '',
    Action: row.action,
    Timestamp: formatDateTime(row.timestamp),
    'Request ID': row.request_id || '',
    'Affected Resource': row.resource || '—',
    'Resource Email/ID': [row.resource_alternate_id, row.resource_id].filter(v => v && v !== 'unknown').join(' / '),
    'Resource Type': row.resource_type_detail || row.resource_type || '',
    Outcome: row.outcome || '',
    'Outcome Reason': row.outcome_reason || '',
    'Event Type': row.event_type,
  }
}

export function complianceReportExportSections(reportLabel: string, rows: ComplianceReportRow[]): ExportSection[] {
  return [{ title: reportLabel, rows: rows.map(complianceReportRow) }]
}
