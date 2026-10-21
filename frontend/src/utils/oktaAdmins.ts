import type { ConfigSnapshotDiff, CrossCheckCard, CrossCheckRow, OktaAdminRow, OktaAdminsReport, SnapshotSummary } from '../types'
import type { ExportSection } from './export'
import { formatDateTime } from './format'

// Presentation helpers for the Okta Admins report and the cross-checks (5.50.0).
// The server computes everything; this file only words it and shapes exports.

export const OKTA_ROLE_LABELS: Record<string, string> = {
  SUPER_ADMIN: 'Super administrator',
  ORG_ADMIN: 'Organization administrator',
  APP_ADMIN: 'Application administrator',
  USER_ADMIN: 'Group administrator',
  GROUP_MEMBERSHIP_ADMIN: 'Group membership administrator',
  HELP_DESK_ADMIN: 'Help desk administrator',
  READ_ONLY_ADMIN: 'Read-only administrator',
  REPORT_ADMIN: 'Report administrator',
  API_ACCESS_MANAGEMENT_ADMIN: 'API access management administrator',
  MOBILE_ADMIN: 'Mobile administrator',
  ACCESS_CERTIFICATIONS_ADMIN: 'Access certifications administrator',
  ACCESS_REQUESTS_ADMIN: 'Access requests administrator',
  WORKFLOWS_ADMIN: 'Workflows administrator',
  CUSTOM: 'Custom role',
}

export function roleLabel(row: Pick<OktaAdminRow, 'role_type' | 'role_label'>): string {
  return row.role_label || (row.role_type ? OKTA_ROLE_LABELS[row.role_type] ?? row.role_type : 'Unknown role')
}

export function scopeText(row: OktaAdminRow): string {
  if (row.status !== 'active') return '—'
  if (row.scope === 'groups') return row.target_groups.length ? `Groups: ${row.target_groups.join(', ')}` : 'All groups (no group targets set)'
  if (row.scope === 'apps') return row.target_apps.length ? `Apps: ${row.target_apps.join(', ')}` : 'All apps (no app targets set)'
  if (row.scope === 'org-wide') return 'Whole org'
  if (row.custom_role) return row.resource_set ? `Resource set: ${row.resource_set}` : 'Resource set not read'
  return 'Not scoped'
}

export function evidenceText(row: OktaAdminRow): string {
  const g = row.last_grant_event
  if (g) return `Granted ${formatDateTime(g.published)}${g.by ? ` by ${g.by}` : ''}`
  if (row.last_revoke_event) return `Revoked ${formatDateTime(row.last_revoke_event.published)}${row.last_revoke_event.by ? ` by ${row.last_revoke_event.by}` : ''}`
  if (row.granted_evidence === 'predates_archive') return 'Before the archive began'
  if (row.granted_evidence === 'event') return 'Privilege event in the archive'
  return 'No privilege event in the archive'
}

export function statusText(row: OktaAdminRow): string {
  if (row.status === 'removed') return 'removed'
  if (row.status === 'unknown') return 'unknown (seen in the log only)'
  return 'active'
}

export function personName(row: OktaAdminRow): string {
  return row.name || row.login || row.email || row.okta_user_id || 'Unknown user'
}

export function snapshotLine(s: SnapshotSummary | null | undefined): string {
  if (!s) return 'none'
  return `#${s.snapshot_id} ${s.captured_at} (sha256 ${s.sha256.slice(0, 12)}…)`
}

/** The sections of the report's CSV / Markdown export: the basis (which snapshot, with its hash), the rows, the separation-of-duties overlaps. */
export function oktaAdminsExportSections(report: OktaAdminsReport | undefined, rows: OktaAdminRow[]): ExportSection[] {
  if (!report || report.state !== 'ok') return []
  const snap = report.as_of_snapshot
  const sections: ExportSection[] = [
    {
      title: 'Okta Admins: report basis',
      rows: [{
        'Snapshot id': snap ? String(snap.snapshot_id) : '',
        'Captured at': snap?.captured_at ?? '',
        'Snapshot sha256': snap?.sha256 ?? '',
        'As of': report.as_of ?? 'latest snapshot',
        'Previous snapshot': snapshotLine(report.previous_snapshot),
        'Report generated': report.generated_at,
        Note: 'Read from a stored, hash-chained snapshot of Okta. Users with a direct role assignment only; roles held only through a group are not listed.',
      }],
    },
    {
      title: 'Okta Admins',
      rows: rows.map(r => ({
        'Okta user id': r.okta_user_id ?? '',
        Login: r.login ?? '',
        Name: r.name ?? '',
        'Okta user status': r.user_status ?? '',
        Status: statusText(r),
        Role: r.role_type ? roleLabel(r) : '',
        'Role type': r.role_type ?? '',
        'Assignment type': r.assignment_type ?? '',
        Scope: scopeText(r),
        'Custom role': r.custom_role ?? '',
        'Custom role permissions': (r.custom_role_permissions ?? []).join('; '),
        'Resource set': r.resource_set ?? '',
        'Assigned at': r.assigned_at ?? '',
        'Time-bound': r.time_bound ? 'Yes' : 'No',
        Expires: r.expires ?? '',
        'Grant evidence': evidenceText(r),
        'Removed between': r.removed_between ? r.removed_between.join(' and ') : '',
      })),
    },
  ]
  if (report.separation_of_duties.state !== 'not_loaded') {
    sections.push({
      title: 'Okta admins who also hold an OPA admin role (candidates for review)',
      rows: report.separation_of_duties.overlaps.map(o => ({
        'Okta login': o.login ?? '',
        'Okta roles': o.okta_roles.map(t => OKTA_ROLE_LABELS[t] ?? t).join('; '),
        'OPA user': o.opa_user_name ?? '',
        'OPA roles': o.opa_roles.join('; '),
        'Through OPA groups': Object.values(o.via_groups).flat().join('; '),
      })),
    })
  }
  return sections
}

export const FLAG_LABEL: Record<CrossCheckRow['flag'], string> = {
  inactive: 'Inactive in Okta',
  absent: 'Not found in Okta',
  unknown: 'Okta status not read',
}

export function oktaStateText(state: string | null): string {
  if (!state) return 'unknown'
  if (state === 'ABSENT') return 'not found'
  if (state === 'UNREADABLE') return 'could not be read'
  return state.toLowerCase().replace(/_/g, ' ')
}

export function crossCheckExportSections(card: CrossCheckCard | undefined): ExportSection[] {
  if (!card || card.state !== 'ok') return []
  return [
    {
      title: 'Lifecycle cross-check: basis',
      rows: [{
        Check: card.title, Statement: card.statement,
        'Okta lookup': snapshotLine(card.inputs.okta_snapshot),
        Checked: String(card.counts.checked ?? 0),
        'Inactive in Okta': String(card.counts.inactive_in_okta ?? 0),
        'Not found in Okta': String(card.counts.absent_in_okta ?? 0),
        'Not read': String(card.counts.unreadable ?? 0),
        Note: 'Candidates for review, not findings.',
      }],
    },
    {
      title: card.title,
      rows: card.rows.map(r => ({
        Source: r.source === 'opa_user' ? 'OPA user' : 'Okta service account',
        Name: r.name ?? '', Email: r.email ?? '', Project: r.project ?? '',
        'Okta status': oktaStateText(r.okta_state), Flag: FLAG_LABEL[r.flag],
        'OPA roles': r.opa_roles.join('; '), 'OPA admin roles': r.opa_powerful_roles.join('; '),
      })),
    },
  ]
}

/** A readable name for an item key of an okta_admins snapshot ("user:00u…" -> the login). */
export function itemLabel(key: string, object: Record<string, unknown> | null): string {
  const text = (v: unknown) => (typeof v === 'string' && v ? v : null)
  if (object) {
    if (key.startsWith('user:')) return text(object.login) ?? text(object.email) ?? text(object.name) ?? key
    return text(object.label) ?? text(object.name) ?? key
  }
  return key
}

export function diffSummary(d: ConfigSnapshotDiff): string {
  return `${d.added.length} added, ${d.removed.length} removed, ${d.changed.length} changed, ${d.unchanged} unchanged`
}
