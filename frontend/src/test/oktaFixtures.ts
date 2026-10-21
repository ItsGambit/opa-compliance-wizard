import type { CrossCheckCard, OktaAdminRow, OktaAdminsReport, Overview } from '../types'

export const snapshot = { snapshot_id: 7, captured_at: '2026-10-02T00:00:00.000Z', status: 'ok' as const, item_count: 4, sha256: 'a'.repeat(64) }

export function adminRow(over: Partial<OktaAdminRow> = {}): OktaAdminRow {
  return {
    okta_user_id: '00uEXAMPLE1', login: 'alex@example.com', email: 'alex@example.com', name: 'Alex Example', user_status: 'ACTIVE',
    role_assignment_id: 'ra1', role_type: 'SUPER_ADMIN', role_label: 'Super administrator', assignment_type: 'USER', role_status: 'ACTIVE',
    assigned_at: '2026-01-01T00:00:00.000Z', custom_role: null, custom_role_permissions: null, resource_set: null,
    target_groups: [], target_apps: [], scope: 'org-wide', time_bound: false, expires: null, granted_evidence: 'predates_archive',
    last_grant_event: null, status: 'active', ...over,
  }
}

export function okReport(over: Partial<OktaAdminsReport> = {}): OktaAdminsReport {
  return {
    state: 'ok', message: null, as_of: null, generated_at: '2026-10-03T00:00:00.000Z', as_of_snapshot: snapshot, previous_snapshot: null,
    last_attempt: { snapshot_id: 7, captured_at: snapshot.captured_at, status: 'ok', error_code: null },
    admins: [], rows: [
      adminRow(),
      adminRow({ okta_user_id: '00uEXAMPLE2', login: 'sam@example.com', name: 'Sam Sample', role_assignment_id: 'ra2', role_type: 'HELP_DESK_ADMIN',
        role_label: 'Help desk administrator', scope: 'groups', target_groups: ['Support'], time_bound: true, expires: '2026-12-09T14:17:22.000Z',
        granted_evidence: 'event', last_grant_event: { type: 'grant', published: '2026-02-02T00:00:00.000Z', role: 'Help desk administrator', by: 'boss@example.com' } }),
      adminRow({ okta_user_id: '00uGONE', login: '=cmd|calc', name: null, role_assignment_id: 'ra9', status: 'removed', scope: null,
        removed_between: ['2026-10-01T00:00:00.000Z', '2026-10-02T00:00:00.000Z'] }),
    ],
    custom_roles: [{ id: 'cr1', label: 'Auditor', description: null, permissions: ['okta.iam.read'] }], resource_sets: [{ id: 'rs1', label: 'All users', description: null }],
    summary: { admins: 2, assignments: 2, removed: 1, unknown: 0, time_bound: 1, sod_overlaps: 1, by_role: { SUPER_ADMIN: 1, HELP_DESK_ADMIN: 1 } },
    separation_of_duties: { state: 'ok', checked: 2, overlaps: [{ okta_user_id: '00uEXAMPLE1', login: 'alex@example.com', okta_roles: ['SUPER_ADMIN'], opa_user_id: 'ou1', opa_user_name: 'alex@example.com', opa_roles: ['pam_admin'], via_groups: { pam_admin: ['PAM-Admins'] } }] },
    notes: ['Admins who hold a role only through a group are not listed yet.'], capture: { status: 'idle' }, ...over,
  }
}

export const REFUSED_MESSAGE = 'Your Okta token cannot read admin role assignments; this report needs a token whose admin can view roles and admin assignments (for example a custom admin role with that permission, or Super Administrator).'

export function c1Card(over: Partial<CrossCheckCard> = {}): CrossCheckCard {
  return {
    id: 'C1', title: 'Okta lifecycle vs OPA principals', statement: 'People still in OPA whose Okta user is gone.', state: 'ok', message: null,
    inputs: { okta_snapshot: snapshot, opa_roster_loaded: true, okta_snapshot_stale: false, skipped_service_users: 1 },
    counts: { checked: 3, inactive_in_okta: 1, absent_in_okta: 1, unreadable: 0, active: 1 },
    rows: [
      { source: 'opa_user', opa_id: 'ou1', name: 'alex@example.com', email: 'alex@example.com', okta_state: 'DEPROVISIONED', okta_id: '00u1', okta_login: 'alex@example.com', flag: 'inactive', opa_roles: ['pam_admin', 'end_user'], opa_powerful_roles: ['pam_admin'] },
      { source: 'okta_ud_account', opa_id: 'acct1', name: 'svc-okta', email: null, project: 'Prod', okta_state: 'ABSENT', okta_id: null, okta_login: null, flag: 'absent', opa_roles: [], opa_powerful_roles: [] },
    ], ...over,
  }
}

export function overview(over: Partial<Overview> = {}): Overview {
  return {
    environment_id: 'e1', as_of: null, generated_at: '2026-10-03T00:00:00.000Z',
    okta_admins: { state: 'ok', message: null, count: 2, by_role: { SUPER_ADMIN: 1 }, time_bound: 1, snapshot },
    opa_privileged_users: { state: 'ok', count: 1, users_total: 3 }, sod_overlaps: { state: 'ok', count: 1 },
    lifecycle_c1: { state: 'ok', message: null, inactive_in_okta: 1, absent_in_okta: 1, unreadable: 0, checked: 3, snapshot },
    opa_service_accounts: { state: 'ok', count: 4 },
    archive: { has_archive: true, coverage_days: 80, oldest_event: '2026-07-14T00:00:00.000Z', last_sync_completed_at: '2026-10-03T00:00:00.000Z', last_sync_status: 'success', ingestion_scope: 'curated', chain: null },
    weekly_privilege_events: { grants: 2, revokes: 1, since: '2026-09-26T00:00:00.000Z', revokes_archived: true },
    snapshot_dates: [{ snapshot_id: 7, captured_at: snapshot.captured_at, status: 'ok' }], ...over,
  }
}
