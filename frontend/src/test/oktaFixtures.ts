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

const WEEKS = ['2026-07-27', '2026-08-03', '2026-08-10', '2026-08-17', '2026-08-24', '2026-08-31', '2026-09-07', '2026-09-14', '2026-09-21', '2026-09-28', '2026-10-05', '2026-10-12', '2026-10-19']

function mfaWeek(week: string, i: number) {
  const base = 2800 + i * 40
  return {
    week, signins: base, mfa_success: 900 + i * 10, by_class: { fastpass: 300 + i * 10, passkey: 200, smart_card: 0, okta_verify_push: 250, okta_verify_code: 80, sms: 40, voice: 3, email: 20, other_code: 0, security_question: 0, other: 0 },
    unclassified: 7, phishing_resistant: 500 + i * 10, phishing_resistant_share: 0.5 + i * 0.012, sms_voice: 43, password_only_derived: base - 900 - i * 10, mfa_failed: 36, mfa_failure_rate: 0.04,
  }
}

export function overview(over: Partial<Overview> = {}): Overview {
  return {
    environment_id: 'e1', as_of: null, generated_at: '2026-10-21T02:20:00.000Z', viewing_as_of: null, attention: [],
    paragraph: '14 people hold an Okta admin role in example.okta.com (3 of them Super Administrator) and 9 hold a privileged OPA role (pam_admin, resource_admin or delegated_resource_admin). 1 person holds both and is listed for separation-of-duties review.',
    sources: {
      okta_snapshot: { captured_at: snapshot.captured_at, index: 13, snapshots_total: 13, first_at: '2026-10-09T02:05:00.000Z', state: 'ok', newest_attempt_status: 'ok', newest_attempt_at: snapshot.captured_at, days_old: 0 },
      archive: { has_archive: true, oldest: '2025-09-04T00:00:00.000Z', newest: '2026-10-21T02:14:00.000Z', days_held: 412, events: 1284310, last_sync_completed_at: '2026-10-21T02:14:00.000Z', last_sync_status: 'success', last_sync_error: null, sync_mode: 'polling', scope: 'curated', days_since_sync: 0 },
      chain: { valid: true, manifest_count: 418, reason: null, head_hash: '9f3a1c7e4d20b86f5a91c0e7d3b2a48f6e15c9d07a3b84e2f1d6c5a9b0e74f2d' },
      opa_model: { loaded: true, refreshed_at: '2026-10-21T02:20:00.000Z', principals_effective: 212 }, okta_org: { users: 1240 },
    },
    tiles: {
      okta_people: 14, okta_by_role: { SUPER_ADMIN: 3, ORG_ADMIN: 2, APP_ADMIN: 5, USER_ADMIN: 4, READ_ONLY_ADMIN: 3 }, opa_privileged: 9, opa_by_role: { pam_admin: 3, resource_admin: 4, delegated_resource_admin: 5 },
      both: 1, left_okta: { people: 0, accounts: 0, state: 'ok', effective_known: true }, service: { saas: 19, okta_ud: 8, service_users: 4, total: 27 }, archive_days: 412,
    },
    trends: {
      admin_holders: { okta: [{ t: '2026-10-09T02:05:00.000Z', count: 13 }, { t: '2026-10-16T02:05:00.000Z', count: 14 }, { t: '2026-10-21T02:05:00.000Z', count: 14 }], opa: [{ t: '2026-10-09T02:05:00.000Z', count: 9 }, { t: '2026-10-21T02:05:00.000Z', count: 9 }] },
      privilege_events: WEEKS.map((week, i) => ({ week, granted: i % 4, revoked: i % 5 === 0 ? 1 : 0 })), revokes_archived: true,
      access_requests: WEEKS.map((week, i) => ({ week, created: 20 + i, resolved: 18 + i, expired: 1 })),
    },
    cross_checks: [
      { id: 'C1', title: 'Left Okta, still holds OPA access', statement: 'An OPA user whose Okta user is deprovisioned or suspended, whose access still resolves.', state: 'ok', message: null, inputs: { okta_snapshot: snapshot, opa_roster_loaded: true }, counts: {}, result: { state: 'ok', people: 0, accounts: 0, unreadable: 0, checked: 41 } },
      { id: 'C5', title: 'Okta admin who is also an OPA admin (separation of duties)', statement: 'An Okta admin who also holds an OPA admin role.', state: 'ok', message: null, inputs: { okta_snapshot: snapshot, opa_roster_loaded: true }, counts: { people: 1 }, result: { state: 'ok', people: 1 } },
    ],
    evidence_readiness: [
      { group: 'CC6 Access controls', reports: ['MFA Enforcement', 'Provisioning'], built_from: 'Archive', current_through: '2026-10-21T02:14:00.000Z' },
      { group: 'Okta Admins', reports: ['User principals'], built_from: 'Snapshot + archive', current_through: snapshot.captured_at },
    ],
    okta_admins: { state: 'ok', message: null, count: 14, by_role: { SUPER_ADMIN: 3 }, time_bound: 1, snapshot },
    opa_privileged_users: { state: 'ok', count: 9, users_total: 212 }, sod_overlaps: { state: 'ok', count: 1 },
    lifecycle_c1: { state: 'ok', message: null, inactive_in_okta: 0, absent_in_okta: 0, unreadable: 0, checked: 41, snapshot },
    opa_service_accounts: { state: 'ok', count: 27 },
    archive: { has_archive: true, coverage_days: 412, oldest_event: '2025-09-04T00:00:00.000Z', last_sync_completed_at: '2026-10-21T02:14:00.000Z', last_sync_status: 'success', ingestion_scope: 'curated', chain: null },
    weekly_privilege_events: { grants: 2, revokes: 1, since: '2026-10-14T00:00:00.000Z', revokes_archived: true },
    snapshot_dates: [{ snapshot_id: 7, captured_at: snapshot.captured_at, status: 'ok' }],
    inventory: {
      state: 'ok', snapshots: 13, latest: snapshot.captured_at, problems: [],
      series: [
        { key: 'opa.servers', label: 'Servers', side: 'opa', first_seen: '2026-10-09T02:05:00.000Z', latest: 318, latest_at: snapshot.captured_at, delta_7d: 3, delta_30d: null, points: [{ t: '2026-10-09T02:05:00.000Z', count: 311 }, { t: '2026-10-21T02:05:00.000Z', count: 318 }] },
        { key: 'okta.users', label: 'Users', side: 'okta', first_seen: '2026-10-09T02:05:00.000Z', latest: 1240, latest_at: snapshot.captured_at, delta_7d: 3, delta_30d: null, points: [{ t: '2026-10-09T02:05:00.000Z', count: 1231 }, { t: '2026-10-21T02:05:00.000Z', count: 1240 }] },
      ],
    },
    signins_mfa: { state: 'ok', built_at: '2026-10-09T02:30:00.000Z', updated_at: '2026-10-21T02:30:00.000Z', events_used: 90000, weeks: WEEKS, everyone: WEEKS.map(mfaWeek), privileged: WEEKS.map(mfaWeek), privileged_cohort: { okta_admins: 14, opa_admin_logins: 9 }, scope: 'curated', notes: ['Password-only is derived.'] },
    ...over,
  }
}
