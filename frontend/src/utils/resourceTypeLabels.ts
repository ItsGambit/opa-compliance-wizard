// resource_type_detail comes from Okta's own debugContext.debugData --
// resourceType on checkout/checkin events (confirmed live 2026-09-30 --
// real values seen: PAM_DATABASE_ACCOUNT, SERVER_ACCOUNT), more specific
// than the generic target-derived resource_type (e.g. "Service Account"),
// which alone can't distinguish a database account checkout from a
// server account checkout. Shared by ReportRowsTable (on screen) and the
// compliance-report CSV export (5.40.0 -- the export used to write the
// raw value) so both show the same label.
export const RESOURCE_TYPE_DETAIL_LABEL: Record<string, string> = {
  PAM_DATABASE_ACCOUNT: 'Database Account',
  SERVER_ACCOUNT: 'Server Account',
  // confirmed live 2026-09-30 via a real tenant's pam.resource.checkout
  // event for a SaaS app account -- not seen during initial probing,
  // found via a later browser verification pass instead.
  MANAGED_SAAS_APP_SERVICE_ACCOUNT: 'SaaS Service Account',
  // confirmed 2026-10-07 across ~130k real pam.service_account.* rows:
  // these events carry no resourceType, but debugData.serviceAccountType
  // names the account family -- audit_store._resource_type_detail_fallback
  // surfaces it in this same column, so the Credential Reveals / Credential
  // Rotation cards can finally tell a SaaS app account from an Okta, DB or
  // AD one instead of showing every row as a bare "Service Account".
  APP_ACCOUNT: 'SaaS Service Account',
  OKTA_USER_ACCOUNT: 'Okta Service Account',
  DATABASE_ACCOUNT: 'Database Account',
  PAM_AD_ACCOUNT: 'Active Directory Account',
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

/** The most specific label available: the detail's label (or the raw
 * detail when unmapped), falling back to the generic resource_type. */
export function resourceTypeLabel(row: { resource_type: string; resource_type_detail: string }): string {
  if (row.resource_type_detail) {
    return RESOURCE_TYPE_DETAIL_LABEL[row.resource_type_detail] ?? row.resource_type_detail
  }
  return row.resource_type
}
