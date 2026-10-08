import type { SecretsAccessStatus } from '../types'

// The active / deleted / unknown status vocabulary shared by the Secrets
// Access Dashboard and the Service Accounts Dashboard (5.40.0) -- both
// reports compute it the same way server-side (present live => active;
// absent live with a real delete event => deleted; otherwise unknown,
// never inferred), so the UI must label it the same way too.

export function statusVariant(status: SecretsAccessStatus): 'active' | 'deleted' | 'unknown' {
  return status
}

/** `unknownHint` explains what "unknown" means for THIS report: for the
 * Secrets report (which may be a live, 90-day-bounded query) it is
 * "outside log window"; for the archive-only Service Accounts report it
 * is "not in the live roster, no delete event". */
export function statusLabel(status: SecretsAccessStatus, unknownHint = 'outside log window'): string {
  if (status === 'unknown') return `unknown (${unknownHint})`
  return status
}
