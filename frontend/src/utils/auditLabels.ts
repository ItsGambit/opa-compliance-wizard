/** 5.53.0: plain-language labels for audit actions whose raw name is not self-explanatory. The raw action stays the entry's
 * title (it is what the search and the exports use); the label is shown beside it. */
import { upgradeActionLabel } from './auditUpgrade'

const LABELS: Record<string, string> = {
  'settings.unlocked': 'Settings and Updates opened with MFA',
  'settings.locked': 'Settings and Updates locked again',
  'settings.access_without_mfa_local': 'Opened without MFA (local mode)',
  'evidence_package.build': 'Evidence package build started',
  'evidence_package.build_finished': 'Evidence package built (compare its sha256 and chain head)',
  'evidence_package.build_failed': 'Evidence package build failed or refused',
  'evidence_package.downloaded': 'Evidence package downloaded',
}

export function auditActionLabel(action: string, details?: Record<string, unknown> | null): string | null {
  return LABELS[action] ?? upgradeActionLabel(action, details)
}
