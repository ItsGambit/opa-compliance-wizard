/** 5.53.0: how the Audit Log shows an `upgrade.*` action. One table, so every action the server can write gets the same
 * treatment: the accent (blue) edge for a normal upgrade event, the red one for a failure or refusal, and a label whose
 * words say which of the two it is (colour is never the only signal). */

export type UpgradeTone = 'normal' | 'failure'

interface UpgradeAction { label: string; failure?: boolean }

const ACTIONS: Record<string, UpgradeAction> = {
  'upgrade.check': { label: 'update check' },
  'upgrade.settings': { label: 'update settings changed' },
  'upgrade.requested': { label: 'upgrade requested' },
  'upgrade.scheduled': { label: 'upgrade scheduled' },
  'upgrade.rescheduled': { label: 'upgrade rescheduled' },
  'upgrade.cancelled': { label: 'upgrade cancelled' },
  'upgrade.started': { label: 'upgrade started' },
  'upgrade.started_by_schedule': { label: 'scheduled upgrade started' },
  'upgrade.staged': { label: 'release downloaded and verified' },
  'upgrade.step': { label: 'upgrade step' },
  'upgrade.migrated': { label: 'data migrated' },
  'upgrade.health_check': { label: 'health checks' },
  'upgrade.completed': { label: 'upgrade completed' },
  'upgrade.backups_pruned': { label: 'old backups removed' },
  'upgrade.bundle_created': { label: 'support bundle created' },
  'upgrade.bundle_downloaded': { label: 'support bundle downloaded' },
  'upgrade.nginx_synced': { label: 'web server settings updated' },
  'upgrade.clear_failure': { label: 'recorded failure cleared' },
  'upgrade.restore_requested': { label: 'restore requested' },
  'upgrade.restored': { label: 'archive restored' },
  'upgrade.key_list_installed': { label: 'signing-key list installed' },
  'upgrade.key_added': { label: 'signing key added' },
  'upgrade.key_revoked': { label: 'signing key revoked' },
  'upgrade.local_started': { label: 'local upgrade started' },
  'upgrade.local_completed': { label: 'local upgrade completed' },
  'upgrade.local_restored': { label: 'previous version restored' },
  'upgrade.failed': { label: 'upgrade failed', failure: true },
  'upgrade.verify_failed': { label: 'release verification failed', failure: true },
  'upgrade.missed': { label: 'scheduled upgrade missed', failure: true },
  'upgrade.key_revocation_rejected': { label: 'key revocation rejected', failure: true },
  'upgrade.local_failed': { label: 'local upgrade failed', failure: true },
  'upgrade.request_rejected': { label: 'upgrade request refused', failure: true },
  'upgrade.rolled_back': { label: 'upgrade rolled back', failure: true },
}

/** Every `upgrade.*` action this table knows. A test compares it with the actions the server code writes. */
export const UPGRADE_AUDIT_ACTIONS = Object.keys(ACTIONS)

export function isUpgradeAction(action: string): boolean {
  return action.startsWith('upgrade.')
}

/** `failure` for a failed or refused step (and a failed update check), `normal` for every other upgrade event. */
export function upgradeTone(action: string, details?: Record<string, unknown> | null): UpgradeTone {
  if (ACTIONS[action]?.failure) return 'failure'
  if (action === 'upgrade.check' && details?.outcome === 'failed') return 'failure'
  return 'normal'
}

/** The words shown beside an upgrade action; null for anything else. A failed update check says so in words. */
export function upgradeActionLabel(action: string, details?: Record<string, unknown> | null): string | null {
  const known = ACTIONS[action]
  if (!known) return isUpgradeAction(action) ? 'upgrade event' : null
  if (action === 'upgrade.check' && details?.outcome === 'failed') return 'update check failed'
  return known.label
}
