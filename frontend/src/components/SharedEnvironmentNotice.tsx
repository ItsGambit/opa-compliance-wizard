import { useEnvironments } from '../api/hooks'
import type { SharedCapabilityKey } from '../types'
import { activeRow, can } from '../utils/environmentRows'

const LABELS: [SharedCapabilityKey, string][] = [
  ['view_archive', 'archived reports'], ['live_read', 'live queries'], ['tenant_write', 'changes in its OPA team or Okta org'],
  ['sync_now', 'Sync now'], ['sync_settings', 'sync settings'], ['import_csv', 'CSV import'], ['reset_watermark', 'watermark reset'],
]

/** 5.42.0: says up front what an admin doesn't allow on the active,
 * shared-with-you environment, so a refused action is no surprise. Hidden
 * for your own environments and when nothing is limited beyond the
 * long-standing owner-only sync controls. */
export function SharedEnvironmentNotice() {
  const { data } = useEnvironments()
  const row = activeRow(data)
  if (!row || row.is_own || !row.permissions) return null
  const denied = LABELS.filter(([key]) => !can(row, key))
  if (denied.every(([key]) => key === 'sync_now' || key === 'sync_settings')) return null
  return (
    <div className="card p-2.5 text-xs text-text-dim" role="note">
      <strong className="text-text">'{row.name}' is shared with you.</strong> An admin hasn't allowed shared users:{' '}
      {denied.map(([, label]) => label).join(', ')}. Its owner can do these.
    </div>
  )
}
