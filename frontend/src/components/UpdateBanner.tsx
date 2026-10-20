import { useState } from 'react'
import { Download, X } from 'lucide-react'
import { useUpgradeStatus } from '../api/hooks'

const DISMISS_KEY_PREFIX = 'opa-update-dismissed:'

// sessionStorage can throw (blocked storage, some private modes): a
// dismissal then just lasts until reload.
function readDismissed(key: string): boolean {
  try { return sessionStorage.getItem(key) === '1' } catch { return false }
}
function writeDismissed(key: string): void {
  try { sessionStorage.setItem(key, '1') } catch { /* in-memory only */ }
}

interface Props {
  /** Admin-only: the status route is admin-only on the server too. */
  canAdmin: boolean
  onOpenUpdates: () => void
}

/** One line for admins when the (opt-in) update check has found a newer
 * release. Dismissal is per browser tab session and per version, so the
 * next release shows again. Same look as the announcement banner. */
export function UpdateBanner({ canAdmin, onOpenUpdates }: Props) {
  const { data: status } = useUpgradeStatus(canAdmin)
  const [dismissed, setDismissed] = useState<string | null>(null)
  const latest = status?.latest
  if (!canAdmin || !status?.check.enabled || !status.update_available || !latest) return null
  const key = DISMISS_KEY_PREFIX + latest.version
  if (dismissed === latest.version || readDismissed(key)) return null
  return (
    <div role="status" className="w-full border-b px-4 py-2 flex items-center gap-2 text-xs bg-accent-dim text-text border-accent/40">
      <Download size={14} className="shrink-0" aria-hidden="true" />
      <span className="flex-1">
        Version {latest.version} is available (this server runs {status.installed_version}).{' '}
        <button type="button" className="underline" onClick={onOpenUpdates}>See how to update</button>
      </span>
      <button
        type="button"
        className="shrink-0 opacity-70 hover:opacity-100"
        title="Dismiss"
        aria-label="Dismiss update notice"
        onClick={() => { writeDismissed(key); setDismissed(latest.version) }}
      >
        <X size={13} aria-hidden="true" />
      </button>
    </div>
  )
}
