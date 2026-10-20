import { useState } from 'react'
import { AlertTriangle, Info, X } from 'lucide-react'
import { useUpgradeStatus } from '../api/hooks'
import { formatDateTime } from '../utils/format'

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

/** The one-line banners the Updates feature adds, same look as the announcement banner:
 * info (a newer release exists; admins only; dismissible per version for this browser session) and
 * red (a signing-key revocation was applied in the last 30 days; admins only; stays). */
export function UpdateBanner({ canAdmin, onOpenUpdates }: Props) {
  const { data: status } = useUpgradeStatus(canAdmin)
  const [dismissed, setDismissed] = useState<string | null>(null)
  if (!canAdmin || !status) return null
  const rev = status.revocation
  const latest = status.latest
  const showAvailable = status.check.enabled && status.update_available && !!latest
  const key = latest ? DISMISS_KEY_PREFIX + latest.version : ''
  const availableHidden = !showAvailable || dismissed === latest?.version || readDismissed(key)
  return (
    <>
      {rev && (
        <div role="alert" className="w-full border-b px-4 py-2 flex items-center gap-2 text-xs bg-loss/15 text-text border-loss/40">
          <AlertTriangle size={14} className="shrink-0" aria-hidden="true" />
          <span className="flex-1">
            Release-key revocation applied on {formatDateTime(rev.applied_at)}: {rev.revoked.length === 1 ? 'the signing key' : 'signing keys'}{' '}
            {rev.revoked.join(', ')} {rev.revoked.length === 1 ? 'is' : 'are'} revoked{rev.added.length > 0 ? ' and a new key is trusted' : ''}.
            Releases signed by the old key after the revocation are no longer accepted.{' '}
            <button type="button" className="underline bg-transparent border-0 p-0 cursor-pointer text-inherit" onClick={onOpenUpdates}>Review on the Updates page</button>
          </span>
        </div>
      )}
      {!availableHidden && latest && (
        <div role="status" className="w-full border-b px-4 py-2 flex items-center gap-2 text-xs bg-accent-dim text-text border-accent/40">
          <Info size={14} className="shrink-0" aria-hidden="true" />
          <span className="flex-1">
            Version {latest.version} of OPA Compliance Wizard is available (this server runs {status.installed_version}).{' '}
            <button type="button" className="underline bg-transparent border-0 p-0 cursor-pointer text-inherit" onClick={onOpenUpdates}>Review it on the Updates page</button>
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
      )}
    </>
  )
}
