import { useState } from 'react'
import { AlertTriangle, Info, X } from 'lucide-react'
import { useBanner } from '../api/hooks'
import type { BannerVariant } from '../types'

const VARIANT_CLASSES: Record<BannerVariant, string> = {
  info: 'bg-accent-dim text-text border-accent/40',
  warning: 'bg-warn/15 text-text border-warn/40',
  danger: 'bg-loss/15 text-text border-loss/40',
}

const VARIANT_ICON: Record<BannerVariant, typeof Info> = {
  info: Info,
  warning: AlertTriangle,
  danger: AlertTriangle,
}

// Dismissal is per-browser-tab-session and keyed by the message text itself
// -- an admin editing the message (even leaving enabled/variant the same)
// should reach everyone again, since a previously-dismissed banner for a
// *different* announcement carries no information about this one.
const DISMISS_KEY_PREFIX = 'opa-banner-dismissed:'

// sessionStorage can throw (blocked storage, some private modes): a
// dismissal then just lasts until reload.
function readDismissed(key: string): boolean {
  try { return sessionStorage.getItem(key) === '1' } catch { return false }
}
function writeDismissed(key: string): void {
  try { sessionStorage.setItem(key, '1') } catch { /* in-memory only */ }
}

export function AnnouncementBanner() {
  const { data: banner } = useBanner()
  // UI-11 (external review, 2026-10-05): remember WHICH message was
  // dismissed, not just "something was" -- a boolean hid every later
  // announcement until reload, including non-dismissible ones.
  const [dismissedMessage, setDismissedMessage] = useState<string | null>(null)

  if (!banner?.enabled || !banner.message) return null

  const dismissKey = DISMISS_KEY_PREFIX + banner.message
  if (banner.dismissible && (dismissedMessage === banner.message || readDismissed(dismissKey))) {
    return null
  }

  const Icon = VARIANT_ICON[banner.variant]

  return (
    <div role={banner.variant === 'info' ? 'status' : 'alert'} className={`w-full border-b px-4 py-2 flex items-center gap-2 text-xs ${VARIANT_CLASSES[banner.variant]}`}>
      <Icon size={14} className="shrink-0" />
      <span className="flex-1">{banner.message}</span>
      {banner.dismissible && (
        <button
          type="button"
          className="shrink-0 opacity-70 hover:opacity-100"
          title="Dismiss"
          aria-label="Dismiss announcement"
          onClick={() => {
            writeDismissed(dismissKey)
            setDismissedMessage(banner.message)
          }}
        >
          <X size={13} aria-hidden="true" />
        </button>
      )}
    </div>
  )
}
