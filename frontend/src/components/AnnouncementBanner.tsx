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

export function AnnouncementBanner() {
  const { data: banner } = useBanner()
  const [dismissed, setDismissed] = useState(false)

  if (!banner?.enabled || !banner.message) return null

  const dismissKey = DISMISS_KEY_PREFIX + banner.message
  if (dismissed || (banner.dismissible && sessionStorage.getItem(dismissKey) === '1')) {
    return null
  }

  const Icon = VARIANT_ICON[banner.variant]

  return (
    <div className={`w-full border-b px-4 py-2 flex items-center gap-2 text-xs ${VARIANT_CLASSES[banner.variant]}`}>
      <Icon size={14} className="shrink-0" />
      <span className="flex-1">{banner.message}</span>
      {banner.dismissible && (
        <button
          type="button"
          className="shrink-0 opacity-70 hover:opacity-100"
          title="Dismiss"
          onClick={() => {
            sessionStorage.setItem(dismissKey, '1')
            setDismissed(true)
          }}
        >
          <X size={13} />
        </button>
      )}
    </div>
  )
}
