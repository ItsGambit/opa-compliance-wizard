import { useState } from 'react'
import { AlertTriangle, CalendarClock, Info, X } from 'lucide-react'
import { useUpgradeNotice } from '../api/hooks'
import { browserZone, formatInZone, formatUtc } from '../utils/upgradeFlow'

const DISMISS_PREFIX = 'opa-upgrade-notice-dismissed:'

function readDismissed(key: string): boolean {
  try { return sessionStorage.getItem(key) === '1' } catch { return false }
}
function writeDismissed(key: string): void {
  try { sessionStorage.setItem(key, '1') } catch { /* in-memory only */ }
}

const STYLE = {
  warn: 'bg-warn/10 text-text border-warn/40',
  err: 'bg-loss/15 text-text border-loss/40',
}

/** The one-line banners of the upgrade flow for EVERY signed-in user (artboards 07, 08a, 10): an upgrade is scheduled (downtime
 * affects everyone), is running, or failed. Same look as the announcement banner. "A newer release exists" stays admin-only
 * (UpdateBanner). A scheduled notice can be dismissed for this browser session; the running and failed ones stay. */
export function UpgradeNoticeBanner({ onOpenUpdates, canAdmin }: { onOpenUpdates: () => void; canAdmin: boolean }) {
  const { data: notice } = useUpgradeNotice()
  const [dismissed, setDismissed] = useState<string | null>(null)
  if (!notice || notice.kind === 'none' || notice.kind === 'available') return null
  const link = canAdmin
    ? <> <button type="button" className="underline bg-transparent border-0 p-0 cursor-pointer text-inherit" onClick={onOpenUpdates}>Open the Updates page</button></>
    : null

  if (notice.kind === 'scheduled') {
    const key = DISMISS_PREFIX + notice.version + notice.when_utc
    if (dismissed === key || readDismissed(key)) return null
    const ms = Date.parse(notice.when_utc)
    const down = notice.downtime_estimate_seconds != null ? Math.max(notice.downtime_estimate_seconds + 5, 30) : 60
    return (
      <div role="status" className={`w-full border-b px-4 py-2 flex items-center gap-2 text-xs ${STYLE.warn}`}>
        <CalendarClock size={14} className="shrink-0 text-warn" aria-hidden="true" />
        <span className="flex-1">
          Scheduled maintenance: OPA Compliance Wizard will upgrade to {notice.version} on {formatInZone(ms, browserZone())} (UTC {formatUtc(ms)}).
          Expect about {down < 90 ? `${down} seconds` : 'a minute or two'} of downtime.{link}
        </span>
        <button type="button" className="shrink-0 opacity-70 hover:opacity-100" title="Dismiss" aria-label="Dismiss announcement"
          onClick={() => { writeDismissed(key); setDismissed(key) }}>
          <X size={13} aria-hidden="true" />
        </button>
      </div>
    )
  }
  if (notice.kind === 'running') {
    return (
      <div role="status" className={`w-full border-b px-4 py-2 flex items-center gap-2 text-xs ${STYLE.warn}`}>
        <Info size={14} className="shrink-0 text-warn" aria-hidden="true" />
        <span className="flex-1">
          Upgrade to {notice.version ?? 'a newer version'} in progress{notice.started_at ? ` (started ${new Date(notice.started_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })})` : ''}.
          The app will restart within the next minute; you will stay signed in.{link}
        </span>
      </div>
    )
  }
  const operator = notice.result === 'failed_needs_operator'
  return (
    <div role="alert" className={`w-full border-b px-4 py-2 flex items-center gap-2 text-xs ${STYLE.err}`}>
      <AlertTriangle size={14} className="shrink-0 text-loss" aria-hidden="true" />
      <span className="flex-1">
        {operator
          ? `The upgrade to ${notice.version} failed and could not be rolled back automatically. An operator must act on the server.`
          : notice.result === 'rolled_back'
            ? `The upgrade to ${notice.version} failed${notice.at ? ` at ${new Date(notice.at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}` : ''} and was rolled back automatically. The app is running ${notice.rolled_back_to ?? 'the previous version'} and is healthy.`
            : `The upgrade to ${notice.version} could not start and nothing was changed.`}
        {canAdmin ? <> Admins: see the Updates page.{link}</> : null}
      </span>
    </div>
  )
}
