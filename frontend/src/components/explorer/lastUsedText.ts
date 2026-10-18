import type { LastUsed } from '../../utils/accessResources'
import { describeEventTypes, usesChip, windowLabel } from '../../utils/accessEvidence'
import { formatDateTime } from '../../utils/format'
import { relativeTime } from '../../utils/relativeTime'

/** "Last used 3 days ago" / "Never used in 90 days" ... for the row's last
 * column. `chip` is the small count ("12 uses · 90d") where the lookup knows
 * it. "Last used" means a reveal, checkout or credential issue, and the
 * title says which (the event types the answer counted). */
export function lastUsedText(lu: LastUsed, now: number): { text: string; title?: string; chip?: string } {
  switch (lu.state) {
    case 'used': {
      const when = relativeTime(lu.at, now) ?? formatDateTime(lu.at)
      const covered = describeEventTypes(lu.eventTypes)
      const title = [
        formatDateTime(lu.at),
        covered ? `Counts: ${covered}` : '',
        lu.anyAccount ? 'Any account of this kind the user used, not only the ones this rule covers' : '',
        lu.newerThanSync ? 'Newer than the last sync: found in the live System Log' : '',
      ].filter(Boolean).join('. ')
      return { text: `Last used ${when}${lu.anyAccount ? ' (any account)' : ''}`, title, chip: usesChip(lu.uses, lu.windowDays) }
    }
    case 'never': {
      const covered = describeEventTypes(lu.eventTypes)
      return {
        text: lu.windowDays === undefined ? 'Never used' : `Never used in ${lu.windowDays} days`,
        title: `No use found in ${windowLabel(lu.windowDays)}${covered ? ` (counts: ${covered})` : ''}${lu.anyAccount ? ', for any account of this kind' : ''}`,
      }
    }
    case 'unknown': return { text: 'Unknown', title: lu.reason ?? 'The lookup did not give a complete answer' }
    case 'ambiguous': return { text: 'Unknown', title: 'Another account has the same name, so it cannot be told which account was used' }
    case 'untracked': return { text: 'Not tracked', title: lu.reason ?? 'The System Log does not record access for this kind of resource' }
    case 'loading': return { text: 'Loading…' }
    case 'error': return { text: 'Unavailable' }
    default: return { text: '' }
  }
}
