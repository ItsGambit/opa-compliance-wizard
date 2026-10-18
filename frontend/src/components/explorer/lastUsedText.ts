import type { LastUsed } from '../../utils/accessResources'
import { formatDateTime } from '../../utils/format'
import { relativeTime } from '../../utils/relativeTime'

/** "Last used 3 days ago" / "Never used" ... for the row's last column. */
export function lastUsedText(lu: LastUsed, now: number): { text: string; title?: string } {
  switch (lu.state) {
    case 'used': return { text: `Last used ${relativeTime(lu.at, now) ?? formatDateTime(lu.at)}`, title: formatDateTime(lu.at) }
    case 'never': return { text: 'Never used', title: 'No access found in the last 90 days' }
    case 'unknown': return { text: 'Unknown', title: 'The lookup did not give a complete answer' }
    case 'untracked': return { text: 'Not tracked', title: 'The System Log does not record access for this kind of resource' }
    case 'loading': return { text: 'Loading…' }
    case 'error': return { text: 'Unavailable' }
    default: return { text: '' }
  }
}
