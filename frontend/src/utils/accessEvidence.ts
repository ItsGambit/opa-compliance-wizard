import type { ResourceAccessInfo } from '../types'
import { formatDateTime } from './format'
import { relativeTime } from './relativeTime'

/** Plain words for the System Log event types the last-used lookup counts. */
const EVENT_WORDS: Record<string, string> = {
  'pam.secret.reveal': 'Revealed secret',
  'pam.service_account.password.reveal': 'Revealed password',
  'pam.server_account.password.reveal': 'Revealed password',
  'pam.resource.checkout': 'Checked out',
  'pam.gateway_creds.issue': 'Issued gateway credentials',
  'pam.user_creds.issue': 'Issued server credentials',
}

export function eventWord(eventType: string | undefined): string {
  if (!eventType) return 'Accessed'
  return EVENT_WORDS[eventType] ?? eventType
}

/** "revealed a password, checked out ..." for a tooltip: the distinct plain
 * phrases of the event types an answer counted. */
export function describeEventTypes(types: string[] | undefined): string {
  const words = [...new Set((types ?? []).map(t => eventWord(t).toLowerCase()))]
  return words.join(', ')
}

/** What "last used" means, said once: shown as the title of the column. */
export const LAST_USED_MEANING =
  'Last used = the newest time this user revealed a password or secret, checked an account out, or was issued gateway or server credentials for it (per the System Log).'

export function windowLabel(days: number | undefined): string {
  return days === undefined ? 'the period read' : `the last ${days} days`
}

export function sourceLabel(source: ResourceAccessInfo['source']): string {
  if (source === 'archive+live') return 'archive + live'
  return source ?? 'live'
}

const ARCHIVE_NOTES: Record<string, string> = {
  no_archive: 'This environment has no synced archive yet, so only the live 90-day System Log was read.',
  type_not_stored: 'The archive does not hold this event type: showing live 90-day data.',
  not_permitted: 'You do not have permission to read the archive here: showing live 90-day data.',
  stale_gap: 'The archive was last synced more than 90 days ago, so a stretch of time cannot be read by anyone.',
}

export function archiveNote(info: ResourceAccessInfo): string | undefined {
  return info.archive_note ? ARCHIVE_NOTES[info.archive_note] : undefined
}

function dateOnly(iso: string | null | undefined): string | undefined {
  return iso ? iso.slice(0, 10) : undefined
}

/** One line saying how the answer was reached:
 * "Source: archive + live · covers 2026-07-20 to now · last synced 3 hours ago". */
export function evidenceFooter(info: ResourceAccessInfo, now: number): string {
  const parts = [`Source: ${sourceLabel(info.source)}`]
  const from = dateOnly(info.coverage_from)
  if (from) parts.push(`covers ${from} to now`)
  else parts.push(`covers ${windowLabel(info.window_days)}`)
  if (info.source !== 'live') {
    parts.push(info.last_synced_at ? `last synced ${relativeTime(info.last_synced_at, now) ?? formatDateTime(info.last_synced_at)}` : 'last sync time unknown')
  }
  return parts.join(' · ')
}

/** The Users-view header note: how far back "last used" can see and where it
 * reads from, summed up over every looked-up resource. Mixed answers (one
 * kind live-only, another from the archive) are said plainly, using the
 * narrowest window so "never" is never over-promised. */
export function coverageNote(infos: ResourceAccessInfo[], now: number): string | undefined {
  const seen = infos.filter(i => i.supported && i.coverage_from)
  if (seen.length === 0) return undefined
  const sources = [...new Set(seen.map(i => sourceLabel(i.source)))]
  const narrowest = seen.map(i => i.coverage_from as string).sort().at(-1) as string
  const synced = seen.find(i => i.last_synced_at)?.last_synced_at
  const parts = [
    `Last used reads ${sources.length === 1 ? sources[0] : `a mix of ${sources.join(' and ')}`}`,
    `covers ${dateOnly(narrowest)} to now`,
  ]
  if (synced) parts.push(`archive last synced ${relativeTime(synced, now) ?? formatDateTime(synced)}`)
  const note = seen.map(archiveNote).find(Boolean)
  return `${parts.join(' · ')}. It counts reveals, checkouts and credentials issued.${note ? ` ${note}` : ''}`
}

/** The short count chip: "12 uses · 90d". Nothing when there is no count or no use. */
export function usesChip(uses: number | undefined, windowDays: number | undefined): string | undefined {
  if (!uses) return undefined
  return `${uses} ${uses === 1 ? 'use' : 'uses'}${windowDays ? ` · ${windowDays}d` : ''}`
}
