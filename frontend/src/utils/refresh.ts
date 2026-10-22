import type { RefreshPart, RefreshPartName, RefreshPartState, RefreshRecord, RefreshStatus } from '../types'

// The combined Refresh (5.51.0): one vocabulary for the Overview, the footer, the Access Explorer and the toasts.
// The server writes every outcome message; this file only names the parts, the states and the one-line summaries.

/** The order the progress card lists the parts in (the OPA scan and the System Log run side by side; the Okta scan follows). */
export const REFRESH_DISPLAY_ORDER: RefreshPartName[] = ['opa', 'log', 'okta']

export const REFRESH_PART_LABELS: Record<RefreshPartName, { name: string; sub: string }> = {
  opa: { name: 'OPA scan', sub: 'roster, policies, resources, devices' },
  log: { name: 'System Log', sub: 'archive sync' },
  okta: { name: 'Okta scan', sub: 'admin roles · lifecycle status · counts · sign-in figures' },
}

export const OKTA_SUB_LABELS: Record<string, string> = {
  admins: 'Admin role holders',
  principal_status: 'Okta status of each OPA principal',
  inventory: 'Inventory counts',
  mfa_aggregates: 'Sign-in and MFA figures from the archive',
}

export const OPA_SCAN_STALE_HOURS = 24
export const OPA_SCAN_VERY_STALE_DAYS = 7
export const OVERVIEW_PATH = '#/overview'
/** Refresh toasts stay at least 10 s (WCAG 2.2.1): the progress card keeps the same information. */
export const REFRESH_TOAST_MS = 10_000

export const ACTIVE_PART_STATES: RefreshPartState[] = ['pending', 'running']
const FAILED_STATES: RefreshPartState[] = ['refused', 'error', 'timed_out', 'partial', 'cancelled']

export function isActive(state: RefreshPartState | undefined): boolean {
  return state === 'pending' || state === 'running'
}

export function isFailed(state: RefreshPartState | undefined): boolean {
  return state != null && FAILED_STATES.includes(state)
}

/** The badge text of a part state. Colour is never the only signal: every badge says its state in words (WCAG 1.4.1). */
export function stateBadge(part: RefreshPart): { label: string; tone: 'ok' | 'warn' | 'error' | 'accent' | 'neutral' } {
  switch (part.state) {
    case 'ok':
      return (part.warnings ?? 0) > 0 ? { label: `Completed with ${part.warnings} unreadable section${part.warnings === 1 ? '' : 's'}`, tone: 'warn' } : { label: 'Completed', tone: 'ok' }
    case 'running': return { label: 'Running', tone: 'accent' }
    case 'pending': return { label: 'Waiting', tone: 'neutral' }
    case 'refused': return { label: 'Refused', tone: 'error' }
    case 'error': return { label: 'Failed', tone: 'error' }
    case 'timed_out': return { label: 'Timed out', tone: 'error' }
    case 'partial': return { label: 'Stopped early', tone: 'warn' }
    case 'cancelled': return { label: 'Stopped', tone: 'warn' }
    case 'skipped': return { label: 'Skipped', tone: 'neutral' }
    default: return { label: 'Not requested', tone: 'neutral' }
  }
}

/** "refused", "failed", ... for a sentence ("Okta scan refused."). */
export function stateWords(state: RefreshPartState): string {
  return ({ refused: 'refused', error: 'failed', skipped: 'was skipped', cancelled: 'was stopped', timed_out: 'timed out', partial: 'stopped early', pending: 'did not run', running: 'is still running', ok: 'completed', not_requested: 'was not requested' } as Record<string, string>)[state] ?? state
}

export function requestedParts(status: RefreshStatus): RefreshPartName[] {
  return REFRESH_DISPLAY_ORDER.filter(p => status.parts_requested.includes(p))
}

/** { done, total, failing } over the parts the job was asked to run. */
export function tally(status: RefreshStatus) {
  const parts = requestedParts(status)
  const failing = parts.filter(p => status.parts[p].state !== 'ok')
  return { total: parts.length, done: parts.length - failing.length, failing }
}

/** "all three parts completed" / "2 of 3 parts completed". */
export function completedText(done: number, total: number): string {
  if (total === 1) return done === 1 ? 'completed' : 'did not complete'
  return done === total ? `all ${total === 3 ? 'three' : total} parts completed` : `${done} of ${total} parts completed`
}

/** The audit entries a refresh wrote, as the success toast lists them ("Audit Log: refresh.started, access_scan.completed, ..."). */
export function auditLine(status: RefreshStatus): string {
  const parts = requestedParts(status)
  const names = ['refresh.started']
  if (parts.includes('opa')) names.push('access_scan.completed')
  if (parts.includes('log')) names.push(status.trigger === 'scheduled' ? 'sync.scheduled_completed' : 'sync.manual_completed')
  if (parts.includes('okta')) {
    const ok = Object.values(status.parts.okta.sub ?? {}).filter(x => x.state === 'ok').length
    if (ok > 0) names.push(`okta_snapshot.captured ×${ok}`)
  }
  names.push('refresh.completed')
  return `Audit Log: ${names.join(', ')}.`
}

/** "all three parts completed" (the sources strip's wording) next to completedText's "all 3 parts completed". */
export function completedWords(done: number, total: number): string {
  return total === 3 && done === 3 ? 'all three parts completed' : completedText(done, total)
}

/** "13th". */
export function ordinal(n: number): string {
  const mod100 = n % 100
  if (mod100 >= 11 && mod100 <= 13) return `${n}th`
  return `${n}${({ 1: 'st', 2: 'nd', 3: 'rd' } as Record<number, string>)[n % 10] ?? 'th'}`
}

/** "08:48": a time on the same day as a time already shown with its date and zone. */
export function formatTimeOnly(iso: string | null | undefined): string {
  if (!iso) return ''
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
}

/** "4 Sep 2025". */
export function formatDayYear(iso: string | null | undefined): string {
  if (!iso) return ''
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? String(iso) : d.toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' })
}

/** The finish toast (the Overview and every other page use the same words). */
export function finishToast(status: RefreshStatus): { title: string; description?: string; variant: 'success' | 'warning' } {
  const t = tally(status)
  if (t.total === 1) {
    const only = t.failing.length === 0 ? null : t.failing[0]
    const label = REFRESH_PART_LABELS[requestedParts(status)[0]].name
    return only ? { title: `Refresh finished: ${label} ${stateWords(status.parts[only].state)}`, description: 'The data from before is kept. Details are on the Overview.', variant: 'warning' }
      : { title: `Refresh finished: ${label} completed`, variant: 'success' }
  }
  if (t.failing.length === 0) return { title: `Refresh finished: ${completedText(t.done, t.total)}`, description: auditLine(status), variant: 'success' }
  return {
    title: `Refresh finished: ${completedText(t.done, t.total)}`,
    description: `${t.failing.map(p => `${REFRESH_PART_LABELS[p].name} ${stateWords(status.parts[p].state)}.`).join(' ')} The figures from the other parts are updated.`,
    variant: 'warning',
  }
}

/** What a screen reader hears when one part reaches an end state (never every step: that would be noise). */
export function partAnnouncement(part: RefreshPartName, data: RefreshPart): string {
  const label = REFRESH_PART_LABELS[part].name
  if (data.state === 'ok') return (data.warnings ?? 0) > 0 ? `${label} completed with ${data.warnings} unreadable section${data.warnings === 1 ? '' : 's'}.` : `${label} completed.`
  return `${label} ${stateWords(data.state)}.${data.message ? ` ${data.message}` : ''}`
}

/** The newest finished refresh the server remembers (the live job, or the stored scheduled / manual record). */
export function latestRefresh(live: RefreshStatus | undefined, stored: { scheduled?: RefreshRecord | null; manual?: RefreshRecord | null } | null | undefined): { finishedAt: string; done: number; total: number; failing: string[] } | null {
  const candidates: { finishedAt: string; parts: Partial<Record<RefreshPartName, { state: RefreshPartState }>> }[] = []
  if (live && live.status === 'done' && live.finished_at) {
    candidates.push({ finishedAt: live.finished_at, parts: Object.fromEntries(requestedParts(live).map(p => [p, live.parts[p]])) })
  }
  for (const record of [stored?.scheduled, stored?.manual]) if (record?.finished_at) candidates.push({ finishedAt: record.finished_at, parts: record.parts })
  if (candidates.length === 0) return null
  const newest = candidates.reduce((a, b) => (a.finishedAt >= b.finishedAt ? a : b))
  const entries = REFRESH_DISPLAY_ORDER.filter(p => newest.parts[p])
  const failing = entries.filter(p => newest.parts[p]!.state !== 'ok').map(p => REFRESH_PART_LABELS[p].name)
  return { finishedAt: newest.finishedAt, done: entries.length - failing.length, total: entries.length, failing }
}

/** "2 min 12 s" from two timestamps (the end defaults to now). */
export function elapsedText(startIso: string | undefined, endIso: string | undefined, now: number): string {
  if (!startIso) return ''
  const start = new Date(startIso).getTime()
  const end = endIso ? new Date(endIso).getTime() : now
  if (Number.isNaN(start) || Number.isNaN(end)) return ''
  const total = Math.max(0, Math.round((end - start) / 1000))
  const m = Math.floor(total / 60)
  const s = total % 60
  return m > 0 ? `${m} min ${String(s).padStart(2, '0')} s` : `${s} s`
}

/** Age of a stored scan as an "as of" status: 'current' under 24 h, 'stale' from 24 h, 'very_stale' from 7 days. */
export function scanFreshness(builtAt: string | null | undefined, now: number): 'current' | 'stale' | 'very_stale' | 'unknown' {
  if (!builtAt) return 'unknown'
  const t = new Date(builtAt).getTime()
  if (Number.isNaN(t)) return 'unknown'
  const hours = (now - t) / 3_600_000
  if (hours >= OPA_SCAN_VERY_STALE_DAYS * 24) return 'very_stale'
  if (hours >= OPA_SCAN_STALE_HOURS) return 'stale'
  return 'current'
}

/** "6 h ago" / "2 days ago": the compact age beside a time. */
export function ageText(iso: string | null | undefined, now: number): string {
  if (!iso) return ''
  const t = new Date(iso).getTime()
  if (Number.isNaN(t)) return ''
  const minutes = Math.max(0, Math.floor((now - t) / 60_000))
  if (minutes < 1) return 'just now'
  if (minutes < 60) return `${minutes} min ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 48) return `${hours} h ago`
  return `${Math.floor(hours / 24)} days ago`
}

/** The badge words for the stale states: "Stale · 2 days", "Very stale · 9 days". */
export function staleBadgeText(builtAt: string, now: number): string | null {
  const f = scanFreshness(builtAt, now)
  if (f !== 'stale' && f !== 'very_stale') return null
  const days = Math.max(1, Math.floor((now - new Date(builtAt).getTime()) / 86_400_000))
  return `${f === 'stale' ? 'Stale' : 'Very stale'} · ${days} day${days === 1 ? '' : 's'}`
}
