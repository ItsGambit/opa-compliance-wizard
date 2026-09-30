import type { SyncStepEvent } from '../types'

/** Real percent complete for a running compliance sync, derived from
 * actual date-window coverage (not an animated/fake bar) -- a backfill
 * walks day-by-day (see audit_store.sync_okta_events), and each "fetch"
 * step's detail is "<chunk_since> .. <chunk_until>" ISO timestamps.
 * Percent = how far the chunk_until of the most recent step has advanced
 * from the very first step's chunk_since, relative to now. Returns null
 * when there isn't yet enough data to compute a real number (no fetch
 * steps, or a degenerate start==now window) -- callers should fall back
 * to a small fixed value in that case rather than showing 0%, since a
 * sync has genuinely started even before the first step lands.
 *
 * Extracted from SyncScheduleDialog's original inline computation so the
 * footer's own "Sync now" trigger (Footer.tsx) can show the same real
 * bar without duplicating the math. */
export function getSyncProgressPercent(steps: SyncStepEvent[]): number | null {
  const fetchSteps = steps.filter(s => s.key === 'fetch' && s.detail)
  if (fetchSteps.length === 0) return null
  const firstSince = fetchSteps[0].detail!.split(' .. ')[0]
  const lastUntil = fetchSteps[fetchSteps.length - 1].detail!.split(' .. ')[1]
  const start = new Date(firstSince).getTime()
  const current = new Date(lastUntil).getTime()
  const end = Date.now()
  if (!Number.isFinite(start) || !Number.isFinite(current) || end <= start) return null
  return Math.min(100, Math.round(((current - start) / (end - start)) * 100))
}
