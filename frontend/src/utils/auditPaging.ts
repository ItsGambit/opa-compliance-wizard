import type { AuditLogEntry } from '../types'

export const AUDIT_PAGE_SIZE = 50

/** Where the next page starts, plus the entry that must come right before
 * it (the last one already loaded). */
export interface AuditPageParam {
  offset: number
  anchor: string | null
}

/** The log was written to while paging: offsets count from the newest
 * entry, so new activity shifts every later page (duplicates or gaps). */
export class AuditLogShiftedError extends Error {
  constructor() {
    super('New audit activity arrived while loading older entries.')
    this.name = 'AuditLogShiftedError'
  }
}

export const entryFingerprint = (e: AuditLogEntry): string => JSON.stringify(e)

/** UI-13 follow-up: an older page is fetched with one entry of overlap and
 * accepted only if that overlap is exactly the last entry already shown --
 * otherwise the log moved under us and the caller reloads instead of
 * showing a duplicated or skipped entry in a compliance view. */
export async function fetchAuditPage(
  param: AuditPageParam,
  fetcher: (limit: number, offset: number) => Promise<{ entries: AuditLogEntry[] }>,
): Promise<{ entries: AuditLogEntry[] }> {
  if (param.offset === 0 || param.anchor === null) return fetcher(AUDIT_PAGE_SIZE, param.offset)
  const { entries } = await fetcher(AUDIT_PAGE_SIZE + 1, param.offset - 1)
  if (entries.length === 0 || entryFingerprint(entries[0]) !== param.anchor) throw new AuditLogShiftedError()
  return { entries: entries.slice(1) }
}

export function nextAuditPageParam(lastPage: { entries: AuditLogEntry[] }, allPages: { entries: AuditLogEntry[] }[]): AuditPageParam | undefined {
  if (lastPage.entries.length < AUDIT_PAGE_SIZE) return undefined
  const loaded = allPages.reduce((n, p) => n + p.entries.length, 0)
  return { offset: loaded, anchor: entryFingerprint(lastPage.entries[lastPage.entries.length - 1]) }
}
