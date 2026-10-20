/** 5.48.0: what the browser remembers about the upgrade it just asked for, so the Updates page can show "Starting the upgrade ..."
 * from the moment the approval returns until the updater's state file names the request. Purely a display convenience: the server
 * holds the truth (state.json, the audit log). */
export interface RequestedUpgrade {
  correlationId: string; version: string; approvedAt: string; email: string | null; stepUp: boolean
  /** Absent = an upgrade ("apply"); else the operation the updater was asked for. */
  kind?: 'rollback' | 'restore' | 'clear_failure' | 'bundle' | 'prune_backups'
}

const KEY = 'opa.upgradeRequested'
const MAX_AGE_MS = 30 * 60_000

export function rememberRequested(r: RequestedUpgrade): void {
  try { sessionStorage.setItem(KEY, JSON.stringify(r)) } catch { /* storage unavailable: the page just polls the status */ }
}

export function readRequested(now = Date.now()): RequestedUpgrade | null {
  try {
    const raw = sessionStorage.getItem(KEY)
    if (!raw) return null
    const r = JSON.parse(raw) as RequestedUpgrade
    if (!r || typeof r.correlationId !== 'string' || typeof r.version !== 'string' || typeof r.approvedAt !== 'string') return null
    if (now - Date.parse(r.approvedAt) > MAX_AGE_MS) return null
    return r
  } catch { return null }
}

export function clearRequested(): void {
  try { sessionStorage.removeItem(KEY) } catch { /* nothing to clear */ }
}

const AUDIT_SEARCH_KEY = 'opa.auditSearch'

/** "View the N audit entries": leave the search text for the Audit Log page to pick up (once) and go there. */
export function openAuditLogFor(text: string, go: () => void = () => { window.location.hash = '#/audit_log' }): void {
  try { sessionStorage.setItem(AUDIT_SEARCH_KEY, text) } catch { /* the page just opens unfiltered */ }
  go()
}

export function takeAuditSearch(): string {
  try {
    const v = sessionStorage.getItem(AUDIT_SEARCH_KEY)
    if (v) sessionStorage.removeItem(AUDIT_SEARCH_KEY)
    return v ?? ''
  } catch { return '' }
}
