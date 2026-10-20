/** 5.48.0: what the browser remembers about the upgrade it just asked for, so the Updates page can show "Starting the upgrade ..."
 * from the moment the approval returns until the updater's state file names the request. Purely a display convenience: the server
 * holds the truth (state.json, the audit log). */
export interface RequestedUpgrade { correlationId: string; version: string; approvedAt: string; email: string | null; stepUp: boolean }

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
