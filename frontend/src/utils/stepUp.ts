import type { EnvironmentFormValues, PermissionSetting, SharedCapabilityKey, SyncSchedule } from '../types'

/** 5.42.0: what the browser remembers across the step-up MFA round trip
 * (a full-page redirect to Okta and back, the same one the Access Control
 * save uses). The change itself is stored on the server; this only says
 * what to do on the way back, and keeps the user's unsaved form input so a
 * cancelled or failed approval loses nothing. Secrets (key secret, Okta API
 * token) are never kept here -- they wait on the server, in memory only,
 * and are re-entered if the approval doesn't complete. */
export type PendingStepUp =
  | { kind: 'access_control' }
  | {
      kind: 'environment_change'
      action: string
      /** What the change was, for the result toast ("Share 'dev'"). */
      label: string
      startedAt: number
      /** Environment form input (never its secrets). */
      environmentDraft?: Omit<EnvironmentFormValues, 'key_secret' | 'okta_api_token'>
      /** Sync settings form input, and which environment it was for. */
      syncDraft?: { environmentId: string; schedule: SyncSchedule }
      /** Shared-permission settings being saved (environmentId absent =
       * the global defaults). */
      permissionsDraft?: { environmentId?: string; settings: Partial<Record<SharedCapabilityKey, PermissionSetting>> }
      /** Which screen to reopen if the change wasn't applied. */
      reopen?: 'environments' | 'orphaned_archives' | 'shared_permissions'
    }

const KEY = 'opa.pendingStepUp'
/** Forget a draft older than the server's own pending-action lifetime. */
const MAX_AGE_MS = 15 * 60 * 1000

export function rememberStepUp(pending: PendingStepUp): void {
  try {
    sessionStorage.setItem(KEY, JSON.stringify(pending))
  } catch {
    // Storage unavailable (private mode, quota): the change still applies
    // on the way back; only the "restore my form" convenience is lost.
  }
}

/** The recorded round trip, or null. `includeStale` keeps an Environments
 * record older than the server's own pending-action lifetime: on the way
 * back from the gate the right save must still be called (the server then
 * says "expired"), never the Access Control one by default. */
export function readPendingStepUp(now = Date.now(), includeStale = false): PendingStepUp | null {
  let raw: string | null = null
  try {
    raw = sessionStorage.getItem(KEY)
  } catch {
    return null
  }
  if (!raw) return null
  try {
    const parsed = JSON.parse(raw) as PendingStepUp
    if (parsed?.kind === 'access_control') return parsed
    if (parsed?.kind !== 'environment_change' || typeof parsed.action !== 'string') return null
    if (typeof parsed.startedAt !== 'number') return null
    if (!includeStale && now - parsed.startedAt > MAX_AGE_MS) return null
    return parsed
  } catch {
    return null
  }
}

export function clearPendingStepUp(): void {
  try {
    sessionStorage.removeItem(KEY)
  } catch {
    // nothing to clear
  }
}

/** Leaves the page for the gate's step-up (fresh MFA) sign-in, approving
 * exactly the change the server stored under `actionId`. */
export function beginStepUp(actionId: string, pending: PendingStepUp, navigate: (url: string) => void = url => { window.location.href = url }): void {
  rememberStepUp(pending)
  navigate(`/step-up?action_id=${encodeURIComponent(actionId)}`)
}

/** The environment form's input minus its secrets. */
export function environmentDraftFrom(values: EnvironmentFormValues): Omit<EnvironmentFormValues, 'key_secret' | 'okta_api_token'> {
  const { key_secret: _secret, okta_api_token: _token, ...rest } = values
  return rest
}

/** What App.tsx does on load (5.42.0): finish an Environments change the
 * gate just approved, report one whose approval never completed, or finish
 * the Access Control save (the original, and the default when nothing was
 * recorded -- e.g. a save started before this version). */
export function stepUpReturnAction(returned: boolean, pending: PendingStepUp | null):
  'finish_environment_change' | 'environment_change_abandoned' | 'finish_access_control' | null {
  if (pending?.kind === 'environment_change') return returned ? 'finish_environment_change' : 'environment_change_abandoned'
  return returned ? 'finish_access_control' : null
}
