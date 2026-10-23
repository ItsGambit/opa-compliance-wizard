import type { AccessControlConfig, BannerConfig, EnvironmentFormValues, GrantUser, PermissionSetting, SharedCapabilityKey, SyncSchedule } from '../types'

/** 5.42.0: what the browser remembers across the step-up MFA round trip
 * (a full-page redirect to Okta and back, the same one the Access Control
 * save uses). The change itself is stored on the server; this only says
 * what to do on the way back, and keeps the user's unsaved form input so a
 * cancelled or failed approval loses nothing. Secrets (key secret, Okta API
 * token) are never kept here -- they wait on the server, in memory only,
 * and are re-entered if the approval doesn't complete. */
export type EnvironmentDraft = Omit<EnvironmentFormValues, 'key_secret' | 'okta_api_token'>
export type SyncDraft = { environmentId: string; schedule: SyncSchedule }
export type PermissionsDraft = {
  environmentId?: string
  user?: GrantUser
  settings: Partial<Record<SharedCapabilityKey, PermissionSetting>>
}
/** The screens a Settings unlock can return to (the one the user was opening, or had open when the window ran out). */
export type SettingsUnlockReopen =
  | 'settings' | 'updates' | 'environments' | 'shared_permissions' | 'orphaned_archives' | 'access_control' | 'banner' | 'sync_schedule'
const UNLOCK_REOPEN: readonly string[] = [
  'settings', 'updates', 'environments', 'shared_permissions', 'orphaned_archives', 'access_control', 'banner', 'sync_schedule',
]

export type PendingStepUp =
  | { kind: 'access_control' }
  // 5.53.0: the MFA that opens Settings or Updates (POST /api/settings/unlock). Nothing is applied by it: `reopen` is the
  // screen to open again once unlocked, with the user's unsaved input (never secrets) restored when the window ran out mid-edit.
  | {
      kind: 'settings_unlock'
      startedAt: number
      reopen: SettingsUnlockReopen
      environmentDraft?: EnvironmentDraft
      syncDraft?: SyncDraft
      permissionsDraft?: PermissionsDraft
      bannerDraft?: BannerConfig
      accessControlDraft?: AccessControlConfig
    }
  // 5.53.0: reserved for the evidence package build (the build itself ships later). The MFA that approves a build is a
  // different approval from the Settings unlock and never opens Settings.
  | {
      kind: 'evidence_package'
      startedAt: number
      environmentId: string
      /** UTC calendar dates, inclusive. */
      period: { start: string; end: string }
      gapsAcknowledged: boolean
    }
  | {
      kind: 'environment_change'
      action: string
      /** What the change was, for the result toast ("Share 'dev'"). */
      label: string
      startedAt: number
      /** Environment form input (never its secrets). */
      environmentDraft?: EnvironmentDraft
      /** Sync settings form input, and which environment it was for. */
      syncDraft?: SyncDraft
      /** Shared-permission settings being saved (environmentId absent =
       * the global defaults; user = one user's exceptions, 5.43.0). */
      permissionsDraft?: PermissionsDraft
      /** Announcement banner input (5.53.0: saving it needs MFA). */
      bannerDraft?: BannerConfig
      /** Access control input (5.53.0: restored after a Settings unlock). */
      accessControlDraft?: AccessControlConfig
      /** Which screen to reopen if the change wasn't applied. */
      reopen?: 'environments' | 'orphaned_archives' | 'shared_permissions' | 'updates' | 'banner' | 'access_control'
    }

/** The approvals the server knows (serve.py ENV_CHANGE_ACTION_TYPES, plus the Access Control save). Documentation for readers
 * of this file; the browser treats an action it does not know as an opaque label from the server. */
export type StepUpActionType =
  | 'environment.upsert' | 'environment.share' | 'environment.delete' | 'sync_schedule.update' | 'sync.reset_watermark'
  | 'sync.import_csv' | 'archive.purge' | 'shared_permissions.update' | 'upgrade.settings' | 'upgrade.request'
  | 'banner.update' | 'settings.unlock' | 'evidence_package.build' | 'access_control.update'

const KEY = 'opa.pendingStepUp'
/** Forget a draft older than the server's own pending-action lifetime. */
const MAX_AGE_MS = 15 * 60 * 1000

/** Defence in depth: whatever a caller passes, the two secrets never reach storage. */
function withoutSecrets(pending: PendingStepUp): PendingStepUp {
  if (pending.kind !== 'settings_unlock' && pending.kind !== 'environment_change') return pending
  if (!pending.environmentDraft) return pending
  const { key_secret: _s, okta_api_token: _t, ...rest } = pending.environmentDraft as EnvironmentDraft & Partial<EnvironmentFormValues>
  return { ...pending, environmentDraft: rest }
}

export function rememberStepUp(pending: PendingStepUp): void {
  try {
    sessionStorage.setItem(KEY, JSON.stringify(withoutSecrets(pending)))
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
    if (parsed?.kind === 'settings_unlock') {
      if (typeof parsed.startedAt !== 'number' || !UNLOCK_REOPEN.includes(parsed.reopen)) return null
      if (!includeStale && now - parsed.startedAt > MAX_AGE_MS) return null
      return parsed
    }
    if (parsed?.kind === 'evidence_package') {
      const period = parsed.period
      if (typeof parsed.startedAt !== 'number' || typeof parsed.environmentId !== 'string' || typeof parsed.gapsAcknowledged !== 'boolean') return null
      if (!period || typeof period.start !== 'string' || typeof period.end !== 'string') return null
      if (!includeStale && now - parsed.startedAt > MAX_AGE_MS) return null
      return parsed
    }
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

/** A Settings unlock that came back (finished or not) as the restore record the screens already understand: the dialog to
 * reopen and the input to put back. null when there is nothing to reopen ("settings", or the Updates page, which is a route). */
export function restoreFromUnlock(pending: Extract<PendingStepUp, { kind: 'settings_unlock' }>): Extract<PendingStepUp, { kind: 'environment_change' }> | null {
  if (pending.reopen === 'settings' || pending.reopen === 'updates') return null
  return {
    kind: 'environment_change', action: 'settings.unlock', label: 'Settings', startedAt: pending.startedAt,
    environmentDraft: pending.environmentDraft, syncDraft: pending.syncDraft, permissionsDraft: pending.permissionsDraft,
    bannerDraft: pending.bannerDraft, accessControlDraft: pending.accessControlDraft,
    reopen: pending.reopen === 'sync_schedule' ? 'environments' : pending.reopen,
  }
}

/** What App.tsx does on load (5.42.0): finish an Environments change the
 * gate just approved, report one whose approval never completed, or finish
 * the Access Control save (the original, and the default when nothing was
 * recorded -- e.g. a save started before this version). */
export function stepUpReturnAction(returned: boolean, pending: PendingStepUp | null):
  | 'finish_environment_change' | 'environment_change_abandoned' | 'finish_access_control'
  | 'finish_settings_unlock' | 'settings_unlock_abandoned' | 'finish_evidence_package' | 'evidence_package_abandoned' | null {
  if (pending?.kind === 'environment_change') return returned ? 'finish_environment_change' : 'environment_change_abandoned'
  // 5.53.0: the Settings unlock is finished by the same save route as every other approved change, but its own kind keeps
  // it from ever being taken for (or spent as) the Access Control save, and the other way round.
  if (pending?.kind === 'settings_unlock') return returned ? 'finish_settings_unlock' : 'settings_unlock_abandoned'
  if (pending?.kind === 'evidence_package') return returned ? 'finish_evidence_package' : 'evidence_package_abandoned'
  return returned ? 'finish_access_control' : null
}
