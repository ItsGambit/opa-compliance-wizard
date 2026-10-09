import type { Environment, EnvironmentsResponse, SharedCapabilityKey } from '../types'

/** UI-07 (external review, 2026-10-05): every action that goes by NAME
 * (activate, sync, reports) acts on whatever that name resolves to for the
 * caller. A row is addressable when that is this very row. The server says
 * so directly since 5.40.7; for an older server, the caller's own rows and
 * shared rows are (the old rule), other owners' private rows are not. */
export function isAddressable(env: Environment): boolean {
  return env.addressable ?? (env.is_own || env.shared)
}

/** The active row is compared by id (an admin sees several owners'
 * same-named rows; comparing names marked all of them active). Falls back
 * to name + addressable for a server without active_id. */
export function isActiveRow(env: Environment, data: EnvironmentsResponse | undefined): boolean {
  if (!data) return false
  if (data.active_id != null) return env.id === data.active_id
  return data.active != null && env.name === data.active && isAddressable(env)
}

/** 5.42.0: whether the caller may use `capability` on this environment --
 * mirrors the server's own answer (the row's `permissions`, resolved from
 * the admin's settings). The caller's own rows always may. A server older
 * than 5.42.0 sends no permissions: shared users could do everything
 * except the owner-only sync routes there, which is what this falls back to. */
export function can(env: Environment, capability: SharedCapabilityKey): boolean {
  if (env.is_own) return true
  // A row the caller's by-name routes don't reach carries no permissions on
  // purpose (5.42.0); it is never "allowed" by the older-server fallback.
  if (env.addressable === false) return false
  const effective = env.permissions?.[capability]
  if (effective) return effective.value === 'allow'
  return capability !== 'sync_now' && capability !== 'sync_settings'
}

/** Why a control is disabled for this environment ('' when it isn't). */
export function permissionReason(env: Environment, capability: SharedCapabilityKey): string {
  if (can(env, capability)) return ''
  return `Shared with you: an admin hasn't allowed shared users to ${CAPABILITY_VERBS[capability]} on '${env.name}'. Its owner can.`
}

const CAPABILITY_VERBS: Record<SharedCapabilityKey, string> = {
  view_archive: 'view its archived reports',
  live_read: 'run live queries',
  tenant_write: 'make changes in its OPA team or Okta org',
  import_csv: 'import a CSV into its archive',
  reset_watermark: 'reset its sync watermark',
  sync_now: 'run its sync',
  sync_settings: 'change its sync settings',
}

/** The compliance-sync dialog is offered when the caller may use any part
 * of it: owners always; shared users when an admin allowed Sync now or the
 * sync settings (before 5.42.0 it was owner-only, and that stays the
 * default). */
export function canManageSync(env: Environment): boolean {
  if (env.is_own) return true
  // Only on a row the name-keyed sync routes actually reach (UI-07): another
  // owner's private row or a shadowed shared one would act elsewhere.
  if (!env.shared || !isAddressable(env) || !env.permissions) return false
  return can(env, 'sync_now') || can(env, 'sync_settings')
}

/** The active environment's row, if the list has it. */
export function activeRow(data: EnvironmentsResponse | undefined): Environment | undefined {
  return data?.environments.find(e => isActiveRow(e, data))
}

/** The tenant the app is connected to, as one string (UI-05): the active
 * environment's id plus the fields that decide WHICH tenant it reaches.
 * Editing the active environment to another OPA team or Okta org keeps
 * its id but changes this, so cached tenant data is dropped then too.
 * The key id is deliberately left out: rotating the API key of the same
 * team must not reset the page (and an unsaved Folder Builder tree).
 * undefined while the list hasn't loaded. */
export function environmentScopeKey(data: EnvironmentsResponse | undefined): string | undefined {
  if (!data) return undefined
  const row = activeRow(data)
  const id = data.active_id ?? data.active ?? ''
  return row ? [id, row.base_domain, row.team_name, row.okta_url].join('|') : id
}
