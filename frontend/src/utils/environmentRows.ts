import type { Environment, EnvironmentsResponse } from '../types'

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

/** Sync settings and "Sync now" are owner-only on the server (the schedule
 * routes resolve the caller's OWN environment by name), so they are offered
 * only on rows the caller owns -- a shared row's controls always 404ed,
 * and an admin's controls on another owner's row changed the admin's own
 * same-named schedule. */
export function canManageSync(env: Environment): boolean {
  return env.is_own
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
