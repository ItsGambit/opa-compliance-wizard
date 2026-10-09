import type { Environment } from '../types'
import { isAddressable } from './environmentRows'

/** Environments the caller can actually activate: their own, plus ones shared with them.
 *
 * Admins' /api/environments lists EVERY owner's environments, but activation
 * (serve.py activate_environment -> get_environment_credentials) only resolves
 * names visible to the caller -- own or shared -- so private environments of
 * other owners are left out here. Activation is by name, and the backend
 * prefers the caller's own environment over a same-named shared one, so a
 * name appears once, as the caller's own when both exist. Sorted by name. */
export function usableEnvironments(environments: Environment[] | undefined): Environment[] {
  const byName = new Map<string, Environment>()
  for (const env of environments ?? []) {
    // 5.40.7: the server's own answer (addressable) when it gives one --
    // exactly the rows a by-name activation (and a saved-session restore)
    // will accept.
    if (!isAddressable(env)) continue
    const existing = byName.get(env.name)
    if (!existing || (env.is_own && !existing.is_own)) byName.set(env.name, env)
  }
  return [...byName.values()].sort((a, b) => a.name.localeCompare(b.name))
}
