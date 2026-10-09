import { useEnvironments } from '../api/hooks'
import type { SharedCapabilityKey } from '../types'
import { activeRow, can, permissionReason } from '../utils/environmentRows'

/** 5.42.0: whether the caller may use `capability` on the ACTIVE
 * environment, and why not -- for controls that act through the active
 * session (Folder Builder, Access Explorer). Mirrors the server, which
 * enforces it; true while the list is loading or for a server without
 * permissions (the server answers for itself then). */
export function useActiveCapability(capability: SharedCapabilityKey): { allowed: boolean; reason: string } {
  const { data } = useEnvironments()
  const row = activeRow(data)
  if (!row) return { allowed: true, reason: '' }
  return { allowed: can(row, capability), reason: permissionReason(row, capability) }
}
