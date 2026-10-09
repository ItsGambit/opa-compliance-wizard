import type { PermissionSetting, PermissionSource, PermissionValue, SharedCapabilityKey } from '../types'

/** 5.42.0: shared-environment permission helpers shared by the global
 * defaults dialog and the per-environment editor. */

export const SOURCE_LABELS: Record<PermissionSource, string> = {
  owner: 'you own it',
  override: 'this environment’s override',
  default: 'the global default',
  built_in: 'the built-in default',
}

export function valueLabel(value: PermissionValue): string {
  return value === 'allow' ? 'Allowed' : 'Not allowed'
}

/** Only the settings that differ from what is stored now. */
export function changedSettings(
  stored: Partial<Record<SharedCapabilityKey, PermissionSetting>>,
  edited: Partial<Record<SharedCapabilityKey, PermissionSetting>>,
): Partial<Record<SharedCapabilityKey, PermissionSetting>> {
  const out: Partial<Record<SharedCapabilityKey, PermissionSetting>> = {}
  for (const [key, value] of Object.entries(edited) as [SharedCapabilityKey, PermissionSetting][]) {
    if ((stored[key] ?? 'inherit') !== value) out[key] = value
  }
  return out
}

/** What a capability would resolve to with this edited setting. */
export function resolvePreview(setting: PermissionSetting, inherited: PermissionValue): PermissionValue {
  return setting === 'inherit' ? inherited : setting
}
