import type {
  GrantUser, PermissionSetting, PermissionSource, PermissionValue, SharedCapabilityKey, SharedPermissionGrant,
} from '../types'

/** 5.42.0: shared-environment permission helpers shared by the global
 * defaults dialog and the per-environment editor. */

export const SOURCE_LABELS: Record<PermissionSource, string> = {
  owner: 'you own it',
  user: 'an exception for you',
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

/** 5.43.0: per-user exception helpers. */
export function userKey(user: GrantUser): string {
  return `${user.issuer} ${user.subject}`
}

/** The Okta org part of an issuer, for display ("login.example.com"). */
export function orgLabel(issuer: string): string {
  try {
    return new URL(issuer).host
  } catch {
    return issuer
  }
}

/** One entry per user with at least one exception, in the server's order. */
export function groupGrants(grants: SharedPermissionGrant[]): { user: GrantUser; email: string | null; grants: SharedPermissionGrant[] }[] {
  const out = new Map<string, { user: GrantUser; email: string | null; grants: SharedPermissionGrant[] }>()
  for (const g of grants) {
    const key = userKey(g)
    if (!out.has(key)) out.set(key, { user: { issuer: g.issuer, subject: g.subject }, email: g.email, grants: [] })
    out.get(key)!.grants.push(g)
  }
  return [...out.values()]
}

/** 5.43.0 (SP-5): an additional login address's nginx site refuses the
 * whole-backend admin screens (shared permissions, orphaned archives) with
 * its own 403 page, which carries no JSON error -- say why instead of
 * "Request failed with status 403". */
export function mainAddressOnly(error: unknown): unknown {
  // Duck-typed (an ApiError has status + body) so this module needn't import the API client.
  const e = error as { status?: unknown; body?: { error?: unknown } } | null
  if (error instanceof Error && e?.status === 403 && !e.body?.error) {
    return new Error('This setting can only be changed from the main login address, not this one.')
  }
  return error
}
