// UI-06 (external review, 2026-10-05): the server's admin-only routes also
// serve the operator of a local-mode run (no login gate exists there), but
// is_admin is only ever true behind the hosted Okta gate -- so the UI used to
// hide the Audit Log and banner settings a local user could legitimately use.
// The server now reports can_admin directly; the fallback covers a server
// older than 5.40.3 (local => allowed, exactly as the server behaved).
export interface WhoamiFlags {
  is_local: boolean
  is_admin: boolean
  can_admin?: boolean
}

export function canAdminFrom(whoami: WhoamiFlags | undefined | null): boolean {
  if (!whoami) return false
  if (typeof whoami.can_admin === 'boolean') return whoami.can_admin
  return whoami.is_admin || whoami.is_local
}
