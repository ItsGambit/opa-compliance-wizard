import type { UpgradeKey, UpgradeStatus } from '../types'

/** Plain-language reason for a failed check (codes come from the server). */
export function describeCheckFailure(code: string | null): string {
  switch (code) {
    case 'network': return "the release server could not be reached (check this server's DNS, firewall and https_proxy)"
    case 'timeout': return 'the release server did not answer in time'
    case 'too_large': case 'truncated': case 'bad_json': case 'bad_response': return 'the release server sent an unusable answer'
    case 'redirect_refused': return 'the release server redirected to a host that is not allowed'
    case 'bad_url': return 'the configured release URL is not valid (it must be https://)'
    case 'http_403': case 'http_429': return 'the release server is rate limiting this address'
    default: return code ? `the release server answered with an error (${code})` : 'unknown reason'
  }
}

export function formatBytes(n: number | null | undefined): string {
  if (!n || n < 0) return ''
  if (n < 1024 * 1024) return `${Math.max(1, Math.round(n / 1024))} KB`
  if (n >= 1e9) return `${(n / 1e9).toFixed(1)} GB`     // GB = 10^9 bytes, as the server's preflight text writes it
  return `${(n / (1024 * 1024)).toFixed(1)} MB`
}

/** The state shown in the status badge of the Updates page. */
export type UpdateState = 'not_enabled' | 'off' | 'update_available' | 'up_to_date' | 'failed' | 'waiting'

export function updateState(status: UpgradeStatus): UpdateState {
  const { check, last_check: last } = status
  if (check.prompt_needed) return 'not_enabled'
  if (!check.enabled) return 'off'
  if (status.update_available) return 'update_available'
  if (last.consecutive_failures > 0) return 'failed'
  if (!last.at) return 'waiting'
  return 'up_to_date'
}

export function frequencyLabel(status: UpgradeStatus): string {
  const f = status.check.frequency
  if (status.check.source === 'env_on') return 'On (set by the server environment)'
  if (f === 'daily') return 'Daily'
  if (f === 'manual') return 'Manual only (when an admin clicks Check now)'
  return 'Off'
}

export function roleLabel(key: UpgradeKey): string {
  return key.role === 'release' ? 'Primary' : 'Standby'
}

/** The pinned release key that will verify a download (the active one), if any. */
export function activeReleaseKey(status: UpgradeStatus): UpgradeKey | undefined {
  return status.signing_keys.keys.find(k => k.role === 'release' && k.status === 'active')
}
