import type { UpgradeKey, UpgradeStatus } from '../types'

export const RELEASE_KEY: UpgradeKey = { key_id: 'E7620F1842B4E81F', role: 'release', alg: 'ed25519-minisign', status: 'active', since: '5.46.0', revoked_at: null }
export const STANDBY_KEY: UpgradeKey = { key_id: '3B9C41D0A7E2F518', role: 'standby', alg: 'es256', status: 'active', since: '5.46.0', revoked_at: null }

/** A complete, valid /api/upgrade/status answer (synthetic data); override any part. */
export function makeStatus(over: Partial<UpgradeStatus> = {}): UpgradeStatus {
  return {
    installed_version: '5.46.0',
    installed_at: '2026-10-12T03:02:00Z',
    check: { enabled: true, source: 'setting', env_locked: false, env_invalid_value: null, prompt_needed: false, share_version: false, mirror: false, frequency: 'daily', url: 'https://api.github.com/repos/example/opa-compliance-wizard/releases/latest' },
    latest: null,
    update_available: false,
    last_check: { at: '2026-10-19T09:00:00Z', status: 'ok', code: 'ok', next_at: '2026-10-20T09:00:00Z', consecutive_failures: 0, failing_since: null, by: null },
    signing_keys: { pinned: true, serial: 0, error: null, keys: [RELEASE_KEY, STANDBY_KEY] },
    revocation: null,
    server: { time: new Date().toISOString(), zone: 'UTC', utc_offset_minutes: 0 },
    ...over,
  }
}

export const NEWER = {
  latest: {
    version: '5.48.0', published_at: '2026-10-17T08:00:00Z', release_url: 'https://github.com/example/example/releases/tag/v5.48.0',
    signed_artifact: true, size: 15_500_000, notes_title: '5.48.0 — Example release', notes: 'First paragraph of the release notes.',
  },
  update_available: true,
}
