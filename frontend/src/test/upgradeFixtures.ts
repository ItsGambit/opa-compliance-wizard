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

import type { UpgradePreview, UpgradeRun, UpgradeView } from '../types'

export const TARGET_SHA = '9f1c3a7e4d20b86f5a91c0e7d3b2a48f6e15c9d07a3b84e2f1d6c5a9b0e74f2d'

/** A complete, valid signed-release review (synthetic data): 5.46.0 -> 5.48.0 with one rollback-safe and one unsafe migration. */
export function makePreview(over: Partial<UpgradePreview> = {}): UpgradePreview {
  return {
    version: '5.48.0', installed_version: '5.46.0', sha256: TARGET_SHA, file: 'ocw-5.48.0.tar.gz', size: 15_500_000,
    key_id: RELEASE_KEY.key_id, key_status: 'active', key_since: '5.46.0', key_role: 'release', signed_at: '2026-10-17T08:00:00Z',
    manifest: {
      min_upgrade_from: '5.45.0', downtime_estimate_seconds: 45,
      migrations: [{ version: 10, since: '5.48.0', rollback_safe: true, description: 'Adds the upgrade_schedule table' }, { version: 11, since: '5.48.0', rollback_safe: false, description: 'Rebuilds the event index for faster range queries' }],
      expected_schema_version: 11, changelog_excerpt: '5.48.0 — In-app upgrade flow\nUpgrade from the Updates page.', nginx_template_changed: true,
      activator_version: '5.48.0', built_at: '2026-10-17T07:00:00Z',
    },
    manifest_source: "The release's manifest.json asset (not itself signed; the updater re-verifies the signed copy inside the archive before installing)",
    checked_at: '2026-10-19T15:52:00Z', db_bytes: 1_100_000_000,
    preflight: [
      { id: 'disk_opt', ok: true, text: 'Disk, code volume: 41.2 GB free; 0.1 GB needed.' },
      { id: 'disk_data', ok: true, text: 'Disk, data volume: 118.0 GB free; 3.4 GB needed.' },
      { id: 'python', ok: true, text: 'Python 3.12.6 (needs 3.9.0 or newer).' },
      { id: 'sqlite', ok: true, text: 'SQLite 3.46.1 (needs 3.35.0 or newer).' },
      { id: 'sync', ok: true, text: 'No sync is running.' },
      { id: 'in_flight', ok: true, text: 'No other upgrade is in flight.' },
      { id: 'updater', ok: true, text: 'Updater present: ocw-updater 5.48.0, activator 5.48.0. No other upgrade in flight.' },
    ],
    preflight_ok: true,
    ...over,
  }
}

export function makeRun(over: Partial<UpgradeRun> = {}): UpgradeRun {
  return {
    correlation_id: 'upg-7f3a9c2e', action: 'apply', version_from: '5.46.0', version_to: '5.48.0', step: 'completed', result: 'completed', reason_code: null,
    started_at: '2026-10-21T02:30:02Z', updated_at: '2026-10-21T02:30:54Z', seconds: 52, failed_step: null, operator_reason: null, bundle: null,
    schema_before: 9, schema_after: 11, steps_done: [], health: [], rollback_health: [], rolled_back_to: null, rollback_seconds: null, failure: null,
    signed_by: RELEASE_KEY.key_id, sha256: TARGET_SHA, requested_by: 'admin@example.com',
    backup: { name: 'audit_store-pre-5.48.0-20261021T023005Z.db', size: 1_100_000_000, integrity: 'ok' },
    manifest: { migrations: [{ version: 10, since: '5.48.0', rollback_safe: true }, { version: 11, since: '5.48.0', rollback_safe: false }], expected_schema_version: 11 },
    ...over,
  }
}

/** The 5.48.0 `upgrade` block of /api/upgrade/status with a working updater and nothing happening. */
export function makeUpgrade(over: Partial<UpgradeView> = {}): UpgradeView {
  return {
    run: null, updater: { ready: true, reason: null, activator: '5.48.0', message: '' }, preview: null, schedule: null, last: null, pending_approval: null,
    settings: { second_approval: false }, rejection: null, rollback: null, failures: {}, history: [], zone: { iana: 'Europe/London' },
    sync_hint: { last_sync_completed_at: '2026-10-19T02:14:00Z', daily_run_times_utc: ['03:00'] }, step_up_required: true, now: new Date().toISOString(),
    ...over,
  }
}
