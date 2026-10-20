import type { UpgradeRun, UpgradeStatus } from '../types'

/** The steps of an upgrade, in the order the updater runs them (server/updater/root/ocw_activate.py STEP_ORDER). */
export const UPGRADE_STEPS: { id: string; title: string; pending: string }[] = [
  { id: 'validated', title: 'Received and validated', pending: 'The updater checks the request: schema, version, hash, approval id unseen, nothing else in flight.' },
  { id: 'downloaded', title: 'Downloaded', pending: 'The signed release is fetched (or taken from a file an operator brought).' },
  { id: 'staged', title: 'Verified and staged', pending: 'Signature, then every file hash against the manifest; Python packages installed with hash pinning.' },
  { id: 'preflight', title: 'Preflight', pending: 'Free space, no sync running, nginx configuration.' },
  { id: 'backup', title: 'Backup', pending: 'The archive is copied with SQLite\'s online backup and integrity-checked.' },
  { id: 'switching', title: 'Switching', pending: 'Maintenance page in place; the current and previous releases swapped by an atomic rename.' },
  { id: 'restarting', title: 'Restarting', pending: 'The app, then the login gates, then host-status. Schema migrations run on start-up. This page loses the server for under a minute and waits.' },
  { id: 'health_check', title: 'Health checks', pending: 'Eight checks on the new release; if any fails the previous code is put back automatically.' },
  { id: 'completed', title: 'Completed', pending: 'Maintenance page removed, updater updates itself, older release pruned.' },
]

export const HEALTH_CHECK_LABELS: Record<string, string> = {
  unit_active: 'Service unit active, no restarts',
  version: '/api/version answers the new version from a new process',
  healthz: '/healthz not worse than before',
  gate_401: 'Login gate /verify answers 401 to an anonymous request',
  quick_check: 'Database quick_check ok',
  schema_version: 'Schema version as the release expects',
  chain_heads: 'Audit chain heads unchanged',
  smoke_read: 'Authenticated smoke read of /api/environments = 200',
}

export const HEALTH_CHECK_ORDER = Object.keys(HEALTH_CHECK_LABELS)

/** True while the updater has a run in flight (state.json has a step and no result yet). */
export function isRunning(run: UpgradeRun | null | undefined): boolean {
  return !!run && run.result === null && !!run.step
}

export function isFailureResult(run: UpgradeRun | null | undefined): boolean {
  return !!run && (run.result === 'rolled_back' || run.result === 'failed' || run.result === 'failed_needs_operator') && run.action === 'apply'
}

/** Current step number (1-based, of 9) for the "Step 6 of 9" badge. */
export function stepNumber(run: UpgradeRun): number {
  const idx = UPGRADE_STEPS.findIndex(s => s.id === run.step)
  if (idx >= 0) return idx + 1
  const done = run.steps_done?.length ?? 0
  return Math.min(Math.max(done, 1), UPGRADE_STEPS.length)
}

/** Plain-language reason for a stable reason code (server/updater/root/ocw_activate.py REASONS). */
export function describeReason(code: string | null | undefined): string {
  switch (code) {
    case 'signature_invalid': return 'the release signature did not verify'
    case 'key_unknown': return 'the release was signed by a key this server does not trust'
    case 'revoked_key': case 'retired_key': return 'the release was signed by a key that is no longer accepted'
    case 'version_not_newer': return 'the release is not newer than the installed version'
    case 'hash_mismatch': return 'the downloaded file does not match the signed hash'
    case 'too_old': return 'this release cannot be installed over the installed version (upgrade to an intermediate release first)'
    case 'disk_space': return 'there was not enough free disk space'
    case 'sync_in_progress': return 'a sync was still running after 10 minutes'
    case 'pip_failed': return 'the Python packages could not be installed'
    case 'migration_failed': return 'a schema migration failed'
    case 'nginx_invalid': return 'the nginx configuration of the release did not validate'
    case 'request_replayed': return 'this approval was already used'
    case 'request_stale': return 'the request was too old'
    case 'in_flight': return 'another upgrade was in progress'
    case 'version_failed_before': return 'this version failed before; an operator must clear the failure on the server first'
    case 'too_many_failures': return 'two upgrades have failed; contact the maintainers with the support bundle'
    case 'rollback_failed': return 'the automatic rollback failed; an operator must act on the server'
    case 'interrupted': return 'the updater was interrupted (power loss or kill) before finishing'
    case 'health_unit': case 'health_version': case 'health_healthz': case 'health_gate': case 'health_quick_check':
    case 'health_schema': case 'health_chain': case 'health_smoke': return 'a health check failed after the restart'
    default: return code ? `reason code ${code}` : 'unknown reason'
  }
}

// ── Time zones ────────────────────────────────────────────────────────────

/** The browser's IANA zone. */
export function browserZone(): string {
  try { return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC' } catch { return 'UTC' }
}

function partsIn(zone: string, ms: number): Record<string, number> {
  const f = new Intl.DateTimeFormat('en-US', {
    timeZone: zone, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
  const out: Record<string, number> = {}
  for (const p of f.formatToParts(new Date(ms))) if (p.type !== 'literal') out[p.type] = Number(p.value)
  return out
}

/** Offset of `zone` from UTC at instant `ms`, in minutes (+60 for BST). */
export function zoneOffsetMinutes(zone: string, ms: number): number {
  const p = partsIn(zone, ms)
  const asUtc = Date.UTC(p.year, p.month - 1, p.day, p.hour, p.minute, p.second)
  return Math.round((asUtc - Math.floor(ms / 1000) * 1000) / 60000)
}

/** The instant (UTC ms) at which the wall clock in `zone` reads `date` (YYYY-MM-DD) `time` (HH:MM). NaN if malformed.
 * Wall times skipped by a clock change resolve forward; repeated ones to the first. */
export function wallToUtc(date: string, time: string, zone: string): number {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(date)
  const t = /^(\d{2}):(\d{2})$/.exec(time)
  if (!m || !t) return NaN
  const [y, mo, d, h, mi] = [m[1], m[2], m[3], t[1], t[2]].map(Number)
  const naive = Date.UTC(y, mo - 1, d, h, mi)
  // reject overflow ("2026-13-45", "99:99"): the fields must survive the round trip
  const back = new Date(naive)
  if (Number.isNaN(naive) || back.getUTCFullYear() !== y || back.getUTCMonth() !== mo - 1 || back.getUTCDate() !== d || h > 23 || mi > 59) return NaN
  try {
    let guess = naive - zoneOffsetMinutes(zone, naive) * 60000
    guess = naive - zoneOffsetMinutes(zone, guess) * 60000
    return guess
  } catch { return NaN }
}

/** "Wed 21 Oct 2026, 03:30 BST (UTC+1)". The abbreviation is shown only when the browser has a real one (not "GMT+1"). */
export function formatInZone(ms: number, zone: string): string {
  try {
    const parts: Record<string, string> = {}
    for (const p of new Intl.DateTimeFormat('en-GB', {
      timeZone: zone, weekday: 'short', day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', hourCycle: 'h23', timeZoneName: 'short',
    }).formatToParts(new Date(ms))) parts[p.type] = p.value
    const off = zoneOffsetMinutes(zone, ms)
    const abs = Math.abs(off)
    const offText = `UTC${off < 0 ? '−' : '+'}${Math.floor(abs / 60)}${abs % 60 ? ':' + String(abs % 60).padStart(2, '0') : ''}`
    const name = parts.timeZoneName && !/^(GMT|UTC)/.test(parts.timeZoneName) ? ` ${parts.timeZoneName}` : ''
    return `${parts.weekday} ${parts.day} ${parts.month} ${parts.year}, ${parts.hour}:${parts.minute}${name} (${offText})`
  } catch { return new Date(ms).toISOString() }
}

/** "2026-10-21 02:30" (UTC), what is stored and logged. */
export function formatUtc(ms: number): string {
  return new Date(ms).toISOString().slice(0, 16).replace('T', ' ')
}

export function toIsoUtc(ms: number): string {
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z')
}

/** "In 1 day 11 h" / "In 35 min" / "Now". */
export function untilText(ms: number, now = Date.now()): string {
  const diff = Math.max(0, ms - now)
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'Now'
  if (mins < 60) return `In ${mins} min`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `In ${hours} h${mins % 60 ? ` ${mins % 60} min` : ''}`
  const days = Math.floor(hours / 24)
  return `In ${days} day${days === 1 ? '' : 's'} ${hours % 24} h`
}

/** The zone the server's clock uses (IANA name when the server told us, else null). */
export function serverZoneOf(status: UpgradeStatus): string | null {
  return status.upgrade?.zone.iana ?? null
}

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds == null) return ''
  if (seconds < 90) return `${Math.round(seconds)} s`
  return `${Math.floor(seconds / 60)} min ${Math.round(seconds % 60)} s`
}

/** Short hash as the mockups show it: first 8 … last 4. */
export function shortSha(sha: string | null | undefined): string {
  return sha && sha.length > 12 ? `${sha.slice(0, 8)}…${sha.slice(-4)}` : sha ?? ''
}

/** The wall-clock date/time fields (YYYY-MM-DD, HH:MM) at instant `ms` in `zone`. */
export function wallFields(ms: number, zone: string): { date: string; time: string } {
  const iso = new Date(ms + zoneOffsetMinutes(zone, ms) * 60000).toISOString()
  return { date: iso.slice(0, 10), time: iso.slice(11, 16) }
}

/** Why the Upgrade / Schedule buttons are off, in words (null = they are on). */
export function blockReason(status: UpgradeStatus, reviewing: boolean): string | null {
  const u = status.upgrade
  const latest = status.latest
  if (!u || !latest) return 'Upgrading from this page needs the newer server.'
  if (!u.updater.ready) return u.updater.message
  if (u.run?.result === 'failed_needs_operator') return 'The last upgrade could not be rolled back automatically. An operator must act on the server (ocw-updater status) before another upgrade.'
  if (u.run && u.run.result === null && u.run.step) return 'An upgrade is in progress.'
  const f = u.failures
  if ((f[latest.version]?.count ?? 0) >= 1) return `${latest.version} failed here before. An operator must run "ocw-updater clear-failure" on the server before it is tried again.`
  if (Object.values(f).reduce((n, x) => n + x.count, 0) >= 2) return 'Two upgrades have failed. Contact the maintainers with the support bundle; an operator must clear the failure on the server first.'
  if (u.schedule?.status === 'scheduled') return 'An upgrade is already scheduled.'
  if (u.pending_approval) return 'A request is waiting for a second admin.'
  if (!u.preview) return reviewing ? 'Reading the signed release information…' : 'The signed release information has not been reviewed yet.'
  if (!u.preview.preflight_ok) return 'A preflight check failed: ' + (u.preview.preflight.find(i => !i.ok)?.text ?? 'see below.')
  return null
}
