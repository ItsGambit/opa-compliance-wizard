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

/** The short names the failure narrative uses ("the health check /healthz failed"). */
export const HEALTH_CHECK_SHORT: Record<string, string> = {
  unit_active: 'unit active', version: '/api/version', healthz: '/healthz', gate_401: 'gate /verify', quick_check: 'database quick_check',
  schema_version: 'schema_version', chain_heads: 'audit chain heads', smoke_read: 'authenticated smoke read',
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

/** "52 seconds", "1 min 12 s" (the mockups spell short durations out). */
export function formatDuration(seconds: number | null | undefined): string {
  if (seconds == null) return ''
  const n = Math.round(seconds)
  if (n < 90) return `${n} seconds`
  return `${Math.floor(n / 60)} min ${n % 60} s`
}

/** "2 min ago" / "just now" / "3 h ago". */
export function agoText(iso: string | null | undefined, now = Date.now()): string {
  const t = iso ? Date.parse(iso) : NaN
  if (Number.isNaN(t)) return ''
  const mins = Math.floor((now - t) / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins} min ago`
  const h = Math.floor(mins / 60)
  return h < 48 ? `${h} h ago` : `${Math.floor(h / 24)} days ago`
}

/** "03:30:02" in `zone`. */
export function clockIn(ms: number, zone: string): string {
  try { return new Intl.DateTimeFormat('en-GB', { timeZone: zone, hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' }).format(new Date(ms)) } catch { return new Date(ms).toISOString().slice(11, 19) }
}

/** The zone's abbreviation when the browser has a real one ("BST", "EDT"), else "". */
export function zoneAbbrev(ms: number, zone: string): string {
  for (const locale of ['en-GB', 'en-US']) {
    try {
      const name = new Intl.DateTimeFormat(locale, { timeZone: zone, timeZoneName: 'short' }).formatToParts(new Date(ms)).find(p => p.type === 'timeZoneName')?.value ?? ''
      if (name && !/^(GMT|UTC)/.test(name)) return name
    } catch { /* unknown zone */ }
  }
  return ''
}

/** "21 Oct 2026, 03:30:54 BST" in `zone`. */
export function dateTimeIn(ms: number, zone: string, seconds = true): string {
  try {
    const parts: Record<string, string> = {}
    for (const p of new Intl.DateTimeFormat('en-GB', { timeZone: zone, day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit',
      second: seconds ? '2-digit' : undefined, hourCycle: 'h23' }).formatToParts(new Date(ms))) parts[p.type] = p.value
    const abbr = zoneAbbrev(ms, zone)
    return `${parts.day} ${parts.month} ${parts.year}, ${parts.hour}:${parts.minute}${seconds ? ':' + parts.second : ''}${abbr ? ' ' + abbr : ''}`
  } catch { return new Date(ms).toISOString() }
}

/** "Wed 21 Oct 2026 at 03:30 BST (02:30 UTC)", for the scheduled-maintenance banner. */
export function maintenanceWhen(ms: number, zone: string): string {
  const full = formatInZone(ms, zone)                      // "Wed 21 Oct 2026, 03:30 BST (UTC+1)"
  const [date, rest] = full.split(', ')
  const time = (rest ?? '').replace(/\s*\(UTC[^)]*\)\s*$/, '')
  const off = /\((UTC[^)]*)\)/.exec(full)?.[1]
  const hasName = /[A-Z]{3,5}$/.test(time)
  return `${date} at ${time}${hasName || !off ? '' : ' ' + off} (${new Date(ms).toISOString().slice(11, 16)} UTC)`
}

/** The plain-text line of a finished or running step, from what the updater recorded (state.json details). */
export function stepText(step: string, d: Record<string, string | number | boolean | string[]> | undefined, run: UpgradeRun): string | null {
  const gb = (mb: unknown) => typeof mb === 'number' ? (mb >= 1024 ? `${(mb / 1024).toFixed(1)} GB` : `${mb} MB`) : '?'
  if (!d) return null
  switch (step) {
    case 'validated': return `Request ${d.request ?? ''} accepted by the updater: schema, version ${run.version_to} > ${run.version_from}, sha256 matches, action id unseen, one in flight.`
    case 'downloaded': return d.source === 'staged earlier' ? 'Done earlier: the release was already on this server.' : `Done: ${d.source ?? 'fetched'}.`
    case 'staged': return `Signature by key ${d.signed_by ?? run.signed_by ?? ''} valid; ${d.files_verified ?? '?'} file hashes match the manifest; Python packages installed with hash pinning. Re-verified by root.`
    case 'preflight': return `Free space ok on both volumes (${gb(d.free_opt_mb)} on the code volume, ${gb(d.free_data_mb)} on the data volume); no sync running${typeof d.sync_waited_s === 'number' && d.sync_waited_s > 0 ? ` (waited ${d.sync_waited_s} s for one)` : ''}; nginx config ${d.nginx_template_changed ? 'updated by this release' : 'unchanged by this release'}.`
    case 'backup': {
      const bytes = typeof d.size === 'number' ? d.size : null
      const size = bytes == null ? '' : bytes >= 1e9 ? ` ${(bytes / 1e9).toFixed(1)} GB,` : ` ${(bytes / 1e6).toFixed(1)} MB,`
      return `${d.name ?? 'backup'}${size} integrity check ${d.integrity ?? '?'}; audit_log.jsonl and access_control.json copied${run.chain_heads_recorded != null ? `; chain heads of ${run.chain_heads_recorded} environment${run.chain_heads_recorded === 1 ? '' : 's'} recorded` : ''}.`
    }
    case 'switching': return `Maintenance page in place; current → releases/${d.current ?? run.version_to}, previous → releases/${d.previous ?? run.version_from} (atomic rename).`
    case 'restarting': return `Restarted ${Array.isArray(d.units) ? d.units.join(', ') : 'the app and its gates'}. Migrations run on start-up.`
    case 'health_check': return `${d.passed ?? '?'} of ${d.total ?? '?'} health checks passed.`
    default: return null
  }
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

/** The first server version that accepts the in-app operations (rollback, restore, clear failure, bundle rebuild) in its inbox. */
export const UPDATER_MIN_FOR_ACTIONS = '5.48.0'

function vt(v: string): number[] { return v.split('.').map(n => parseInt(n, 10) || 0) }

export function versionLess(a: string, b: string): boolean {
  const x = vt(a), y = vt(b)
  for (let i = 0; i < 3; i++) { if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) < (y[i] ?? 0) }
  return false
}

/** The installed updater predates the in-app operations: they stay off until the operator refreshes it. */
export function updaterTooOld(status: UpgradeStatus): boolean {
  const act = status.upgrade?.updater.activator
  return !!act && versionLess(act, UPDATER_MIN_FOR_ACTIONS)
}

/** The timestamp inside a file name like ocw-support-…-20261021T023158Z-k4q9.tar.gz or audit_store-pre-…-20261021T023005Z.db, as ms. */
export function stampFromName(name: string | null | undefined): number | null {
  const m = /(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z/.exec(name ?? '')
  return m ? Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) : null
}
