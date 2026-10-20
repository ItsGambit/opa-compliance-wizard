import { AlertTriangle, CalendarClock, CheckCircle2, Download, RefreshCw, ShieldCheck } from 'lucide-react'
import type { UpgradeStatus } from '../../types'
import { formatDateTime } from '../../utils/format'
import { activeReleaseKey, formatBytes } from '../../utils/upgrade'
import { formatDuration, shortSha } from '../../utils/upgradeFlow'
import { Badge, CARD_TITLE, CommandBlock, KeyId, KV, Row } from './parts'

interface Props {
  status: UpgradeStatus
  isLocal: boolean
  reviewing: boolean
  reviewError: string | null
  onReview: () => void
  onUpgradeNow: () => void
  onSchedule: () => void
  onSecondApproval: () => void
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

export function AvailableSection({ status, isLocal, reviewing, reviewError, onReview, onUpgradeNow, onSchedule, onSecondApproval }: Props) {
  const latest = status.latest!
  const u = status.upgrade
  const preview = u?.preview ?? null
  const key = activeReleaseKey(status)
  const reason = isLocal ? null : blockReason(status, reviewing)
  const hosted = !isLocal
  const pending = u?.pending_approval ?? null
  const m = preview?.manifest
  const migrations = m?.migrations ?? []
  const lastRun = u?.history.find(h => h.action === 'apply' && h.result === 'completed')
  const downtime = m?.downtime_estimate_seconds
  const approx = downtime != null ? Math.max(downtime + 5, 30) : null
  return (
    <>
      <section className="card p-4 border-accent/50" aria-labelledby="t-avail">
        <div className="flex justify-between gap-4 flex-wrap items-start">
          <div className="min-w-0 flex-1">
            <h2 className={CARD_TITLE} id="t-avail">
              {latest.version} is available
              {latest.prerelease && <Badge tone="warn">PRERELEASE</Badge>}
              {preview
                ? <Badge tone="ok"><ShieldCheck size={12} aria-hidden="true" />Signed · verified</Badge>
                : latest.signed_artifact
                  ? <Badge tone="ok"><ShieldCheck size={12} aria-hidden="true" />Signed download attached</Badge>
                  : <Badge tone="warn"><AlertTriangle size={12} aria-hidden="true" />No signed download</Badge>}
              {(preview?.key_id ?? key?.key_id) && (
                <span className="text-xs text-muted font-normal">key <KeyId id={(preview?.key_id ?? key!.key_id)} /> (primary, active)</span>
              )}
            </h2>
            <div className={KV}>
              <Row label="Installed">{status.installed_version}{status.installed_at && <> · installed {formatDateTime(status.installed_at)}</>}</Row>
              <Row label="Available">
                <strong className="text-text text-sm">{latest.version}</strong>
                {latest.published_at && <> · released {formatDateTime(latest.published_at)}</>}
                {latest.signed_artifact && <> · <code className="font-mono text-xs">ocw-{latest.version}.tar.gz</code>{latest.size ? ` ${formatBytes(latest.size)}` : ''}</>}
                {preview && <> · sha256 <code className="font-mono text-xs">{shortSha(preview.sha256)}</code></>}
                {latest.release_url && <> · <a href={latest.release_url} target="_blank" rel="noreferrer noopener" className="text-accent-text underline">release notes</a></>}
              </Row>
              {m?.min_upgrade_from && (
                <Row label="Upgrade path">Allowed: the manifest's <code className="font-mono text-xs">min_upgrade_from</code> is {m.min_upgrade_from}</Row>
              )}
              <Row label="Downloaded">
                Not yet. {hosted
                  ? 'The updater downloads and verifies the signed release on this server when the upgrade starts; this page only reads its signature file and manifest (a few KB).'
                  : 'The check itself never downloads anything.'}
              </Row>
              {status.last_check.at && (
                <Row label="Last check">{formatDateTime(status.last_check.at)}{status.last_check.by && <> · by {status.last_check.by.replace(/^admin:/, '')} (Check now)</>}</Row>
              )}
            </div>
          </div>
          {hosted && (
            <div className="flex gap-2 flex-wrap items-center shrink-0">
              <button type="button" className="btn-primary" disabled={!!reason} onClick={onUpgradeNow} aria-describedby={reason ? 'upgrade-block' : undefined}>
                <Download size={14} aria-hidden="true" />Upgrade now
              </button>
              <button type="button" className="btn-secondary !text-text-dim" disabled={!!reason} onClick={onSchedule} aria-describedby={reason ? 'upgrade-block' : undefined}>
                <CalendarClock size={14} aria-hidden="true" />Schedule…
              </button>
            </div>
          )}
        </div>
        {hosted && reason && (
          <p id="upgrade-block" className="text-xs text-muted mt-3 mb-0" role="status">{reason}</p>
        )}
        {hosted && !reason && (
          <p className="text-xs text-muted mt-3 mb-0">Both continue to a confirmation screen that shows exactly what changes, then a step-up MFA approval. Nothing is installed before that.</p>
        )}
        {hosted && reviewError && (
          <p role="alert" className="flex items-start gap-1.5 text-warn text-xs mt-2 mb-0">
            <AlertTriangle size={14} className="shrink-0 mt-0.5" aria-hidden="true" />
            Could not read the signed release information: {reviewError}{' '}
            <button type="button" className="underline bg-transparent border-0 p-0 cursor-pointer text-inherit" onClick={onReview}>Try again</button>
          </p>
        )}
        {hosted && pending && !pending.mine && (
          <div className="mt-3 rounded-lg border border-accent/40 bg-accent-dim p-2.5 text-xs text-text flex items-center gap-3 flex-wrap">
            <span>{pending.first_email ?? 'An admin'} asked to upgrade to {pending.version} and needs a second admin's approval (expires {formatDateTime(pending.expires_at)}).</span>
            <button type="button" className="btn-primary" onClick={onSecondApproval}>Review and approve…</button>
          </div>
        )}
        {hosted && pending?.mine && (
          <p className="text-xs text-text-dim mt-3 mb-0" role="status">
            You approved this request; a different admin must approve it before it runs (expires {formatDateTime(pending.expires_at)}).{' '}
            <button type="button" className="underline bg-transparent border-0 p-0 cursor-pointer text-accent-text" onClick={onSecondApproval}>Withdraw it…</button>
          </p>
        )}
        {hosted && u && !u.updater.ready && latest.signed_artifact && (
          <div className="mt-3">
            <p className="text-xs text-muted mt-0 mb-1">Until the updater is installed, install from a shell on the server, as the account that owns the installation:</p>
            <CommandBlock label="Manual install command">{`server/deploy.sh --release ${latest.version}`}</CommandBlock>
          </div>
        )}
        {!latest.signed_artifact && (
          <p className="flex items-start gap-1.5 text-warn text-xs mt-3 mb-0" role="alert">
            <AlertTriangle size={14} className="shrink-0 mt-0.5" aria-hidden="true" />
            This release has no signed download attached, so it cannot be installed with the verified upgrade. Wait for the maintainers to
            publish a signed one; do not install an unsigned copy on a production server.
          </p>
        )}
      </section>

      {hosted && !preview && (latest.notes || latest.notes_title) && (
        <section className="card p-4" aria-labelledby="t-new0">
          <h2 className={CARD_TITLE} id="t-new0">What's new</h2>
          <div className="border-l-2 border-border pl-3">
            {latest.notes_title && <h3 className="m-0 mb-0.5 text-xs font-semibold text-text">{latest.notes_title}</h3>}
            {latest.notes && <p className="m-0 text-xs text-text-dim whitespace-pre-line">{latest.notes}</p>}
          </div>
          <p className="text-xs text-muted mt-2.5 mb-0">Excerpt of the release's published notes (not signed). The signed information is read when you review the upgrade.</p>
        </section>
      )}

      {hosted && preview && (
        <>
          <div className="grid gap-5 md:grid-cols-2">
            <section className="card p-4" aria-labelledby="t-new">
              <h2 className={CARD_TITLE} id="t-new">What's new (from the release manifest)</h2>
              {m?.changelog_excerpt ? (
                <div className="border-l-2 border-border pl-3">
                  <p className="m-0 text-xs text-text-dim whitespace-pre-line">{m.changelog_excerpt}</p>
                </div>
              ) : <p className="text-xs text-text-dim m-0">The release carries no change summary.</p>}
              <p className="text-xs text-muted mt-2.5 mb-0">{preview.manifest_source}.</p>
            </section>
            <section className="card p-4" aria-labelledby="t-mig">
              <h2 className={CARD_TITLE} id="t-mig">Schema migrations</h2>
              {migrations.length === 0 ? <p className="text-xs text-text-dim m-0">None in the manifest.</p> : (
                <table className="w-full text-xs border-collapse">
                  <thead><tr className="text-left">
                    <th scope="col" className="section-label pb-1 pr-3">#</th>
                    <th scope="col" className="section-label pb-1 pr-3">Since</th>
                    <th scope="col" className="section-label pb-1">Rollback-safe</th>
                  </tr></thead>
                  <tbody>
                    {migrations.map(x => (
                      <tr key={x.version} className="border-t border-border-sub">
                        <td className="py-1.5 pr-3 text-text">{x.version}</td>
                        <td className="py-1.5 pr-3 text-text-dim">{x.since ?? '—'}</td>
                        <td className="py-1.5">{x.rollback_safe
                          ? <><Badge tone="ok">Yes</Badge> <span className="text-text-dim">{status.installed_version} runs on it unchanged</span></>
                          : <Badge tone="warn"><AlertTriangle size={12} aria-hidden="true" />No</Badge>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
              {migrations.some(x => !x.rollback_safe) && (
                <p className="text-xs text-text-dim mt-2.5 mb-0">
                  <strong>Migration {migrations.filter(x => !x.rollback_safe).map(x => x.version).join(', ')} {migrations.filter(x => !x.rollback_safe).length > 1 ? 'are' : 'is'} not rollback-safe.</strong>{' '}
                  If the upgrade fails, the previous code is restored automatically but the archive keeps the new schema. Restoring the pre-upgrade copy is a separate action, and it drops events synced after the upgrade.
                  {m?.expected_schema_version != null && <> Schema goes to {m.expected_schema_version}.</>}
                </p>
              )}
            </section>
          </div>
          <div className="grid gap-5 md:grid-cols-2">
            <section className="card p-4" aria-labelledby="t-down">
              <h2 className={CARD_TITLE} id="t-down">Downtime</h2>
              <p className="text-xs text-text-dim mt-0 mb-2">
                <strong className="text-text text-sm">{approx != null ? `About ${formatDuration(approx)}.` : 'A short restart.'}</strong>{' '}
                {downtime != null && <>Manifest estimate {downtime} s</>}{lastRun?.seconds != null && <>; the last upgrade on this host took {Math.round(lastRun.seconds)} s</>}.
              </p>
              <ul className="m-0 p-0 list-none flex flex-col gap-1.5 text-xs text-text-dim">
                {['Signed-in users stay signed in; other users see a short "upgrading" page meanwhile.',
                  'A compliance report being generated during the switch fails and must be re-run.',
                  'A running sync is allowed to finish first; no new sync starts during the upgrade.'].map(t => (
                  <li key={t} className="flex gap-2 items-start"><CheckCircle2 size={14} className="text-win shrink-0 mt-px" aria-hidden="true" />{t}</li>
                ))}
              </ul>
            </section>
            <section className="card p-4" aria-labelledby="t-pre">
              <h2 className={`${CARD_TITLE} !mb-2.5`} id="t-pre">
                Preflight {preview.preflight_ok ? <Badge tone="ok">All passed</Badge> : <Badge tone="warn">Needs attention</Badge>}
                <span className="text-xs text-muted font-normal">checked {formatDateTime(preview.checked_at)}</span>
                <button type="button" className="btn-secondary !text-text-dim !text-xs !py-1 !px-2.5 ml-auto" onClick={onReview} disabled={reviewing}>
                  <RefreshCw size={12} aria-hidden="true" className={reviewing ? 'animate-spin' : ''} />Re-check
                </button>
              </h2>
              <ul className="m-0 p-0 list-none flex flex-col gap-1.5 text-xs text-text-dim">
                {preview.preflight.map(i => (
                  <li key={i.id} className="flex gap-2 items-start">
                    {i.ok ? <CheckCircle2 size={14} className="text-win shrink-0 mt-px" aria-label="passed" /> : <AlertTriangle size={14} className="text-warn shrink-0 mt-px" aria-label="needs attention" />}
                    <span>{i.text}</span>
                  </li>
                ))}
              </ul>
            </section>
          </div>
        </>
      )}
    </>
  )
}
