import { useEffect, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, CheckCircle2, Download, RefreshCw } from 'lucide-react'
import { ApiError, checkUpgradeNow, fetchUpgradeStatus, reviewUpgrade } from '../api/client'
import { useUpgradeStatus, useVersion, useWhoami } from '../api/hooks'
import { toast } from '../hooks/useToast'
import type { UpgradeStatus } from '../types'
import { clearRequested, readRequested, type RequestedUpgrade } from '../utils/upgradeRequested'
import { isFailureResult, isRunning } from '../utils/upgradeFlow'
import { formatDateTime } from '../utils/format'
import { describeCheckFailure, frequencyLabel, updateState } from '../utils/upgrade'
import { UpdateCheckForm } from './UpdateCheckForm'
import { AvailableSection } from './upgrade/AvailableSection'
import { BackupsCard } from './upgrade/BackupsCard'
import { ConfirmUpgrade, type ConfirmMode } from './upgrade/ConfirmUpgrade'
import { Badge, CARD_TITLE, CommandBlock, KeyId, KV, Row } from './upgrade/parts'
import { ProgressCard } from './upgrade/ProgressCard'
import { FailureCards, SuccessCards } from './upgrade/ResultCards'
import { ScheduledCard } from './upgrade/ScheduledCard'
import { ScheduleDialog, type ScheduleChoice } from './upgrade/ScheduleDialog'
import { StartingCard } from './upgrade/StartingCard'

export { Badge, KeyId } from './upgrade/parts'

/** How far the server's clock is from this browser's (seconds), for the "your browser agrees" note. */
function clockSkewSeconds(status: UpgradeStatus): number {
  return Math.round(Math.abs(new Date(status.server.time).getTime() - Date.now()) / 1000)
}

function StatusCard({ status, onCheckNow, checking, disabled }: { status: UpgradeStatus; onCheckNow: () => void; checking: boolean; disabled?: boolean }) {
  const state = updateState(status)
  const { latest, last_check: last, check } = status
  const skew = clockSkewSeconds(status)
  const canCheck = check.enabled
  return (
    <section className="card p-4" aria-labelledby="t-status">
      <div className="flex justify-between gap-4 flex-wrap items-start">
        <div className="min-w-0 flex-1">
          <h2 className={CARD_TITLE} id="t-status">
            Installed version
            {state === 'up_to_date' && <Badge tone="ok"><CheckCircle2 size={12} aria-hidden="true" />Up to date</Badge>}
            {state === 'update_available' && <Badge tone="acc"><Download size={12} aria-hidden="true" />Update available</Badge>}
            {state === 'failed' && <Badge tone="warn"><AlertTriangle size={12} aria-hidden="true" />Last check failed</Badge>}
            {(state === 'not_enabled') && <Badge tone="neu">Update check not enabled</Badge>}
            {state === 'off' && <Badge tone="neu">Update check off</Badge>}
            {state === 'waiting' && <Badge tone="neu">Waiting for the first check</Badge>}
          </h2>
          <div className={KV}>
            <Row label="Installed">
              <strong className="text-text text-sm">{status.installed_version}</strong>
              {status.installed_at && <> · installed {formatDateTime(status.installed_at)}</>}
            </Row>
            <Row label="Latest stable">
              {latest
                ? <>{latest.version}{latest.published_at && <> (released {formatDateTime(latest.published_at)})</>}{!status.update_available && ' · no newer release'}</>
                : state === 'not_enabled' || !last.at ? 'Unknown — this server has never checked.' : 'No stable release is published.'}
            </Row>
            {last.at && (
              <Row label="Last check">
                {formatDateTime(last.at)} · result: {last.status === 'ok' ? (status.update_available ? 'newer release found' : 'up to date') : describeCheckFailure(last.code)}
                {last.by && <> · by {last.by.replace(/^admin:/, '')} (Check now)</>}
                {last.next_at && check.frequency === 'daily' && <> · next automatic check {formatDateTime(last.next_at)}</>}
              </Row>
            )}
            {!check.prompt_needed && <Row label="Server clock">
              {formatDateTime(status.server.time)}{status.server.zone && <> ({status.server.zone})</>} ·{' '}
              {skew <= 5 ? `your browser agrees within ${Math.max(skew, 1)} s` : <span className="text-warn">your browser differs by {skew} s</span>}
            </Row>}
          </div>
        </div>
        {check.prompt_needed ? null : <div className="flex gap-2 flex-wrap items-center shrink-0">
          <button type="button" className="btn-secondary !text-text-dim" onClick={onCheckNow} disabled={!canCheck || checking || !!disabled}
            title={canCheck ? (disabled ? 'Disabled while an upgrade is scheduled or running' : undefined) : 'Turn the update check on first'}>
            <RefreshCw size={14} aria-hidden="true" className={checking ? 'animate-spin' : ''} />Check now
          </button>
        </div>}
      </div>
      {!check.prompt_needed && (
        <p className="text-xs text-muted mt-3 mb-0">Check now asks the release server for the latest stable release. It is limited to once a minute and never installs anything.</p>
      )}
      {disabled && <p className="text-xs text-muted mt-2 mb-0">Check now is off while an upgrade is scheduled or running.</p>}
      {last.consecutive_failures > 0 && (
        <p className="text-xs text-warn mt-2 mb-0" role="alert">
          The last {last.consecutive_failures} check{last.consecutive_failures === 1 ? '' : 's'} failed
          {last.failing_since && <> (since {formatDateTime(last.failing_since)})</>}: {describeCheckFailure(last.code)}.
          It will try again by itself; details are in the Audit Log.
        </p>
      )}
    </section>
  )
}

function CheckSettingsCard({ status, isLocal }: { status: UpgradeStatus; isLocal?: boolean }) {
  const [editing, setEditing] = useState(false)
  const { check } = status
  return (
    <section className="card p-4" aria-labelledby="t-check">
      <h2 className={CARD_TITLE} id="t-check">Update check</h2>
      {editing && !check.env_locked ? (
        <UpdateCheckForm status={status} secondaryLabel="Cancel" onSecondary={() => setEditing(false)} onSaved={() => setEditing(false)} />
      ) : (
        <>
          <div className={KV}>
            <Row label="Schedule">{frequencyLabel(status)}</Row>
            <Row label="Sends">
              {check.frequency === 'off'
                ? 'Nothing: the check is off.'
                : <>One HTTPS request a day to <code className="font-mono text-xs">{checkHost(check.url)}</code> and nothing about your tenant, users or data.</>}
            </Row>
            <Row label="Version in request">{check.share_version ? 'Shared (on)' : 'Not shared (off)'}</Row>
            <Row label="Release channel">
              {check.channel === 'prerelease' ? 'Pre-release (release candidates are offered too)' : 'Stable'}{check.mirror && ' (via a configured mirror)'}
              {check.channel_source === 'env' && ' · set by the server environment'}
            </Row>
            {!isLocal && <Row label="Two-person rule">{check.second_approval ? 'On: a second admin must approve every upgrade' : 'Off'}</Row>}
          </div>
          {check.env_locked ? (
            <p className="text-xs text-muted mt-3 mb-0" role="status">
              Set by this server's configuration (OPA_UPDATE_CHECK = {check.enabled ? 'on' : 'off'}). Change it there; this screen cannot override it.
            </p>
          ) : (
            <div className="flex flex-wrap items-center gap-2 mt-3">
              <button type="button" className="btn-secondary !text-text-dim" onClick={() => setEditing(true)}>Change…</button>
              <span className="text-xs text-muted">Changes need a step-up MFA approval, like other settings (local installs apply at once).</span>
            </div>
          )}
          {check.env_invalid_value && (
            <p className="text-xs text-warn mt-2 mb-0" role="alert">OPA_UPDATE_CHECK has the value "{check.env_invalid_value}", which is ignored. Use "on" or "off".</p>
          )}
        </>
      )}
    </section>
  )
}

function checkHost(url: string | undefined): string {
  try { return url ? new URL(url).host : 'the release server' } catch { return 'the release server' }
}

function FirstRunCard({ status, onNotNow }: { status: UpgradeStatus; onNotNow: () => void }) {
  return (
    <section className="card p-4 border-accent/50" aria-labelledby="t-enable">
      <h2 className={CARD_TITLE} id="t-enable">Enable the update check?</h2>
      <p className="text-xs text-text-dim mb-3 max-w-[80ch]">
        OPA Compliance Wizard does not contact anything until you choose. This is a one-time decision; you can change it here later.
      </p>
      <div className="grid gap-5 md:grid-cols-2">
        <div>
          <div className="text-[11px] font-semibold uppercase tracking-[0.08em] text-muted mb-1.5">What the check sends</div>
          <ul className="m-0 pl-[18px] list-disc flex flex-col gap-1.5 text-xs text-text-dim">
            <li>One HTTPS <code className="font-mono">GET</code> to <code className="font-mono break-all">{status.check.url ?? 'the release API'}</code>, once a day (or only when an admin clicks Check now).</li>
            <li>Request headers: <code className="font-mono">User-Agent: opa-compliance-wizard-update-check</code> and the <code className="font-mono">ETag</code> of the previous answer. That is all.</li>
            <li>GitHub sees this server's public IP address, as with any HTTPS request.</li>
          </ul>
        </div>
        <div>
          <div className="text-[11px] font-semibold uppercase tracking-[0.08em] text-muted mb-1.5">What it never sends</div>
          <ul className="m-0 pl-[18px] list-disc flex flex-col gap-1.5 text-xs text-text-dim">
            <li>Your tenant, environment names, users, groups, secrets, archive data or audit log.</li>
            <li>The installed version (unless you turn on the optional toggle below).</li>
            <li>Nothing is downloaded or installed by the check. An upgrade is always a separate, deliberate step.</li>
          </ul>
        </div>
      </div>
      <div className="mt-4">
        <UpdateCheckForm status={status} secondaryLabel="Not now" onSecondary={onNotNow} />
      </div>
      <p className="text-xs text-muted mt-3 mb-0">
        Fleet-managed servers can force this off with <code className="font-mono">OPA_UPDATE_CHECK=off</code> in <code className="font-mono">/etc/opa-compliance-wizard.env</code>;
        proxies use <code className="font-mono">https_proxy</code>; a corporate mirror uses <code className="font-mono">OPA_RELEASE_API_URL</code> (signatures are still verified against
        the pinned keys, so a mirror can delay a release but not change one).
      </p>
    </section>
  )
}

export function KeysSummaryCard({ status, onOpenKeys }: { status: UpgradeStatus; onOpenKeys: () => void }) {
  const keys = status.signing_keys
  const primary = keys.keys.filter(k => k.role === 'release')
  const standby = keys.keys.filter(k => k.role === 'standby')
  return (
    <section className="card p-4" aria-labelledby="t-keys">
      <h2 className={CARD_TITLE} id="t-keys">Release signing keys</h2>
      {keys.error ? (
        <p className="flex items-start gap-1.5 text-loss text-xs m-0" role="alert">
          <AlertTriangle size={14} className="shrink-0 mt-0.5" aria-hidden="true" />
          The signing-key list on this server is damaged: {keys.error}
        </p>
      ) : !keys.pinned ? (
        <p className="text-xs text-text-dim m-0">
          No release signing key is pinned on this server yet, so signed upgrades (<code className="font-mono">deploy.sh --release</code>) are not available until the
          project publishes its key. Everything else works as before; existing installs are unaffected.
        </p>
      ) : (
        <div className={KV}>
          <Row label="Primary">
            {primary.map(k => (
              <span key={k.key_id} className="mr-3">
                <KeyId id={k.key_id} struck={k.status === 'revoked'} /> · <Badge tone={k.status === 'active' ? 'ok' : k.status === 'revoked' ? 'err' : 'neu'}>{k.status === 'active' ? 'Active' : k.status === 'revoked' ? 'Revoked' : 'Retired'}</Badge>
                {k.status === 'active' && <> since {k.since} · signs releases</>}
              </span>
            ))}
          </Row>
          <Row label="Standby">
            {standby.map(k => (
              <span key={k.key_id} className="mr-3">
                <KeyId id={k.key_id} struck={k.status === 'revoked'} /> · <Badge tone="neu">{k.status === 'active' ? 'Standby' : k.status === 'revoked' ? 'Revoked' : 'Retired'}</Badge>
                {k.status === 'active' && <> pinned since {k.since}, kept offline · can only sign a revocation of the primary</>}
              </span>
            ))}
          </Row>
        </div>
      )}
      <p className="text-xs text-muted mt-2.5 mb-0">
        Revocations are fetched with the update check or applied from a file.{' '}
        <button type="button" className="text-accent-text underline bg-transparent border-0 p-0 cursor-pointer" onClick={onOpenKeys}>Details and history</button>
      </p>
    </section>
  )
}

function HistoryCard({ status }: { status: UpgradeStatus }) {
  const rows = status.upgrade?.history ?? []
  if (rows.length === 0) return null
  return (
    <section className="card p-4" aria-labelledby="t-hist">
      <h2 className={CARD_TITLE} id="t-hist">Upgrade history</h2>
      <table className="w-full text-xs border-collapse">
        <thead><tr className="text-left">
          {['Upgrade', 'When', 'Result', 'Correlation'].map(h => <th key={h} scope="col" className="section-label pb-1 pr-3">{h}</th>)}
        </tr></thead>
        <tbody>
          {rows.map(r => (
            <tr key={`${r.correlation_id}-${r.started_at}`} className="border-t border-border-sub align-top">
              <td className="py-1.5 pr-3 text-text">{r.action === 'apply' ? `${r.version_from} → ${r.version_to}` : `${r.action} ${r.version_to ?? ''}`}</td>
              <td className="py-1.5 pr-3 text-text-dim">{formatDateTime(r.started_at)}</td>
              <td className="py-1.5 pr-3 text-text-dim">
                {r.result === 'completed' ? <Badge tone="ok">Completed</Badge> : r.result === 'rolled_back' ? <Badge tone="warn">Rolled back</Badge> : <Badge tone="err">{r.result ?? 'Unknown'}</Badge>}
                {r.seconds != null && <> in {Math.round(r.seconds)} s</>}{r.reason_code && <> · <code className="font-mono">{r.reason_code}</code></>}
              </td>
              <td className="py-1.5 text-text-dim"><code className="font-mono">{r.correlation_id}</code></td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="text-xs text-muted mt-2 mb-0">Every step of each upgrade is an entry in the Audit Log under its correlation id.</p>
    </section>
  )
}

/** Local mode (Local-Mode artboard, command-line hint): no identity provider to step up with, so the hosted flow is not offered. */
function LocalModeCard({ status }: { status: UpgradeStatus }) {
  const latest = status.latest
  return (
    <section className="card p-4 border-accent/50" aria-labelledby="t-local">
      <h2 className={CARD_TITLE} id="t-local">
        {status.update_available && latest ? `${latest.version} is available` : 'Upgrading a local install'}
        {status.update_available && latest?.prerelease && <Badge tone="warn">PRERELEASE</Badge>}
        <Badge tone="neu">Local mode · no sign-in</Badge>
      </h2>
      <p className="text-xs text-text-dim mt-0 mb-3 max-w-[80ch]">
        This install runs on this computer and has no identity provider to step up with, so upgrading from this page (with MFA, scheduling and progress) is for hosted installs.
        Upgrade from a terminal in the install folder instead:
      </p>
      <div className="grid gap-3 md:grid-cols-2">
        <div>
          <div className="section-label mb-1">Upgrade</div>
          <CommandBlock label="Upgrade command">python launch.py upgrade</CommandBlock>
        </div>
        <div>
          <div className="section-label mb-1">Restore the previous version</div>
          <CommandBlock label="Restore command">python launch.py upgrade --restore-previous</CommandBlock>
        </div>
      </div>
      <p className="text-xs text-muted mt-3 mb-0">The release is signed and verified before anything changes; the old version is kept so it can be restored.</p>
    </section>
  )
}

function isTransient(error: unknown): boolean {
  if (error instanceof ApiError) return error.status === 502 || error.status === 503 || error.status === 504 || error.status === 0
  return error instanceof TypeError          // fetch() rejects with a TypeError when nothing answered (the app is restarting)
}

/** The admin-only Updates page: check for signed releases, review what changes, upgrade now or on a schedule with a step-up MFA
 * approval, follow the live progress through the restart, and see the result. The daily check is OFF until an admin chooses. */
export function UpdatesPage({ onOpenKeys }: { onOpenKeys: () => void }) {
  const { data: whoami } = useWhoami()
  const isLocal = !!whoami?.is_local
  const { data: loadedVersion } = useVersion()
  const [polling, setPolling] = useState(false)
  const { data: status, isLoading, isError, error } = useUpgradeStatus(true, polling ? 2000 : undefined)
  const queryClient = useQueryClient()
  const [notNow, setNotNow] = useState(false)
  const [requested, setRequested] = useState<RequestedUpgrade | null>(() => readRequested())
  const [view, setView] = useState<'overview' | 'confirm'>('overview')
  const [mode, setMode] = useState<ConfirmMode>('apply')
  const [choice, setChoice] = useState<ScheduleChoice | null>(null)
  const [scheduleOpen, setScheduleOpen] = useState(false)
  const [scheduleMode, setScheduleMode] = useState<'schedule' | 'reschedule'>('schedule')
  const [reviewError, setReviewError] = useState<string | null>(null)
  const [tried, setTried] = useState<string | null>(null)

  const run = status?.upgrade?.run ?? null
  const running = isRunning(run)
  const received = (r: RequestedUpgrade) => {
    if (!run) return false
    if (r.kind === 'rollback' || r.kind === 'restore') return run.action === r.kind && Date.parse(run.started_at ?? '') >= Date.parse(r.approvedAt) - 60_000
    if (r.kind) return Date.now() - Date.parse(r.approvedAt) > 20_000      // bundle / clear / delete: done in seconds; the cards above show the result
    return run.correlation_id === r.correlationId
  }
  const startedWaiting = !!requested && !received(requested) && !(status?.upgrade?.rejection?.correlation_id === requested.correlationId)
  const restarting = isError && isTransient(error) && !!status

  // Poll every 2 s while an upgrade is starting or running (the server restarts underneath; failed polls just wait for the next tick).
  useEffect(() => { setPolling(running || startedWaiting) }, [running, startedWaiting])

  // While the request is waiting for the updater, ask for the refusal belonging to it.
  useEffect(() => {
    if (!requested || !startedWaiting) return
    const id = setInterval(() => {
      fetchUpgradeStatus(requested.correlationId).then(s => queryClient.setQueryData(['upgrade_status'], s)).catch(() => { /* the poll above retries */ })
    }, 4000)
    return () => clearInterval(id)
  }, [requested, startedWaiting, queryClient])

  // When the new version answers, reload once so the browser runs the new interface.
  useEffect(() => {
    if (!status || !loadedVersion || !run || run.result !== 'completed') return
    if (status.installed_version === loadedVersion.version) return
    const guard = `opa.upgradeReloaded:${run.correlation_id}`
    try { if (sessionStorage.getItem(guard)) return; sessionStorage.setItem(guard, '1') } catch { /* reload anyway, once per mount */ }
    clearRequested()
    window.location.reload()
  }, [status, loadedVersion, run])

  // Once the updater has the request, the "starting" card has done its job.
  useEffect(() => {
    if (requested && run && received(requested)) { clearRequested(); setRequested(null) }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [requested, run])

  const review = useMutation({
    mutationFn: reviewUpgrade,
    onSuccess: () => { setReviewError(null); queryClient.invalidateQueries({ queryKey: ['upgrade_status'] }); queryClient.invalidateQueries({ queryKey: ['audit_log'] }) },
    onError: (err: Error) => setReviewError(err.message),
  })

  const latestVersion = status?.latest?.version ?? null
  const preview = status?.upgrade?.preview ?? null
  useEffect(() => {
    if (isLocal || !status || !status.update_available || !latestVersion || !status.upgrade?.updater.ready || preview || review.isPending || tried === latestVersion) return
    setTried(latestVersion)
    review.mutate()
  }, [isLocal, status, latestVersion, preview, review, tried])

  const checkNow = useMutation({
    mutationFn: checkUpgradeNow,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['upgrade_status'] })
      queryClient.invalidateQueries({ queryKey: ['audit_log'] })
    },
    onError: (err: Error) => toast({ title: 'Could not check now', description: err.message, variant: 'error' }),
  })

  if (isLoading) return <p className="text-xs text-muted">Loading…</p>
  if (!status) return <p role="alert" className="text-xs text-loss">Could not load the update status: {(error as Error | null)?.message}</p>

  const state = updateState(status)
  const u = status.upgrade
  const sched = u?.schedule && (u.schedule.status === 'scheduled' || u.schedule.status === 'missed') ? u.schedule : null
  const busy = running || sched?.status === 'scheduled' || startedWaiting
  const failureShown = !!run && isFailureResult(run)
  const successShown = !!run && run.result === 'completed' && run.action === 'apply' && !!u?.rollback?.available   // for the 24 h rollback window
  const editing = view === 'confirm' && !!preview
  const openSchedule = (m: 'schedule' | 'reschedule') => { setScheduleMode(m); setScheduleOpen(true) }
  const pending = u?.pending_approval ?? null

  if (editing && preview) {
    return (
      <ConfirmUpgrade status={status} preview={preview} mode={mode} choice={choice} isLocal={isLocal} adminEmail={whoami?.email ?? null}
        onBack={() => { setView('overview'); setChoice(null) }} onDone={() => { setView('overview'); setChoice(null) }}
        onDecline={() => setView('overview')} />
    )
  }

  return (
    <div className="flex flex-col gap-5">
      {restarting && !running && (
        <p role="status" className="text-xs text-muted m-0">The server did not answer just now (it may be restarting). This page keeps trying.</p>
      )}
      {running && run && <ProgressCard run={run} restarting={restarting} />}
      {!running && requested && (startedWaiting || status.upgrade?.rejection?.correlation_id === requested.correlationId) && (
        <StartingCard requested={requested} status={status} ageMs={Date.now() - Date.parse(requested.approvedAt)} />
      )}
      {!running && requested && status.upgrade?.rejection?.correlation_id === requested.correlationId && (
        <div><button type="button" className="btn-secondary !text-text-dim" onClick={() => { clearRequested(); setRequested(null) }}>Dismiss</button></div>
      )}
      {!running && failureShown && run && <FailureCards run={run} status={status} />}
      {!running && successShown && run && <SuccessCards run={run} status={status} />}
      {!running && !isLocal && sched && (
        <ScheduledCard status={status} onReschedule={() => openSchedule('reschedule')}
          onRunNow={() => { setMode('apply'); setChoice(null); setView('confirm') }} />
      )}

      {/* Mockup 03: when an update is available, its card leads the page and replaces the installed-version card (owner, 2026-10-20). */}
      {!running && state === 'update_available' && status.latest
        ? (isLocal
          ? <><LocalModeCard status={status} /></>
          : <AvailableSection status={status} isLocal={isLocal} reviewing={review.isPending} reviewError={reviewError}
              onReview={() => review.mutate()}
              onUpgradeNow={() => { setMode('apply'); setChoice(null); setView('confirm') }}
              onSchedule={() => openSchedule('schedule')}
              onSecondApproval={() => { setMode('second'); setView('confirm') }} />)
        : !running && <StatusCard status={status} onCheckNow={() => checkNow.mutate()} checking={checkNow.isPending} disabled={busy} />}
      {!running && isLocal && state !== 'update_available' && <LocalModeCard status={status} />}
      {!running && pending && !pending.mine && state !== 'update_available' && (
        <section className="card p-4 border-accent/50">
          <p className="text-xs text-text-dim m-0">A request to upgrade to {pending.version} is waiting for a second admin's approval.{' '}
            <button type="button" className="btn-primary ml-2" onClick={() => { setMode('second'); setView('confirm') }}>Review and approve…</button></p>
        </section>
      )}

      {status.check.prompt_needed && !notNow && <FirstRunCard status={status} onNotNow={() => setNotNow(true)} />}
      {status.check.prompt_needed && notNow && (
        <section className="card p-4 flex items-center justify-between gap-3 flex-wrap">
          <p className="text-xs text-text-dim m-0">The update check stays off until you choose. Nothing is sent.</p>
          <button type="button" className="btn-secondary !text-text-dim" onClick={() => setNotNow(false)}>Enable the update check…</button>
        </section>
      )}
      {!status.check.prompt_needed && !running && <CheckSettingsCard status={status} isLocal={isLocal} />}
      {!status.check.prompt_needed && !running && !isLocal && <BackupsCard status={status} />}
      {!status.check.prompt_needed && !running && !isLocal && <HistoryCard status={status} />}
      {!status.check.prompt_needed && <KeysSummaryCard status={status} onOpenKeys={onOpenKeys} />}

      {preview && (
        <ScheduleDialog open={scheduleOpen} onOpenChange={setScheduleOpen} status={status} version={preview.version}
          initialMs={scheduleMode === 'reschedule' && sched ? Date.parse(sched.when_utc) : undefined}
          title={scheduleMode === 'reschedule' ? `Reschedule the upgrade to ${preview.version}` : undefined}
          onContinue={c => { setChoice(c); setMode(scheduleMode); setView('confirm') }} />
      )}
    </div>
  )
}
