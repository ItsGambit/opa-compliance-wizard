import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, CheckCircle2, ShieldCheck, Users } from 'lucide-react'
import { isStepUpRequired, requestUpgrade } from '../../api/client'
import { toast } from '../../hooks/useToast'
import type { UpgradePreview, UpgradeRequestBody, UpgradeStatus } from '../../types'
import { formatDateTime } from '../../utils/format'
import { beginStepUp } from '../../utils/stepUp'
import { rememberRequested } from '../../utils/upgradeRequested'
import { agoText, browserZone, formatDuration, formatInZone, formatUtc, serverZoneOf, shortSha, toIsoUtc } from '../../utils/upgradeFlow'
import { README_ROLLBACK_URL } from '../../utils/links'
import { useEnvironments } from '../../api/hooks'
import { formatBytes } from '../../utils/upgrade'
import type { ScheduleChoice } from './ScheduleDialog'
import { Badge, CARD_TITLE, Excerpt, KeyId, KV, Row, SEC_LABEL } from './parts'

export type ConfirmMode = 'apply' | 'schedule' | 'reschedule' | 'second'

interface Props {
  status: UpgradeStatus
  preview: UpgradePreview
  mode: ConfirmMode
  choice: ScheduleChoice | null
  isLocal: boolean
  adminEmail: string | null
  onBack: () => void
  /** Called when a request was made without a step-up round trip (local installs). */
  onDone: () => void
  /** Second-admin screen: drop the held request. */
  onDecline?: () => void
}

const SEC = 'border-t border-border-sub pt-3 mt-3'

/** Artboards 05a and 05b: exactly what the admin is approving, read from the signed release information and checked live,
 * then the step-up MFA approval bound to this version, hash and time. */
export function ConfirmUpgrade({ status, preview, mode, choice, isLocal, adminEmail, onBack, onDone, onDecline }: Props) {
  const queryClient = useQueryClient()
  const { data: envs } = useEnvironments()
  const [ack, setAck] = useState(false)
  const u = status.upgrade
  const pending = u?.pending_approval ?? null
  const second = mode === 'second'
  const m = preview.manifest
  const migrations = m.migrations
  const unsafe = migrations.filter(x => !x.rollback_safe)
  const schemaFrom = status.upgrade?.run?.schema_after ?? null
  const lastRun = u?.history.find(h => h.action === 'apply' && h.result === 'completed')
  const downtime = m.downtime_estimate_seconds ?? 60
  const approxDown = Math.max(downtime + 5, 30)
  const twoPerson = !!status.check.second_approval && !isLocal && !second
  const whenMs = second && pending?.when_utc ? Date.parse(pending.when_utc) : choice?.whenMs ?? null
  const isScheduled = (mode === 'schedule' || mode === 'reschedule' || (second && pending && pending.kind !== 'apply')) && whenMs != null
  const serverZone = serverZoneOf(status)
  const failed = preview.preflight.filter(i => !i.ok)
  const preflightAt = new Date(preview.checked_at)
  const approveDisabledBecauseMine = second && !!pending?.mine

  const submit = useMutation({
    mutationFn: () => {
      const body: UpgradeRequestBody = second ? { kind: 'approve_second' }
        : mode === 'apply' ? { kind: 'apply', version: preview.version, sha256: preview.sha256, acknowledged: true }
          : { kind: mode, version: preview.version, sha256: preview.sha256, acknowledged: true, when_utc: toIsoUtc(whenMs!),
              entered_tz: choice?.enteredZone, entered_local: choice?.enteredLocal }
      return requestUpgrade(body)
    },
    onSuccess: resp => {
      if (isStepUpRequired(resp)) {
        beginStepUp(resp.action_id, {
          kind: 'environment_change', action: resp.action, label: `Upgrade to ${preview.version}`, startedAt: Date.now(), reopen: 'updates',
        })
        return
      }
      if (!isScheduled && !resp.awaiting_second_approval && resp.correlation_id) {
        rememberRequested({ correlationId: resp.correlation_id, version: preview.version, approvedAt: new Date().toISOString(), email: adminEmail, stepUp: false })
      }
      for (const key of ['upgrade_status', 'upgrade_notice', 'audit_log']) queryClient.invalidateQueries({ queryKey: [key] })
      toast({ title: `Upgrade to ${preview.version}: ${resp.awaiting_second_approval ? 'waiting for a second admin' : isScheduled ? 'scheduled' : 'requested'}`,
        description: isLocal ? 'Applied at once (local install: no identity provider).' : 'Approved.', variant: 'success' })
      onDone()
    },
    onError: (err: Error & { body?: { reason?: string } }) => {
      queryClient.invalidateQueries({ queryKey: ['upgrade_status'] })
      toast({ title: 'Could not start the approval', description: err.message, variant: 'error' })
    },
  })

  const decline = useMutation({
    mutationFn: () => requestUpgrade({ kind: 'cancel' }),
    onSuccess: resp => {
      if (isStepUpRequired(resp)) {
        beginStepUp(resp.action_id, { kind: 'environment_change', action: resp.action, label: 'Decline the upgrade request', startedAt: Date.now(), reopen: 'updates' })
        return
      }
      queryClient.invalidateQueries({ queryKey: ['upgrade_status'] })
      onDecline?.()
    },
    onError: (err: Error) => toast({ title: 'Could not decline', description: err.message, variant: 'error' }),
  })

  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-start justify-between gap-4 flex-wrap">
       <div>
        <nav aria-label="Breadcrumb" className="text-xs text-muted mb-1">
          <button type="button" className="bg-transparent border-0 p-0 cursor-pointer text-accent-text underline" onClick={onBack}>Updates</button> › Confirm upgrade
        </nav>
        <h2 className="m-0 text-lg font-semibold text-text">Confirm the upgrade to {preview.version}</h2>
        <p className="text-xs text-muted mt-1 mb-0 max-w-[72ch]">
          {second
            ? 'This install requires two admins. The first approval is recorded; the request runs only after a different admin approves the same artifact with MFA.'
            : 'Everything below is read from the release manifest and checked live on this server. Approving binds your MFA to exactly this artifact.'}
        </p>
       </div>
       <div className="flex items-center gap-3 text-xs text-muted">
         {envs?.active && <span>Connected: <span className="text-text-dim font-medium">{envs.active}</span></span>}
         {adminEmail && <span className="text-text-dim font-medium">{adminEmail}</span>}
       </div>
      </div>

      {second && pending && (
        <section className="card p-4 border-accent/50" aria-labelledby="t-wait">
          <h3 className={CARD_TITLE} id="t-wait"><Users size={14} aria-hidden="true" />Waiting for a second admin <Badge tone="acc">1 of 2 approvals</Badge></h3>
          <ol className="m-0 p-0 list-none flex flex-col gap-2 text-xs text-text-dim" aria-label="Approval progress">
            <li className="flex gap-2.5 items-start"><span className="w-5 h-5 rounded-full bg-win/15 text-win grid place-items-center shrink-0" aria-hidden="true">✓</span>
              <span><strong className="text-text">Requested and approved</strong><br />{pending.first_email ?? 'an admin'} · {formatDateTime(pending.created_at)} · step-up MFA verified · audit <code className="font-mono">upgrade.requested</code></span></li>
            <li className="flex gap-2.5 items-start"><span className="w-5 h-5 rounded-full bg-accent-dim text-accent-text grid place-items-center shrink-0" aria-hidden="true">2</span>
              <span><strong className="text-text">Second approval — you</strong><br />Must be a different admin. Expires {formatDateTime(pending.expires_at)} (24 h); then the request is dropped and logged as expired.</span></li>
            <li className="flex gap-2.5 items-start"><span className="w-5 h-5 rounded-full bg-bg-hover text-text-dim grid place-items-center shrink-0" aria-hidden="true">3</span>
              <span><strong className="text-text">Runs</strong><br />{pending.kind === 'apply' ? 'Immediately after the second approval returns (requested as "Now").' : 'At the scheduled time.'}</span></li>
          </ol>
          <p className="text-xs text-muted mt-2.5 mb-0">The second approval is bound to the same artifact hash as the first. If the signed release information changed in between, both approvals are refused and the request must be made again.</p>
        </section>
      )}

      <section className="card p-4" aria-labelledby="t-what">
        <h3 className={CARD_TITLE} id="t-what">{second ? 'What the first admin approved — review it yourself' : 'You are approving'}</h3>
        <div className={KV}>
          <Row label="Upgrade"><strong className="text-text text-sm">{preview.installed_version} → {preview.version}</strong>{preview.crosses && preview.crosses.length > 0 && <> (crosses {preview.crosses.join(', ')})</>}</Row>
          <Row label="When">
            {isScheduled && whenMs != null ? (
              <><Badge tone="warn">Scheduled</Badge>{' '}{serverZone ? formatInZone(whenMs, serverZone) : formatInZone(whenMs, browserZone())} · UTC {formatUtc(whenMs)} · about {formatDuration(approxDown)} of downtime</>
            ) : (
              <><Badge tone="neu">Now</Badge> {second ? 'after the second approval' : 'starts as soon as the MFA approval returns'} · about {formatDuration(approxDown)} of downtime</>
            )}
          </Row>
          <Row label="Artifact"><code className="font-mono text-xs">{preview.file}</code>{preview.size ? ` · ${formatBytes(preview.size)}` : ''}</Row>
          <Row label="sha256"><code className="font-mono text-xs break-all">{preview.sha256}</code></Row>
          <Row label="Signature">
            <Badge tone="ok"><CheckCircle2 size={12} aria-hidden="true" />Verified</Badge> minisign Ed25519, key <KeyId id={preview.key_id} />
            {' '}({preview.key_role === 'release' ? 'primary' : preview.key_role}, {preview.key_status}{preview.key_since ? ` since ${preview.key_since}` : ''}).
            The updater verifies it again, independently, before anything is installed.
          </Row>
          <Row label="Approver">
            {adminEmail ?? 'you'} · {isLocal ? 'no identity provider in local mode' : 'fresh MFA required'} · two-person rule: {status.check.second_approval ? 'on for this install' : 'off for this install'}
          </Row>
        </div>

        <div className={`grid gap-5 md:grid-cols-2 ${SEC}`}>
          <div>
            <h4 className={`${SEC_LABEL} m-0 mb-2`}>What changes</h4>
            {m.changelog_excerpt
              ? <Excerpt text={m.changelog_excerpt} />
              : <p className="text-xs text-text-dim m-0">The release carries no change summary.</p>}
            <p className="text-[11px] text-muted mt-1.5 mb-0">{preview.manifest_source}.</p>
          </div>
          <div>
            <h4 className={`${SEC_LABEL} m-0 mb-2`}>Schema migrations</h4>
            {migrations.length === 0 ? <p className="text-xs text-text-dim m-0">None in the manifest.</p> : (
              <ul className="m-0 p-0 list-none flex flex-col gap-1.5 text-xs text-text-dim">
                {migrations.map(x => (
                  <li key={x.version} className="flex gap-2 items-start">
                    {x.rollback_safe
                      ? <CheckCircle2 size={14} className="text-win shrink-0 mt-px" aria-hidden="true" />
                      : <AlertTriangle size={14} className="text-warn shrink-0 mt-px" aria-hidden="true" />}
                    <span><strong className="text-text">{x.version}</strong> {x.description ? x.description.charAt(0).toLowerCase() + x.description.slice(1) : `(since ${x.since ?? 'an earlier release'})`} — {x.rollback_safe ? 'rollback-safe.' : <><strong>not rollback-safe</strong>. A code rollback after it keeps the new schema.</>}</span>
                  </li>
                ))}
              </ul>
            )}
            {m.expected_schema_version != null && (
              <p className="text-xs text-muted mt-2 mb-0">
                Schema {schemaFrom ?? 'now'} → {m.expected_schema_version}. Migrations run one transaction each; a power loss leaves the schema at a whole version, never between.
              </p>
            )}
          </div>
        </div>

        <div className={`grid gap-5 md:grid-cols-2 ${SEC}`}>
          <div>
            <h4 className={`${SEC_LABEL} m-0 mb-2`}>Backup before the switch</h4>
            <p className="text-xs text-text-dim m-0 max-w-[80ch]">
              A copy of the archive (<code className="font-mono">audit_store.db</code>{preview.db_bytes ? `, ${formatBytes(preview.db_bytes)}` : ''}, taken with SQLite's online backup and integrity-checked),{' '}
              <code className="font-mono">audit_log.jsonl</code> and <code className="font-mono">access_control.json</code> is written to{' '}
              <code className="font-mono break-all">{preview.backup_dir ? `${preview.backup_dir}/` : 'the upgrade/backups directory in the data directory'}</code>. Backups are never deleted automatically.
              {preview.free_bytes?.data != null && <> Free space was checked {agoText(preview.checked_at) || 'just now'}: {formatBytes(preview.free_bytes.data)} on the data volume{preview.free_bytes.opt != null ? `, ${formatBytes(preview.free_bytes.opt)} on the code volume` : ''}.</>}
            </p>
          </div>
          <div>
            <h4 className={`${SEC_LABEL} m-0 mb-2`}>If something goes wrong</h4>
            <p className="text-xs text-text-dim m-0 max-w-[80ch]">
              If any health check fails, the previous code ({preview.installed_version}) is put back automatically and the service restarted; <strong>your data is not touched by that</strong>.
              {unsafe.length > 0 && <> Because migration {unsafe.map(x => x.version).join(', ')} cannot be undone, {preview.installed_version} would then run on the newer schema.</>}{' '}
              Restoring the pre-upgrade copy is a separate action you would choose later, and it drops events synced after the upgrade. A redacted support bundle is prepared for you to download.{' '}
              <a href={README_ROLLBACK_URL} target="_blank" rel="noreferrer noopener" className="text-accent-text underline">Rollback and restore, in the README</a>
            </p>
          </div>
        </div>

        <div className={SEC}>
          <h4 className={`${SEC_LABEL} m-0 mb-2`}>Downtime</h4>
          <p className="text-xs text-text-dim m-0 max-w-[80ch]">
            About {formatDuration(approxDown)} (manifest estimate {downtime} s{lastRun?.seconds != null ? `; last upgrade here took ${Math.round(lastRun.seconds)} s` : ''}).
            Signed-in users stay signed in and see a short "upgrading" page; a report being generated during the switch fails and must be re-run; a running sync finishes first and no new sync starts.
          </p>
        </div>

        <div className={SEC}>
          <h4 className={`${SEC_LABEL} m-0 mb-2`}>Requirements, re-checked just now</h4>
          {failed.length === 0 ? (
            <p className="flex gap-2 items-start text-xs text-text-dim m-0">
              <CheckCircle2 size={14} className="text-win shrink-0 mt-px" aria-hidden="true" />
              <span>Disk space on both volumes · Python · SQLite · no sync running · no other upgrade in flight · updater present — all passed at {preflightAt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}.</span>
            </p>
          ) : (
            <ul role="alert" className="m-0 p-0 list-none text-xs text-warn flex flex-col gap-1">
              {failed.map(i => <li key={i.id} className="flex gap-2"><AlertTriangle size={14} className="shrink-0 mt-px" aria-hidden="true" />{i.text}</li>)}
            </ul>
          )}
        </div>

        <label className="mt-4 flex gap-2.5 items-start p-3 rounded-lg border border-warn/40 bg-warn/10 text-xs text-text cursor-pointer">
          <input type="checkbox" className="mt-0.5 w-4 h-4 accent-[var(--color-accent)] shrink-0" checked={ack} onChange={e => setAck(e.target.checked)} />
          <span>
            {second && 'I have reviewed this myself. '}I understand that an automatic rollback restores <strong>code only</strong>
            {unsafe.length > 0 && <>, that migration {unsafe.map(x => x.version).join(', ')} cannot be undone without the separate restore action</>}
            {second ? '.' : ', and that this install will be unavailable for about a minute.'}
          </span>
        </label>

        <div className="flex gap-2 flex-wrap items-center mt-4">
          <button type="button" className="btn-primary" disabled={!ack || submit.isPending || failed.length > 0 || approveDisabledBecauseMine} onClick={() => submit.mutate()}>
            <ShieldCheck size={14} aria-hidden="true" />
            {second ? 'Approve as second admin with MFA' : isLocal ? 'Upgrade' : twoPerson ? 'Approve with MFA (first of two)' : 'Approve with MFA'}
          </button>
          {second
            ? <button type="button" className="btn-secondary !text-text-dim" disabled={decline.isPending} onClick={() => decline.mutate()}>Decline and drop the request…</button>
            : <button type="button" className="btn-secondary !text-text-dim" onClick={onBack}>Back</button>}
          <span className="text-xs text-muted max-w-[70ch]">
            {second
              ? <>Declining also needs a step-up approval and is logged as <code className="font-mono">upgrade.cancelled</code>.</>
              : isLocal
                ? 'Local install: there is no identity provider, so the request is applied at once.'
                : 'You will leave this page for a fresh Okta MFA challenge. The request is held on the server for 15 minutes and is applied only when you return; nothing changes until then.'}
          </span>
        </div>
        {approveDisabledBecauseMine && (
          <p role="status" className="text-xs text-muted mt-3 mb-0">You already approved this request; a different admin must approve it.</p>
        )}
        {shortSha(preview.sha256) && <span className="sr-only">Approval is bound to {preview.file}, sha256 {shortSha(preview.sha256)}</span>}
      </section>
    </div>
  )
}
