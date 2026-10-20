import { useState } from 'react'
import { AlertTriangle, CheckCircle2, Download, RefreshCw, Undo2 } from 'lucide-react'
import { upgradeBundleUrl } from '../../api/client'
import type { UpgradeRun, UpgradeStatus } from '../../types'
import { formatDateTime } from '../../utils/format'
import { formatBytes } from '../../utils/upgrade'
import { HEALTH_CHECK_LABELS, HEALTH_CHECK_ORDER, describeReason, formatDuration, shortSha } from '../../utils/upgradeFlow'
import { Badge, CARD_TITLE, KV, Row, SEC_LABEL } from './parts'
import { TypedConfirmDialog } from './TypedConfirmDialog'
import { useUpgradeRequest } from './useUpgradeRequest'

/** Artboard 09: success. */
export function SuccessCards({ run, status }: { run: UpgradeRun; status: UpgradeStatus }) {
  const [rollbackOpen, setRollbackOpen] = useState(false)
  const rollback = useUpgradeRequest(`Roll back to ${status.upgrade?.rollback?.to ?? 'the previous version'}`, () => setRollbackOpen(false))
  const u = status.upgrade
  const crossed = (run.manifest?.migrations ?? [])
  const checks = run.health ?? []
  const passed = checks.filter(c => c.ok).length
  const rb = u?.rollback
  const migText = crossed.length ? `Migration${crossed.length > 1 ? 's' : ''} ${crossed.map(m => m.version).join(' and ')} applied (schema ${run.schema_before ?? '?'} → ${run.schema_after ?? '?'}). ` : 'No schema migrations. '
  return (
    <>
      <section className="card p-4 border-win/50" aria-labelledby="t-done">
        <h2 className="m-0 text-lg font-semibold text-text flex items-center gap-2" id="t-done">
          <CheckCircle2 size={20} className="text-win" aria-hidden="true" />Upgraded to {run.version_to} in {formatDuration(run.seconds)}
        </h2>
        <p className="text-xs text-text-dim mt-2 mb-0">Finished {formatDateTime(run.updated_at)}. {migText}Nothing else to do.</p>
        <div className="grid gap-5 md:grid-cols-2 mt-3">
          <div className={KV}>
            <Row label="From → to">{run.version_from} → {run.version_to}</Row>
            <Row label="Requested by">{run.requested_by ?? 'an admin'}</Row>
            <Row label="Correlation"><code className="font-mono text-xs">{run.correlation_id}</code></Row>
          </div>
          <div className={KV}>
            <Row label="Backup kept">{run.backup ? <><code className="font-mono text-xs">{run.backup.name}</code> {formatBytes(run.backup.size)} · integrity {run.backup.integrity} · not deleted automatically</> : 'none recorded'}</Row>
            <Row label="Previous release">{run.version_from} is kept on the server for rollback</Row>
          </div>
        </div>
      </section>
      <section className="card p-4" aria-labelledby="t-checked">
        <h2 className={CARD_TITLE} id="t-checked">What was checked after the restart {checks.length > 0 && <Badge tone={passed === checks.length ? 'ok' : 'warn'}>{passed} of {HEALTH_CHECK_ORDER.length} passed</Badge>}</h2>
        <ul className="m-0 p-0 list-none flex flex-col gap-1.5 text-xs text-text-dim">
          {(checks.length ? checks : HEALTH_CHECK_ORDER.map(id => ({ id, ok: true, detail: '' }))).map(c => (
            <li key={c.id} className="flex gap-2 items-start">
              <CheckCircle2 size={14} className={`shrink-0 mt-px ${c.ok ? 'text-win' : 'text-loss'}`} aria-hidden="true" />
              <span>{HEALTH_CHECK_LABELS[c.id] ?? c.id}{c.detail ? <span className="text-muted"> — {c.detail}</span> : null}</span>
            </li>
          ))}
        </ul>
        <p className="text-xs text-muted mt-3 mb-0">The audit log holds every step of this upgrade under correlation <code className="font-mono">{run.correlation_id}</code>.</p>
      </section>
      {rb?.to && (
        <section className="card p-4" aria-labelledby="t-rb">
          <h2 className={CARD_TITLE} id="t-rb">Roll back to {rb.to} {rb.available ? <Badge tone="warn">Available until {formatDateTime(rb.until)}</Badge> : <Badge tone="neu">Window closed {formatDateTime(rb.until)}</Badge>}</h2>
          <p className="text-xs text-text-dim m-0 max-w-[80ch]">
            For 24 hours after an upgrade the operator can put the previous code back (the only case where a lower version is allowed). This is a <strong>code-only</strong> rollback: the archive keeps its schema
            ({run.schema_after ?? 'current'}){crossed.some(m => !m.rollback_safe) ? ' because a migration of this upgrade is not rollback-safe; the previous release runs on it, but newer indexes are unused' : ''}.
            The pre-upgrade copy stays available for the separate restore action.
          </p>
          <div className="flex gap-2 items-center flex-wrap mt-3">
            <button type="button" className="btn-secondary !text-text-dim" onClick={() => setRollbackOpen(true)} disabled={!rb.available}>
              <Undo2 size={14} aria-hidden="true" />Roll back to {rb.to}…
            </button>
            <span className="text-xs text-muted">Typed confirmation, then a step-up MFA approval. From the server's command line: <code className="font-mono">sudo ocw-updater rollback</code></span>
          </div>
          <TypedConfirmDialog open={rollbackOpen} onOpenChange={setRollbackOpen} title={`Roll back to ${rb.to}?`} word="ROLLBACK" confirmLabel={`Roll back to ${rb.to}`}
            busy={rollback.isPending} onConfirm={() => rollback.mutate({ kind: 'rollback', confirm: 'ROLLBACK' })}>
            <p className="m-0">The previous code ({rb.to}) is put back and the service restarted. This is <strong>code only</strong>: the archive keeps schema {run.schema_after ?? 'its current version'} and no data is touched.
              It is the only case where a lower version is allowed, and it is logged under a new correlation id.</p>
          </TypedConfirmDialog>
        </section>
      )}
    </>
  )
}

/** Artboard 10: failed. Rolled back automatically (the common case), failed before anything was switched, or a rollback that
 * could not complete (an operator must act). */
export function FailureCards({ run, status }: { run: UpgradeRun; status: UpgradeStatus }) {
  const [typed, setTyped] = useState('')
  const [clearOpen, setClearOpen] = useState(false)
  const [hosts, setHosts] = useState(false)
  const clear = useUpgradeRequest('Clear the recorded failure', () => setClearOpen(false))
  const rebuild = useUpgradeRequest('Rebuild the support bundle')
  const restore = useUpgradeRequest('Restore the pre-upgrade archive copy')
  const u = status.upgrade
  const rolled = run.result === 'rolled_back'
  const operator = run.result === 'failed_needs_operator'
  const failure = run.failure
  const bundle = run.bundle
  const migrations = run.manifest?.migrations ?? []
  const unsafe = migrations.filter(m => !m.rollback_safe)
  const failures = u?.failures ?? {}
  const total = Object.values(failures).reduce((n, f) => n + f.count, 0)
  const fixedHealth = (run.health ?? []).find(h => !h.ok)
  return (
    <>
      <section className="card p-4 border-loss/50" aria-labelledby="t-fail">
        <h2 className="m-0 text-lg font-semibold text-text flex items-center gap-2" id="t-fail" role="alert">
          <AlertTriangle size={20} className="text-loss" aria-hidden="true" />
          {operator ? `The upgrade to ${run.version_to} failed and could not be rolled back automatically`
            : rolled ? `The upgrade to ${run.version_to} failed and was rolled back automatically`
              : `The upgrade to ${run.version_to} failed before anything was switched`}
        </h2>
        <div className="grid gap-5 md:grid-cols-2 mt-3">
          <div>
            <h3 className={`${SEC_LABEL} m-0 mb-2`}>What happened</h3>
            <p className="text-xs text-text-dim m-0">
              {failure?.step || run.failed_step ? <>At step <strong>{failure?.step ?? run.failed_step}</strong>: </> : null}
              {describeReason(run.reason_code)} (reason code <code className="font-mono">{run.reason_code}</code>).
              {fixedHealth && <> {fixedHealth.detail}</>}
              {failure?.detail && !fixedHealth && <> {failure.detail}</>}
              {operator && run.operator_reason && <> {run.operator_reason}</>}
            </p>
          </div>
          <div>
            <h3 className={`${SEC_LABEL} m-0 mb-2`}>Where you are now</h3>
            {operator ? (
              <ul className="m-0 pl-[18px] list-disc flex flex-col gap-1.5 text-xs text-text-dim">
                <li><strong>An operator must act on the server.</strong> Nothing more can be done from this page. The previous release is still on disk; a maintenance page tells other users.</li>
                <li>Run <code className="font-mono">ocw-updater status</code> there. Any version other than {run.version_to} is refused until the failure is cleared.</li>
              </ul>
            ) : (
              <ul className="m-0 pl-[18px] list-disc flex flex-col gap-1.5 text-xs text-text-dim">
                <li>Running <strong>{rolled ? run.rolled_back_to ?? run.version_from : run.version_from}</strong>, the version from before.{rolled && run.rollback_health?.length ? ` Rollback health checks passed (${run.rollback_health.filter(h => h.ok).length} of ${run.rollback_health.length}).` : ''}</li>
                {rolled && run.schema_after != null && (
                  <li>The archive schema is at <strong>{run.schema_after}</strong>
                    {unsafe.length > 0 && <>: migration{unsafe.length > 1 ? 's' : ''} {unsafe.map(m => m.version).join(', ')} cannot be undone by a code rollback. {run.version_from} reads it, but newer indexes go unused</>}.</li>
                )}
                <li><strong>No data was changed by the rollback.</strong> Syncs continue.</li>
                <li>{run.version_to} will not be retried until an operator clears this failure. {total >= 2 ? 'Two upgrades have failed, so the Upgrade button stays off: contact the maintainers with the bundle.' : 'After two failures the Upgrade button stays off: contact the maintainers with the bundle.'}</li>
              </ul>
            )}
          </div>
        </div>
        <div className={`${KV} mt-3`}>
          <Row label="Correlation"><code className="font-mono text-xs">{run.correlation_id}</code> · journal: <code className="font-mono text-xs">journalctl -u ocw-upgrade -o cat | jq 'select(.correlation_id=="{run.correlation_id}")'</code></Row>
          <Row label="Requested by">{run.requested_by ?? 'an admin'}</Row>
        </div>
      </section>

      <section className="card p-4" aria-labelledby="t-bundle">
        <h2 className={CARD_TITLE} id="t-bundle">Send the maintainers a support bundle</h2>
        <div className="grid gap-5 md:grid-cols-2">
          <div>
            {bundle ? (
              <>
                <div className={KV}>
                  <Row label="File"><code className="font-mono text-xs break-all">{bundle.name}</code></Row>
                  <Row label="Size">{formatBytes(bundle.size)} (cap 5 MB; journals truncated head and tail if needed)</Row>
                  <Row label="sha256"><code className="font-mono text-xs">{shortSha(bundle.sha256)}</code></Row>
                  <Row label="Built by">the updater on the server, before anyone asked — no shell access needed to get it</Row>
                </div>
                <label className="flex gap-2.5 items-start mt-3 text-xs text-text-dim cursor-pointer">
                  <input type="checkbox" className="mt-0.5 w-[15px] h-[15px] accent-[var(--color-accent)]" checked={hosts} onChange={e => setHosts(e.target.checked)} />
                  <span>Include host names and environment names unredacted (off: they appear as <code className="font-mono">host-a1b2c3</code>, <code className="font-mono">env-d4e5f6</code>). Re-builds the bundle; needs a step-up approval.</span>
                </label>
                <div className="flex gap-2 flex-wrap items-center mt-3">
                  <a className="btn-primary no-underline" href={upgradeBundleUrl(bundle.name)} download={bundle.name}><Download size={14} aria-hidden="true" />Download support bundle</a>
                  {hosts && (
                    <button type="button" className="btn-secondary !text-text-dim" disabled={rebuild.isPending}
                      onClick={() => rebuild.mutate({ kind: 'bundle', include_hosts: true, for_correlation_id: run.correlation_id ?? undefined })}>
                      <RefreshCw size={14} aria-hidden="true" />Rebuild with host names…
                    </button>
                  )}
                  <button type="button" className="btn-secondary !text-text-dim" onClick={() => setClearOpen(true)}>Clear failure…</button>
                </div>
                <p className="text-xs text-muted mt-2 mb-0">Clearing (step-up) allows {run.version_to} to be tried again, for example after a fixed release is out. From the server: <code className="font-mono">sudo ocw-updater clear-failure</code></p>
                <TypedConfirmDialog open={clearOpen} onOpenChange={setClearOpen} title="Clear the recorded failure?" confirmLabel="Clear failure"
                  busy={clear.isPending} onConfirm={() => clear.mutate({ kind: 'clear_failure' })}>
                  <p className="m-0">The updater forgets that {run.version_to} failed, so it can be approved again. Nothing is installed by this. If the same release fails again it is recorded again (after two failures the Upgrade button stays off).</p>
                </TypedConfirmDialog>
              </>
            ) : <p className="text-xs text-text-dim m-0">No support bundle could be built for this run. The journal on the server has the details (correlation id above).</p>}
            <p className="text-xs text-text-dim mt-3 mb-0"><strong>Email this file to the security contact in SECURITY.md</strong> with the correlation id in the subject. <strong>Nothing is sent automatically.</strong></p>
          </div>
          <div>
            <div className={`${SEC_LABEL} mb-1.5`}>What is in it</div>
            <ul className="m-0 pl-[18px] list-disc flex flex-col gap-1 text-xs text-text-dim">
              <li><code className="font-mono">summary.json</code>: versions, reason code and failed step, timings, OS/Python/SQLite/systemd versions, free space, the manifest, verifier output, <code className="font-mono">pip freeze</code>, schema before/after, health responses, chain-head comparison, state history</li>
              <li>Last 500 journal lines of each service unit and of the updater since the run started; <code className="font-mono">nginx -t</code>; <code className="font-mono">systemctl status</code></li>
              <li>The audit entries with this correlation id</li>
              <li><code className="font-mono">redaction-report.txt</code>: what was redacted and how many times</li>
            </ul>
            <div className={`${SEC_LABEL} mt-2.5 mb-1.5`}>Never included</div>
            <p className="text-xs text-text-dim m-0">The environment file, keyring contents, session key, the archive or any row from it, environment metadata, the nginx site file, request bodies, cookies.</p>
            <div className={`${SEC_LABEL} mt-2.5 mb-1.5`}>Redacted before the archive is written</div>
            <p className="text-xs text-text-dim m-0">Secrets, tokens, passwords and keys; Authorization and cookie headers; Okta tokens and JWTs; e-mail addresses; Okta subject ids; host names and IPs; tenant and environment names. Hashes use a per-bundle salt.</p>
          </div>
        </div>
      </section>

      {rolled && !!run.backup && (
        <section className="card p-4 border-loss/50" aria-labelledby="t-restore">
          <h2 className={CARD_TITLE} id="t-restore"><AlertTriangle size={14} className="text-loss" aria-hidden="true" />Restore the pre-upgrade archive copy <Badge tone="err">Loses data</Badge></h2>
          <p className="text-xs text-text-dim m-0 max-w-[80ch]">
            This is <strong>not</strong> part of the rollback and is normally not needed. It replaces the current archive with the copy taken before the upgrade
            {run.backup ? <> (<code className="font-mono">{run.backup.name}</code>, {formatBytes(run.backup.size)})</> : null}.
            <strong> Every event archived since then would disappear from the archive.</strong> The current database is moved aside, never deleted. Only do this if the maintainers tell you to, and after you have the support bundle.
          </p>
          <div className="flex gap-2 flex-wrap items-center mt-3">
            <label htmlFor="restore-typed" className={SEC_LABEL}>Type <code className="font-mono normal-case">RESTORE</code> to confirm</label>
            <input id="restore-typed" className="text-input w-40" autoComplete="off" spellCheck={false} value={typed} onChange={e => setTyped(e.target.value)} />
            <button type="button" className="btn-primary !bg-loss" disabled={typed !== 'RESTORE' || restore.isPending}
              onClick={() => restore.mutate({ kind: 'restore', confirm: 'RESTORE' })}>Restore pre-upgrade copy…</button>
            <span className="text-xs text-muted">Then a step-up MFA approval. Logged as <code className="font-mono">upgrade.restore_requested</code>. From the server: <code className="font-mono">sudo ocw-updater restore --confirm RESTORE</code></span>
          </div>
        </section>
      )}
    </>
  )
}
