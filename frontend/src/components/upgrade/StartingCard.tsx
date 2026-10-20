import { AlertTriangle } from 'lucide-react'
import type { UpgradeStatus } from '../../types'
import { formatDateTime } from '../../utils/format'
import { describeReason } from '../../utils/upgradeFlow'
import type { RequestedUpgrade } from '../../utils/upgradeRequested'
import { Badge, CARD_TITLE, KV, Row, Spinner } from './parts'

/** Artboard 06 (after the approval): "Starting the upgrade ... Received by the updater". Shown from the moment the MFA approval
 * returns until the updater's state file names this request (or refuses it). */
const WHAT: Record<string, { ing: string; noun: string }> = {
  apply: { ing: 'Starting the upgrade', noun: 'the upgrade' },
  rollback: { ing: 'Rolling back to the previous version', noun: 'the rollback' },
  restore: { ing: 'Restoring the pre-upgrade archive copy', noun: 'the restore' },
  clear_failure: { ing: 'Clearing the recorded failure', noun: 'clearing the failure' },
  bundle: { ing: 'Rebuilding the support bundle', noun: 'rebuilding the bundle' },
  prune_backups: { ing: 'Deleting the older backups', noun: 'deleting the backups' },
}

export function StartingCard({ requested, status, ageMs }: { requested: RequestedUpgrade; status: UpgradeStatus; ageMs: number }) {
  const rejection = status.upgrade?.rejection
  const what = WHAT[requested.kind ?? 'apply']
  const title = requested.kind ? `${what.ing}` : `Starting the upgrade to ${requested.version}`
  const refusedTitle = requested.kind ? `The updater refused: ${what.noun}` : `The updater refused the upgrade to ${requested.version}`
  const received = status.upgrade?.run?.correlation_id === requested.correlationId
  if (rejection && rejection.correlation_id === requested.correlationId) {
    return (
      <section className="card p-4 border-loss/50" aria-labelledby="t-start" role="alert">
        <h2 className={CARD_TITLE} id="t-start"><AlertTriangle size={14} className="text-loss" aria-hidden="true" />{refusedTitle} <Badge tone="err">Refused</Badge></h2>
        <p className="text-xs text-text-dim m-0">{describeReason(rejection.code)}. <span className="text-muted">({rejection.message})</span></p>
        <p className="text-xs text-muted mt-2 mb-0">Nothing was changed. Correlation <code className="font-mono">{requested.correlationId}</code>; details are in the Audit Log.</p>
      </section>
    )
  }
  const slow = ageMs > 3 * 60_000 && !received
  return (
    <section className="card p-4 border-accent/50" aria-labelledby="t-start">
      <h2 className={CARD_TITLE} id="t-start"><Spinner />{title} <Badge tone="acc">{received ? 'Received by the updater' : 'Waiting for the updater'}</Badge></h2>
      <div className={KV}>
        <Row label="Approved">{requested.email ?? 'an admin'} · {formatDateTime(requested.approvedAt)}{requested.stepUp && ' · step-up MFA verified'}</Row>
        <Row label="Correlation"><code className="font-mono text-xs">{requested.correlationId}</code> · ties the browser request, pending action, request file, updater run and audit events together</Row>
        <Row label="Next">The updater downloads and verifies the signed release, then runs preflight, backup, switch, restart and health checks. This page keeps polling every 2 s.</Row>
      </div>
      {slow && (
        <p role="alert" className="text-xs text-warn mt-3 mb-0 flex gap-1.5">
          <AlertTriangle size={14} className="shrink-0 mt-px" aria-hidden="true" />
          The updater has not picked the request up after three minutes. On the server, check <code className="font-mono">systemctl status ocw-upgrade.path ocw-upgrade.service</code> or run <code className="font-mono">ocw-updater status</code>.
        </p>
      )}
    </section>
  )
}
