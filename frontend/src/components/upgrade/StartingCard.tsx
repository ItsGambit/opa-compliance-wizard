import { AlertTriangle } from 'lucide-react'
import type { UpgradeStatus } from '../../types'
import { formatDateTime } from '../../utils/format'
import { describeReason } from '../../utils/upgradeFlow'
import type { RequestedUpgrade } from '../../utils/upgradeRequested'
import { Badge, CARD_TITLE, KV, Row, Spinner } from './parts'

const WHAT: Record<string, { ing: string; noun: string }> = {
  apply: { ing: 'Starting the upgrade', noun: 'the upgrade' },
  rollback: { ing: 'Rolling back to the previous version', noun: 'the rollback' },
  restore: { ing: 'Restoring the pre-upgrade archive copy', noun: 'the restore' },
  clear_failure: { ing: 'Clearing the recorded failure', noun: 'clearing the failure' },
  bundle: { ing: 'Rebuilding the support bundle', noun: 'rebuilding the bundle' },
}

/** Artboard 06, the explainer: how an approval travels (the app's existing step-up pattern, unchanged). */
export function ApprovalTravels({ version }: { version: string }) {
  return (
    <section className="card p-4" aria-labelledby="t-flow">
      <h2 className={CARD_TITLE} id="t-flow">How the approval travels (OCW's existing step-up pattern, unchanged)</h2>
      <div className="grid gap-3 md:grid-cols-[1fr_auto_1fr_auto_1fr] items-stretch">
        <div className="rounded-lg border border-border bg-bg-elevated p-3 text-xs text-text-dim flex flex-col gap-2">
          <h3 className="m-0 text-xs font-semibold text-text">1 · Approve with MFA</h3>
          <span><code className="font-mono">POST /api/upgrade/request</code> stores the exact version and sha256 as a pending action and answers <code className="font-mono">202 step_up_required</code>.
            The browser remembers "upgrade {version}" and leaves for <code className="font-mono">/step-up?action_id=…</code>.</span>
        </div>
        <span className="hidden md:grid place-items-center text-muted" aria-hidden="true">→</span>
        <div className="rounded-lg border border-dashed border-border bg-bg-elevated p-3 text-xs text-text-dim flex flex-col gap-2">
          <h3 className="m-0 text-xs font-semibold text-text">2 · Fresh MFA at the identity provider (external)</h3>
          <span>Okta Identity Engine challenge with <code className="font-mono">max_age=0</code> and <code className="font-mono">acr_values=urn:okta:loa:2fa:any</code>; the gate refuses a stale <code className="font-mono">auth_time</code>. It is Okta's own page.</span>
          <span className="text-muted">Single-use proof, valid 120 s; the pending action expires after 15 min.</span>
        </div>
        <span className="hidden md:grid place-items-center text-muted" aria-hidden="true">→</span>
        <div className="rounded-lg border border-border bg-bg-elevated p-3 text-xs text-text-dim flex flex-col gap-2">
          <h3 className="m-0 text-xs font-semibold text-text">3 · Back with <code className="font-mono">?stepup_complete=1</code></h3>
          <span><code className="font-mono">POST /api/environment_changes/save</code> consumes the action bound to this admin, re-checks the signed hash, writes <code className="font-mono">inbox/requests/&lt;correlation&gt;.json</code> and logs <code className="font-mono">upgrade.requested</code> with <code className="font-mono">step_up_verified: true</code>.</span>
          <span><Badge tone="ok">Approved via step-up MFA</Badge></span>
        </div>
      </div>
      <p className="text-xs text-muted mt-2.5 mb-0">If the approval does not complete, the page says so ("The MFA approval expired before the change was applied", "This approval was already used or abandoned", "The MFA approval wasn't completed, so nothing changed") and reopens with your choices restored.</p>
    </section>
  )
}

interface Props {
  requested: RequestedUpgrade
  status: UpgradeStatus
  ageMs: number
  /** The updater has the request and is in its first steps. */
  received: boolean
  onFollow: () => void
}

/** Artboard 06 (after the approval): "Starting the upgrade ... Received by the updater", with Follow progress. Shown from the moment the MFA
 * approval returns until the user follows or the run is past its download step; or, if the updater refused it, the refusal. */
export function StartingCard({ requested, status, ageMs, received, onFollow }: Props) {
  const rejection = status.upgrade?.rejection
  const what = WHAT[requested.kind ?? 'apply']
  const title = requested.kind ? what.ing : `Starting the upgrade to ${requested.version}`
  if (rejection && rejection.correlation_id === requested.correlationId) {
    const title2 = requested.kind ? `The updater refused: ${what.noun}` : `The updater refused the upgrade to ${requested.version}`
    return (
      <section className="card p-4 border-loss/50" aria-labelledby="t-start" role="alert">
        <h2 className={CARD_TITLE} id="t-start"><AlertTriangle size={14} className="text-loss" aria-hidden="true" />{title2} <Badge tone="err">Refused</Badge></h2>
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
        <Row label="Next">
          {requested.kind
            ? 'The updater picks the request up within seconds and re-checks it before doing anything. This page keeps polling every 2 s.'
            : 'The updater now downloads and verifies the signed release, then runs preflight, backup, switch, restart and health checks. This page keeps polling every 2 s.'}
        </Row>
      </div>
      {received && (
        <div className="mt-3"><button type="button" className="btn-secondary !text-text-dim" onClick={onFollow}>Follow progress</button></div>
      )}
      {slow && (
        <p role="alert" className="text-xs text-warn mt-3 mb-0 flex gap-1.5">
          <AlertTriangle size={14} className="shrink-0 mt-px" aria-hidden="true" />
          The updater has not picked the request up after three minutes. On the server, check <code className="font-mono">systemctl status ocw-upgrade.path ocw-upgrade.service</code> or run <code className="font-mono">ocw-updater status</code>.
        </p>
      )}
    </section>
  )
}
