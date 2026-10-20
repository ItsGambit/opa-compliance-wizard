import { useState } from 'react'
import * as AlertDialog from '@radix-ui/react-alert-dialog'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { CalendarClock, Play, X } from 'lucide-react'
import { isStepUpRequired, requestUpgrade } from '../../api/client'
import { toast } from '../../hooks/useToast'
import type { UpgradeStatus } from '../../types'
import { formatDateTime } from '../../utils/format'
import { beginStepUp } from '../../utils/stepUp'
import { browserZone, formatInZone, formatUtc, serverZoneOf, shortSha, untilText } from '../../utils/upgradeFlow'
import { Badge, CARD_TITLE, KeyId, KV, Row } from './parts'

interface Props {
  status: UpgradeStatus
  onReschedule: () => void
  onRunNow: () => void
  now?: () => number
}

/** Artboard 07: the schedule, in the server's zone, the admin's and UTC; what happens at the time; cancel / reschedule / run it now.
 * A missed schedule (the application was not running at the time) is shown instead, never run late. */
export function ScheduledCard({ status, onReschedule, onRunNow, now = Date.now }: Props) {
  const queryClient = useQueryClient()
  const [confirmCancel, setConfirmCancel] = useState(false)
  const sched = status.upgrade!.schedule!
  const missed = sched.status === 'missed'
  const whenMs = Date.parse(sched.when_utc)
  const serverZone = serverZoneOf(status)
  const local = browserZone()
  const cancel = useMutation({
    mutationFn: () => requestUpgrade({ kind: 'cancel' }),
    onSuccess: resp => {
      if (isStepUpRequired(resp)) {
        beginStepUp(resp.action_id, { kind: 'environment_change', action: resp.action, label: `Cancel the upgrade to ${sched.version}`, startedAt: Date.now(), reopen: 'updates' })
        return
      }
      for (const key of ['upgrade_status', 'upgrade_notice', 'audit_log']) queryClient.invalidateQueries({ queryKey: [key] })
      toast({ title: 'Scheduled upgrade cancelled', variant: 'success' })
    },
    onError: (err: Error) => toast({ title: 'Could not cancel', description: err.message, variant: 'error' }),
  })
  return (
    <section className={`card p-4 ${missed ? 'border-loss/50' : 'border-warn/50'}`} aria-labelledby="t-sched">
      <h2 className={CARD_TITLE} id="t-sched">
        <CalendarClock size={14} className={missed ? 'text-loss' : 'text-warn'} aria-hidden="true" />
        {missed ? `The scheduled upgrade to ${sched.version} was missed` : `Upgrade to ${sched.version} scheduled`}
        {missed ? <Badge tone="err">Missed</Badge> : <Badge tone="warn">{untilText(whenMs, now())}</Badge>}
      </h2>
      <div className="text-xl font-semibold text-text mb-1">
        {formatInZone(whenMs, serverZone ?? local)} <span className="text-sm font-normal text-muted">({serverZone ? `server time, ${serverZone}` : `your time, ${local}`})</span>
      </div>
      <div className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs mb-3 items-baseline">
        {serverZone && <><span className="section-label">Your local</span><span className="text-text-dim">{formatInZone(whenMs, local)}</span></>}
        <span className="section-label">UTC</span><span className="text-text-dim">{formatUtc(whenMs)}</span>
        <span className="section-label">Entered as</span>
        <span className="text-text-dim">{sched.entered ?? 'UTC'}, by {sched.actor_email ?? 'an admin'} · {formatDateTime(sched.approved_at)} · step-up MFA verified · audit <code className="font-mono">upgrade.scheduled</code></span>
      </div>
      <div className={KV}>
        <Row label="Release">
          {sched.version} · <Badge tone="ok">Signed hash approved</Badge> sha256 <code className="font-mono text-xs">{shortSha(sched.sha256)}</code>{sched.key_id && <> · key <KeyId id={sched.key_id} /></>}.
          The updater downloads it, verifies it again and refuses it if anything differs from what you approved.
        </Row>
        <Row label="At the time">Preflight re-runs (disk, no sync running); a running sync finishes first and no new sync starts. Expected downtime about a minute.</Row>
        <Row label="If the app is down">The upgrade is marked <strong>missed</strong>, shown here, and does not run late. Schedule it again.</Row>
        <Row label="Correlation"><code className="font-mono text-xs">{sched.correlation_id}</code></Row>
      </div>
      <div className="flex gap-2 flex-wrap items-center mt-3.5">
        <button type="button" className="btn-secondary !text-text-dim" onClick={onReschedule}><CalendarClock size={14} aria-hidden="true" />{missed ? 'Schedule again…' : 'Reschedule…'}</button>
        {!missed && (
          <AlertDialog.Root open={confirmCancel} onOpenChange={setConfirmCancel}>
            <AlertDialog.Trigger asChild>
              <button type="button" className="btn-secondary !text-loss !border-loss/40"><X size={14} aria-hidden="true" />Cancel upgrade…</button>
            </AlertDialog.Trigger>
            <AlertDialog.Portal>
              <AlertDialog.Overlay className="fixed inset-0 bg-black/60 z-40" />
              <AlertDialog.Content className="card fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-50 w-[calc(100vw-2rem)] sm:w-[28rem] p-5">
                <AlertDialog.Title className="m-0 text-sm font-semibold text-text">Cancel the scheduled upgrade?</AlertDialog.Title>
                <AlertDialog.Description className="text-xs text-text-dim mt-2">
                  The upgrade to {sched.version} will not run. Cancelling needs a step-up MFA approval and is written to the audit log.
                </AlertDialog.Description>
                <div className="flex justify-end gap-2 mt-4">
                  <AlertDialog.Cancel asChild><button type="button" className="btn-secondary !text-text-dim">Keep the schedule</button></AlertDialog.Cancel>
                  <AlertDialog.Action asChild><button type="button" className="btn-primary" onClick={() => cancel.mutate()}>Cancel the upgrade</button></AlertDialog.Action>
                </div>
              </AlertDialog.Content>
            </AlertDialog.Portal>
          </AlertDialog.Root>
        )}
        {!missed && <button type="button" className="btn-secondary !text-text-dim" onClick={onRunNow}><Play size={14} aria-hidden="true" />Run it now instead…</button>}
        <span className="text-xs text-muted">Each of these needs a step-up MFA approval and is written to the audit log.</span>
      </div>
    </section>
  )
}
