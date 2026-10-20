import { useEffect, useMemo, useState } from 'react'
import * as Dialog from '@radix-ui/react-dialog'
import { Info } from 'lucide-react'
import type { UpgradeStatus } from '../../types'
import {
  browserZone, formatInZone, formatUtc, serverZoneOf, wallFields, wallToUtc,
} from '../../utils/upgradeFlow'
import { DialogCloseButton } from '../DialogCloseButton'

/** What the dialog hands to the confirmation screen. */
export interface ScheduleChoice {
  whenMs: number
  /** The IANA zone the admin typed the time in, and the wall time they typed (for the audit log). */
  enteredZone: string
  enteredLocal: string
}

interface Props {
  open: boolean
  onOpenChange: (open: boolean) => void
  status: UpgradeStatus
  version: string
  /** Pre-filled when rescheduling. */
  initialMs?: number
  title?: string
  onContinue: (choice: ScheduleChoice) => void
  /** Injected in tests. */
  now?: () => number
}

const MIN_LEAD_MS = 2 * 60_000
const MAX_AHEAD_MS = 31 * 24 * 3600_000

function nextOccurrenceUtc(hhmm: string, afterMs: number): number {
  const day = new Date(afterMs).toISOString().slice(0, 10)
  let t = wallToUtc(day, hhmm, 'UTC')
  if (t < afterMs + MIN_LEAD_MS) t += 24 * 3600_000
  return t
}

function addMinutes(hhmm: string, minutes: number): string {
  const [h, m] = hhmm.split(':').map(Number)
  const total = (h * 60 + m + minutes) % (24 * 60)
  return `${String(Math.floor(total / 60)).padStart(2, '0')}:${String(total % 60).padStart(2, '0')}`
}

/** Artboard 04: date, time, which zone the time is entered in (server or the admin's own), the same moment in server /
 * local / UTC (what is stored and logged), the clock agreement, and the maintenance-window hint. */
export function ScheduleDialog({ open, onOpenChange, status, version, initialMs, title, onContinue, now = Date.now }: Props) {
  const serverZone = serverZoneOf(status)
  const localZone = useMemo(browserZone, [])
  const zones = useMemo(() => {
    const list: { id: 'server' | 'local' | 'utc'; zone: string; label: string }[] = []
    if (serverZone) list.push({ id: 'server', zone: serverZone, label: `Server time — ${serverZone}` })
    list.push({ id: 'local', zone: localZone, label: `My local time — ${localZone}` })
    if (!serverZone || localZone !== 'UTC') list.push({ id: 'utc', zone: 'UTC', label: 'UTC' })
    return list
  }, [serverZone, localZone])
  const [zoneId, setZoneId] = useState<'server' | 'local' | 'utc'>(zones[0].id)
  const zone = (zones.find(z => z.id === zoneId) ?? zones[0]).zone
  const [date, setDate] = useState('')
  const [time, setTime] = useState('')

  // Defaults each time the dialog opens: the existing time when rescheduling, else tomorrow 03:30 in the chosen zone.
  useEffect(() => {
    if (!open) return
    const base = initialMs ?? wallToUtc(wallFields(now() + 24 * 3600_000, zone).date, '03:30', zone)
    const f = wallFields(base, zone)
    setDate(f.date)
    setTime(f.time)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open])

  const whenMs = wallToUtc(date, time, zone)
  const valid = !Number.isNaN(whenMs)
  const tooSoon = valid && whenMs < now() + MIN_LEAD_MS
  const tooFar = valid && whenMs > now() + MAX_AHEAD_MS
  const error = !valid ? 'Enter a date and a time.' : tooSoon ? 'That time is in the past or less than two minutes away. Pick a later time.'
    : tooFar ? 'An upgrade can be scheduled at most 31 days ahead.' : null
  const skew = Math.round(Math.abs(new Date(status.server.time).getTime() - now()) / 1000)

  const switchZone = (id: 'server' | 'local' | 'utc') => {
    const next = zones.find(z => z.id === id)!
    if (valid) {          // keep the same moment, show it in the new zone
      const f = wallFields(whenMs, next.zone)
      setDate(f.date)
      setTime(f.time)
    }
    setZoneId(id)
  }

  const hint = status.upgrade?.sync_hint
  const runTimes = hint?.daily_run_times_utc ?? []
  const lastRun = runTimes.length ? runTimes[runTimes.length - 1] : null
  const suggestion = lastRun ? addMinutes(lastRun, 30) : null
  const useSuggestion = () => {
    if (!suggestion) return
    const ms = nextOccurrenceUtc(suggestion, now())
    const f = wallFields(ms, zone)
    setDate(f.date)
    setTime(f.time)
  }
  const lastSync = hint?.last_sync_completed_at ? new Date(hint.last_sync_completed_at) : null

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/60 z-40" />
        <Dialog.Content
          aria-describedby="schedule-desc"
          className="card fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-50 w-[calc(100vw-2rem)] sm:w-[34rem] max-h-[90vh] overflow-y-auto p-5"
        >
          <div className="flex items-center justify-between mb-3">
            <Dialog.Title className="m-0 text-sm font-semibold text-text">{title ?? `Schedule the upgrade to ${version}`}</Dialog.Title>
            <DialogCloseButton />
          </div>
          <p id="schedule-desc" className="sr-only">Choose when the upgrade should start. You approve it with MFA on the next screen.</p>
          <div className="grid grid-cols-2 gap-3">
            <div className="flex flex-col gap-1">
              <label className="section-label" htmlFor="sched-date">Date</label>
              <input id="sched-date" type="date" className="text-input" value={date} onChange={e => setDate(e.target.value)} />
            </div>
            <div className="flex flex-col gap-1">
              <label className="section-label" htmlFor="sched-time">Time</label>
              <input id="sched-time" type="time" className="text-input" value={time} onChange={e => setTime(e.target.value)} />
            </div>
          </div>
          <fieldset className="border-0 p-0 mt-3 mb-0 flex gap-4 flex-wrap">
            <legend className="section-label mb-1.5">Time entered in</legend>
            {zones.map(z => (
              <label key={z.id} className="flex items-center gap-1.5 text-xs text-text-dim cursor-pointer">
                <input type="radio" name="sched-zone" className="accent-[var(--color-accent)]" checked={zoneId === z.id} onChange={() => switchZone(z.id)} />
                {z.label}
              </label>
            ))}
          </fieldset>
          <div className="mt-3 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-xs items-baseline" aria-live="polite" data-testid="sched-times">
            {valid ? (
              <>
                {serverZone && <><span className="section-label">Server</span><span className="text-text-dim">{formatInZone(whenMs, serverZone)}</span></>}
                <span className="section-label">Your local</span><span className="text-text-dim">{formatInZone(whenMs, localZone)}</span>
                <span className="section-label">UTC</span>
                <span className="text-text-dim">{formatUtc(whenMs)} — what is stored and logged, with the zone you chose</span>
              </>
            ) : <span className="col-span-2 text-text-dim">Enter a date and time to see it in each zone.</span>}
            <span className="section-label">Clocks</span>
            <span className={skew <= 5 ? 'text-text-dim' : 'text-warn'}>
              {skew <= 5 ? <><span className="text-win" aria-hidden="true">✓</span> your browser and the server agree within {Math.max(skew, 1)} s</>
                : `your browser and the server differ by ${skew} s: check which clock is right before relying on a local time`}
            </span>
          </div>
          {error && <p role="alert" className="text-xs text-loss mt-2 mb-0">{error}</p>}
          <div className="mt-3 flex gap-2 items-start rounded-lg border border-accent/40 bg-accent-dim p-2.5 text-xs text-text">
            <Info size={14} className="shrink-0 mt-0.5" aria-hidden="true" />
            <span>
              <strong>Maintenance window hint.</strong>{' '}
              {runTimes.length ? (
                <>
                  {lastSync && <>Last sync finished {lastSync.toISOString().slice(11, 16)} UTC; </>}a sync runs daily at {runTimes.join(', ')} UTC. The upgrade waits for a running
                  sync to finish and refuses to start one{suggestion && <>, so <strong>{suggestion} UTC</strong> (after the sync, about a minute of downtime) is a quiet slot</>}.{' '}
                  {suggestion && <button type="button" className="btn-secondary !text-xs !py-0.5 !px-2 ml-1" onClick={useSuggestion}>Use {suggestion} UTC</button>}
                </>
              ) : <>No daily sync is scheduled, so any time is quiet. A running sync would finish first, and no new sync starts during the upgrade.</>}
            </span>
          </div>
          <p className="text-xs text-muted mt-3 mb-0">
            The signed release is checked when you approve; the updater downloads and verifies it again when the upgrade starts. You can cancel or
            reschedule any time before it starts; both need a step-up MFA approval and are written to the audit log. If the application is not running at that time,
            the upgrade is marked <strong>missed</strong> and does not run late.
          </p>
          <div className="flex justify-end gap-2 mt-4">
            <button type="button" className="btn-secondary !text-text-dim" onClick={() => onOpenChange(false)}>Cancel</button>
            <button type="button" className="btn-primary" disabled={!!error}
              onClick={() => { onContinue({ whenMs, enteredZone: zone, enteredLocal: `${date}T${time}` }); onOpenChange(false) }}>
              Continue to confirmation
            </button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}
