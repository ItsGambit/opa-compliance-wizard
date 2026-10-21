import { useEffect, useRef, useState } from 'react'
import { Check, CircleDashed, Loader2, X } from 'lucide-react'
import type { BootstrapStepEvent } from '../api/client'
import type { JobPhase } from '../hooks/useAccessScanJob'
import type { RefreshPart, RefreshPartName, RefreshStatus } from '../types'
import {
  ACTIVE_PART_STATES, completedText, elapsedText, isActive, isFailed, OKTA_SUB_LABELS, partAnnouncement, REFRESH_PART_LABELS, requestedParts, stateBadge, tally,
} from '../utils/refresh'
import { formatDateTimeZone } from '../utils/format'
import { deriveSteps } from '../utils/bootstrapSteps'
import { StatusBadge } from './StatusBadge'

const COLLAPSE_AFTER_MS = 60_000
const TONE_VARIANT = { ok: 'active', warn: 'warn', error: 'error', accent: 'exists', neutral: 'neutral' } as const

interface StepRow { key: string; label: string; status: 'pending' | 'active' | 'done' | 'error' | 'skipped'; detail?: string }

const STATUS_TEXT: Record<StepRow['status'], string> = { pending: 'not started', active: 'running', done: 'done', error: 'failed', skipped: 'skipped' }

function StepIcon({ status }: { status: StepRow['status'] }) {
  if (status === 'done') return <Check size={12} aria-hidden="true" className="text-win shrink-0" />
  if (status === 'active') return <Loader2 size={12} aria-hidden="true" className="text-accent-text animate-spin shrink-0" />
  if (status === 'error') return <X size={12} aria-hidden="true" className="text-loss shrink-0" />
  return <CircleDashed size={12} aria-hidden="true" className="text-text-faint shrink-0" />
}

function Steps({ rows }: { rows: StepRow[] }) {
  if (rows.length === 0) return null
  return (
    <ul className="flex flex-col gap-0.5 mt-1 list-none p-0 m-0">
      {rows.map(r => (
        <li key={r.key} className={`flex gap-1.5 items-center text-[0.6875rem] ${r.status === 'pending' || r.status === 'skipped' ? 'text-muted' : 'text-text-dim'}`}>
          <StepIcon status={r.status} />
          {/* The icon's colour is not the only signal (WCAG 1.4.1): the state is also text. */}
          <span className="sr-only">{STATUS_TEXT[r.status]}: </span>
          <span>{r.label}</span>
          {r.detail && <span className="text-text-faint">— {r.detail}</span>}
        </li>
      ))}
    </ul>
  )
}

function opaSteps(part: RefreshPart): StepRow[] {
  const defs = part.step_defs ?? []
  const phase: JobPhase = part.state === 'running' || part.state === 'pending' ? 'running' : (part.state === 'ok' ? 'done' : 'error')
  return deriveSteps(defs, (part.steps ?? []) as BootstrapStepEvent[], phase).map(s => ({
    key: s.key, label: s.label, detail: s.detail, status: s.status === 'active' ? 'active' : s.status,
  }))
}

function oktaSteps(part: RefreshPart, opaRunning: boolean): StepRow[] {
  const sub = part.sub ?? {}
  return Object.keys(OKTA_SUB_LABELS).filter(k => sub[k] && sub[k].state !== 'not_requested').map(k => {
    const s = sub[k]
    const status: StepRow['status'] = s.state === 'ok' ? 'done' : s.state === 'running' ? 'active' : s.state === 'refused' || s.state === 'error' ? 'error'
      : s.state === 'skipped' || s.state === 'cancelled' ? 'skipped' : 'pending'
    const detail = s.state === 'waiting' ? (opaRunning ? 'waiting for the OPA scan' : 'waiting') : status === 'done' || status === 'error' || status === 'skipped' ? s.message : undefined
    return { key: k, label: OKTA_SUB_LABELS[k], status, detail }
  })
}

function logDetail(part: RefreshPart): string | undefined {
  if (part.state === 'ok') {
    const n = part.events_new ?? 0
    return `${n.toLocaleString()} new event${n === 1 ? '' : 's'}${part.adopted ? ' · used a sync that was already running' : ''}`
  }
  const last = [...(part.steps ?? [])].reverse().find(s => s.detail)
  return last?.detail ?? undefined
}

function PartRow({ name, part, opaRunning, elapsed, canRun, onRetry }: { name: RefreshPartName; part: RefreshPart; opaRunning: boolean; elapsed: string; canRun: boolean; onRetry: (p: RefreshPartName) => void }) {
  const labels = REFRESH_PART_LABELS[name]
  const badge = stateBadge(part)
  const failed = isFailed(part.state)
  const steps = name === 'opa' ? opaSteps(part) : name === 'okta' ? oktaSteps(part, opaRunning) : []
  const showSteps = isActive(part.state) || failed || (name === 'okta' && part.state !== 'ok')
  return (
    <div className={`grid gap-3 rounded-lg border bg-bg-elevated p-3 sm:grid-cols-[9.5rem_7rem_1fr_5.5rem] ${failed ? 'border-loss/45' : 'border-border-sub'}`}>
      <div className="text-[0.8125rem] font-semibold text-text">{labels.name}<small className="block font-normal text-[0.6875rem] text-muted">{labels.sub}</small></div>
      <div><StatusBadge label={badge.label} variant={TONE_VARIANT[badge.tone]} /></div>
      <div className="text-xs text-text-dim leading-relaxed min-w-0">
        {name === 'log' && logDetail(part) && <div>{logDetail(part)}</div>}
        {showSteps && <Steps rows={steps} />}
        {part.state !== 'running' && part.state !== 'pending' && part.message && <div className={`mt-1 ${failed ? 'text-loss' : 'text-text'}`}>{part.message}</div>}
        {failed && canRun && (
          <div className="mt-1.5"><button type="button" className="text-accent-text underline underline-offset-2 text-xs" onClick={() => onRetry(name)}>Retry this part<span className="sr-only">: {labels.name}</span></button></div>
        )}
      </div>
      <div className="text-[0.6875rem] text-muted text-right tabular-nums">{elapsed}</div>
    </div>
  )
}

interface Props {
  status: RefreshStatus
  canRun: boolean
  onRetry: (part: RefreshPartName) => void
  onStop: () => void
  /** For tests: a fixed "now" instead of the clock. */
  now?: number
}

/** The Overview's refresh progress (5.51.0): three rows with a state badge, the current step and the outcome of each part. Visible while a
 * refresh runs and for a minute after; then one line with "Details". Screen readers hear each part's end state once, in a polite live region
 * (not every step), and the summary at the end. */
export function RefreshProgressCard({ status, canRun, onRetry, onStop, now: fixedNow }: Props) {
  const [tick, setTick] = useState(() => Date.now())
  const [detailsOpen, setDetailsOpen] = useState(false)
  const running = status.status === 'running'
  const finishedMs = status.finished_at ? new Date(status.finished_at).getTime() : null
  const clock = fixedNow ?? tick

  // The clock only ticks while something changes with it: elapsed times, and the one-minute collapse.
  useEffect(() => {
    if (fixedNow != null) return
    const recent = finishedMs != null && Date.now() - finishedMs < COLLAPSE_AFTER_MS
    if (!running && !recent) return
    const id = setInterval(() => setTick(Date.now()), 1000)
    return () => clearInterval(id)
  }, [running, finishedMs, fixedNow])

  // Live announcements: each part once, when it ends; the summary when the job does. A new job starts fresh.
  const seen = useRef<{ job: string | null; parts: Record<string, string>; summary: boolean }>({ job: null, parts: {}, summary: false })
  const [announcement, setAnnouncement] = useState('')
  useEffect(() => {
    if (!status.job_id) return
    if (seen.current.job !== status.job_id) {
      // Attaching to a job this page did not see start: what has already ended is on screen, not announced again.
      seen.current = { job: status.job_id, parts: Object.fromEntries(requestedParts(status).filter(p => !isActive(status.parts[p].state)).map(p => [p, status.parts[p].state])), summary: status.status === 'done' }
      setDetailsOpen(false)
      return
    }
    const fresh: string[] = []
    for (const p of requestedParts(status)) {
      const state = status.parts[p].state
      if (!ACTIVE_PART_STATES.includes(state) && seen.current.parts[p] !== state) {
        seen.current.parts[p] = state
        fresh.push(partAnnouncement(p, status.parts[p]))
      }
    }
    if (status.status === 'done' && !seen.current.summary) {
      seen.current.summary = true
      const t = tally(status)
      fresh.push(`Refresh finished: ${completedText(t.done, t.total)}.`)
    }
    if (fresh.length) setAnnouncement(fresh.join(' '))
  }, [status])

  if (status.status === 'idle') return null
  const t = tally(status)
  const collapsed = !running && !detailsOpen && finishedMs != null && clock - finishedMs >= COLLAPSE_AFTER_MS
  const live = <div role="status" aria-live="polite" className="sr-only" data-testid="refresh-live">{announcement}</div>
  const summary = running ? 'Refreshing…' : t.failing.length === 0 ? `Refresh finished ${formatDateTime(status.finished_at)}: ${completedText(t.done, t.total)}.` : `Refresh finished ${formatDateTime(status.finished_at)}: ${completedText(t.done, t.total)}; ${t.failing.map(p => `${REFRESH_PART_LABELS[p].name} ${status.parts[p].state === 'refused' ? 'refused' : status.parts[p].state === 'timed_out' ? 'timed out' : 'did not complete'}`).join(', ')}.`

  if (collapsed) {
    return (
      <section aria-label="Refresh progress" className="card px-4 py-2.5">
        {live}
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <span className="text-[0.8125rem] font-semibold text-text flex items-center gap-2"><StatusBadge label={t.failing.length === 0 ? 'Completed' : `${t.done} of ${t.total} completed`} variant={t.failing.length === 0 ? 'active' : 'warn'} /> {summary}</span>
          <button type="button" className="text-accent-text underline underline-offset-2 text-xs" onClick={() => setDetailsOpen(true)}>Details</button>
        </div>
      </section>
    )
  }
  const parts = requestedParts(status)
  const order = (['opa', 'log', 'okta'] as RefreshPartName[]).filter(p => parts.includes(p))
  const opaRunning = status.parts.opa.state === 'running'
  const elapsedFor = (p: RefreshPartName) => elapsedText(status.parts[p].started_at, status.parts[p].finished_at, clock)
  return (
    <section aria-label="Refresh progress" className="card p-4 flex flex-col gap-3">
      {live}
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <h2 className="text-sm font-semibold text-text flex items-center gap-2">
          {running ? 'Refreshing' : 'Refresh finished'}
          <StatusBadge label={running ? `running · ${elapsedText(status.started_at ?? undefined, undefined, clock)}` : completedText(t.done, t.total)} variant={running ? 'exists' : t.failing.length === 0 ? 'active' : 'warn'} />
        </h2>
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs text-muted">
            {status.started_at ? `Started ${formatDateTimeZone(status.started_at)}` : ''}{status.finished_at ? ` · finished ${formatDateTimeZone(status.finished_at)}` : ''}
          </span>
          {running && canRun && <button type="button" className="btn-secondary" onClick={onStop} disabled={status.cancel_requested}>{status.cancel_requested ? 'Stopping…' : 'Stop'}</button>}
          {!running && detailsOpen && <button type="button" className="text-accent-text underline underline-offset-2 text-xs" onClick={() => setDetailsOpen(false)}>Hide</button>}
        </div>
      </div>
      <div className="flex flex-col gap-2">
        {order.map(p => <PartRow key={p} name={p} part={status.parts[p]} opaRunning={opaRunning} elapsed={elapsedFor(p)} canRun={canRun && !running} onRetry={onRetry} />)}
      </div>
    </section>
  )
}

function formatDateTime(iso: string | null): string {
  return formatDateTimeZone(iso)
}
