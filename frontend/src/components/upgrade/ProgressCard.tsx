import { useEffect, useState } from 'react'
import { CheckCircle2 } from 'lucide-react'
import type { UpgradeRun } from '../../types'
import { HEALTH_CHECK_LABELS, HEALTH_CHECK_ORDER, UPGRADE_STEPS, clockIn, stepNumber, stepText } from '../../utils/upgradeFlow'
import { Badge, CARD_TITLE, Spinner } from './parts'

interface Props {
  run: UpgradeRun
  /** The poll is failing because the app is restarting underneath the page (502/503/network). */
  restarting: boolean
  /** The zone the times are shown in (the server's, else the browser's). */
  zone: string
  now?: () => number
}

function clock(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000))
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`
}

/** A small empty ring: a check that has not run yet (mockup 08a). */
function Ring() {
  return <span aria-hidden="true" className="inline-block w-2 h-2 rounded-full border border-muted shrink-0 mt-[3px]" />
}

/** Artboard 08a: the live step list. Polled every 2 s by the page; when the backend disappears during the restart the card says so
 * and keeps waiting (the page reloads itself once the new version answers). */
export function ProgressCard({ run, restarting, zone, now = Date.now }: Props) {
  const [tick, setTick] = useState(now())
  useEffect(() => {
    const id = setInterval(() => setTick(now()), 1000)
    return () => clearInterval(id)
  }, [now])
  const started = run.started_at ? Date.parse(run.started_at) : tick
  const done = new Map((run.steps_done ?? []).map(s => [s.step, s]))
  const current = stepNumber(run)
  const total = UPGRADE_STEPS.length
  const rollingBack = run.step === 'rolling_back'
  const stepLabel = UPGRADE_STEPS[Math.min(current, total) - 1]
  const pct = Math.min(100, Math.round(((done.size + 0.5) / total) * 100))
  return (
    <section className="card p-4 border-accent/50" aria-labelledby="t-prog">
      <div aria-live="polite">
        <h2 className={CARD_TITLE} id="t-prog">
          <Spinner />
          {rollingBack ? `Rolling back to ${run.version_from}` : `Upgrading to ${run.version_to}`}
          <Badge tone="acc">Step {current} of {total} · {rollingBack ? 'rolling back' : stepLabel.id.replace('_', ' ')}</Badge>
          <span className="text-xs text-muted font-normal ml-auto">elapsed {clock(tick - started)} · correlation <code className="font-mono font-bold text-text-dim">{run.correlation_id}</code></span>
        </h2>
        {restarting && (
          <p role="status" className="text-xs text-text mt-0 mb-3 flex items-center gap-2 rounded-lg border border-accent/40 bg-accent-dim px-2.5 py-2">
            <Spinner size={12} />Restarting — this normally takes under a minute. This page keeps asking and reloads itself when the new version answers.
          </p>
        )}
      </div>
      <div className="h-1 rounded bg-bg-hover overflow-hidden mb-2" role="progressbar" aria-label="Upgrade progress" aria-valuemin={0} aria-valuemax={total} aria-valuenow={current}>
        <span className="block h-full bg-accent" style={{ width: `${pct}%` }} />
      </div>
      <ol className="m-0 p-0 list-none flex flex-col">
        {UPGRADE_STEPS.map((step, i) => {
          const d = done.get(step.id)
          const isCurrent = !d && i + 1 === current && !rollingBack
          const state = d ? 'done' : isCurrent ? 'current' : 'todo'
          const text = d ? stepText(step.id, d.detail, run) : null
          return (
            <li key={step.id} data-state={state} className="grid grid-cols-[20px_1fr_auto] gap-3 items-start py-2.5 border-t border-border-sub first:border-t-0 text-xs">
              {state === 'done' ? <CheckCircle2 size={16} className="text-win mt-px" aria-hidden="true" />
                : state === 'current' ? <span className="mt-0.5"><Spinner /></span>
                  : <span className="mt-1 ml-1"><Ring /></span>}
              <div>
                <div className={`font-medium ${state === 'current' ? 'text-accent-text' : state === 'todo' ? 'text-muted' : 'text-text'}`}>
                  {i + 1} · {step.title}{state === 'current' && <> <Badge tone="acc">now</Badge></>}
                  <span className="sr-only"> ({state === 'done' ? 'done' : state === 'current' ? 'in progress' : 'pending'})</span>
                </div>
                <div className={state === 'todo' ? 'text-muted' : 'text-text-dim'}>
                  {text ?? step.pending}
                  {step.id === 'health_check' && (
                    <ul className="mt-1.5 mb-0 p-0 list-none grid sm:grid-cols-2 gap-x-6 gap-y-0.5">
                      {HEALTH_CHECK_ORDER.map(id => {
                        const r = run.health?.find(h => h.id === id)
                        return (
                          <li key={id} className={`flex gap-2 items-start ${r ? (r.ok ? 'text-text-dim' : 'text-loss') : 'text-muted'}`}>
                            {r ? (r.ok ? <CheckCircle2 size={12} className="text-win shrink-0 mt-0.5" aria-hidden="true" /> : <span className="text-loss" aria-hidden="true">✗</span>) : <Ring />}
                            <span>{HEALTH_CHECK_LABELS[id]}{r ? (r.ok ? '' : ' (failed)') : ''}</span>
                          </li>
                        )
                      })}
                    </ul>
                  )}
                </div>
              </div>
              <span className="text-muted tabular-nums whitespace-nowrap">{d ? `${clockIn(Date.parse(d.at), zone)} · ${d.seconds} s` : state === 'current' ? `${run.step_started_at ? clockIn(Date.parse(run.step_started_at), zone) : ''} · …` : 'pending'}</span>
            </li>
          )
        })}
      </ol>
    </section>
  )
}

/** Artboard 08a, second card: what the page does while the server restarts. */
export function WhileRestarting({ from, to }: { from: string | null; to: string | null }) {
  return (
    <section className="card p-4" aria-labelledby="t-restart">
      <h2 className={CARD_TITLE} id="t-restart">While the server restarts</h2>
      <p className="text-xs text-text-dim m-0 max-w-[90ch]">
        When the backend stops answering (nginx returns 503 with the maintenance page), this page shows "Restarting — this normally takes under a minute" and keeps asking{' '}
        <code className="font-mono">/api/version</code>. Once {to ?? 'the new version'} answers it reloads once; if {from ?? 'the previous version'} answers instead, it shows the rollback result.
        Other users see the maintenance page. Your session cookie survives the restart.
      </p>
    </section>
  )
}
