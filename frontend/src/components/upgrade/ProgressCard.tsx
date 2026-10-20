import { useEffect, useState } from 'react'
import { CheckCircle2 } from 'lucide-react'
import type { UpgradeRun } from '../../types'
import { HEALTH_CHECK_LABELS, HEALTH_CHECK_ORDER, UPGRADE_STEPS, stepNumber } from '../../utils/upgradeFlow'
import { Badge, CARD_TITLE, Spinner } from './parts'

interface Props {
  run: UpgradeRun
  /** The poll is failing because the app is restarting underneath the page (502/503/network). */
  restarting: boolean
  now?: () => number
}

function clock(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000))
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`
}

/** Artboard 08a: the live step list. Polled every 2 s by the page; when the backend disappears during the restart the card says so
 * and keeps waiting (the page reloads itself once the new version answers). */
export function ProgressCard({ run, restarting, now = Date.now }: Props) {
  const [tick, setTick] = useState(now())
  useEffect(() => {
    const id = setInterval(() => setTick(now()), 1000)
    return () => clearInterval(id)
  }, [now])
  const started = run.started_at ? Date.parse(run.started_at) : tick
  const done = new Map((run.steps_done ?? []).map(s => [s.step, s]))
  const current = stepNumber(run)
  const total = UPGRADE_STEPS.length
  const stepLabel = UPGRADE_STEPS[Math.min(current, total) - 1]
  const rollingBack = run.step === 'rolling_back'
  return (
    <section className="card p-4 border-accent/50" aria-labelledby="t-prog">
      <div aria-live="polite">
        <h2 className={CARD_TITLE} id="t-prog">
          <Spinner />
          {rollingBack ? `Rolling back to ${run.version_from}` : `Upgrading to ${run.version_to}`}
          <Badge tone="acc">Step {current} of {total} · {rollingBack ? 'rolling back' : stepLabel.id.replace('_', ' ')}</Badge>
          <span className="text-xs text-muted font-normal ml-auto">elapsed {clock(tick - started)} · correlation <code className="font-mono">{run.correlation_id}</code></span>
        </h2>
        {restarting && (
          <p role="status" className="text-xs text-text mt-0 mb-3 flex items-center gap-2 rounded-lg border border-accent/40 bg-accent-dim px-2.5 py-2">
            <Spinner size={12} />Restarting — this normally takes under a minute. This page keeps asking and reloads itself when the new version answers.
          </p>
        )}
      </div>
      <div className="h-1.5 rounded bg-bg-hover overflow-hidden mb-3" role="progressbar" aria-label="Upgrade progress" aria-valuemin={0} aria-valuemax={total} aria-valuenow={current}>
        <span className="block h-full bg-accent" style={{ width: `${Math.round((Math.min(current, total) / total) * 100)}%` }} />
      </div>
      <ol className="m-0 p-0 list-none flex flex-col">
        {UPGRADE_STEPS.map((step, i) => {
          const d = done.get(step.id)
          const isCurrent = !d && i + 1 === current && !rollingBack
          const state = d ? 'done' : isCurrent ? 'current' : 'todo'
          return (
            <li key={step.id} data-state={state} className="grid grid-cols-[20px_1fr_auto] gap-3 items-start py-2 border-t border-border-sub first:border-t-0 text-xs">
              {state === 'done' ? <CheckCircle2 size={16} className="text-win mt-px" aria-hidden="true" />
                : state === 'current' ? <span className="mt-0.5"><Spinner /></span>
                  : <span className="mt-1.5 ml-1.5 w-2 h-2 rounded-full bg-border" aria-hidden="true" />}
              <div>
                <div className={`font-medium ${state === 'current' ? 'text-accent-text' : state === 'todo' ? 'text-muted' : 'text-text'}`}>
                  {i + 1} · {step.title}{state === 'current' && <> <Badge tone="acc">now</Badge></>}
                  <span className="sr-only"> ({state === 'done' ? 'done' : state === 'current' ? 'in progress' : 'pending'})</span>
                </div>
                <div className={state === 'todo' ? 'text-muted' : 'text-text-dim'}>
                  {step.pending}
                  {step.id === 'health_check' && (
                    <ul className="mt-1 mb-0 pl-4 list-disc grid sm:grid-cols-2 gap-x-4">
                      {HEALTH_CHECK_ORDER.map(id => {
                        const r = run.health?.find(h => h.id === id)
                        return <li key={id} className={r ? (r.ok ? 'text-text-dim' : 'text-loss') : 'text-muted'}>{HEALTH_CHECK_LABELS[id]}{r ? (r.ok ? ' ✓' : ' ✗') : ''}</li>
                      })}
                    </ul>
                  )}
                </div>
              </div>
              <span className="text-muted tabular-nums whitespace-nowrap">{d ? `${d.at.slice(11, 19)} · ${d.seconds} s` : state === 'current' ? '…' : 'pending'}</span>
            </li>
          )
        })}
      </ol>
      <p className="text-xs text-muted mt-3 mb-0">The updater runs on the server; closing this tab does not stop it. If any health check fails, the previous release is put back automatically.</p>
    </section>
  )
}
