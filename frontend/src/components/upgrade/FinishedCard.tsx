import { useEffect, useState } from 'react'
import { CheckCircle2, XCircle } from 'lucide-react'
import type { UpgradeRun } from '../../types'
import { HEALTH_CHECK_LABELS, HEALTH_CHECK_ORDER, UPGRADE_STEPS, clockIn, formatDuration } from '../../utils/upgradeFlow'
import { Badge, CARD_TITLE, KV, Row } from './parts'

/** 5.53.0: every step of a run with what became of it and when (the same list the progress card showed live), then the health checks.
 * Works from the progress-only run too: times and pass or fail, no step details. */
export function StepSummary({ run, zone, title = 'What ran', showHealth = true }: { run: UpgradeRun; zone: string; title?: string; showHealth?: boolean }) {
  const done = new Map((run.steps_done ?? []).map(s => [s.step, s]))
  const checks = run.health ?? []
  const passed = checks.filter(c => c.ok).length
  return (
    <section className="card p-4" aria-labelledby="t-steps">
      <h2 className={CARD_TITLE} id="t-steps">{title}</h2>
      <ol className="m-0 p-0 list-none flex flex-col text-xs">
        {UPGRADE_STEPS.map((step, i) => {
          const d = done.get(step.id)
          // "completed" is the run's own last step: it is done when the run says so, even if the updater restarted before it could record it
          const ok = !!d || (step.id === 'completed' && run.result === 'completed')
          const failed = !ok && run.failed_step === step.id
          return (
            <li key={step.id} data-state={ok ? 'done' : failed ? 'failed' : 'skipped'} className="grid grid-cols-[20px_1fr_auto] gap-3 items-center py-1.5 border-t border-border-sub first:border-t-0">
              {ok ? <CheckCircle2 size={16} className="text-win" aria-hidden="true" /> : failed ? <XCircle size={16} className="text-loss" aria-hidden="true" />
                : <span aria-hidden="true" className="inline-block w-2 h-2 ml-1 rounded-full border border-muted" />}
              <span className={ok ? 'text-text' : failed ? 'text-loss' : 'text-muted'}>
                {i + 1} · {step.title} <span className="sr-only">({ok ? 'done' : failed ? 'failed' : 'not run'})</span>
                {failed && <> — failed</>}{!ok && !failed && <> — not run</>}
              </span>
              <span className="text-muted tabular-nums whitespace-nowrap">{d ? `${clockIn(Date.parse(d.at), zone)} · ${d.seconds} s` : ''}</span>
            </li>
          )
        })}
      </ol>
      {showHealth && checks.length > 0 && (
        <>
          <h3 className="text-xs font-semibold text-text mt-3 mb-1.5 flex items-center gap-2">
            Health checks <Badge tone={passed === checks.length ? 'ok' : 'warn'}>{passed} of {HEALTH_CHECK_ORDER.length} passed</Badge>
          </h3>
          <ul className="m-0 p-0 list-none grid sm:grid-cols-2 gap-x-6 gap-y-0.5 text-xs text-text-dim">
            {checks.map(c => (
              <li key={c.id} className={`flex gap-2 items-start ${c.ok ? '' : 'text-loss'}`}>
                {c.ok ? <CheckCircle2 size={12} className="text-win shrink-0 mt-0.5" aria-hidden="true" /> : <XCircle size={12} className="text-loss shrink-0 mt-0.5" aria-hidden="true" />}
                <span>{HEALTH_CHECK_LABELS[c.id] ?? c.id}{c.ok ? '' : ' (failed)'}</span>
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  )
}

interface FinishedProps {
  run: UpgradeRun
  zone: string
  /** Seconds before the page reloads itself on the new version; `Infinity` never reloads by itself. */
  autoReloadSeconds?: number
  onReload: () => void
}

/** 5.53.0: what the page shows when the new version answers and this browser still runs the old interface: the result of the upgrade
 * (from → to, every step with its time, the health checks) and a visible countdown to the reload, instead of reloading at once. */
export function UpgradeFinishedCard({ run, zone, autoReloadSeconds = 10, onReload }: FinishedProps) {
  const [left, setLeft] = useState(autoReloadSeconds)
  const [kept, setKept] = useState(false)
  useEffect(() => {
    if (kept || !Number.isFinite(autoReloadSeconds)) return
    if (left <= 0) { onReload(); return }
    const id = setTimeout(() => setLeft(n => n - 1), 1000)
    return () => clearTimeout(id)
  }, [left, kept, autoReloadSeconds, onReload])
  const checks = run.health ?? []
  const passed = checks.filter(c => c.ok).length
  return (
    <div className="flex flex-col gap-5">
      <section className="card p-4 border-win/50" aria-labelledby="t-finished">
        <h2 className="m-0 text-2xl font-semibold text-text flex items-center gap-2.5" id="t-finished">
          <CheckCircle2 size={24} className="text-win" aria-hidden="true" />Upgraded to {run.version_to}{run.seconds != null && <> in {formatDuration(run.seconds)}</>}
        </h2>
        <div className={`${KV} mt-3`}>
          <Row label="From → to">{run.version_from} → {run.version_to}</Row>
          <Row label="Health checks">{checks.length > 0 ? `${passed} of ${HEALTH_CHECK_ORDER.length} passed` : 'passed (the updater only finishes an upgrade when they do)'}</Row>
          <Row label="Correlation"><code className="font-mono text-xs">{run.correlation_id}</code></Row>
        </div>
        <div className="flex items-center gap-3 flex-wrap mt-3" role="status">
          <button type="button" className="btn-primary" onClick={onReload}>Reload on {run.version_to} now</button>
          {!kept && Number.isFinite(autoReloadSeconds)
            ? <>
              <span className="text-xs text-text-dim">Reloading by itself in {Math.max(left, 0)} s so this page runs the new version.</span>
              <button type="button" className="btn-secondary !text-text-dim" onClick={() => setKept(true)}>Keep this summary open</button>
            </>
            : <span className="text-xs text-text-dim">This page still runs the old version until you reload.</span>}
        </div>
      </section>
      <StepSummary run={run} zone={zone} />
    </div>
  )
}
