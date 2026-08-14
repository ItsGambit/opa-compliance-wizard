import { Check, CircleDashed, Loader2, X } from 'lucide-react'
import type { BootstrapStepEvent } from '../api/client'
import type { JobPhase } from '../hooks/useAccessBootstrapJob'

interface StepDisplay {
  key: string
  label: string
  status: 'pending' | 'active' | 'done' | 'error'
  detail?: string
}

/** Steps run strictly in order, so at most one step is ever "started but
 * not done" at a time — when the job errors, that's the one that failed;
 * everything after it never started. */
function deriveSteps(stepDefs: [string, string][], events: BootstrapStepEvent[], phase: JobPhase): StepDisplay[] {
  return stepDefs.map(([key, label]) => {
    const keyEvents = events.filter(e => e.key === key)
    const doneEvent = keyEvents.find(e => e.status === 'done')
    if (doneEvent) return { key, label, status: 'done', detail: doneEvent.detail ?? undefined }

    const started = keyEvents.some(e => e.status === 'start')
    if (started) {
      const latest = [...keyEvents].reverse()[0]
      if (phase === 'error') return { key, label, status: 'error', detail: latest.detail ?? undefined }
      return { key, label, status: 'active', detail: latest.detail ?? undefined }
    }
    return { key, label, status: 'pending' }
  })
}

function StepIcon({ status }: { status: StepDisplay['status'] }) {
  if (status === 'done') return <Check size={14} className="text-win shrink-0" />
  if (status === 'active') return <Loader2 size={14} className="text-accent animate-spin shrink-0" />
  if (status === 'error') return <X size={14} className="text-loss shrink-0" />
  return <CircleDashed size={14} className="text-text-faint shrink-0" />
}

interface Props {
  phase: JobPhase
  stepDefs: [string, string][]
  events: BootstrapStepEvent[]
  error: string | null
  onRetry: () => void
  /** "fullpage" replaces the whole tab content (first load). "bottom" is a
   * compact panel meant to sit at the bottom of the screen while the
   * previous result stays visible underneath (refresh). */
  variant: 'fullpage' | 'bottom'
}

export function BootstrapProgressPanel({ phase, stepDefs, events, error, onRetry, variant }: Props) {
  const steps = deriveSteps(stepDefs, events, phase)

  const body = (
    <div className="flex flex-col gap-2">
      {phase === 'starting' && <p className="text-sm text-text-dim">Starting…</p>}
      {steps.map(step => (
        <div key={step.key} className="flex items-center gap-2 text-sm">
          <StepIcon status={step.status} />
          <span className={step.status === 'pending' ? 'text-text-faint' : 'text-text-dim'}>{step.label}</span>
          {step.detail && <span className="text-xs text-text-faint">— {step.detail}</span>}
        </div>
      ))}
      {phase === 'error' && (
        <div className="flex items-center gap-3 mt-1">
          <p className="text-sm text-loss">{error ?? 'Something went wrong.'}</p>
          <button type="button" className="btn-secondary shrink-0" onClick={onRetry}>
            Retry
          </button>
        </div>
      )}
    </div>
  )

  if (variant === 'bottom') {
    return (
      <div className="fixed bottom-4 right-4 left-4 sm:left-auto sm:w-96 card p-3 shadow-xl z-40 flex flex-col gap-2 max-h-64 overflow-y-auto">
        <span className="section-label">
          {phase === 'error' ? 'Refresh failed' : 'Refreshing access data…'}
        </span>
        {body}
      </div>
    )
  }

  return (
    <div className="card p-6 flex flex-col gap-3">
      <p className="text-sm text-text-dim text-center">
        Scanning every resource group, project, policy, group, and user across your tenant…
      </p>
      {body}
    </div>
  )
}
