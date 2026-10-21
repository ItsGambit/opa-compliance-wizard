import { Check, CircleDashed, Loader2, X } from 'lucide-react'
import type { BootstrapStepEvent } from '../api/client'
import type { JobPhase } from '../hooks/useAccessScanJob'
import { formatDateTimeZone } from '../utils/format'
import { deriveSteps, type StepDisplay } from '../utils/bootstrapSteps'

const STEP_STATE_TEXT: Record<StepDisplay['status'], string> = { pending: 'not started', active: 'running', done: 'done', error: 'failed' }

function StepIcon({ status }: { status: StepDisplay['status'] }) {
  // The icon's colour and motion are not the only signal (WCAG 1.4.1): the state is also text for a screen reader.
  const icon = status === 'done' ? <Check size={14} aria-hidden="true" className="text-win shrink-0" />
    : status === 'active' ? <Loader2 size={14} aria-hidden="true" className="text-accent animate-spin shrink-0" />
    : status === 'error' ? <X size={14} aria-hidden="true" className="text-loss shrink-0" />
    : <CircleDashed size={14} aria-hidden="true" className="text-text-faint shrink-0" />
  return <>{icon}<span className="sr-only">{STEP_STATE_TEXT[status]}: </span></>
}

interface Props {
  phase: JobPhase
  stepDefs: [string, string][]
  events: BootstrapStepEvent[]
  error: string | null
  onRetry: () => void
  /** Bottom variant only: hides a failed-refresh panel (data stays). */
  onDismiss?: () => void
  /** The stored scan that stays on screen while a refresh runs or after one fails (bottom variant): named in the failure message. */
  previousBuiltAt?: string | null
  /** "fullpage" replaces the whole tab content (first load). "bottom" is a
   * compact panel meant to sit at the bottom of the screen while the
   * previous result stays visible underneath (refresh). */
  variant: 'fullpage' | 'bottom'
}

export function BootstrapProgressPanel({ phase, stepDefs, events, error, onRetry, onDismiss, variant, previousBuiltAt }: Props) {
  const steps = deriveSteps(stepDefs, events, phase)

  const body = (
    <div className="flex flex-col gap-2" role="status" aria-live="polite">
      {phase === 'starting' && <p className="text-sm text-text-dim">Starting…</p>}
      {phase === 'running' && steps.length === 0 && <p className="text-sm text-text-dim">Working…</p>}
      {steps.map(step => (
        <div key={step.key} className="flex items-center gap-2 text-sm">
          <StepIcon status={step.status} />
          <span className={step.status === 'pending' ? 'text-text-faint' : 'text-text-dim'}>{step.label}</span>
          {step.detail && <span className="text-xs text-text-faint">— {step.detail}</span>}
        </div>
      ))}
      {phase === 'error' && (
        <div className="flex items-center gap-3 mt-1">
          <p className="text-sm text-loss">
            {variant === 'bottom' ? 'Refresh failed: ' : ''}{error ?? 'Something went wrong.'}{' '}
            <span className="text-text-dim">
              {variant === 'bottom'
                ? (previousBuiltAt ? `The scan from ${formatDateTimeZone(previousBuiltAt)} is still shown.` : 'No scan is stored yet.')
                : 'No scan is stored yet.'}
            </span>
          </p>
          <button type="button" className="btn-secondary shrink-0" onClick={onRetry}>
            {variant === 'bottom' && previousBuiltAt ? 'Retry' : 'Try again'}
          </button>
          {onDismiss && variant === 'bottom' && (
            <button type="button" className="btn-secondary shrink-0" onClick={onDismiss}>
              Dismiss
            </button>
          )}
        </div>
      )}
    </div>
  )

  if (variant === 'bottom') {
    return (
      <div className="fixed bottom-4 right-4 left-4 sm:left-auto sm:w-96 card p-3 shadow-xl z-40 flex flex-col gap-2 max-h-64 overflow-y-auto">
        <span className="section-label">
          {phase === 'error' ? 'Refresh failed' : 'Refreshing the OPA scan…'}
        </span>
        {body}
      </div>
    )
  }

  return (
    <div className="card p-6 flex flex-col gap-3">
      <p className="text-sm text-text-dim text-center">
        No stored OPA scan for this environment yet. Scanning every resource group, project, policy, group, and user across your tenant…
      </p>
      {body}
    </div>
  )
}
