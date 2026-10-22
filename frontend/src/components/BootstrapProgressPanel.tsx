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
  /** The stored scan that stays on screen while a refresh runs or after one fails (bottom variant). */
  previousBuiltAt?: string | null
  /** The OPA part's end state ("refused", "error", "cancelled", "timed_out"): "Refresh refused" leads the panel for a refusal. */
  failureState?: string | null
  /** The audit entry that records the failure, printed under the buttons. */
  auditLine?: string | null
  /** Bottom variant, while running: stops the refresh. */
  onStop?: () => void
  /** Bottom variant, failed: opens the Environments dialog (a refused key is fixed there). */
  onOpenEnvironments?: () => void
  /** "fullpage" replaces the whole tab content (first load). "bottom" is a
   * compact panel meant to sit at the bottom of the screen while the
   * previous result stays visible underneath (refresh). */
  variant: 'fullpage' | 'bottom'
}

/** The server writes a failure as "<what happened> (HTTP 403). Nothing was changed: <...>. To fix: <...>": the panel leads with the outcome
 * (bold what-happened sentence), then whether anything changed, then "To fix:". Text in another shape is shown as it is. */
function FailureText({ message }: { message: string }) {
  const fixAt = message.indexOf('To fix:')
  const head = (fixAt >= 0 ? message.slice(0, fixAt) : message).trim()
  const fix = fixAt >= 0 ? message.slice(fixAt + 'To fix:'.length).trim() : null
  const m = /^(.*?)( \(HTTP \d+\))?\. ([\s\S]*)$/.exec(head)
  return (
    <p className="text-xs text-text-dim m-0 leading-relaxed" data-testid="failure-text">
      {m ? <><strong className="text-text">{m[1]}</strong>{m[2]}. {m[3]}</> : head}
      {fix && <> <strong className="text-text">To fix:</strong> {fix}</>}
    </p>
  )
}

export function BootstrapProgressPanel({ phase, stepDefs, events, error, onRetry, onDismiss, variant, previousBuiltAt, failureState, auditLine, onStop, onOpenEnvironments }: Props) {
  const allSteps = deriveSteps(stepDefs, events, phase)
  // After a failure only the steps that were reached are listed (the ones after it never started): the outcome is what the panel is for.
  const steps = variant === 'bottom' && phase === 'error' ? allSteps.filter(s => s.status !== 'pending') : allSteps
  const doneCount = allSteps.filter(s => s.status === 'done').length
  const percent = allSteps.length ? Math.round((doneCount / allSteps.length) * 100) : 0
  const failedWord = failureState === 'refused' ? 'refused' : 'failed'

  const stepList = (
    <>
      {phase === 'starting' && <p className="text-sm text-text-dim">Starting…</p>}
      {phase === 'running' && steps.length === 0 && <p className="text-sm text-text-dim">Working…</p>}
      {steps.map(step => (
        <div key={step.key} className="flex items-center gap-2 text-sm">
          <StepIcon status={step.status} />
          <span className={step.status === 'pending' ? 'text-text-faint' : 'text-text-dim'}>{step.label}</span>
          {step.status === 'error' ? <span className="text-xs text-text-faint">— {failedWord}</span> : step.detail && <span className="text-xs text-text-faint">— {step.detail}</span>}
        </div>
      ))}
    </>
  )

  if (variant === 'bottom') {
    const failed = phase === 'error'
    return (
      <div role="status" aria-live="polite"
        className={`fixed bottom-4 right-4 left-4 sm:left-auto sm:w-[25rem] card p-3 shadow-xl z-40 flex flex-col gap-2 ${failed && failureState !== 'busy' ? 'border-loss/45' : ''}`}>
        <span className={`section-label ${failed && failureState !== 'busy' ? '!text-loss' : ''}`}>{failed ? (failureState === 'busy' ? 'Refresh not started' : failureState === 'refused' ? 'Refresh refused' : 'Refresh failed') : 'Refreshing the OPA scan…'}</span>
        <div className="flex flex-col gap-1">{stepList}</div>
        {failed ? (
          <>
            <FailureText message={error ?? 'Something went wrong.'} />
            <div className="flex items-center gap-2 flex-wrap">
              <button type="button" className="btn-secondary" onClick={onRetry}>Retry</button>
              {onOpenEnvironments && failureState === 'refused' && <button type="button" className="btn-secondary" onClick={onOpenEnvironments}>Open Environments</button>}
              {onDismiss && <button type="button" className="text-accent-text underline underline-offset-2 text-xs" onClick={onDismiss}>Dismiss</button>}
            </div>
            {auditLine && <p className="text-xs text-muted m-0">Audit Log: {auditLine}</p>}
          </>
        ) : (
          <>
            <div className="h-1 rounded-full bg-bg-hover overflow-hidden" role="progressbar" aria-label="Scan progress" aria-valuemin={0} aria-valuemax={100} aria-valuenow={percent}>
              <span className="block h-full rounded-full bg-accent" style={{ width: `${percent}%` }} />
            </div>
            <p className="text-xs text-muted m-0">
              {previousBuiltAt ? `The scan from ${formatDateTimeZone(previousBuiltAt)} stays on screen until the new one finishes.` : 'Working…'}
              {onStop && <> <button type="button" className="text-accent-text underline underline-offset-2" onClick={onStop}>Stop</button></>}
            </p>
          </>
        )}
      </div>
    )
  }

  return (
    <div className="card p-6 flex flex-col gap-3">
      <p className="text-sm text-text-dim text-center">
        No stored OPA scan for this environment yet. Scanning every resource group, project, policy, group, and user across your tenant…
      </p>
      <div className="flex flex-col gap-2" role="status" aria-live="polite">
        {stepList}
        {phase === 'error' && (
          <div className="flex items-center gap-3 mt-1">
            <p className="text-sm text-loss m-0">{error ?? 'Something went wrong.'}</p>
            <button type="button" className="btn-secondary shrink-0" onClick={onRetry}>Try again</button>
          </div>
        )}
      </div>
    </div>
  )
}
