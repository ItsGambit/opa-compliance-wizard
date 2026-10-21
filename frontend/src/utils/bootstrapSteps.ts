import type { BootstrapStepEvent } from '../api/client'
import type { JobPhase } from '../hooks/useAccessScanJob'

export interface StepDisplay {
  key: string
  label: string
  status: 'pending' | 'active' | 'done' | 'error'
  detail?: string
}

/** Steps run strictly in order, so at most one step is ever "started but
 * not done" at a time — when the job errors, that's the one that failed;
 * everything after it never started. */
export function deriveSteps(stepDefs: [string, string][], events: BootstrapStepEvent[], phase: JobPhase): StepDisplay[] {
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
