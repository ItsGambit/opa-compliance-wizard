import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiError, fetchAccessModel, fetchRefreshStatus, startRefresh } from '../api/client'
import type { BootstrapStepEvent } from '../api/client'
import type { AccessModelResponse, RefreshStatus } from '../types'
import { busyRefreshMessage } from '../utils/refresh'
import { JOB_LOST_MESSAGE, startPollLoop } from './pollLoop'

export type JobPhase = 'idle' | 'starting' | 'running' | 'done' | 'error'

interface JobState {
  phase: JobPhase
  stepDefs: [string, string][]
  events: BootstrapStepEvent[]
  error: string | null
  result: AccessModelResponse | null
  /** The OPA part's end state when it failed ("refused", "error", "timed_out", "cancelled") and the audit entry that records it. */
  failureState: string | null
  auditLine: string | null
}

const INITIAL_STATE: JobState = { phase: 'idle', stepDefs: [], events: [], error: null, result: null, failureState: null, auditLine: null }

const errorText = (err: unknown) => (err instanceof Error ? err.message : String(err))

/** Drives the OPA scan (the `opa` part of the combined refresh, 5.51.0): POST /refresh with `parts: ["opa"]`, poll /refresh/status,
 * and fetch the stored scan once the part is done. The server writes the outcome message (what happened, whether anything changed,
 * what to do), so a refused or failed scan shows that wording, not a raw error.
 *
 * FE-04 / UI-10: polls never overlap; nothing runs after unmount; "idle" while running means the server lost the job (restart) and
 * ends in an error instead of polling forever; a refresh that was already running is attached to and its progress shown. */
export function useAccessScanJob() {
  const [state, setState] = useState<JobState>(INITIAL_STATE)
  const generation = useRef(0)
  const cancelPoll = useRef<(() => void) | null>(null)

  const stopPolling = useCallback(() => {
    cancelPoll.current?.()
    cancelPoll.current = null
  }, [])

  const start = useCallback((environment: string) => {
    stopPolling()
    generation.current += 1
    const gen = generation.current
    setState({ ...INITIAL_STATE, phase: 'starting' })
    startRefresh(environment, ['opa'], 'explorer')
      .then(() => {
        if (gen !== generation.current) return
        setState(s => ({ ...s, phase: 'running' }))
        cancelPoll.current = startPollLoop<RefreshStatus>({
          fetchStatus: () => fetchRefreshStatus(environment),
          onStatus: async status => {
            if (gen !== generation.current) return 'stop'
            const part = status.parts.opa
            setState(s => ({ ...s, events: (part.steps ?? []) as BootstrapStepEvent[], stepDefs: part.step_defs ?? s.stepDefs }))
            if (status.status === 'running') return 'continue'
            if (status.status === 'idle') {
              setState(s => ({ ...s, phase: 'error', error: JOB_LOST_MESSAGE }))
            } else if (part.state === 'ok' || part.state === 'not_requested') {
              const result = await fetchAccessModel()  // awaited once, before anything else happens
              if (gen === generation.current) setState(s => ({ ...s, phase: 'done', result }))
            } else {
              setState(s => ({ ...s, phase: 'error', error: part.message ?? 'The OPA scan did not complete.', failureState: part.state, auditLine: part.audit_line ?? null }))
            }
            return 'stop'
          },
          onFatal: message => {
            if (gen !== generation.current) return
            setState(s => ({ ...s, phase: 'error', error: message }))
          },
        })
      })
      .catch(err => {
        if (gen !== generation.current) return
        // A busy answer (another refresh is running without the OPA part) is not a failed scan: nothing was started, nothing was lost.
        setState(s => ({ ...s, phase: 'error', error: busyRefreshMessage(err, ['opa']) ?? errorText(err), failureState: err instanceof ApiError && err.status === 409 ? 'busy' : null }))
      })
  }, [stopPolling])

  useEffect(() => () => {
    generation.current += 1
    stopPolling()
  }, [stopPolling])

  return { ...state, start }
}
