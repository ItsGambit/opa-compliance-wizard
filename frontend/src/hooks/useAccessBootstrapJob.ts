import { useCallback, useEffect, useRef, useState } from 'react'
import { fetchAccessBootstrapResult, fetchAccessBootstrapStatus, startAccessBootstrap } from '../api/client'
import type { BootstrapStepEvent } from '../api/client'
import type { AccessModel } from '../types'

const POLL_INTERVAL_MS = 1000

export type JobPhase = 'idle' | 'starting' | 'running' | 'done' | 'error'

interface JobState {
  phase: JobPhase
  stepDefs: [string, string][]
  events: BootstrapStepEvent[]
  error: string | null
  result: AccessModel | null
}

const INITIAL_STATE: JobState = { phase: 'idle', stepDefs: [], events: [], error: null, result: null }

/** Drives the background bootstrap job: POST /start, poll /status every
 * second, fetch /result once done. Exposes enough for a UI to show real
 * step-by-step progress (not just a spinner) and a Retry that restarts
 * cleanly from scratch — simplest correct recovery, given steps build on
 * each other so resuming mid-way isn't worth the complexity. */
export function useAccessBootstrapJob() {
  const [state, setState] = useState<JobState>(INITIAL_STATE)
  const pollHandle = useRef<number | null>(null)

  const stopPolling = useCallback(() => {
    if (pollHandle.current !== null) {
      window.clearInterval(pollHandle.current)
      pollHandle.current = null
    }
  }, [])

  const poll = useCallback(() => {
    fetchAccessBootstrapStatus()
      .then(status => {
        setState(s => ({ ...s, events: status.steps, error: status.error }))
        if (status.status === 'done') {
          // FIX (external review, 2026-09-30): stopPolling() used to run
          // BEFORE this fetch, so a transient failure fetching the result
          // (the job itself succeeded, but e.g. a network blip on this
          // one follow-up request) left polling permanently stopped with
          // no automatic retry -- the only recovery was the user manually
          // clicking Retry, which restarts the whole bootstrap from
          // scratch rather than just re-fetching an already-finished
          // result. Stop polling only once the result fetch itself has
          // actually resolved (success OR failure), not preemptively.
          return fetchAccessBootstrapResult()
            .then(result => {
              stopPolling()
              setState(s => ({ ...s, phase: 'done', result }))
            })
            .catch(err => {
              stopPolling()
              setState(s => ({ ...s, phase: 'error', error: err instanceof Error ? err.message : String(err) }))
            })
        }
        if (status.status === 'error') {
          stopPolling()
          setState(s => ({ ...s, phase: 'error' }))
        }
      })
      .catch(err => {
        stopPolling()
        setState(s => ({ ...s, phase: 'error', error: err instanceof Error ? err.message : String(err) }))
      })
  }, [stopPolling])

  const start = useCallback(() => {
    stopPolling()
    setState({ phase: 'starting', stepDefs: [], events: [], error: null, result: null })
    startAccessBootstrap()
      .then(resp => {
        setState(s => ({ ...s, phase: 'running', stepDefs: resp.steps ?? [] }))
        pollHandle.current = window.setInterval(poll, POLL_INTERVAL_MS)
        poll()
      })
      .catch(err => {
        setState(s => ({ ...s, phase: 'error', error: err instanceof Error ? err.message : String(err) }))
      })
  }, [poll, stopPolling])

  useEffect(() => stopPolling, [stopPolling])

  return { ...state, start }
}
