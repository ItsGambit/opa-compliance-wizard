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
          stopPolling()
          return fetchAccessBootstrapResult().then(result => setState(s => ({ ...s, phase: 'done', result })))
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
