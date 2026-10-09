import { useCallback, useEffect, useRef, useState } from 'react'
import { fetchAccessBootstrapResult, fetchAccessBootstrapStatus, startAccessBootstrap } from '../api/client'
import type { BootstrapStatusResponse, BootstrapStepEvent } from '../api/client'
import type { AccessModel } from '../types'
import { JOB_LOST_MESSAGE, startPollLoop } from './pollLoop'

export type JobPhase = 'idle' | 'starting' | 'running' | 'done' | 'error'

interface JobState {
  phase: JobPhase
  stepDefs: [string, string][]
  events: BootstrapStepEvent[]
  error: string | null
  result: AccessModel | null
}

const INITIAL_STATE: JobState = { phase: 'idle', stepDefs: [], events: [], error: null, result: null }

const errorText = (err: unknown) => (err instanceof Error ? err.message : String(err))

/** Drives the background bootstrap job: POST /start, poll /status, fetch
 * /result once (see startPollLoop). Exposes enough for a UI to show real
 * step-by-step progress and a Retry that restarts cleanly from scratch.
 *
 * FE-04 / UI-10 (external review, 2026-10-05): polls never overlap (the
 * result download used to be started again on every tick while the
 * previous one was still in flight); nothing runs after unmount; "idle"
 * while running means the server lost the job (restart, or the active
 * environment changed) and ends in an error instead of polling forever;
 * and a job that was already running still shows its step list (the
 * server now returns `steps` with already_running). */
export function useAccessBootstrapJob() {
  const [state, setState] = useState<JobState>(INITIAL_STATE)
  const generation = useRef(0)
  const cancelPoll = useRef<(() => void) | null>(null)

  const stopPolling = useCallback(() => {
    cancelPoll.current?.()
    cancelPoll.current = null
  }, [])

  const start = useCallback(() => {
    stopPolling()
    generation.current += 1
    const gen = generation.current
    setState({ ...INITIAL_STATE, phase: 'starting' })
    startAccessBootstrap()
      .then(resp => {
        if (gen !== generation.current) return
        setState(s => ({ ...s, phase: 'running', stepDefs: resp.steps ?? [] }))
        cancelPoll.current = startPollLoop<BootstrapStatusResponse>({
          fetchStatus: fetchAccessBootstrapStatus,
          onStatus: async status => {
            if (gen !== generation.current) return 'stop'
            setState(s => ({ ...s, events: status.steps, error: status.error }))
            if (status.status === 'running') return 'continue'
            if (status.status === 'done') {
              // One result download, awaited before anything else happens.
              const result = await fetchAccessBootstrapResult()
              if (gen === generation.current) setState(s => ({ ...s, phase: 'done', result }))
            } else if (status.status === 'error') {
              setState(s => ({ ...s, phase: 'error' }))
            } else {
              setState(s => ({ ...s, phase: 'error', error: JOB_LOST_MESSAGE }))
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
        setState(s => ({ ...s, phase: 'error', error: errorText(err) }))
      })
  }, [stopPolling])

  useEffect(() => () => {
    generation.current += 1
    stopPolling()
  }, [stopPolling])

  return { ...state, start }
}
