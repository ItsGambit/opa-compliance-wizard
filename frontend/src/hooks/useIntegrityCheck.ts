import { useCallback, useEffect, useRef, useState } from 'react'
import { fetchIntegrity } from '../api/client'
import type { IntegrityResult } from '../types'
import { startPollLoop } from './pollLoop'

/** How often to ask again while a deep check answers 202 (it runs in the
 * background on the server, single-flight per environment). */
export const DEEP_POLL_INTERVAL_MS = 3000

export type IntegrityState =
  | { phase: 'idle' }
  | { phase: 'checking'; deep: boolean }
  | { phase: 'done'; deep: boolean; result: IntegrityResult }
  | { phase: 'error'; deep: boolean; error: string }

/** FE-15 (external review, 2026-10-05): the evidence-chain check existed
 * only as a URL. This runs it from the sync dialog: the basic check is one
 * request; the admin-only deep check (re-hashes every sealed event) may
 * answer 202 "running" and is polled until it answers. Cancelled on
 * unmount or environment change. */
export function useIntegrityCheck(environmentName: string) {
  const [state, setState] = useState<IntegrityState>({ phase: 'idle' })
  const cancel = useRef<(() => void) | null>(null)

  const stop = useCallback(() => {
    cancel.current?.()
    cancel.current = null
  }, [])

  const run = useCallback((deep: boolean) => {
    stop()
    setState({ phase: 'checking', deep })
    let finished = false
    cancel.current = startPollLoop({
      fetchStatus: () => fetchIntegrity(environmentName, deep),
      intervalMs: DEEP_POLL_INTERVAL_MS,
      maxConsecutiveFailures: 1,
      onStatus: body => {
        if ('status' in body && body.status === 'running') return 'continue'
        finished = true
        setState({ phase: 'done', deep, result: body as IntegrityResult })
        return 'stop'
      },
      onFatal: message => {
        if (!finished) setState({ phase: 'error', deep, error: message })
      },
    })
  }, [environmentName, stop])

  useEffect(() => {
    setState({ phase: 'idle' })
    return stop
  }, [environmentName, stop])

  return { state, run }
}
