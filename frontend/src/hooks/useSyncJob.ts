import { useCallback, useEffect, useRef, useState } from 'react'
import { fetchSyncStatus, startSync } from '../api/client'
import type { IngestionScope, SyncStatusResponse } from '../types'

const POLL_INTERVAL_MS = 1000

export type SyncJobPhase = 'idle' | 'starting' | 'running' | 'done' | 'error'

interface SyncJobState {
  phase: SyncJobPhase
  status: SyncStatusResponse | null
  error: string | null
  /** True once a status fetch has settled (succeeded OR failed) -- lets a
   * caller tell "still loading" from "loaded nothing" (UI-09: the sync
   * settings dialog waits for this before enabling Save). */
  statusLoaded: boolean
  /** The last status fetch's error, if it failed -- shown instead of
   * silently keeping a stale/empty status. */
  statusError: string | null
}

const INITIAL_STATE: SyncJobState = { phase: 'idle', status: null, error: null, statusLoaded: false, statusError: null }

/** Drives one environment's compliance-sync background job: POST
 * /sync/start, poll /sync/status every second until done/error. Mirrors
 * useAccessBootstrapJob.ts's exact polling shape (plain useState +
 * setInterval, not TanStack Query — same reasoning: polling-until-done
 * doesn't map cleanly onto a query cache). Also exposes a plain
 * `refreshStatus()` for callers that just want the current state on
 * mount (e.g. the settings panel showing "last synced" without the user
 * having clicked anything this session). */
export function useSyncJob(environmentName: string | undefined) {
  const [state, setState] = useState<SyncJobState>(INITIAL_STATE)
  const pollHandle = useRef<number | null>(null)

  const stopPolling = useCallback(() => {
    if (pollHandle.current !== null) {
      window.clearInterval(pollHandle.current)
      pollHandle.current = null
    }
  }, [])

  const poll = useCallback(() => {
    if (!environmentName) return
    fetchSyncStatus(environmentName)
      .then(status => {
        setState(s => ({ ...s, status }))
        if (status.status === 'done') {
          stopPolling()
          setState(s => ({ ...s, phase: 'done' }))
        } else if (status.status === 'error') {
          stopPolling()
          setState(s => ({ ...s, phase: 'error', error: status.error }))
        }
      })
      .catch(err => {
        stopPolling()
        setState(s => ({ ...s, phase: 'error', error: err instanceof Error ? err.message : String(err) }))
      })
  }, [environmentName, stopPolling])

  const refreshStatus = useCallback(() => {
    if (!environmentName) return
    fetchSyncStatus(environmentName)
      .then(status => setState(s => ({ ...s, status, statusLoaded: true, statusError: null })))
      .catch(err => setState(s => ({ ...s, statusLoaded: true, statusError: err instanceof Error ? err.message : String(err) })))
  }, [environmentName])

  const start = useCallback((ingestionScope?: IngestionScope) => {
    if (!environmentName) return
    stopPolling()
    setState(s => ({ ...s, phase: 'starting', status: null, error: null }))
    startSync(environmentName, ingestionScope)
      .then(() => {
        setState(s => ({ ...s, phase: 'running' }))
        pollHandle.current = window.setInterval(poll, POLL_INTERVAL_MS)
        poll()
      })
      .catch(err => {
        setState(s => ({ ...s, phase: 'error', error: err instanceof Error ? err.message : String(err) }))
      })
  }, [environmentName, poll, stopPolling])

  useEffect(() => stopPolling, [stopPolling])
  useEffect(() => { refreshStatus() }, [refreshStatus])

  return { ...state, start, refreshStatus }
}
