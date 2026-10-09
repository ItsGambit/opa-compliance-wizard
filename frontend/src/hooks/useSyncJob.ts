import { useCallback, useEffect, useRef, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { fetchSyncStatus, onSessionRestored, startSync } from '../api/client'
import { invalidateArchiveQueries } from '../api/queryClient'
import type { IngestionScope, SyncStatusResponse } from '../types'
import { JOB_LOST_MESSAGE, startPollLoop } from './pollLoop'

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

const errorText = (err: unknown) => (err instanceof Error ? err.message : String(err))

/** Drives one environment's compliance-sync background job: POST
 * /sync/start, then poll /sync/status until done/error (see startPollLoop
 * for the loop itself). Also exposes `refreshStatus()` for callers that
 * just want the current state.
 *
 * FE-04 (external review, 2026-10-05): state and any running poll are
 * reset whenever `environmentName` changes (the Footer used to keep
 * polling the previous environment and show its progress under the new
 * name); every response is ignored once the hook has moved on to another
 * environment or unmounted; a status of "idle" while a job was believed
 * running means the server lost it (restart) and ends in an error instead
 * of polling forever; and a sync that is already running on the server
 * (a scheduled run, a page reload) is picked up and shown. When a job
 * this hook watched finishes, every archive-backed view is refreshed. */
export function useSyncJob(environmentName: string | undefined) {
  const [state, setState] = useState<SyncJobState>(INITIAL_STATE)
  const queryClient = useQueryClient()
  // Bumped on every environment change/unmount: a response from an older
  // generation must never land in the current state.
  const generation = useRef(0)
  const cancelPoll = useRef<(() => void) | null>(null)
  // The phase as of the last commit, for reconciling after a fresh sign-in.
  const phaseRef = useRef<SyncJobPhase>(state.phase)
  // True only when a poll of a job that really started on the server died
  // (e.g. the session expired mid-run) -- the one case where a fresh
  // sign-in may reconcile the phase from the server's current status.
  const lostPoll = useRef(false)
  useEffect(() => { phaseRef.current = state.phase }, [state.phase])

  const stopPolling = useCallback(() => {
    cancelPoll.current?.()
    cancelPoll.current = null
  }, [])

  const beginPolling = useCallback((name: string, gen: number) => {
    stopPolling()
    lostPoll.current = false
    cancelPoll.current = startPollLoop<SyncStatusResponse>({
      fetchStatus: () => fetchSyncStatus(name),
      onStatus: status => {
        if (gen !== generation.current) return 'stop'
        if (status.status === 'running') {
          setState(s => ({ ...s, status, phase: 'running' }))
          return 'continue'
        }
        if (status.status === 'done') {
          setState(s => ({ ...s, status, phase: 'done', error: null }))
          invalidateArchiveQueries(queryClient)
        } else if (status.status === 'error') {
          setState(s => ({ ...s, status, phase: 'error', error: status.error }))
        } else {
          setState(s => ({ ...s, status, phase: 'error', error: JOB_LOST_MESSAGE }))
        }
        cancelPoll.current = null
        return 'stop'
      },
      onFatal: message => {
        if (gen !== generation.current) return
        cancelPoll.current = null
        lostPoll.current = true
        setState(s => ({ ...s, phase: 'error', error: message }))
      },
    })
  }, [queryClient, stopPolling])

  const refreshStatus = useCallback((reconcile = false) => {
    if (!environmentName) return
    const gen = generation.current
    fetchSyncStatus(environmentName)
      .then(status => {
        if (gen !== generation.current) return
        setState(s => ({ ...s, status, statusLoaded: true, statusError: null }))
        // After a fresh sign-in: a run this hook was watching (its polling
        // died with the session, phase "error") may have finished
        // meanwhile -- show its real outcome, and refresh the archive
        // views if it completed.
        if (reconcile && lostPoll.current && phaseRef.current === 'error' && cancelPoll.current === null) {
          lostPoll.current = false
          if (status.status === 'done') {
            setState(s => ({ ...s, phase: 'done', error: null }))
            invalidateArchiveQueries(queryClient)
          } else if (status.status === 'error') {
            setState(s => ({ ...s, phase: 'error', error: status.error }))
          }
        }
        // Attach to a sync the server is already running (scheduled run,
        // another tab, a reload) so its progress shows here too. Not to a
        // CSV import: it holds the same slot, but when it ends the slot
        // goes back to idle or the PREVIOUS sync's result, which would
        // read as a lost job or a sync that never ran.
        if (status.status === 'running' && status.kind !== 'csv_import' && cancelPoll.current === null) {
          setState(s => ({ ...s, phase: 'running', error: null }))
          beginPolling(environmentName, gen)
        }
      })
      .catch(err => {
        if (gen !== generation.current) return
        setState(s => ({ ...s, statusLoaded: true, statusError: errorText(err) }))
      })
  }, [environmentName, beginPolling, queryClient])

  const start = useCallback((ingestionScope?: IngestionScope) => {
    if (!environmentName) return
    stopPolling()
    const gen = generation.current
    lostPoll.current = false
    setState(s => ({ ...s, phase: 'starting', error: null }))
    startSync(environmentName, ingestionScope)
      .then(() => {
        if (gen !== generation.current) return
        // started or already_running: either way there is a job to follow.
        setState(s => ({ ...s, phase: 'running' }))
        beginPolling(environmentName, gen)
      })
      .catch(err => {
        if (gen !== generation.current) return
        setState(s => ({ ...s, phase: 'error', error: errorText(err) }))
      })
  }, [environmentName, beginPolling, stopPolling])

  // After a fresh sign-in, pick a running job back up (its polling stopped
  // when the session expired).
  useEffect(() => onSessionRestored(() => refreshStatus(true)), [refreshStatus])

  // New environment (or first mount): forget everything about the old one.
  useEffect(() => {
    generation.current += 1
    lostPoll.current = false
    setState(INITIAL_STATE)
    refreshStatus(false)
    return () => {
      generation.current += 1
      stopPolling()
    }
  }, [refreshStatus, stopPolling])

  return { ...state, start, refreshStatus }
}
