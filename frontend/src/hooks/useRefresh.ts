import { useCallback, useEffect, useRef } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { cancelRefresh, fetchRefreshStatus, startRefresh } from '../api/client'
import { invalidateArchiveQueries } from '../api/queryClient'
import type { RefreshPartName, RefreshStatus } from '../types'
import { finishToast, OVERVIEW_PATH, REFRESH_TOAST_MS } from '../utils/refresh'
import { toast } from './useToast'

// The combined Refresh (5.51.0), seen from the browser: one status query per environment that every screen shares
// (the Overview's progress card, the footer's Sync now, the Access Explorer), polled every 2 s while a job runs.

export const REFRESH_POLL_MS = 2000

export const refreshKey = (environment: string | undefined) => ['refresh', environment ?? null] as const

export function useRefreshStatus(environment: string | undefined) {
  return useQuery<RefreshStatus>({
    queryKey: refreshKey(environment),
    queryFn: () => fetchRefreshStatus(environment!),
    enabled: !!environment,
    retry: false,
    refetchOnWindowFocus: false,
    refetchInterval: query => (query.state.data?.status === 'running' ? REFRESH_POLL_MS : false),
  })
}

// Jobs this browser started or watched running: when one ends, the finish toast and the data reload happen once.
const watched = new Set<string>()

function onOverview(): boolean {
  return typeof window !== 'undefined' && window.location.hash.startsWith(OVERVIEW_PATH)
}

/** Starting, attaching to and stopping the refresh of one environment. */
export function useRefreshActions(environment: string | undefined) {
  const queryClient = useQueryClient()

  const start = useCallback(async (parts?: RefreshPartName[]) => {
    if (!environment) return null
    try {
      const out = await startRefresh(environment, parts)
      if (out.job_id) watched.add(out.job_id)
      void queryClient.invalidateQueries({ queryKey: refreshKey(environment) })
      if (!onOverview()) {
        // Off the Overview nothing else shows the job: say it started (or that it already ran) and where its progress is.
        toast({
          title: out.already_running ? 'A refresh is already running' : 'Refresh started',
          description: out.already_running ? 'It is not started twice; this one will finish as usual.' : 'It reads OPA and Okta and syncs the System Log. You can keep working.',
          variant: 'default', duration: REFRESH_TOAST_MS, action: { label: 'View progress', href: OVERVIEW_PATH },
        })
      }
      return out
    } catch (err) {
      toast({ title: 'Could not start the refresh', description: (err as Error).message, variant: 'error', duration: REFRESH_TOAST_MS })
      return null
    }
  }, [environment, queryClient])

  const stop = useCallback(async () => {
    if (!environment) return
    try {
      await cancelRefresh(environment)
      void queryClient.invalidateQueries({ queryKey: refreshKey(environment) })
    } catch (err) {
      toast({ title: 'Could not stop the refresh', description: (err as Error).message, variant: 'error', duration: REFRESH_TOAST_MS })
    }
  }, [environment, queryClient])

  return { start, stop }
}

/** Mounted once (the footer is on every page): when a refresh this browser knows about finishes, say how it went and reload the
 * figures it changed. The Overview shows the same outcome in its progress card. */
export function useRefreshWatcher(environment: string | undefined) {
  const { data } = useRefreshStatus(environment)
  const queryClient = useQueryClient()
  const handled = useRef<string | null>(null)

  useEffect(() => {
    if (!data || !data.job_id) return
    if (data.status === 'running') {
      watched.add(data.job_id)
      return
    }
    if (data.status !== 'done' || !watched.has(data.job_id) || handled.current === data.job_id) return
    handled.current = data.job_id
    watched.delete(data.job_id)
    const t = finishToast(data)
    toast({ ...t, duration: REFRESH_TOAST_MS, ...(onOverview() ? {} : { action: { label: 'View details', href: OVERVIEW_PATH } }) })
    void queryClient.invalidateQueries({ queryKey: ['overview', environment] })
    for (const key of ['okta_admins_report', 'cross_checks', 'config_snapshots', 'sync_status']) void queryClient.invalidateQueries({ queryKey: [key] })
    invalidateArchiveQueries(queryClient)
  }, [data, environment, queryClient])
}
