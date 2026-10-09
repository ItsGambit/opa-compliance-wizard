import { isSessionExpiredError } from '../api/client'

export type PollVerdict = 'continue' | 'stop'

export interface PollLoopOptions<S> {
  fetchStatus: () => Promise<S>
  /** Called with every status; may be async (e.g. fetch a finished
   * result). The next poll is scheduled only after it settles, so polls
   * never overlap. */
  onStatus: (status: S) => PollVerdict | Promise<PollVerdict>
  /** Called once when polling gives up (too many consecutive failures, or
   * the session expired). Never called after cancel(). */
  onFatal: (message: string) => void
  intervalMs?: number
  /** Consecutive failed status reads tolerated (with back-off) before
   * giving up -- one network blip no longer kills a long job's progress. */
  maxConsecutiveFailures?: number
}

export const DEFAULT_POLL_INTERVAL_MS = 1000
export const DEFAULT_MAX_CONSECUTIVE_FAILURES = 3

/** FE-04 (external review, 2026-10-05): the job hooks used setInterval,
 * which fired whether or not the previous request had settled (overlapping
 * multi-MB result downloads), and a `.then` that ran after unmount could
 * install an interval nobody cleared. This loop schedules the next poll
 * with setTimeout only after the previous one (and its handler) settled,
 * and every callback checks `cancelled` first, so a cancelled loop never
 * touches state or the network again. Starts with an immediate poll.
 * Returns cancel(). */
export function startPollLoop<S>({
  fetchStatus,
  onStatus,
  onFatal,
  intervalMs = DEFAULT_POLL_INTERVAL_MS,
  maxConsecutiveFailures = DEFAULT_MAX_CONSECUTIVE_FAILURES,
}: PollLoopOptions<S>): () => void {
  let cancelled = false
  let timer: ReturnType<typeof setTimeout> | null = null
  let failures = 0

  const schedule = (ms: number) => {
    if (cancelled) return
    timer = setTimeout(() => { timer = null; void tick() }, ms)
  }

  const tick = async () => {
    if (cancelled) return
    let status: S
    try {
      status = await fetchStatus()
    } catch (err) {
      if (cancelled) return
      failures += 1
      if (isSessionExpiredError(err) || failures >= maxConsecutiveFailures) {
        onFatal(err instanceof Error ? err.message : String(err))
        return
      }
      schedule(intervalMs * 2 ** failures)
      return
    }
    if (cancelled) return
    failures = 0
    let verdict: PollVerdict
    try {
      verdict = await onStatus(status)
    } catch (err) {
      if (!cancelled) onFatal(err instanceof Error ? err.message : String(err))
      return
    }
    if (verdict === 'continue') schedule(intervalMs)
  }

  void tick()
  return () => {
    cancelled = true
    if (timer !== null) clearTimeout(timer)
    timer = null
  }
}

/** Shown when the server reports no job for something the UI saw running:
 * job state lives in the server's memory, so a restart (every deploy)
 * forgets it. */
export const JOB_LOST_MESSAGE = 'The server no longer has this job (it may have restarted). Check the result, then start it again.'
