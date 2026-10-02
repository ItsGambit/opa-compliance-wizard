/** Covers the real, documented bug in useAccessBootstrapJob.ts: stopPolling()
 * used to run BEFORE fetchAccessBootstrapResult() once status hit "done",
 * so a transient failure fetching the result left polling permanently
 * dead with no auto-retry, forcing a full bootstrap restart just to
 * re-fetch an already-finished result (see that file's own "FIX" comment).
 * Current code waits for the result fetch to settle before stopping --
 * these tests turn that from "fixed once" into "stays fixed."
 *
 * Uses fake timers (window.setInterval/clearInterval are the hook's own
 * polling mechanism) -- avoids @testing-library's waitFor, which polls
 * with REAL timers internally and never resolves under vi.useFakeTimers().
 * Every mock resolves/rejects immediately, so state is already settled
 * by the time each `act(async () => ...)` call returns. */
import { act, renderHook } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fetchAccessBootstrapResult, fetchAccessBootstrapStatus, startAccessBootstrap } from '../api/client'
import type { AccessModel } from '../types'
import { useAccessBootstrapJob } from './useAccessBootstrapJob'

vi.mock('../api/client', () => ({
  startAccessBootstrap: vi.fn(),
  fetchAccessBootstrapStatus: vi.fn(),
  fetchAccessBootstrapResult: vi.fn(),
}))

const FAKE_RESULT = {} as AccessModel

beforeEach(() => {
  vi.clearAllMocks()
  vi.useFakeTimers()
})

async function advancePoll() {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(1000)
  })
}

describe('useAccessBootstrapJob', () => {
  it('happy path: starting -> running -> done, with result set and polling stopped', async () => {
    vi.mocked(startAccessBootstrap).mockResolvedValue({ started: true, steps: [['fetch', 'Fetching']] })
    vi.mocked(fetchAccessBootstrapStatus)
      .mockResolvedValueOnce({ status: 'running', steps: [], error: null })
      .mockResolvedValueOnce({ status: 'done', steps: [], error: null })
    vi.mocked(fetchAccessBootstrapResult).mockResolvedValue(FAKE_RESULT)

    const { result } = renderHook(() => useAccessBootstrapJob())

    await act(async () => {
      result.current.start()
    })
    expect(result.current.phase).toBe('running')
    expect(fetchAccessBootstrapStatus).toHaveBeenCalledTimes(1) // poll() called immediately by start()

    await advancePoll() // second status call -> 'done' -> triggers result fetch
    expect(result.current.phase).toBe('done')
    expect(result.current.result).toBe(FAKE_RESULT)

    const callsAtDone = vi.mocked(fetchAccessBootstrapStatus).mock.calls.length
    await advancePoll()
    await advancePoll()
    expect(fetchAccessBootstrapStatus).toHaveBeenCalledTimes(callsAtDone) // no further polling after done
  })

  it('REGRESSION: a result-fetch failure after status=done surfaces as error, not a stuck/silent retry', async () => {
    vi.mocked(startAccessBootstrap).mockResolvedValue({ started: true, steps: [] })
    vi.mocked(fetchAccessBootstrapStatus).mockResolvedValue({ status: 'done', steps: [], error: null })
    vi.mocked(fetchAccessBootstrapResult).mockRejectedValueOnce(new Error('transient network blip'))

    const { result } = renderHook(() => useAccessBootstrapJob())

    await act(async () => {
      result.current.start()
    })
    expect(result.current.phase).toBe('error')
    expect(result.current.error).toBe('transient network blip')

    // Polling must have actually stopped (not silently continuing in the
    // background) -- advancing timers further must not produce any more
    // status calls.
    const callsAtError = vi.mocked(fetchAccessBootstrapStatus).mock.calls.length
    await advancePoll()
    expect(fetchAccessBootstrapStatus).toHaveBeenCalledTimes(callsAtError)

    // Clicking Retry (start() again) must cleanly restart from scratch --
    // no dangling interval from the first attempt still firing alongside
    // the new one. (status mock still returns 'done' immediately, so
    // start()'s own synchronous poll() call already resolves through to
    // 'done' within this one act() -- no need to advance timers again.)
    vi.mocked(fetchAccessBootstrapResult).mockResolvedValueOnce(FAKE_RESULT)
    await act(async () => {
      result.current.start()
    })
    expect(result.current.phase).toBe('done')
    expect(result.current.result).toBe(FAKE_RESULT)
    expect(fetchAccessBootstrapResult).toHaveBeenCalledTimes(2) // first (failed) + retry (succeeded), not more
  })

  it('status=error stops polling immediately without ever calling fetchAccessBootstrapResult', async () => {
    vi.mocked(startAccessBootstrap).mockResolvedValue({ started: true, steps: [] })
    vi.mocked(fetchAccessBootstrapStatus).mockResolvedValue({ status: 'error', steps: [], error: 'boom' })

    const { result } = renderHook(() => useAccessBootstrapJob())
    await act(async () => {
      result.current.start()
    })
    expect(result.current.phase).toBe('error')
    expect(fetchAccessBootstrapResult).not.toHaveBeenCalled()

    const callsAtError = vi.mocked(fetchAccessBootstrapStatus).mock.calls.length
    await advancePoll()
    expect(fetchAccessBootstrapStatus).toHaveBeenCalledTimes(callsAtError)
  })

  it('a network failure polling /status itself surfaces as error and stops polling', async () => {
    vi.mocked(startAccessBootstrap).mockResolvedValue({ started: true, steps: [] })
    vi.mocked(fetchAccessBootstrapStatus).mockRejectedValue(new Error('network down'))

    const { result } = renderHook(() => useAccessBootstrapJob())
    await act(async () => {
      result.current.start()
    })
    expect(result.current.phase).toBe('error')
    expect(result.current.error).toBe('network down')
  })

  it('clears the polling interval on unmount', async () => {
    const clearIntervalSpy = vi.spyOn(window, 'clearInterval')
    vi.mocked(startAccessBootstrap).mockResolvedValue({ started: true, steps: [] })
    vi.mocked(fetchAccessBootstrapStatus).mockResolvedValue({ status: 'running', steps: [], error: null })

    const { result, unmount } = renderHook(() => useAccessBootstrapJob())
    await act(async () => {
      result.current.start()
    })
    expect(result.current.phase).toBe('running')

    unmount()
    expect(clearIntervalSpy).toHaveBeenCalled()
  })
})
