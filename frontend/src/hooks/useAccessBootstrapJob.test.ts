/** useAccessBootstrapJob (FE-04 / UI-10). Fake timers drive the poll loop;
 * every mock settles immediately unless a test holds it open. */
import { act, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fetchAccessBootstrapResult, fetchAccessBootstrapStatus, startAccessBootstrap } from '../api/client'
import type { AccessModel } from '../types'
import { JOB_LOST_MESSAGE } from './pollLoop'
import { useAccessBootstrapJob } from './useAccessBootstrapJob'

vi.mock('../api/client', () => ({
  startAccessBootstrap: vi.fn(),
  fetchAccessBootstrapStatus: vi.fn(),
  fetchAccessBootstrapResult: vi.fn(),
  isSessionExpiredError: () => false,
}))

const FAKE_RESULT = {} as AccessModel

beforeEach(() => {
  vi.clearAllMocks()
  vi.useFakeTimers()
})
afterEach(() => { vi.useRealTimers() })

async function advance(ms = 1000) {
  await act(async () => { await vi.advanceTimersByTimeAsync(ms) })
}

async function startJob(result: { current: ReturnType<typeof useAccessBootstrapJob> }) {
  await act(async () => { result.current.start() })
}

describe('useAccessBootstrapJob', () => {
  it('happy path: starting -> running -> done, one result download, polling stopped', async () => {
    vi.mocked(startAccessBootstrap).mockResolvedValue({ started: true, steps: [['fetch', 'Fetching']] })
    vi.mocked(fetchAccessBootstrapStatus)
      .mockResolvedValueOnce({ status: 'running', steps: [], error: null })
      .mockResolvedValueOnce({ status: 'done', steps: [], error: null })
    vi.mocked(fetchAccessBootstrapResult).mockResolvedValue(FAKE_RESULT)

    const { result } = renderHook(() => useAccessBootstrapJob())
    await startJob(result)
    expect(result.current.phase).toBe('running')
    expect(result.current.stepDefs).toEqual([['fetch', 'Fetching']])
    await advance()
    expect(result.current.phase).toBe('done')
    expect(result.current.result).toBe(FAKE_RESULT)
    const calls = vi.mocked(fetchAccessBootstrapStatus).mock.calls.length
    await advance(5000)
    expect(fetchAccessBootstrapStatus).toHaveBeenCalledTimes(calls)
    expect(fetchAccessBootstrapResult).toHaveBeenCalledTimes(1)
  })

  it('a slow result download is fetched exactly once (no overlapping polls)', async () => {
    vi.mocked(startAccessBootstrap).mockResolvedValue({ started: true, steps: [] })
    vi.mocked(fetchAccessBootstrapStatus).mockResolvedValue({ status: 'done', steps: [], error: null })
    let release!: (m: AccessModel) => void
    vi.mocked(fetchAccessBootstrapResult).mockImplementation(() => new Promise(r => { release = r }))
    const { result } = renderHook(() => useAccessBootstrapJob())
    await startJob(result)
    await advance(10_000)
    expect(fetchAccessBootstrapResult).toHaveBeenCalledTimes(1)
    expect(fetchAccessBootstrapStatus).toHaveBeenCalledTimes(1)
    await act(async () => { release(FAKE_RESULT) })
    expect(result.current.phase).toBe('done')
  })

  it('a result-fetch failure surfaces as an error and Retry restarts cleanly', async () => {
    vi.mocked(startAccessBootstrap).mockResolvedValue({ started: true, steps: [] })
    vi.mocked(fetchAccessBootstrapStatus).mockResolvedValue({ status: 'done', steps: [], error: null })
    vi.mocked(fetchAccessBootstrapResult).mockRejectedValueOnce(new Error('transient network blip'))
    const { result } = renderHook(() => useAccessBootstrapJob())
    await startJob(result)
    expect(result.current.phase).toBe('error')
    expect(result.current.error).toBe('transient network blip')
    const calls = vi.mocked(fetchAccessBootstrapStatus).mock.calls.length
    await advance(5000)
    expect(fetchAccessBootstrapStatus).toHaveBeenCalledTimes(calls)

    vi.mocked(fetchAccessBootstrapResult).mockResolvedValueOnce(FAKE_RESULT)
    await startJob(result)
    expect(result.current.phase).toBe('done')
    expect(fetchAccessBootstrapResult).toHaveBeenCalledTimes(2)
  })

  it('status=error stops polling without fetching a result', async () => {
    vi.mocked(startAccessBootstrap).mockResolvedValue({ started: true, steps: [] })
    vi.mocked(fetchAccessBootstrapStatus).mockResolvedValue({ status: 'error', steps: [], error: 'boom' })
    const { result } = renderHook(() => useAccessBootstrapJob())
    await startJob(result)
    expect(result.current.phase).toBe('error')
    expect(result.current.error).toBe('boom')
    expect(fetchAccessBootstrapResult).not.toHaveBeenCalled()
  })

  it('FE-04: "idle" while running means the server lost the job -- error, no endless polling', async () => {
    vi.mocked(startAccessBootstrap).mockResolvedValue({ started: true, steps: [] })
    vi.mocked(fetchAccessBootstrapStatus).mockResolvedValue({ status: 'idle', steps: [], error: null })
    const { result } = renderHook(() => useAccessBootstrapJob())
    await startJob(result)
    expect(result.current.phase).toBe('error')
    expect(result.current.error).toBe(JOB_LOST_MESSAGE)
    await advance(10_000)
    expect(fetchAccessBootstrapStatus).toHaveBeenCalledTimes(1)
  })

  it('one failed status read is retried; three in a row end in an error', async () => {
    vi.mocked(startAccessBootstrap).mockResolvedValue({ started: true, steps: [] })
    vi.mocked(fetchAccessBootstrapStatus).mockRejectedValue(new Error('network down'))
    const { result } = renderHook(() => useAccessBootstrapJob())
    await startJob(result)
    expect(result.current.phase).toBe('running')
    await advance(30_000)
    expect(result.current.phase).toBe('error')
    expect(result.current.error).toBe('network down')
    expect(fetchAccessBootstrapStatus).toHaveBeenCalledTimes(3)
  })

  it('UI-10: attaching to a job that is already running still shows its steps', async () => {
    vi.mocked(startAccessBootstrap).mockResolvedValue({ started: false, already_running: true, steps: [['a', 'A'], ['b', 'B']] })
    vi.mocked(fetchAccessBootstrapStatus).mockResolvedValue({ status: 'running', steps: [], error: null })
    const { result } = renderHook(() => useAccessBootstrapJob())
    await startJob(result)
    expect(result.current.stepDefs).toHaveLength(2)
    expect(result.current.phase).toBe('running')
  })

  it('FE-04: unmounting before /start answers leaves no polling behind', async () => {
    let resolveStart!: (v: { started: boolean; steps: [string, string][] }) => void
    vi.mocked(startAccessBootstrap).mockImplementation(() => new Promise(r => { resolveStart = r }))
    vi.mocked(fetchAccessBootstrapStatus).mockResolvedValue({ status: 'running', steps: [], error: null })
    const { result, unmount } = renderHook(() => useAccessBootstrapJob())
    act(() => { result.current.start() })
    unmount()
    await act(async () => { resolveStart({ started: true, steps: [] }) })
    await advance(10_000)
    expect(fetchAccessBootstrapStatus).not.toHaveBeenCalled()
  })

  it('stops polling on unmount', async () => {
    vi.mocked(startAccessBootstrap).mockResolvedValue({ started: true, steps: [] })
    vi.mocked(fetchAccessBootstrapStatus).mockResolvedValue({ status: 'running', steps: [], error: null })
    const { result, unmount } = renderHook(() => useAccessBootstrapJob())
    await startJob(result)
    const calls = vi.mocked(fetchAccessBootstrapStatus).mock.calls.length
    unmount()
    await advance(10_000)
    expect(fetchAccessBootstrapStatus).toHaveBeenCalledTimes(calls)
  })
})
