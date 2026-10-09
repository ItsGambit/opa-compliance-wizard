/** FE-04: the shared poll loop -- no overlapping polls, nothing after
 * cancel, a blip tolerated, a dead session ends it at once. */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { SessionExpiredError } from '../api/client'
import { startPollLoop } from './pollLoop'

beforeEach(() => { vi.useFakeTimers() })
afterEach(() => { vi.useRealTimers() })

const flush = () => vi.advanceTimersByTimeAsync(0)

describe('startPollLoop', () => {
  it('never starts a poll while the previous handler is still running', async () => {
    let release!: () => void
    const fetchStatus = vi.fn().mockResolvedValue('done')
    const onStatus = vi.fn(() => new Promise<'stop'>(r => { release = () => r('stop') }))
    startPollLoop({ fetchStatus, onStatus, onFatal: vi.fn(), intervalMs: 100 })
    await flush()
    await vi.advanceTimersByTimeAsync(1000)
    expect(fetchStatus).toHaveBeenCalledTimes(1) // the slow handler blocks the next poll
    release()
    await vi.advanceTimersByTimeAsync(1000)
    expect(fetchStatus).toHaveBeenCalledTimes(1) // and 'stop' ends the loop
  })

  it('makes no call and no callback after cancel()', async () => {
    const fetchStatus = vi.fn().mockResolvedValue('running')
    const onStatus = vi.fn(() => 'continue' as const)
    const cancel = startPollLoop({ fetchStatus, onStatus, onFatal: vi.fn(), intervalMs: 100 })
    await flush()
    expect(onStatus).toHaveBeenCalledTimes(1)
    cancel()
    await vi.advanceTimersByTimeAsync(1000)
    expect(fetchStatus).toHaveBeenCalledTimes(1)
  })

  it('ignores a response that arrives after cancel()', async () => {
    let resolve!: (v: string) => void
    const fetchStatus = vi.fn(() => new Promise<string>(r => { resolve = r }))
    const onStatus = vi.fn(() => 'continue' as const)
    const cancel = startPollLoop({ fetchStatus, onStatus, onFatal: vi.fn() })
    cancel()
    resolve('running')
    await flush()
    expect(onStatus).not.toHaveBeenCalled()
  })

  it('tolerates failures below the limit, then gives up once', async () => {
    const fetchStatus = vi.fn()
      .mockRejectedValueOnce(new Error('blip'))
      .mockResolvedValueOnce('running')
      .mockRejectedValue(new Error('down'))
    const onStatus = vi.fn(() => 'continue' as const)
    const onFatal = vi.fn()
    startPollLoop({ fetchStatus, onStatus, onFatal, intervalMs: 10, maxConsecutiveFailures: 3 })
    await vi.advanceTimersByTimeAsync(10_000)
    expect(onStatus).toHaveBeenCalledTimes(1) // recovered after the first blip
    expect(onFatal).toHaveBeenCalledTimes(1)
    expect(onFatal).toHaveBeenCalledWith('down')
    expect(fetchStatus).toHaveBeenCalledTimes(5) // blip, ok, then 3 consecutive failures
  })

  it('stops at once when the session has expired', async () => {
    const fetchStatus = vi.fn().mockRejectedValue(new SessionExpiredError())
    const onFatal = vi.fn()
    startPollLoop({ fetchStatus, onStatus: vi.fn(), onFatal, maxConsecutiveFailures: 5 })
    await vi.advanceTimersByTimeAsync(10_000)
    expect(fetchStatus).toHaveBeenCalledTimes(1)
    expect(onFatal).toHaveBeenCalledTimes(1)
  })

  it('reports a failing handler (e.g. the result download) as fatal', async () => {
    const onFatal = vi.fn()
    startPollLoop({ fetchStatus: vi.fn().mockResolvedValue('done'), onStatus: () => Promise.reject(new Error('result failed')), onFatal })
    await flush()
    expect(onFatal).toHaveBeenCalledWith('result failed')
  })
})
