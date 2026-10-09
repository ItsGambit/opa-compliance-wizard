/** FE-15: evidence-chain check from the UI; deep check polls its 202. */
import { act, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fetchIntegrity } from '../api/client'
import { DEEP_POLL_INTERVAL_MS, useIntegrityCheck } from './useIntegrityCheck'

vi.mock('../api/client', () => ({ fetchIntegrity: vi.fn(), isSessionExpiredError: () => false }))

const OK = { valid: true, manifest_count: 3, broken_at: null, reason: null }

beforeEach(() => { vi.clearAllMocks(); vi.useFakeTimers() })
afterEach(() => { vi.useRealTimers() })

describe('useIntegrityCheck', () => {
  it('basic check: one request, result shown', async () => {
    vi.mocked(fetchIntegrity).mockResolvedValue(OK)
    const { result } = renderHook(() => useIntegrityCheck('dev'))
    await act(async () => { result.current.run(false) })
    expect(fetchIntegrity).toHaveBeenCalledWith('dev', false)
    expect(result.current.state).toEqual({ phase: 'done', deep: false, result: OK })
  })

  it('deep check: keeps asking while the server answers "running"', async () => {
    vi.mocked(fetchIntegrity).mockResolvedValueOnce({ status: 'running' }).mockResolvedValueOnce({ status: 'running' }).mockResolvedValue(OK)
    const { result } = renderHook(() => useIntegrityCheck('dev'))
    await act(async () => { result.current.run(true) })
    expect(result.current.state.phase).toBe('checking')
    await act(async () => { await vi.advanceTimersByTimeAsync(DEEP_POLL_INTERVAL_MS * 2) })
    expect(fetchIntegrity).toHaveBeenCalledTimes(3)
    expect(result.current.state.phase).toBe('done')
  })

  it('a failure is shown, not retried forever', async () => {
    vi.mocked(fetchIntegrity).mockRejectedValue(new Error('Admin access required'))
    const { result } = renderHook(() => useIntegrityCheck('dev'))
    await act(async () => { result.current.run(true) })
    expect(result.current.state).toEqual({ phase: 'error', deep: true, error: 'Admin access required' })
    await act(async () => { await vi.advanceTimersByTimeAsync(60_000) })
    expect(fetchIntegrity).toHaveBeenCalledTimes(1)
  })

  it('stops polling on unmount', async () => {
    vi.mocked(fetchIntegrity).mockResolvedValue({ status: 'running' })
    const { result, unmount } = renderHook(() => useIntegrityCheck('dev'))
    await act(async () => { result.current.run(true) })
    unmount()
    await act(async () => { await vi.advanceTimersByTimeAsync(60_000) })
    expect(fetchIntegrity).toHaveBeenCalledTimes(1)
  })
})
