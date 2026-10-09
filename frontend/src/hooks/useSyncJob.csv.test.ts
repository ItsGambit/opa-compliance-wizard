/** Review finding 7: a CSV import holding the slot is not a sync to watch;
 * and a fresh sign-in re-attaches to a running sync. */
import { act } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fetchSyncStatus, notifySessionRestored } from '../api/client'
import { renderHookWithClient } from '../test/renderWithClient'
import type { SyncStatusResponse } from '../types'
import { useSyncJob } from './useSyncJob'

vi.mock('../api/client', async importOriginal => ({ ...(await importOriginal<typeof import('../api/client')>()), fetchSyncStatus: vi.fn(), startSync: vi.fn() }))
import { startSync } from '../api/client'

const st = (s: SyncStatusResponse['status'], kind?: string): SyncStatusResponse => ({ status: s, kind, steps: [], error: null, sync_state: null, is_first_sync: false })

beforeEach(() => { vi.clearAllMocks(); vi.useFakeTimers() })
afterEach(() => { vi.useRealTimers() })
const advance = async (ms = 0) => { await act(async () => { await vi.advanceTimersByTimeAsync(ms) }) }

describe('useSyncJob attach rules', () => {
  it('does not attach to a CSV import', async () => {
    vi.mocked(fetchSyncStatus).mockResolvedValueOnce(st('running', 'csv_import')).mockResolvedValue(st('idle'))
    const { result } = renderHookWithClient(() => useSyncJob('dev'))
    await advance(5000)
    expect(result.current.phase).toBe('idle')
    expect(fetchSyncStatus).toHaveBeenCalledTimes(1)
  })

  it('re-attaches to a running sync after a fresh sign-in', async () => {
    vi.mocked(fetchSyncStatus).mockResolvedValueOnce(st('idle')).mockResolvedValue(st('running'))
    const { result } = renderHookWithClient(() => useSyncJob('dev'))
    await advance()
    expect(result.current.phase).toBe('idle')
    await act(async () => { notifySessionRestored() })
    await advance()
    expect(result.current.phase).toBe('running')
  })

  it('after a fresh sign-in, a watched run that finished meanwhile shows as done and refreshes reports', async () => {
    vi.mocked(startSync).mockResolvedValue({ started: true, already_running: false })
    vi.mocked(fetchSyncStatus).mockResolvedValueOnce(st('idle')).mockRejectedValueOnce(new Error('x')).mockRejectedValueOnce(new Error('x')).mockRejectedValueOnce(new Error('x')).mockResolvedValue(st('done'))
    const { result, client } = renderHookWithClient(() => useSyncJob('dev'))
    await advance()
    await act(async () => { result.current.start() })
    await advance(30_000)
    expect(result.current.phase).toBe('error')
    const spy = vi.spyOn(client, 'invalidateQueries')
    await act(async () => { notifySessionRestored() })
    await advance()
    expect(result.current.phase).toBe('done')
    expect(spy.mock.calls.map(c => (c[0] as { queryKey: string[] }).queryKey[0])).toContain('report')
  })

  it('a hook that was not watching anything stays idle on a fresh sign-in', async () => {
    vi.mocked(fetchSyncStatus).mockResolvedValue(st('done'))
    const { result } = renderHookWithClient(() => useSyncJob('dev'))
    await advance()
    await act(async () => { notifySessionRestored() })
    await advance()
    expect(result.current.phase).toBe('idle')
  })

  it('a start that never reached the server is not reconciled to the previous run\'s "done"', async () => {
    vi.mocked(fetchSyncStatus).mockResolvedValue(st('done'))
    vi.mocked(startSync).mockRejectedValue(new Error('Your session has expired'))
    const { result } = renderHookWithClient(() => useSyncJob('dev'))
    await advance()
    await act(async () => { result.current.start() })
    expect(result.current.phase).toBe('error')
    await act(async () => { notifySessionRestored() })
    await advance()
    expect(result.current.phase).toBe('error')
  })
})
