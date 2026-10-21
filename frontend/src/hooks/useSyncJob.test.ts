/** useSyncJob (FE-04): reset on environment change, lost jobs, attach. */
import { act } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fetchRefreshStatus, fetchSyncStatus, startRefresh } from '../api/client'
import { renderHookWithClient } from '../test/renderWithClient'
import type { RefreshStatus, SyncStatusResponse } from '../types'
import { JOB_LOST_MESSAGE } from './pollLoop'
import { useSyncJob } from './useSyncJob'

vi.mock('../api/client', () => ({
  fetchSyncStatus: vi.fn(),
  startRefresh: vi.fn(),
  fetchRefreshStatus: vi.fn(),
  isSessionExpiredError: () => false, onSessionRestored: () => () => {},
}))

const status = (s: SyncStatusResponse['status'], extra: Partial<SyncStatusResponse> = {}): SyncStatusResponse =>
  ({ status: s, steps: [], error: null, sync_state: null, is_first_sync: false, ...extra })

const refresh = (s: RefreshStatus['status'], log: RefreshStatus['parts']['log'] = { state: 'ok', events_new: 4 }): RefreshStatus => ({
  status: s, job_id: 'j1', trigger: 'manual', started_at: null, finished_at: null, parts_requested: ['log'], cancel_requested: false, summary: null,
  parts: { opa: { state: 'not_requested' }, okta: { state: 'not_requested' }, log },
})

beforeEach(() => {
  vi.clearAllMocks()
  vi.useFakeTimers()
})
afterEach(() => { vi.useRealTimers() })

const advance = async (ms = 1000) => { await act(async () => { await vi.advanceTimersByTimeAsync(ms) }) }

describe('useSyncJob', () => {
  it('loads the status on mount and handles a failed load (no unhandled rejection)', async () => {
    vi.mocked(fetchSyncStatus).mockRejectedValue(new Error('404 gone'))
    const { result } = renderHookWithClient(() => useSyncJob('dev'))
    await advance(0)
    expect(result.current.statusLoaded).toBe(true)
    expect(result.current.statusError).toBe('404 gone')
  })

  it('a run that ends in "idle" was lost by the server: error, polling stops', async () => {
    vi.mocked(fetchSyncStatus).mockResolvedValue(status('done'))
    vi.mocked(fetchRefreshStatus).mockResolvedValue(refresh('idle'))
    vi.mocked(startRefresh).mockResolvedValue({ started: true, already_running: false, job_id: 'j1' })
    const { result } = renderHookWithClient(() => useSyncJob('dev'))
    await advance(0)
    await act(async () => { result.current.start() })
    await advance(0)
    expect(result.current.phase).toBe('error')
    expect(result.current.error).toBe(JOB_LOST_MESSAGE)
    const calls = vi.mocked(fetchRefreshStatus).mock.calls.length
    await advance(10_000)
    expect(fetchRefreshStatus).toHaveBeenCalledTimes(calls)
  })

  it('done refreshes every archive-backed view', async () => {
    vi.mocked(fetchSyncStatus).mockResolvedValue(status('idle'))
    vi.mocked(fetchRefreshStatus).mockResolvedValue(refresh('done'))
    vi.mocked(startRefresh).mockResolvedValue({ started: true, already_running: false, job_id: 'j1' })
    const { result, client } = renderHookWithClient(() => useSyncJob('dev'))
    const spy = vi.spyOn(client, 'invalidateQueries')
    await advance(0)
    await act(async () => { result.current.start() })
    await advance(0)
    expect(result.current.phase).toBe('done')
    expect(startRefresh).toHaveBeenCalledWith('dev', ['log'])  // the System Log part of the refresh; the legacy sync/start route is not called
    expect(result.current.status?.result?.inserted).toBe(4)
    const keys = spy.mock.calls.map(c => (c[0] as { queryKey: string[] }).queryKey[0])
    expect(keys).toEqual(expect.arrayContaining(['report', 'report_defs', 'resource_history', 'secrets_access_report', 'service_accounts_report', 'sync_status']))
  })

  it('attaches to a sync already running on the server', async () => {
    vi.mocked(fetchSyncStatus).mockResolvedValueOnce(status('running')).mockResolvedValueOnce(status('running')).mockResolvedValue(status('done'))
    const { result } = renderHookWithClient(() => useSyncJob('dev'))
    await advance(0)
    expect(result.current.phase).toBe('running')
    await advance(2000)
    expect(result.current.phase).toBe('done')
    expect(startRefresh).not.toHaveBeenCalled()
  })

  it('switching environment resets state and stops polling the old one', async () => {
    vi.mocked(fetchSyncStatus).mockImplementation(async (name: string) => (name === 'old' ? status('running') : status('idle')))
    vi.mocked(startRefresh).mockResolvedValue({ started: true, already_running: false, job_id: 'j1' })
    const { result, rerender } = renderHookWithClient((p: { env: string }) => useSyncJob(p.env), undefined, { env: 'old' })
    await advance(0)
    expect(result.current.phase).toBe('running')
    rerender({ env: 'new' })
    await advance(0)
    expect(result.current.phase).toBe('idle')
    const oldCalls = vi.mocked(fetchSyncStatus).mock.calls.filter(c => c[0] === 'old').length
    await advance(10_000)
    expect(vi.mocked(fetchSyncStatus).mock.calls.filter(c => c[0] === 'old').length).toBe(oldCalls)
  })

  it('a late answer for the previous environment is ignored', async () => {
    let resolveOld!: (s: SyncStatusResponse) => void
    vi.mocked(fetchSyncStatus).mockImplementation((name: string) =>
      name === 'old' ? new Promise(r => { resolveOld = r }) : Promise.resolve(status('idle', { is_first_sync: true })))
    const { result, rerender } = renderHookWithClient((p: { env: string }) => useSyncJob(p.env), undefined, { env: 'old' })
    rerender({ env: 'new' })
    await advance(0)
    await act(async () => { resolveOld(status('running', { is_first_sync: false })) })
    await advance(0)
    expect(result.current.status?.is_first_sync).toBe(true)
    expect(result.current.phase).toBe('idle')
  })

  it('a failed start is an error', async () => {
    vi.mocked(fetchSyncStatus).mockResolvedValue(status('idle'))
    vi.mocked(startRefresh).mockRejectedValue(new Error('No saved environment'))
    const { result } = renderHookWithClient(() => useSyncJob('dev'))
    await advance(0)
    await act(async () => { result.current.start() })
    expect(result.current.phase).toBe('error')
    expect(result.current.error).toBe('No saved environment')
  })

  it('a System Log part the server refused ends in the server\'s message', async () => {
    vi.mocked(fetchSyncStatus).mockResolvedValue(status('idle'))
    vi.mocked(fetchRefreshStatus).mockResolvedValue(refresh('done', { state: 'refused', message: 'Okta refused the System Log read (HTTP 403).' }))
    vi.mocked(startRefresh).mockResolvedValue({ started: true, already_running: false, job_id: 'j1' })
    const { result } = renderHookWithClient(() => useSyncJob('dev'))
    await advance(0)
    await act(async () => { result.current.start() })
    await advance(0)
    expect(result.current.phase).toBe('error')
    expect(result.current.error).toBe('Okta refused the System Log read (HTTP 403).')
  })
})
