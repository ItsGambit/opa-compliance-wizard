/** The refresh watcher: the finish toast (the same words everywhere), the reload of the figures, and the link off the Overview. */
import { act, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fetchRefreshStatus, startRefresh } from '../api/client'
import { renderHookWithClient } from '../test/renderWithClient'
import type { RefreshStatus } from '../types'
import { useRefreshActions, useRefreshWatcher } from './useRefresh'
import * as toasts from './useToast'

vi.mock('../api/client', () => ({ fetchRefreshStatus: vi.fn(), startRefresh: vi.fn(), cancelRefresh: vi.fn(), isSessionExpiredError: () => false }))

const status = (over: Partial<RefreshStatus> = {}): RefreshStatus => ({
  status: 'idle', job_id: null, trigger: null, started_at: null, finished_at: null, parts_requested: [], cancel_requested: false, summary: null,
  parts: { opa: { state: 'not_requested' }, okta: { state: 'not_requested' }, log: { state: 'not_requested' } }, ...over,
})
const done = (states: [string, string, string]): RefreshStatus => status({
  status: 'done', job_id: 'jd', finished_at: '2026-10-21T08:48:00.000Z', parts_requested: ['opa', 'okta', 'log'],
  parts: { opa: { state: states[0] }, okta: { state: states[1] }, log: { state: states[2] } } as RefreshStatus['parts'],
})

beforeEach(() => { vi.clearAllMocks(); window.location.hash = '#/reports/browse' })

describe('refresh watcher and actions', () => {
  it('starting off the Overview says it started and links to the progress card; on the Overview it does not repeat it', async () => {
    const spy = vi.spyOn(toasts, 'toast')
    vi.mocked(startRefresh).mockResolvedValue({ started: true, already_running: false, job_id: 'j1' })
    const { result } = renderHookWithClient(() => useRefreshActions('dev'))
    await act(async () => { await result.current.start() })
    expect(startRefresh).toHaveBeenCalledWith('dev', undefined)
    expect(spy).toHaveBeenCalledWith(expect.objectContaining({ title: 'Refresh started', action: { label: 'View progress', href: '#/overview' } }))
    spy.mockClear()
    window.location.hash = '#/overview'
    await act(async () => { await result.current.start() })
    expect(spy).not.toHaveBeenCalled()
  })

  it('an already running refresh is attached to and the toast says so (never a second job)', async () => {
    const spy = vi.spyOn(toasts, 'toast')
    vi.mocked(startRefresh).mockResolvedValue({ started: false, already_running: true, job_id: 'j0' })
    const { result } = renderHookWithClient(() => useRefreshActions('dev'))
    await act(async () => { await result.current.start(['opa']) })
    expect(spy).toHaveBeenCalledWith(expect.objectContaining({ title: 'A refresh is already running' }))
  })

  it('a busy answer (the running job does not include the part) is the server\'s message, never "already running"', async () => {
    const spy = vi.spyOn(toasts, 'toast')
    vi.mocked(startRefresh).mockRejectedValue(Object.assign(new Error('A refresh of System Log is running. The Okta scan can start when it finishes.'), { status: 409 }))
    const { result } = renderHookWithClient(() => useRefreshActions('dev'))
    await act(async () => { await result.current.start(['okta']) })
    expect(spy).toHaveBeenCalledTimes(1)
    expect(spy).toHaveBeenCalledWith(expect.objectContaining({ title: 'Could not start the refresh', description: 'A refresh of System Log is running. The Okta scan can start when it finishes.', variant: 'error' }))
  })

  it('a refused start is a toast with the server\'s message', async () => {
    const spy = vi.spyOn(toasts, 'toast')
    vi.mocked(startRefresh).mockRejectedValue(new Error('An upgrade is starting; refreshes are paused until it finishes (a few minutes).'))
    const { result } = renderHookWithClient(() => useRefreshActions('dev'))
    await act(async () => { await result.current.start() })
    expect(spy).toHaveBeenCalledWith(expect.objectContaining({ title: 'Could not start the refresh', description: expect.stringContaining('An upgrade is starting'), variant: 'error' }))
  })

  it('a refresh this browser started ends with one finish toast and a reload of the figures; a finished job it never saw is not announced', async () => {
    const spy = vi.spyOn(toasts, 'toast')
    vi.mocked(startRefresh).mockResolvedValue({ started: true, already_running: false, job_id: 'jd' })
    vi.mocked(fetchRefreshStatus).mockResolvedValue(done(['ok', 'refused', 'ok']))
    const { result, client } = renderHookWithClient(() => ({ a: useRefreshActions('dev'), w: useRefreshWatcher('dev') }))
    const invalidated = vi.spyOn(client, 'invalidateQueries')
    await act(async () => { await result.current.a.start() })
    await waitFor(() => expect(spy.mock.calls.some(c => String(c[0].title).startsWith('Refresh finished'))).toBe(true))
    const finish = spy.mock.calls.map(c => c[0]).find(t => String(t.title).startsWith('Refresh finished'))!
    expect(finish.title).toBe('Refresh finished: 2 of 3 parts completed')
    expect(finish.variant).toBe('warning')
    expect(finish.description).toMatch(/Okta scan refused\. The figures from the other parts are updated\./)
    expect(finish.duration).toBeGreaterThanOrEqual(10_000)
    expect(invalidated.mock.calls.map(c => (c[0] as { queryKey: string[] }).queryKey[0])).toEqual(expect.arrayContaining(['overview', 'okta_admins_report', 'report']))
    // a second render with the same finished job does not announce it again
    const count = spy.mock.calls.filter(c => String(c[0].title).startsWith('Refresh finished')).length
    renderHookWithClient(() => useRefreshWatcher('dev'))
    await new Promise(r => setTimeout(r, 20))
    expect(spy.mock.calls.filter(c => String(c[0].title).startsWith('Refresh finished')).length).toBe(count)
  })
})
