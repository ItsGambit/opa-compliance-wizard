/** FE-05 / FE-07 / FE-15: the fetch wrapper. */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, SessionExpiredError, activateEnvironment, fetchEnvironments, fetchReportCsv, onSessionExpired, saveAccessControl, saveBanner } from './client'

function mockFetch(response: Partial<Response> & { json?: () => Promise<unknown> }) {
  const fn = vi.fn().mockResolvedValue({ ok: false, status: 200, type: 'basic', json: async () => ({}), ...response })
  vi.stubGlobal('fetch', fn)
  return fn
}

afterEach(() => { vi.unstubAllGlobals() })

describe('apiFetch', () => {
  it('asks fetch not to follow redirects', async () => {
    const fetch = mockFetch({ ok: true, json: async () => ({ environments: [], active: null }) })
    await fetchEnvironments()
    expect(fetch.mock.calls[0][1].redirect).toBe('manual')
  })

  it('turns the login gate redirect (opaqueredirect) into one SessionExpiredError and notifies listeners', async () => {
    mockFetch({ type: 'opaqueredirect', status: 0 })
    const listener = vi.fn()
    const off = onSessionExpired(listener)
    await expect(fetchEnvironments()).rejects.toBeInstanceOf(SessionExpiredError)
    expect(listener).toHaveBeenCalledTimes(1)
    off()
    await expect(fetchEnvironments()).rejects.toBeInstanceOf(SessionExpiredError)
    expect(listener).toHaveBeenCalledTimes(1)
  })

  it('treats a bare 401 as an expired session, but shows serve.py\'s own 401 error as an error', async () => {
    mockFetch({ status: 401, json: async () => { throw new Error('no body') } })
    await expect(fetchEnvironments()).rejects.toBeInstanceOf(SessionExpiredError)
    mockFetch({ status: 401, json: async () => ({ error: 'Missing or invalid proxy secret' }) })
    const err = await fetchEnvironments().catch(e => e)
    expect(err).toBeInstanceOf(ApiError)
    expect(err.message).toBe('Missing or invalid proxy secret')
  })

  it('the step-up save reports an expired step-up to its caller without the global sign-in prompt', async () => {
    mockFetch({ type: 'opaqueredirect', status: 0 })
    const listener = vi.fn()
    const off = onSessionExpired(listener)
    await expect(saveAccessControl()).rejects.toBeInstanceOf(SessionExpiredError)
    expect(listener).not.toHaveBeenCalled()
    off()
  })

  it('throws ApiError with the status and server message', async () => {
    mockFetch({ status: 409, json: async () => ({ error: 'busy', reason: 'busy' }) })
    const err = await fetchEnvironments().catch(e => e)
    expect(err).toBeInstanceOf(ApiError)
    expect(err.status).toBe(409)
    expect(err.message).toBe('busy')
    expect(err.body.reason).toBe('busy')
  })

  it('falls back to a generic message for a non-JSON error body', async () => {
    mockFetch({ status: 502, json: async () => { throw new Error('not json') } })
    const err = await fetchEnvironments().catch(e => e)
    expect(err.message).toBe('Request failed with status 502')
  })

  it('sends Content-Type only with a body', async () => {
    const fetch = mockFetch({ ok: true, json: async () => ({}) })
    await fetchEnvironments()
    expect(fetch.mock.calls[0][1].headers['Content-Type']).toBeUndefined()
    await saveBanner({ enabled: false, message: '', variant: 'info', dismissible: true })
    expect(fetch.mock.calls[1][1].headers['Content-Type']).toBe('application/json')
  })

  it('activate sends the row id so the server can refuse a different same-named environment', async () => {
    const fetch = mockFetch({ ok: true, json: async () => ({ activated: true, active: 'dev' }) })
    await activateEnvironment('dev', 'id-1')
    expect(fetch.mock.calls[0][0]).toBe('/api/environments/dev/activate')
    expect(JSON.parse(fetch.mock.calls[0][1].body)).toEqual({ id: 'id-1' })
  })
})

describe('fetchReportCsv (5.53.0)', () => {
  it('asks the report export route for the range, and returns the file and the server row count', async () => {
    const blob = new Blob(['a,b'])
    const fetch = mockFetch({ ok: true, headers: new Headers({ 'X-Report-Rows': '1250' }), blob: async () => blob } as never)
    const out = await fetchReportCsv('my env', 'session_activity', '2026-01-01', '2026-03-31')
    expect(fetch.mock.calls[0][0]).toBe('/api/environments/my%20env/reports/session_activity/export.csv?since=2026-01-01&until=2026-03-31')
    expect(out).toEqual({ blob, rows: 1250 })
  })

  it('throws the server\'s reason, with no file', async () => {
    mockFetch({ ok: false, status: 400, json: async () => ({ error: 'The end date is in the future (dates are UTC)' }) })
    await expect(fetchReportCsv('dev', 'session_activity', '2026-01-01', '2999-01-01')).rejects.toMatchObject({ message: 'The end date is in the future (dates are UTC)', status: 400 })
  })
})
