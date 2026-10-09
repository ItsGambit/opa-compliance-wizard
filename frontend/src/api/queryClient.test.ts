/** FE-07 / UI-05: query defaults and the environment-scope reset. */
import { describe, expect, it } from 'vitest'
import { ApiError, SessionExpiredError } from './client'
import { createQueryClient, removeEnvironmentScopedQueries, shouldRetry } from './queryClient'

describe('shouldRetry', () => {
  it('never retries a 4xx that cannot succeed', () => {
    for (const status of [400, 403, 404, 409]) expect(shouldRetry(0, new ApiError('x', status))).toBe(false)
  })
  it('retries 5xx and network failures at most twice', () => {
    expect(shouldRetry(0, new ApiError('x', 502))).toBe(true)
    expect(shouldRetry(1, new TypeError('Failed to fetch'))).toBe(true)
    expect(shouldRetry(2, new ApiError('x', 502))).toBe(false)
  })
  it('never retries an expired session or a 501', () => {
    expect(shouldRetry(0, new SessionExpiredError())).toBe(false)
    expect(shouldRetry(0, new ApiError('x', 501))).toBe(false)
  })
})

describe('createQueryClient', () => {
  it('turns window-focus refetching off by default', () => {
    expect(createQueryClient().getDefaultOptions().queries?.refetchOnWindowFocus).toBe(false)
  })
})

describe('removeEnvironmentScopedQueries', () => {
  it('drops tenant data but keeps identity, version, banner and the environment list', () => {
    const qc = createQueryClient()
    for (const key of ['whoami', 'version', 'banner', 'environments', 'groups', 'report', 'secrets_access_report', 'user_resource_access']) {
      qc.setQueryData([key], { x: 1 })
    }
    removeEnvironmentScopedQueries(qc)
    const left = qc.getQueryCache().getAll().map(q => q.queryKey[0]).sort()
    expect(left).toEqual(['banner', 'environments', 'version', 'whoami'])
  })
})
