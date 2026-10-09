/** The environment list refetches on focus (another tab may have switched
 * the shared server session) even though other queries don't. */
import { describe, expect, it, vi } from 'vitest'
import { renderHookWithClient } from '../test/renderWithClient'
import { createQueryClient } from './queryClient'
import { useEnvironments } from './hooks'

vi.mock('./client', async importOriginal => ({ ...(await importOriginal<typeof import('./client')>()), fetchEnvironments: vi.fn().mockResolvedValue({ environments: [], active: null }) }))

describe('useEnvironments', () => {
  it('opts into window-focus refetching with no stale time', () => {
    const { result, client } = renderHookWithClient(() => useEnvironments(), createQueryClient())
    const q = client.getQueryCache().find({ queryKey: ['environments'] })!
    const observer = q.observers[0]
    expect(observer.options.refetchOnWindowFocus).toBe(true)
    expect(observer.options.staleTime).toBe(0)
    expect(result.current).toBeTruthy()
  })
})
