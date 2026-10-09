import type { ReactElement, ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, renderHook } from '@testing-library/react'

/** A QueryClient with no retries and no cache time, for component tests. */
export function testQueryClient(): QueryClient {
  return new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } } })
}

export function wrapperFor(client: QueryClient) {
  return function Wrapper({ children }: { children: ReactNode }) {
    return <QueryClientProvider client={client}>{children}</QueryClientProvider>
  }
}

export function renderWithClient(ui: ReactElement, client: QueryClient = testQueryClient()) {
  return { client, ...render(ui, { wrapper: wrapperFor(client) }) }
}

export function renderHookWithClient<R, P>(hook: (props: P) => R, client: QueryClient = testQueryClient(), initialProps?: P) {
  return { client, ...renderHook(hook, { wrapper: wrapperFor(client), initialProps }) }
}
