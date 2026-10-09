import { QueryClient } from '@tanstack/react-query'
import { ApiError, SessionExpiredError } from './client'

/** FE-07 (external review, 2026-10-05): the default QueryClient retried
 * every failure three times (TanStack's client default) -- a 403/404/409
 * that can never succeed was sent four times and the user waited ~7 s for
 * the message, and a 502 caused by Okta/OPA rate limiting got three more
 * calls at the worst moment. Retry only what may be transient: a network
 * failure (no response at all) or a 5xx other than 501, at most twice.
 * failureCount starts at 0 for the first retry (TanStack docs). */
export function shouldRetry(failureCount: number, error: unknown): boolean {
  if (failureCount >= 2) return false
  if (error instanceof SessionExpiredError) return false
  if (error instanceof ApiError) return error.status >= 500 && error.status !== 501
  // fetch() rejects with a TypeError when no response arrived at all.
  return error instanceof TypeError
}

/** Shared app defaults. Window-focus refetch is OFF: every alt-tab used to
 * re-run live Okta/OPA walks (secrets report, user access lookups, policy
 * lists). Views have explicit Refresh / Sync now controls, and the banner
 * opts back in (useBanner) because it is meant to change while the page is
 * open. A short staleTime stops a remount (tab switch) from re-fetching
 * what was just loaded. Mutations keep TanStack's default of no retry. */
export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: shouldRetry,
        refetchOnWindowFocus: false,
        staleTime: 30_000,
      },
    },
  })
}

/** Query keys that do NOT depend on the active environment -- everything
 * else is tenant data and is dropped when the active environment changes
 * (UI-05). */
export const GLOBAL_QUERY_KEYS = new Set(['whoami', 'version', 'banner', 'environments', 'csv_files', 'access_control', 'audit_log', 'orphaned_archives'])

export function removeEnvironmentScopedQueries(queryClient: QueryClient): void {
  queryClient.removeQueries({ predicate: q => !GLOBAL_QUERY_KEYS.has(String(q.queryKey[0])) })
}

/** Every view that reads the compliance archive -- refreshed when a sync
 * finishes (shared by the Footer's and the sync dialog's "Sync now"). */
export function invalidateArchiveQueries(queryClient: QueryClient): void {
  for (const key of ['report', 'report_defs', 'resource_history', 'secrets_access_report', 'service_accounts_report', 'sync_status']) {
    queryClient.invalidateQueries({ queryKey: [key] })
  }
}
