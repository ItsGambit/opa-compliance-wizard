import { useEffect, useMemo, useState } from 'react'
import { useInfiniteQuery } from '@tanstack/react-query'
import { RefreshCw, Search } from 'lucide-react'
import { backfillMfaLogEvents, fetchAuditLog } from '../api/client'
import { toast } from '../hooks/useToast'
import { AuditLogShiftedError, fetchAuditPage, nextAuditPageParam, type AuditPageParam } from '../utils/auditPaging'
import { cellValue, formatDateTime, labelize } from '../utils/format'
import { HighlightedText, useFuzzyFilter } from '../utils/fuzzySearch'

/** Every write action across every environment and user, admin-only, for
 * compliance visibility -- a full page (was a modal popup, AuditLogDialog)
 * per explicit user feedback that this deserves the same real-page
 * treatment as Compliance Reports, plus real field-by-field rendering
 * (was a raw <pre>{JSON.stringify(details)}</pre> blob) closer to how
 * Okta's own System Log presents an event. client_ip/user_agent are new
 * fields captured as of 2026-09-30 (see create_secret_folders.py's
 * log_audit_event) -- shown as "—" on any entry written before that
 * change, since neither was ever captured for those. */
export function AuditLogPage() {
  const [query, setQuery] = useState('')
  // UI-13: Refresh first runs the MFA backfill (Okta lookups) -- guarded
  // by its own flag so repeated clicks can't queue several of them.
  const [refreshing, setRefreshing] = useState(false)

  // UI-13 (external review, 2026-10-05): "Load more" used to change the
  // query key (limit 50 -> 100 -> ...), so the whole list blanked to
  // "Loading…" and re-downloaded every earlier entry. Pages of PAGE_SIZE by
  // offset instead (the API supports it); a refetch re-reads every loaded
  // page in order (TanStack infinite-query behaviour).
  // Each older page must line up with the last entry shown (see
  // utils/auditPaging): if new activity shifted the log, the list is
  // refetched from the newest entry instead of showing duplicates/gaps.
  const { data, isLoading, isFetching, isFetchingNextPage, isError, error, refetch, fetchNextPage, hasNextPage } = useInfiniteQuery({
    queryKey: ['audit_log'],
    queryFn: ({ pageParam }) => fetchAuditPage(pageParam, fetchAuditLog),
    initialPageParam: { offset: 0, anchor: null } as AuditPageParam,
    getNextPageParam: nextAuditPageParam,
    refetchOnReconnect: false,
  })

  // A shift (new activity while paging) is answered by one reload from
  // the newest entry; the toast says what actually happened.
  const reloadAfterShift = async () => {
    const reloaded = await refetch()
    if (reloaded.error) {
      toast({ title: 'Could not reload the audit log', description: reloaded.error.message, variant: 'error' })
      return false
    }
    toast({ title: 'The audit log changed while loading', description: 'New activity arrived, so the list was reloaded from the newest entry. Use "Load more" again to go further back.', variant: 'default' })
    return true
  }

  const loadMore = async () => {
    const result = await fetchNextPage()
    if (result.error instanceof AuditLogShiftedError) await reloadAfterShift()
  }
  const entries = useMemo(() => (data?.pages ?? []).flatMap(p => p.entries), [data])

  // A failed fetch (network blip, expired session, a 403 if admin status
  // lapsed mid-session) previously left the page showing whatever it last
  // successfully loaded with ZERO indication anything went wrong -- the
  // Refresh button's spinner would stop and nothing else would happen,
  // which is indistinguishable from "the button doesn't do anything."
  // Surface it the same way every mutation in this app already does.
  useEffect(() => {
    if (isError && !(error instanceof AuditLogShiftedError)) {
      toast({ title: 'Could not refresh audit log', description: (error as Error)?.message, variant: 'error' })
    }
  }, [isError, error])

  // Same gap on the SUCCESS side, reported directly by the user: clicking
  // Refresh when there's genuinely nothing new looks identical to the
  // button doing nothing at all -- no visible change, no message either
  // way. This only fires for an explicit click (not the initial mount
  // fetch, which has nothing to "compare" against yet), and always says
  // something -- either how many new entries arrived or that there
  // weren't any -- so every outcome of clicking Refresh is visible.
  //
  // Also triggers a backfill attempt for any access_control.update entry
  // still missing Okta MFA corroboration (see engine.backfill_mfa_log_events)
  // BEFORE re-fetching, so a late-indexed Okta event shows up in the same
  // click rather than requiring a separate action -- directly requested:
  // "when refresh is pressed it goes out and looks for items it needs from
  // Okta logs... deltas from system log lag is also captured." A failure
  // here is swallowed, not surfaced as an error -- it's a best-effort
  // enhancement to the refresh, not the refresh's own success/failure.
  const handleRefresh = async () => {
    if (refreshing) return
    setRefreshing(true)
    try {
      await doRefresh()
    } finally {
      setRefreshing(false)
    }
  }

  const doRefresh = async () => {
    const previousTopTimestamp = entries[0]?.timestamp
    const previousTopAction = entries[0]?.action
    let backfillBusy = false
    const backfill = await backfillMfaLogEvents().catch((err: Error & { body?: { reason?: string } }) => {
      // 409 reason=busy (5.40.3): another Refresh's MFA lookups are still running.
      backfillBusy = err.body?.reason === 'busy'
      return null
    })
    const result = await refetch()
    if (result.error) {
      // Activity landed between the pages of this refresh: reload once
      // more and say so; any other error is reported by the effect above.
      if (result.error instanceof AuditLogShiftedError) await reloadAfterShift()
      return
    }
    const freshEntries = result.data?.pages[0]?.entries ?? []
    const isNew = freshEntries[0] && (freshEntries[0].timestamp !== previousTopTimestamp || freshEntries[0].action !== previousTopAction)
    const backfillNote = backfill && backfill.updated_count > 0
      ? ` Found Okta MFA corroboration for ${backfill.updated_count} earlier ${backfill.updated_count === 1 ? 'entry' : 'entries'}.`
      : backfillBusy ? ' (MFA corroboration lookups from another refresh are still running.)' : ''
    toast({
      title: 'Audit log refreshed',
      description: (isNew ? 'New activity loaded.' : 'No new entries since last refresh.') + backfillNote,
      variant: 'default',
    })
  }

  // Fuzzy-matches action/actor/client_ip/user_agent AND every value inside
  // `details` (flattened to a real searchable field, _detailsText, since
  // useFuzzyFilter needs an actual property on each item -- not just a
  // key name) -- same useFuzzyFilter/HighlightedText infrastructure every
  // other list/table in this app already uses, per the standing
  // "implement globally, not per-view" rule.
  const searchableEntries = useMemo(
    () => entries.map((entry, position) => ({ ...entry, _position: position, _detailsText: Object.values(entry.details ?? {}).map(v => cellValue(v)).join(' ') })),
    [entries]
  )
  const results = useFuzzyFilter(searchableEntries, query, ['action', 'actor_email', 'actor_sub', 'client_ip', 'user_agent', '_detailsText'])

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1.5 text-input min-w-72">
          <Search size={13} className="text-text-faint shrink-0" aria-hidden="true" />
          <input
            type="text"
            aria-label="Search the loaded audit log entries"
            placeholder="Search action, actor, IP, details…"
            value={query}
            onChange={e => setQuery(e.target.value)}
            className="flex-1 bg-transparent outline-none placeholder:text-text-faint"
          />
        </div>
        <button type="button" className="btn-secondary text-xs" onClick={handleRefresh} disabled={isFetching || refreshing}>
          <RefreshCw size={12} aria-hidden="true" className={isFetching || refreshing ? 'animate-spin' : ''} /> Refresh
        </button>
      </div>

      {/* UI-13: the search runs over what is loaded, and says so. */}
      {query.trim() && entries.length > 0 && (
        <div className="text-[0.6875rem] text-text-dim" role="status">
          Searching the {entries.length.toLocaleString()} most recent entries loaded
          {hasNextPage ? ' — use "Load more" below to search further back.' : ' (the whole log).'}
        </div>
      )}

      {isError && !(error instanceof AuditLogShiftedError) && (
        <div className="card p-3 text-sm text-loss">
          Could not load the audit log: {(error as Error)?.message ?? 'unknown error'}. What's shown
          below (if anything) may be stale — click Refresh to try again.
        </div>
      )}

      {isLoading ? (
        <div className="text-xs text-text-faint py-6 text-center">Loading…</div>
      ) : entries.length === 0 ? (
        <div className="text-xs text-text-faint py-6 text-center">No audit log entries yet.</div>
      ) : results.length === 0 ? (
        <div className="text-xs text-text-faint py-6 text-center">No entries match "{query}".</div>
      ) : (
        <div className="flex flex-col gap-2">
          {results.map(({ item: entry, matches }) => {
            const actionMatch = matches.find(m => m.key === 'action')
            const actor = entry.actor_email ?? entry.actor_sub ?? null
            const detailEntries = Object.entries(entry.details ?? {})
            // Deploy events (deploy.started/.completed/.failed, logged by
            // server/deploy.sh directly via engine.log_audit_event, same
            // file/locking every other write action already uses) have no
            // logged-in actor at all -- "local / CLI" would be misleading
            // here, since this is a server-side script, not someone using
            // the dashboard. Visually distinct (left border + tinted action
            // text) so a deploy is scannable at a glance in a feed otherwise
            // dominated by user actions. deploy.failed specifically uses
            // this app's existing text-loss/red error convention (same as
            // every other failure state), NOT the neutral accent color the
            // other two deploy.* actions get -- a failed deploy is a real
            // problem, not just "a different shape of event."
            const isDeployEvent = entry.action.startsWith('deploy.')
            const isDeployFailure = entry.action === 'deploy.failed'
            const deployBorderColor = isDeployFailure ? 'border-l-loss' : 'border-l-accent'
            const deployTextColor = isDeployFailure ? 'text-loss' : 'text-accent'
            return (
              <div
                // UI-13: timestamp+action collided for entries written in the
                // same second; the entry's position in the loaded log is
                // unique (and stable across Load more, which only appends).
                key={`${entry._position}-${entry.timestamp}-${entry.action}`}
                className={`card p-3 text-xs ${isDeployEvent ? `border-l-2 ${deployBorderColor}` : ''}`}
              >
                <div className="flex items-center justify-between gap-2 mb-1.5">
                  <span className={`font-medium ${isDeployEvent ? deployTextColor : 'text-text'}`}>
                    <HighlightedText text={entry.action} indices={actionMatch?.indices} />
                  </span>
                  <span className="text-text-faint whitespace-nowrap">{formatDateTime(entry.timestamp)}</span>
                </div>
                <div className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-[0.6875rem]">
                  <span className="section-label">Actor</span>
                  <span className="text-text-dim">{isDeployEvent ? 'deploy.sh (server)' : actor ?? 'local / CLI'}</span>
                  <span className="section-label">Client IP</span>
                  <span className="text-text-dim">{entry.client_ip ?? '—'}</span>
                  <span className="section-label">User Agent</span>
                  <span className="text-text-dim break-all">{entry.user_agent ?? '—'}</span>
                  {detailEntries.map(([key, value]) => (
                    <FieldRow key={key} label={key} value={value} />
                  ))}
                </div>
              </div>
            )
          })}
        </div>
      )}

      {hasNextPage && (
        <button
          type="button"
          className="btn-secondary self-center text-xs"
          disabled={isFetching}
          onClick={() => { void loadMore() }}
        >
          {isFetchingNextPage ? 'Loading…' : 'Load more'}
        </button>
      )}
    </div>
  )
}

function FieldRow({ label, value }: { label: string; value: unknown }) {
  return (
    <>
      <span className="section-label">{labelize(label)}</span>
      <span className="text-text-dim break-all">{cellValue(value) || '—'}</span>
    </>
  )
}
