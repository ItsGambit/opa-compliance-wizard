import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { RefreshCw, Search } from 'lucide-react'
import { fetchAuditLog } from '../api/client'
import { cellValue, formatDateTime, labelize } from '../utils/format'
import { HighlightedText, useFuzzyFilter } from '../utils/fuzzySearch'

const PAGE_SIZE = 50

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
  const [visibleCount, setVisibleCount] = useState(PAGE_SIZE)
  const [query, setQuery] = useState('')

  const { data, isLoading, isFetching, refetch } = useQuery({
    queryKey: ['audit_log', visibleCount],
    queryFn: () => fetchAuditLog(visibleCount, 0),
  })
  const entries = data?.entries ?? []

  // Fuzzy-matches action/actor/client_ip/user_agent AND every value inside
  // `details` (flattened to a real searchable field, _detailsText, since
  // useFuzzyFilter needs an actual property on each item -- not just a
  // key name) -- same useFuzzyFilter/HighlightedText infrastructure every
  // other list/table in this app already uses, per the standing
  // "implement globally, not per-view" rule.
  const searchableEntries = useMemo(
    () => entries.map(entry => ({ ...entry, _detailsText: Object.values(entry.details ?? {}).map(v => cellValue(v)).join(' ') })),
    [entries]
  )
  const results = useFuzzyFilter(searchableEntries, query, ['action', 'actor_email', 'actor_sub', 'client_ip', 'user_agent', '_detailsText'])

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1.5 text-input min-w-72">
          <Search size={13} className="text-text-faint shrink-0" />
          <input
            type="text"
            placeholder="Search action, actor, IP, details…"
            value={query}
            onChange={e => setQuery(e.target.value)}
            className="flex-1 bg-transparent outline-none placeholder:text-text-faint"
          />
        </div>
        <button type="button" className="btn-secondary text-xs" onClick={() => refetch()} disabled={isFetching}>
          <RefreshCw size={12} className={isFetching ? 'animate-spin' : ''} /> Refresh
        </button>
      </div>

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
            return (
              <div key={`${entry.timestamp}-${entry.action}`} className="card p-3 text-xs">
                <div className="flex items-center justify-between gap-2 mb-1.5">
                  <span className="font-medium text-text">
                    <HighlightedText text={entry.action} indices={actionMatch?.indices} />
                  </span>
                  <span className="text-text-faint whitespace-nowrap">{formatDateTime(entry.timestamp)}</span>
                </div>
                <div className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-[0.6875rem]">
                  <span className="section-label">Actor</span>
                  <span className="text-text-dim">{actor ?? 'local / CLI'}</span>
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

      {entries.length >= visibleCount && (
        <button
          type="button"
          className="btn-secondary self-center text-xs"
          disabled={isFetching}
          onClick={() => setVisibleCount(c => c + PAGE_SIZE)}
        >
          Load more
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
