import { useState } from 'react'
import { ChevronDown, ChevronUp } from 'lucide-react'
import type { AuditEntry, RevealEntry } from '../types'
import { formatDateTime } from '../utils/format'

// Shared by the Secrets Access Dashboard and the Service Accounts
// Dashboard (5.40.0) -- one implementation of "who, when, which request,
// and did it actually succeed" so the two per-resource compliance views
// can never drift apart in how they render the same AuditEntry shape.
// Extracted verbatim from SecretsAccessDashboard.tsx; the only addition
// is the outcome rendering below, which Secrets entries simply don't
// carry (undefined -> nothing rendered, so that dashboard is unchanged).

/** One audit entry: actor, timestamp, Okta request id, and -- when the
 * entry carries one and it isn't a plain success -- the real outcome,
 * since a service-account create/rotation genuinely ends DEFERRED or
 * FAILURE on real tenants and an entry without that reads as "it
 * happened" when it may not have. */
export function AuditCell({ entry }: { entry: AuditEntry | null | undefined }) {
  if (!entry) return <span className="text-text-faint">—</span>
  const nonSuccess = entry.outcome && entry.outcome !== 'SUCCESS'
  return (
    <span className="text-text-dim">
      {entry.by ?? 'unknown'}
      <span className="text-text-faint"> · {formatDateTime(entry.at)}</span>
      {nonSuccess && (
        <span className="text-loss" title={entry.outcome_reason ?? undefined}> · {entry.outcome}</span>
      )}
      {entry.request_id && (
        <span className="text-text-faint"> · request <code className="text-[0.625rem]">{entry.request_id}</code></span>
      )}
    </span>
  )
}

/** A single most-recent entry, with the rest tucked behind an expand toggle
 * — same interaction PolicyRuleCard's ResourceAccessSummary uses for reveal
 * history, reused for "updated" (AuditEntry[]), "retrieved" (RevealEntry[])
 * and every service-account history column. `renderEntry` lets a caller
 * decorate each line (e.g. a checkout's expiry) without re-implementing
 * the expand/collapse behaviour. */
export function AuditHistoryCell<T extends AuditEntry | RevealEntry>({
  entries,
  renderEntry,
}: {
  entries: T[]
  renderEntry?: (entry: T) => React.ReactNode
}) {
  const [expanded, setExpanded] = useState(false)
  if (entries.length === 0) return <span className="text-text-faint">—</span>

  const render = renderEntry ?? ((entry: T) => <AuditCell entry={entry} />)
  const [latest, ...rest] = entries
  return (
    <span className="inline-flex flex-col gap-0.5">
      <span className="inline-flex items-center gap-1">
        {render(latest)}
        {rest.length > 0 && (
          <button
            type="button"
            onClick={() => setExpanded(e => !e)}
            className="text-text-faint hover:text-text-dim"
            title={expanded ? 'Hide earlier entries' : `Show ${rest.length} earlier entr${rest.length === 1 ? 'y' : 'ies'}`}
          >
            {expanded ? <ChevronUp size={11} /> : <ChevronDown size={11} />}
          </button>
        )}
      </span>
      {expanded &&
        rest.map((entry, i) => (
          <span key={i} className="pl-3">
            {render(entry)}
          </span>
        ))}
    </span>
  )
}
