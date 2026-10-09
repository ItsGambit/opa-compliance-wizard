import type { IntegrityState } from '../hooks/useIntegrityCheck'
import { formatDateTime } from '../utils/format'

/** Plain-language rendering of an evidence-chain check (see
 * audit_store.verify_ingestion_chain for the fields). Never says
 * "verified" for a deep check that had nothing content-sealed to re-read. */
export function IntegrityResultView({ state }: { state: IntegrityState }) {
  if (state.phase === 'idle') return null
  if (state.phase === 'checking') {
    return <div className="text-[0.6875rem] text-text-dim" role="status">{state.deep ? 'Deep check running on the server…' : 'Checking…'}</div>
  }
  if (state.phase === 'error') {
    return <div className="text-[0.6875rem] text-loss" role="alert">Could not run the check: {state.error}</div>
  }
  const r = state.result
  return (
    <div className={`text-[0.6875rem] ${r.valid ? 'text-win' : 'text-loss'}`} role="status">
      {r.valid
        ? r.manifest_count === 0
          ? 'Intact: nothing has been archived yet, so there is no chain to check.'
          : `Intact: ${r.manifest_count.toLocaleString()} ingestion record(s) link up end to end.`
        : `Broken${r.broken_at != null ? ` at record ${r.broken_at}` : ''}: ${r.reason ?? 'unknown reason'}.`}
      {state.deep && r.deep_applicable === false && (
        <span className="block text-text-dim">No record carries a content seal yet (all predate 5.40.4), so there were no sealed events to re-read.</span>
      )}
      {state.deep && r.deep_applicable !== false && r.verified_rows != null && (
        <span className="block text-text-dim">
          Re-read {r.verified_rows.toLocaleString()} sealed event(s)
          {r.unverifiable_rows ? `; ${r.unverifiable_rows.toLocaleString()} non-curated event(s) were already pruned by retention (not a failure)` : ''}.
        </span>
      )}
      {r.checked_at && <span className="block text-text-faint">Checked {formatDateTime(r.checked_at)}</span>}
    </div>
  )
}
