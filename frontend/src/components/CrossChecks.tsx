import { useMemo, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { RefreshCw, Search } from 'lucide-react'
import { startOktaCapture } from '../api/client'
import { useCrossChecks, useEnvironments } from '../api/hooks'
import { toast } from '../hooks/useToast'
import type { ApiErrorBody, CrossCheckCard, CrossCheckRow } from '../types'
import { formatDateTime } from '../utils/format'
import { HighlightedText, useFuzzyFilter } from '../utils/fuzzySearch'
import { FLAG_LABEL, crossCheckExportSections, oktaStateText, snapshotLine } from '../utils/oktaAdmins'
import { ExportButtons } from './ExportButtons'
import { StatusBadge } from './StatusBadge'

// Cross-checks (5.50.0): questions only a tool that holds both the Okta side and the OPA side can answer.
// Each card says what it compared and when; its results are candidates for review, never findings.

const FUZZY_KEYS = ['name', 'email', 'okta_login', 'project']

function Tile({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="card px-3 py-2 min-w-24">
      <div className="text-lg font-bold text-text leading-tight">{value}</div>
      <div className="text-[0.625rem] text-text-faint uppercase tracking-wide">{label}</div>
    </div>
  )
}

function C1Card({ card, onRun, running, rosterLoaded }: { card: CrossCheckCard; onRun: () => void; running: boolean; rosterLoaded: boolean }) {
  const [query, setQuery] = useState('')
  const results = useFuzzyFilter(card.rows, query, FUZZY_KEYS)
  const sections = useMemo(() => crossCheckExportSections(card), [card])
  return (
    <section className="card p-3 flex flex-col gap-3" aria-label={card.title}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="max-w-[70ch]">
          <h2 className="text-sm font-semibold text-text"><span className="text-text-faint font-normal">{card.id}</span> {card.title}</h2>
          <p className="text-xs text-text-faint mt-0.5">{card.statement}</p>
        </div>
        <div className="flex items-center gap-2">
          <button type="button" className="btn-secondary" disabled={running || !rosterLoaded} onClick={onRun}
            title={rosterLoaded ? 'Look every OPA principal up in Okta (read-only) and store the result as a snapshot' : 'Open the Access Explorer once so the OPA roster is loaded'}>
            <RefreshCw size={13} className={running ? 'animate-spin' : ''} aria-hidden="true" /> {running ? 'Looking up…' : card.state === 'never_run' ? 'Run lookup' : 'Run again'}
          </button>
          <ExportButtons sections={sections} filenameBase="opa-cross-check-lifecycle" />
        </div>
      </div>

      {!rosterLoaded && (
        <p className="text-xs text-warn">The OPA roster is not loaded in this session. Open the Access Explorer once, then come back to run the lookup.</p>
      )}
      {card.state === 'never_run' && <p className="text-sm text-text-dim">{card.message}</p>}
      {card.state === 'refused' && <p className="text-sm text-loss" role="status">{card.message}</p>}
      {card.state === 'error' && <p className="text-sm text-loss" role="status">{card.message}</p>}

      {card.state === 'ok' && (
        <>
          <div className="flex flex-wrap gap-2">
            <Tile label="Checked" value={card.counts.checked ?? 0} />
            <Tile label="Inactive in Okta" value={card.counts.inactive_in_okta ?? 0} />
            <Tile label="Not found in Okta" value={card.counts.absent_in_okta ?? 0} />
            <Tile label="Not read" value={card.counts.unreadable ?? 0} />
          </div>
          <p className="text-xs text-text-faint">
            Okta looked up {formatDateTime(card.inputs.okta_snapshot?.captured_at)} ({snapshotLine(card.inputs.okta_snapshot)}).
            {(card.inputs.skipped_service_users ?? 0) > 0 && <> {card.inputs.skipped_service_users} OPA service user(s) have no Okta identity and were not looked up.</>}
            {' '}“Inactive” means the Okta user is deprovisioned or suspended. “Not found” means Okta has no such user. These people may still
            have OPA access through their groups; check the Access Explorer Users view.
          </p>
          {card.message && <p className="text-xs text-warn" role="status">{card.message}</p>}
          {card.rows.length === 0 ? (
            <span className="text-sm text-text-dim">Every OPA principal that was looked up is active in Okta.</span>
          ) : (
            <>
              <div className="relative max-w-sm">
                <Search size={13} aria-hidden="true" className="absolute left-2 top-1/2 -translate-y-1/2 text-text-faint" />
                <input type="text" aria-label="Search the results" value={query} onChange={e => setQuery(e.target.value)}
                  placeholder="Name, e-mail, project…" className="text-input pl-7 w-full" />
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left text-xs text-text-faint border-b border-border">
                      <th className="px-2 py-1 font-medium">OPA principal</th>
                      <th className="px-2 py-1 font-medium">Type</th>
                      <th className="px-2 py-1 font-medium">Okta says</th>
                      <th className="px-2 py-1 font-medium">OPA roles</th>
                    </tr>
                  </thead>
                  <tbody>
                    {results.map(({ item: r, matches }, i) => (
                      <tr key={`${r.source}:${r.opa_id}:${i}`} className="border-b border-border/50 align-top">
                        <td className="px-2 py-1">
                          <div className="text-text-dim"><HighlightedText text={r.name ?? r.opa_id ?? ''} indices={matches.find(m => m.key === 'name')?.indices} /></div>
                          {r.email && r.email !== r.name && <div className="text-xs text-text-faint">{r.email}</div>}
                          {r.project && <div className="text-xs text-text-faint">Project {r.project}</div>}
                        </td>
                        <td className="px-2 py-1 text-text-dim">{r.source === 'opa_user' ? 'OPA user' : 'Okta service account'}</td>
                        <td className="px-2 py-1">
                          <StatusBadge label={FLAG_LABEL[r.flag as CrossCheckRow['flag']]} variant={r.flag === 'unknown' ? 'unknown' : 'deleted'} />
                          <div className="text-xs text-text-faint">{r.flag === 'absent' && r.absent_text ? r.absent_text : oktaStateText(r.okta_state)}</div>
                        </td>
                        <td className="px-2 py-1 text-xs">
                          {r.opa_powerful_roles.length > 0 && <div className="text-warn">{r.opa_powerful_roles.join(', ')}</div>}
                          {r.opa_roles.filter(x => !r.opa_powerful_roles.includes(x)).length > 0 && <div className="text-text-faint">{r.opa_roles.filter(x => !r.opa_powerful_roles.includes(x)).join(', ')}</div>}
                          {r.opa_roles.length === 0 && <span className="text-text-faint">—</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {query && results.length === 0 && <span className="text-xs text-text-faint">No results match “{query}”.</span>}
            </>
          )}
        </>
      )}
    </section>
  )
}

export function CrossChecks() {
  const { data: environments } = useEnvironments()
  const environment = environments?.active ?? undefined
  const queryClient = useQueryClient()
  const { data, isLoading, isError, error } = useCrossChecks(environment)
  const [starting, setStarting] = useState(false)
  const running = starting || data?.capture?.status === 'running'

  const run = async () => {
    if (!environment) return
    setStarting(true)
    try {
      await startOktaCapture(environment, 'opa_principal_status')
      await queryClient.invalidateQueries({ queryKey: ['cross_checks', environment] })
    } catch (e) {
      const body = (e as Error & { body?: ApiErrorBody }).body
      toast({ title: 'Could not start the lookup', description: body?.error ?? (e as Error).message, variant: 'error' })
    } finally {
      setStarting(false)
    }
  }

  return (
    <div className="flex flex-col gap-4">
      {isLoading && <span className="text-sm text-text-faint">Loading…</span>}
      {isError && <div className="card p-3 text-sm text-loss">Could not load the cross-checks: {(error as Error).message}</div>}
      {data?.capture?.status === 'error' && data.capture.error && <div className="card p-3 text-sm text-loss" role="status">The last lookup failed: {data.capture.error}</div>}
      {data?.cards.map(card => (
        <C1Card key={card.id} card={card} onRun={run} running={running} rosterLoaded={card.inputs.opa_roster_loaded} />
      ))}
    </div>
  )
}
