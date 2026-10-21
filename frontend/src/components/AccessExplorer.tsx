import { useEffect, useState } from 'react'
import { Loader2, RefreshCw } from 'lucide-react'
import { useAccessModel } from '../hooks/useAccessModel'
import { BootstrapProgressPanel } from './BootstrapProgressPanel'
import { GroupsTab } from './GroupsTab'
import { PoliciesTab } from './PoliciesTab'
import { ProjectsTab } from './ProjectsTab'
import { RelationshipsTab } from './RelationshipsTab'
import { ResourceGroupsTab } from './ResourceGroupsTab'
import { ResourcesTab } from './ResourcesTab'
import { UsersView } from './UsersView'
import { ExportButtons } from './ExportButtons'
import { accessModelExportSections } from '../utils/exportSections'
import { formatDateTimeZone } from '../utils/format'
import { ageText, scanFreshness, staleBadgeText } from '../utils/refresh'
import { StatusBadge } from './StatusBadge'

// Exported so App.tsx / SideNav can render these as sidebar sub-nav items
// (this used to be an internal tab bar rendered inside this component --
// moved to the sidebar per the Okta-console-style redesign, see the
// "splendid-floating-moth" plan).
export const ACCESS_SUB_TABS = [
  { value: 'resource_groups', label: 'Resource Groups' },
  { value: 'projects', label: 'Projects' },
  { value: 'resources', label: 'Resources' },
  { value: 'policies', label: 'Policies' },
  { value: 'relationships', label: 'Relationships' },
  { value: 'users', label: 'Users' },
  { value: 'groups', label: 'Groups' },
]

interface Props {
  subTab: string
}

const ASOF_HELP_ID = 'access-explorer-asof-help'

/** A clock that ticks once a minute, so "6 h ago" stays true while the page is open. */
function useMinuteClock(): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 60_000)
    return () => clearInterval(id)
  }, [])
  return now
}

export function AccessExplorer({ subTab }: Props) {
  // UI-10: model + job live in AccessModelProvider (survives page switches). 5.51.0: the model is the stored OPA scan.
  const { job, model: displayedModel, meta, loading, loadError, ensureLoaded, refresh, updateModel } = useAccessModel()
  const now = useMinuteClock()

  useEffect(() => { ensureLoaded() }, [ensureLoaded])

  // A refresh is in progress only while the job is actually starting or
  // running -- a FAILED refresh used to keep "Refreshing…" (and a disabled
  // button) on screen until the bottom panel's Retry was found.
  const isRefreshing = displayedModel !== null && (job.phase === 'starting' || job.phase === 'running')
  const refreshFailed = displayedModel !== null && job.phase === 'error'
  // The failed-refresh panel can be dismissed (the previous data stays);
  // any new job phase brings it back.
  const [dismissedFailure, setDismissedFailure] = useState(false)
  useEffect(() => { setDismissedFailure(false) }, [job.phase])

  if (!displayedModel) {
    if (loading) return <div className="card p-6 text-sm text-text-dim text-center" role="status">Opening the stored OPA scan…</div>
    return (
      <BootstrapProgressPanel
        phase={loadError ? 'error' : job.phase}
        stepDefs={job.stepDefs}
        events={job.events}
        error={loadError ?? job.error}
        onRetry={refresh}
        variant="fullpage"
      />
    )
  }

  const builtAt = meta?.built_at ?? null
  const stale = builtAt ? staleBadgeText(builtAt, now) : null
  const freshness = builtAt ? scanFreshness(builtAt, now) : 'unknown'

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <span className="inline-flex items-center gap-2 flex-wrap text-xs text-text-dim px-2.5 py-1.5 border border-border rounded-lg bg-bg-elevated" aria-describedby={ASOF_HELP_ID}>
          {builtAt ? (
            <>
              <span className="text-muted">{isRefreshing ? 'Showing the OPA scan as of' : 'OPA scan as of'}</span> {formatDateTimeZone(builtAt)}
              <span className="text-muted">·</span> {ageText(builtAt, now)}
              {isRefreshing ? <StatusBadge label="Refreshing…" variant="exists" />
                : stale ? <StatusBadge label={stale} variant={freshness === 'very_stale' ? 'error' : 'warn'} />
                : <StatusBadge label="Current" variant="active" />}
              {meta?.modified_at && <StatusBadge label="Edited since the scan" variant="neutral" />}
            </>
          ) : <span>OPA scan</span>}
        </span>
        <span id={ASOF_HELP_ID} className="sr-only">Policies, groups and resources are read from the stored scan. Refresh OPA scan reads OPA again.</span>
        <div className="flex items-center gap-2">
          <ExportButtons sections={accessModelExportSections(displayedModel)} filenameBase="opa-access-explorer-all" />
          <button type="button" className="btn-secondary shrink-0" aria-disabled={isRefreshing} aria-describedby={ASOF_HELP_ID} onClick={() => { if (!isRefreshing) refresh() }}>
            {isRefreshing ? <Loader2 size={13} aria-hidden="true" className="animate-spin" /> : <RefreshCw size={13} aria-hidden="true" />}
            {isRefreshing ? 'Refreshing…' : 'Refresh OPA scan'}
          </button>
        </div>
      </div>
      <p className="text-[0.6875rem] text-muted -mt-2">Policies, groups and resources are read from the stored scan. Live lookups (last accessed, resource evidence) say so where they appear.</p>

      {(displayedModel.warnings?.length ?? 0) > 0 && (
        <div className="card p-3 border-warn/40 text-xs text-warn flex flex-col gap-1" role="status">
          <div className="font-medium">Some sections are incomplete — the service key may not read them, so they are shown empty:</div>
          {displayedModel.warnings!.map((w, i) => (
            <div key={`${i}:${w.section}`}>{w.message}</div>
          ))}
        </div>
      )}

      {subTab === 'resource_groups' && <ResourceGroupsTab model={displayedModel} />}
      {subTab === 'projects' && <ProjectsTab model={displayedModel} />}
      {subTab === 'resources' && <ResourcesTab model={displayedModel} />}
      {subTab === 'policies' && <PoliciesTab model={displayedModel} />}
      {subTab === 'relationships' && <RelationshipsTab model={displayedModel} />}
      {subTab === 'users' && (
        <UsersView
          model={displayedModel}
          onUserGroupRemoved={(userId, groupId) =>
            updateModel(prev => ({
              ...prev,
              users: prev.users.map(u => (u.id === userId ? { ...u, groups: u.groups.filter(g => g.id !== groupId) } : u)),
            }))
          }
        />
      )}
      {subTab === 'groups' && <GroupsTab model={displayedModel} />}

      {(isRefreshing || (refreshFailed && !dismissedFailure)) && (
        <BootstrapProgressPanel
          phase={job.phase}
          stepDefs={job.stepDefs}
          events={job.events}
          error={job.error}
          onRetry={refresh}
          onDismiss={() => setDismissedFailure(true)}
          previousBuiltAt={builtAt}
          variant="bottom"
        />
      )}
    </div>
  )
}
