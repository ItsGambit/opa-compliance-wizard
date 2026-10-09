import { useEffect, useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { useAccessModel } from '../hooks/useAccessModel'
import { BootstrapProgressPanel } from './BootstrapProgressPanel'
import { GroupsTab } from './GroupsTab'
import { PoliciesTab } from './PoliciesTab'
import { ProjectsTab } from './ProjectsTab'
import { RelationshipsTab } from './RelationshipsTab'
import { ResourceGroupsTab } from './ResourceGroupsTab'
import { ResourcesTab } from './ResourcesTab'
import { UsersTab } from './UsersTab'
import { ExportButtons } from './ExportButtons'
import { accessModelExportSections } from '../utils/exportSections'

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

export function AccessExplorer({ subTab }: Props) {
  // UI-10: model + job live in AccessModelProvider (survives page switches).
  const { job, model: displayedModel, ensureLoaded, refresh, updateModel } = useAccessModel()

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
    return (
      <BootstrapProgressPanel
        phase={job.phase}
        stepDefs={job.stepDefs}
        events={job.events}
        error={job.error}
        onRetry={refresh}
        variant="fullpage"
      />
    )
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-end">
        <div className="flex items-center gap-2">
          <ExportButtons sections={accessModelExportSections(displayedModel)} filenameBase="opa-access-explorer-all" />
          <button type="button" className="btn-secondary shrink-0" onClick={refresh} disabled={isRefreshing}>
            <RefreshCw size={13} className={isRefreshing ? 'animate-spin' : ''} />
            {isRefreshing ? 'Refreshing…' : 'Refresh'}
          </button>
        </div>
      </div>

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
        <UsersTab
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
          variant="bottom"
        />
      )}
    </div>
  )
}
