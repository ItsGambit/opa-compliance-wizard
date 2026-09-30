import { useEffect, useRef, useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { useAccessBootstrapJob } from '../hooks/useAccessBootstrapJob'
import type { AccessModel } from '../types'
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
// (this used to be an internal TabBar rendered inside this component --
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
  const job = useAccessBootstrapJob()
  const startedOnce = useRef(false)
  // The last successfully loaded model stays visible during a refresh
  // (job.result briefly clears while the new job runs) so a Refresh
  // doesn't blank the screen while its own progress panel shows at the
  // bottom.
  const [displayedModel, setDisplayedModel] = useState<AccessModel | null>(null)

  useEffect(() => {
    if (!startedOnce.current) {
      startedOnce.current = true
      job.start()
    }
  }, [job])

  useEffect(() => {
    if (job.phase === 'done' && job.result) setDisplayedModel(job.result)
  }, [job.phase, job.result])

  const isRefreshing = displayedModel !== null && job.phase !== 'done'

  if (!displayedModel) {
    return (
      <BootstrapProgressPanel
        phase={job.phase}
        stepDefs={job.stepDefs}
        events={job.events}
        error={job.error}
        onRetry={job.start}
        variant="fullpage"
      />
    )
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-end">
        <div className="flex items-center gap-2">
          <ExportButtons sections={accessModelExportSections(displayedModel)} filenameBase="opa-access-explorer-all" />
          <button type="button" className="btn-secondary shrink-0" onClick={job.start} disabled={isRefreshing}>
            <RefreshCw size={13} className={isRefreshing ? 'animate-spin' : ''} />
            {isRefreshing ? 'Refreshing…' : 'Refresh'}
          </button>
        </div>
      </div>

      {subTab === 'resource_groups' && <ResourceGroupsTab model={displayedModel} />}
      {subTab === 'projects' && <ProjectsTab model={displayedModel} />}
      {subTab === 'resources' && <ResourcesTab model={displayedModel} />}
      {subTab === 'policies' && <PoliciesTab model={displayedModel} />}
      {subTab === 'relationships' && <RelationshipsTab model={displayedModel} />}
      {subTab === 'users' && (
        <UsersTab
          model={displayedModel}
          onUserGroupRemoved={(userId, groupId) =>
            setDisplayedModel(prev =>
              prev
                ? {
                    ...prev,
                    users: prev.users.map(u =>
                      u.id === userId ? { ...u, groups: u.groups.filter(g => g.id !== groupId) } : u
                    ),
                  }
                : prev
            )
          }
        />
      )}
      {subTab === 'groups' && <GroupsTab model={displayedModel} />}

      {isRefreshing && (
        <BootstrapProgressPanel
          phase={job.phase}
          stepDefs={job.stepDefs}
          events={job.events}
          error={job.error}
          onRetry={job.start}
          variant="bottom"
        />
      )}
    </div>
  )
}
