import { useEffect, useRef, useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { useAccessBootstrapJob } from '../hooks/useAccessBootstrapJob'
import type { AccessModel } from '../types'
import { BootstrapProgressPanel } from './BootstrapProgressPanel'
import { GroupsTab } from './GroupsTab'
import { PoliciesTab } from './PoliciesTab'
import { ProjectsTab } from './ProjectsTab'
import { ResourceGroupsTab } from './ResourceGroupsTab'
import { TabBar } from './TabBar'
import { UsersTab } from './UsersTab'
import { ExportButtons } from './ExportButtons'
import { accessModelExportSections } from '../utils/exportSections'

const SUB_TABS = [
  { value: 'resource_groups', label: 'Resource Groups' },
  { value: 'projects', label: 'Projects' },
  { value: 'policies', label: 'Policies' },
  { value: 'users', label: 'Users' },
  { value: 'groups', label: 'Groups' },
]

export function AccessExplorer() {
  const [subTab, setSubTab] = useState('resource_groups')
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
      <div className="flex items-center justify-between">
        <TabBar tabs={SUB_TABS} value={subTab} onChange={setSubTab} />
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
      {subTab === 'policies' && <PoliciesTab model={displayedModel} />}
      {subTab === 'users' && <UsersTab model={displayedModel} />}
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
