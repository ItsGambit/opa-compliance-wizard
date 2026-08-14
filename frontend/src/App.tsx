import { useState } from 'react'
import { useEnvironments } from './api/hooks'
import { AboutDialog } from './components/AboutDialog'
import { AccessExplorer } from './components/AccessExplorer'
import { EnvironmentManagerDialog } from './components/EnvironmentManagerDialog'
import { EnvironmentSetup } from './components/EnvironmentSetup'
import { FolderBuilder } from './components/FolderBuilder'
import { TabBar } from './components/TabBar'

const TABS = [
  { value: 'builder', label: 'Folder Builder' },
  { value: 'access', label: 'Access Explorer' },
]

export default function App() {
  const [activeTab, setActiveTab] = useState('builder')
  const { data: environments, isLoading: environmentsLoading } = useEnvironments()
  const isConfigured = !!environments?.active

  if (environmentsLoading) {
    return <div className="px-6 py-16 text-center text-sm text-text-faint">Loading…</div>
  }

  if (!isConfigured) {
    return (
      <div className="max-w-4xl mx-auto px-6 py-8">
        <EnvironmentSetup />
      </div>
    )
  }

  return (
    <div className="px-6 py-8 flex flex-col gap-5">
      <div className="max-w-4xl mx-auto w-full flex flex-col gap-5">
        <header className="flex items-start justify-between">
          <div>
            <h1 className="text-lg font-semibold text-text">OPA Secrets Wizard</h1>
            <p className="text-xs text-text-faint mt-1">
              {activeTab === 'builder'
                ? 'Pick or create a resource group and project, build the folder tree, then preview and create.'
                : 'Explore who has access to what, across resource groups, projects, policies, users, and groups.'}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs text-text-faint">
              Connected: <span className="text-text-dim font-medium">{environments?.active}</span>
            </span>
            <AboutDialog />
            <EnvironmentManagerDialog data={environments} />
          </div>
        </header>

        <TabBar tabs={TABS} value={activeTab} onChange={setActiveTab} />
      </div>

      {activeTab === 'builder' ? (
        <div className="max-w-4xl mx-auto w-full">
          <FolderBuilder />
        </div>
      ) : (
        <div className="max-w-6xl mx-auto w-full">
          <AccessExplorer />
        </div>
      )}
    </div>
  )
}
