import { useState } from 'react'
import { useEnvironments } from './api/hooks'
import { AboutDialog } from './components/AboutDialog'
import { AccessExplorer } from './components/AccessExplorer'
import { AnnouncementBanner } from './components/AnnouncementBanner'
import { BannerSettingsDialog } from './components/BannerSettingsDialog'
import { EnvironmentManagerDialog } from './components/EnvironmentManagerDialog'
import { EnvironmentSetup } from './components/EnvironmentSetup'
import { Footer } from './components/Footer'
import { FolderBuilder } from './components/FolderBuilder'
import { SecretsAccessDashboard } from './components/SecretsAccessDashboard'
import { TabBar } from './components/TabBar'
import { UserMenu } from './components/UserMenu'

const TABS = [
  { value: 'builder', label: 'Folder Builder' },
  { value: 'access', label: 'Access Explorer' },
  { value: 'secrets_access', label: 'Secrets Access Dashboard' },
]

export default function App() {
  const [activeTab, setActiveTab] = useState('builder')
  const { data: environments, isLoading: environmentsLoading } = useEnvironments()
  const isConfigured = !!environments?.active

  if (environmentsLoading) {
    return (
      <>
        <AnnouncementBanner />
        <div className="px-6 py-16 text-center text-sm text-text-faint">Loading…</div>
      </>
    )
  }

  if (!isConfigured) {
    return (
      <>
        <AnnouncementBanner />
        <div className="px-6 py-8">
          <div className="max-w-4xl mx-auto">
            <EnvironmentSetup />
          </div>
          <Footer />
        </div>
      </>
    )
  }

  return (
    <>
      <AnnouncementBanner />
      <div className="px-6 py-8 flex flex-col gap-5">
        <div className="max-w-4xl mx-auto w-full flex flex-col gap-5">
          <header className="flex items-start justify-between">
            <div>
              <h1 className="text-lg font-semibold text-text">OPA Secrets Wizard</h1>
              <p className="text-xs text-text-faint mt-1">
                {activeTab === 'builder' &&
                  'Pick or create a resource group and project, build the folder tree, then preview and create.'}
                {activeTab === 'access' &&
                  'Explore who has access to what, across resource groups, projects, policies, users, and groups.'}
                {activeTab === 'secrets_access' &&
                  'See who created, updated, retrieved, or deleted each secret and folder in a resource group/project.'}
              </p>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-xs text-text-faint">
                Connected: <span className="text-text-dim font-medium">{environments?.active}</span>
              </span>
              <UserMenu />
              <div className="flex items-center gap-2">
                <BannerSettingsDialog />
                <AboutDialog />
                <EnvironmentManagerDialog data={environments} />
              </div>
            </div>
          </header>

          <TabBar tabs={TABS} value={activeTab} onChange={setActiveTab} />
        </div>

        {activeTab === 'builder' && (
          <div className="max-w-4xl mx-auto w-full">
            <FolderBuilder />
          </div>
        )}
        {activeTab === 'access' && (
          <div className="max-w-6xl mx-auto w-full">
            <AccessExplorer />
          </div>
        )}
        {activeTab === 'secrets_access' && (
          <div className="max-w-6xl mx-auto w-full">
            <SecretsAccessDashboard />
          </div>
        )}

        <Footer />
      </div>
    </>
  )
}
