import { useState } from 'react'
import { useEnvironments } from './api/hooks'
import { AboutDialog } from './components/AboutDialog'
import { AccessExplorer, ACCESS_SUB_TABS } from './components/AccessExplorer'
import { AnnouncementBanner } from './components/AnnouncementBanner'
import { BannerSettingsDialog } from './components/BannerSettingsDialog'
import { ComplianceReports } from './components/ComplianceReports'
import { EnvironmentManagerDialog } from './components/EnvironmentManagerDialog'
import { EnvironmentSetup } from './components/EnvironmentSetup'
import { Footer } from './components/Footer'
import { FolderBuilder } from './components/FolderBuilder'
import { SecretsAccessDashboard } from './components/SecretsAccessDashboard'
import { SideNav } from './components/SideNav'
import { UserMenu } from './components/UserMenu'

export default function App() {
  const [activeTab, setActiveTab] = useState('builder')
  const [accessSubTab, setAccessSubTab] = useState(ACCESS_SUB_TABS[0].value)
  const [environmentsOpen, setEnvironmentsOpen] = useState(false)
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
    <div className="flex flex-col h-dvh">
      <AnnouncementBanner />
      <div className="flex flex-1 min-h-0">
        <SideNav
          activeTab={activeTab}
          onTabChange={setActiveTab}
          accessSubTabs={ACCESS_SUB_TABS}
          accessSubTab={accessSubTab}
          onAccessSubTabChange={setAccessSubTab}
          onOpenEnvironments={() => setEnvironmentsOpen(true)}
        />

        <main className="flex-1 overflow-y-auto px-8 py-6 flex flex-col gap-5">
          <header className="flex items-start justify-between">
            <div>
              <h1 className="text-lg font-semibold text-text">
                {activeTab === 'builder' && 'Folder Builder'}
                {activeTab === 'access' && 'Access Explorer'}
                {activeTab === 'reports' && 'Compliance Reports'}
                {activeTab === 'secrets_access' && 'Secrets Access Dashboard'}
              </h1>
              <p className="text-xs text-text-faint mt-1">
                {activeTab === 'builder' &&
                  'Pick or create a resource group and project, build the folder tree, then preview and create.'}
                {activeTab === 'access' &&
                  'Explore who has access to what, across resource groups, projects, policies, users, and groups.'}
                {activeTab === 'reports' &&
                  'SOC 2 / SOX / ISO 27001 evidence, generated from OPA + core Okta audit history.'}
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
                <EnvironmentManagerDialog
                  data={environments}
                  open={environmentsOpen}
                  onOpenChange={setEnvironmentsOpen}
                />
              </div>
            </div>
          </header>

          {activeTab === 'builder' && <FolderBuilder />}
          {activeTab === 'access' && <AccessExplorer subTab={accessSubTab} />}
          {activeTab === 'reports' && <ComplianceReports />}
          {activeTab === 'secrets_access' && <SecretsAccessDashboard />}

          <Footer />
        </main>
      </div>
    </div>
  )
}
