import { useState } from 'react'
import { useEnvironments, useWhoami } from './api/hooks'
import { AboutDialog } from './components/AboutDialog'
import { AccessExplorer, ACCESS_SUB_TABS } from './components/AccessExplorer'
import { AnnouncementBanner } from './components/AnnouncementBanner'
import { AuditLogPage } from './components/AuditLogPage'
import { BannerSettingsDialog } from './components/BannerSettingsDialog'
import { ComplianceReports } from './components/ComplianceReports'
import { EnvironmentManagerDialog } from './components/EnvironmentManagerDialog'
import { EnvironmentSetup } from './components/EnvironmentSetup'
import { Footer } from './components/Footer'
import { FolderBuilder } from './components/FolderBuilder'
import { SecretsAccessDashboard } from './components/SecretsAccessDashboard'
import { REPORTS_SUB_TABS, SideNav } from './components/SideNav'
import { UserMenu } from './components/UserMenu'

export default function App() {
  const [activeTab, setActiveTab] = useState('reports')
  const [accessSubTab, setAccessSubTab] = useState(ACCESS_SUB_TABS[0].value)
  const [reportsSubTab, setReportsSubTab] = useState(REPORTS_SUB_TABS[0].value)
  const [environmentsOpen, setEnvironmentsOpen] = useState(false)
  const [bannerOpen, setBannerOpen] = useState(false)
  const [aboutOpen, setAboutOpen] = useState(false)
  const { data: environments, isLoading: environmentsLoading } = useEnvironments()
  const { data: whoami } = useWhoami()
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
          reportsSubTab={reportsSubTab}
          onReportsSubTabChange={setReportsSubTab}
          onOpenEnvironments={() => setEnvironmentsOpen(true)}
          isAdmin={whoami?.is_admin}
          onOpenBanner={() => setBannerOpen(true)}
          onOpenAbout={() => setAboutOpen(true)}
        />

        <main className="flex-1 overflow-y-auto px-8 py-6 flex flex-col gap-5">
          <header className="flex items-start justify-between">
            <div>
              <h1 className="text-lg font-semibold text-text">
                {activeTab === 'reports' && reportsSubTab === 'browse' && 'Compliance Reports'}
                {activeTab === 'reports' && reportsSubTab === 'secrets_access' && 'Secrets Access Dashboard'}
                {activeTab === 'access' && 'Access Explorer'}
                {activeTab === 'builder' && 'Folder Builder'}
                {activeTab === 'audit_log' && 'Audit Log'}
              </h1>
              <p className="text-xs text-text-faint mt-1">
                {activeTab === 'reports' && reportsSubTab === 'browse' &&
                  'SOC 2 / SOX / ISO 27001 evidence, generated from OPA + core Okta audit history.'}
                {activeTab === 'reports' && reportsSubTab === 'secrets_access' &&
                  'See who created, updated, retrieved, or deleted each secret and folder in a resource group/project.'}
                {activeTab === 'access' &&
                  'Explore who has access to what, across resource groups, projects, policies, users, and groups.'}
                {activeTab === 'builder' &&
                  'Pick or create a resource group and project, build the folder tree, then preview and create.'}
                {activeTab === 'audit_log' &&
                  'Every write action across every environment and user — admin-only, for compliance visibility.'}
              </p>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-xs text-text-faint">
                Connected: <span className="text-text-dim font-medium">{environments?.active}</span>
              </span>
              <UserMenu />
            </div>
          </header>

          {activeTab === 'reports' && reportsSubTab === 'browse' && <ComplianceReports />}
          {activeTab === 'reports' && reportsSubTab === 'secrets_access' && <SecretsAccessDashboard />}
          {activeTab === 'access' && <AccessExplorer subTab={accessSubTab} />}
          {activeTab === 'builder' && <FolderBuilder />}
          {activeTab === 'audit_log' && whoami?.is_admin && <AuditLogPage />}

          <Footer />
        </main>
      </div>

      <EnvironmentManagerDialog
        data={environments}
        open={environmentsOpen}
        onOpenChange={setEnvironmentsOpen}
        isAdmin={whoami?.is_admin}
      />
      <BannerSettingsDialog open={bannerOpen} onOpenChange={setBannerOpen} />
      <AboutDialog open={aboutOpen} onOpenChange={setAboutOpen} />
    </div>
  )
}
