import { useEffect, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useEnvironments, useWhoami } from './api/hooks'
import { isSessionExpiredError, saveAccessControl, saveEnvironmentChange, type ApiError } from './api/client'
import { useHashRoute } from './hooks/useHashRoute'
import { toast } from './hooks/useToast'
import { AboutDialog } from './components/AboutDialog'
import { AccessControlDialog } from './components/AccessControlDialog'
import { AccessExplorer, ACCESS_SUB_TABS } from './components/AccessExplorer'
import { AccessModelProvider } from './components/AccessModelProvider'
import { AnnouncementBanner } from './components/AnnouncementBanner'
import { AuditLogPage } from './components/AuditLogPage'
import { BannerSettingsDialog } from './components/BannerSettingsDialog'
import { ComplianceReports } from './components/ComplianceReports'
import { EnvironmentManagerDialog } from './components/EnvironmentManagerDialog'
import { EnvironmentScope } from './components/EnvironmentScope'
import { EnvironmentSetup } from './components/EnvironmentSetup'
import { Footer } from './components/Footer'
import { FolderBuilder } from './components/FolderBuilder'
import { OrphanedArchivesDialog } from './components/OrphanedArchivesDialog'
import { SecretsAccessDashboard } from './components/SecretsAccessDashboard'
import { ServiceAccountsDashboard } from './components/ServiceAccountsDashboard'
import { REPORTS_SUB_TABS, SideNav } from './components/SideNav'
import { UserMenu } from './components/UserMenu'
import { environmentScopeKey } from './utils/environmentRows'
import { canAdminFrom } from './utils/whoami'
import { SharedPermissionsDialog } from './components/SharedPermissionsDialog'
import { SharedEnvironmentNotice } from './components/SharedEnvironmentNotice'
import { clearPendingStepUp, readPendingStepUp, stepUpReturnAction, type PendingStepUp } from './utils/stepUp'

// Every navigable view is a hash route (see utils/route.ts) so the browser
// keeps a history entry per in-app navigation -- the mouse back button on
// a compliance report returns to the reports home, not out of the app.
const ROUTE_VOCAB = {
  tabs: ['reports', 'access', 'builder', 'audit_log'],
  reportsSubTabs: REPORTS_SUB_TABS.map(t => t.value),
  accessSubTabs: ACCESS_SUB_TABS.map(t => t.value),
}

export default function App() {
  const { route, navigate } = useHashRoute(ROUTE_VOCAB)
  const { tab: activeTab, accessSubTab, reportsSubTab } = route
  const setActiveTab = (tab: string) => navigate({ tab })
  const setAccessSubTab = (accessSubTab: string) => navigate({ tab: 'access', accessSubTab })
  const setReportsSubTab = (reportsSubTab: string) => navigate({ tab: 'reports', reportsSubTab })
  const [environmentsOpen, setEnvironmentsOpen] = useState(false)
  const [bannerOpen, setBannerOpen] = useState(false)
  const [accessControlOpen, setAccessControlOpen] = useState(false)
  const [aboutOpen, setAboutOpen] = useState(false)
  const [orphansOpen, setOrphansOpen] = useState(false)
  const [sharedPermissionsOpen, setSharedPermissionsOpen] = useState(false)
  // 5.42.0: an Environments change whose step-up approval didn't complete --
  // its screen reopens with the user's input (see utils/stepUp.ts).
  const [restore, setRestore] = useState<Extract<PendingStepUp, { kind: 'environment_change' }> | null>(null)
  const { data: environments, isLoading: environmentsLoading } = useEnvironments()
  const { data: whoami } = useWhoami()
  // UI-06: the Audit Log and banner settings follow what the server will
  // actually serve this caller (verified admin, or a local-mode operator).
  const canAdmin = canAdminFrom(whoami)
  const isConfigured = !!environments?.active
  const queryClient = useQueryClient()

  // UI-05: the content below is scoped to the active tenant (see
  // EnvironmentScope) -- its id plus the connection fields, so a
  // "Save & Reconnect" to a different team/org also resets it.
  const scopeKey = environmentScopeKey(environments)

  // Completes the Access Control save flow after the browser comes back
  // from Okta's step-up (fresh MFA) redirect -- see
  // AccessControlDialog.tsx's Save button, which already validated and
  // stored the pending settings server-side (POST /api/access_control/
  // prepare) before navigating away. This finalize call takes no payload
  // of its own (Phase 3): the server retrieves the exact reviewed values
  // via the action_id bound into the step-up cookie itself, never
  // anything this component could supply. Runs once per completed
  // step-up, not on every render -- the effect strips the query param
  // immediately, so a page refresh afterward can't accidentally replay it.
  const finishStepUpMutation = useMutation({
    mutationFn: () => saveAccessControl(),
    onSuccess: ({ saved_at }) => {
      // Phase 10: confirms Phase 3's new guarantee is legible to the
      // admin who just relied on it -- the save was approved via a
      // validated step-up MFA transaction bound to this exact change,
      // not just "a save happened" the same way a generic toast would
      // read regardless of whether that protection existed at all.
      toast({
        title: 'Access control settings saved',
        description: `Approved via step-up MFA at ${new Date(saved_at).toLocaleString()}`,
        variant: 'success',
      })
      queryClient.invalidateQueries({ queryKey: ['access_control'] })
    },
    onError: (err: Error & { body?: { reason?: string } }) => {
      // FE-11: say what to do, not just what broke -- the step-up proof
      // lasts two minutes and is single-use.
      const expired: boolean = isSessionExpiredError(err as unknown)
      const reason = err.body?.reason
      toast({
        title: 'Could not save access control settings',
        description: expired || reason === 'expired'
          ? 'The step-up sign-in expired before the save finished. Open Access control and save again.'
          : reason === 'already_consumed' || reason === 'not_found'
            ? 'This change was already applied or abandoned. Open Access control to check the current settings.'
            : err.message,
        variant: 'error',
      })
    },
  })

  // 5.42.0: the same finish step for an Environments change (create, edit,
  // delete, share, sync settings, CSV import, watermark reset, archive purge,
  // shared permissions) -- the server runs the request it stored before the
  // redirect. On failure the screen reopens with the user's input.
  const finishEnvironmentChange = useMutation({
    mutationFn: (_pending: Extract<PendingStepUp, { kind: 'environment_change' }>) => saveEnvironmentChange(),
    onSuccess: (resp, pending) => {
      clearPendingStepUp()
      const active = typeof resp.active === 'string' ? resp.active : null
      toast({
        title: resp.activated && active ? `Connected to '${active}'` : `${pending.label}: done`,
        description: 'Approved via step-up MFA.',
        variant: 'success',
      })
      for (const key of ['environments', 'shared_permissions', 'orphaned_archives', 'audit_log', 'sync_status']) {
        queryClient.invalidateQueries({ queryKey: [key] })
      }
    },
    onError: (err: ApiError, pending) => {
      clearPendingStepUp()
      const reason = err.body?.reason
      if (err.body?.saved) {
        // The environment WAS saved (502 "Saved, but could not connect").
        queryClient.invalidateQueries({ queryKey: ['environments'] })
        toast({ title: 'Saved, but could not connect', description: err.message, variant: 'error' })
        return
      }
      setRestore(pending)
      toast({
        title: `${pending.label}: not applied`,
        description: isSessionExpiredError(err as unknown) || reason === 'expired'
          ? 'The MFA approval expired before the change was applied. Your input is restored -- try again.'
          : reason === 'already_consumed' || reason === 'not_found'
            ? 'This approval was already used or abandoned. Your input is restored -- check the current state and try again.'
            : reason === 'secrets_expired'
              ? 'The secrets you typed are no longer held by the server (they are never stored). Enter them again and save.'
              : err.message,
        variant: 'error',
      })
    },
  })

  useEffect(() => {
    const url = new URL(window.location.href)
    const returned = url.searchParams.get('stepup_complete') === '1'
    if (returned) {
      url.searchParams.delete('stepup_complete')
      window.history.replaceState({}, '', url.toString())
    }
    const pending = readPendingStepUp(Date.now(), returned)
    const next = stepUpReturnAction(returned, pending)
    if (pending?.kind === 'environment_change') {
      if (next === 'finish_environment_change') {
        finishEnvironmentChange.mutate(pending)
      } else {
        // Back without finishing the MFA step (cancelled at Okta, or the
        // tab was reopened): nothing changed on the server.
        clearPendingStepUp()
        setRestore(pending)
        toast({
          title: `${pending.label}: not applied`,
          description: "The MFA approval wasn't completed, so nothing changed. Your input is restored.",
          variant: 'error',
        })
      }
      return
    }
    if (next !== 'finish_access_control') {
      if (pending?.kind === 'access_control') clearPendingStepUp()  // never came back: nothing to finish
      return
    }
    clearPendingStepUp()
    finishStepUpMutation.mutate()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Reopen the screen a not-applied change came from.
  useEffect(() => {
    if (!restore) return
    if (restore.reopen === 'orphaned_archives') setOrphansOpen(true)
    else if (restore.reopen === 'shared_permissions') setSharedPermissionsOpen(true)
    else setEnvironmentsOpen(true)
  }, [restore])

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
            <EnvironmentSetup draft={restore?.action === 'environment.upsert' ? restore.environmentDraft : undefined} />
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
          canAdmin={canAdmin}
          onOpenBanner={() => setBannerOpen(true)}
          onOpenAccessControl={() => setAccessControlOpen(true)}
          onOpenAbout={() => setAboutOpen(true)}
          onOpenOrphanedArchives={() => setOrphansOpen(true)}
          onOpenSharedPermissions={() => setSharedPermissionsOpen(true)}
        />

        <EnvironmentScope scopeKey={scopeKey}>
        <AccessModelProvider>
        <main className="flex-1 overflow-y-auto px-8 py-6 flex flex-col gap-5">
          <header className="flex items-start justify-between">
            <div>
              <h1 className="text-lg font-semibold text-text">
                {activeTab === 'reports' && reportsSubTab === 'browse' && 'Compliance Reports'}
                {activeTab === 'reports' && reportsSubTab === 'secrets_access' && 'Secrets Access Dashboard'}
                {activeTab === 'reports' && reportsSubTab === 'service_accounts' && 'Service Accounts Dashboard'}
                {activeTab === 'access' && 'Access Explorer'}
                {activeTab === 'builder' && 'Folder Builder'}
                {activeTab === 'audit_log' && 'Audit Log'}
              </h1>
              <p className="text-xs text-text-faint mt-1">
                {activeTab === 'reports' && reportsSubTab === 'browse' &&
                  'Audit evidence for SOC 2 / SOX / ISO 27001 and similar frameworks, generated from OPA + core Okta audit history.'}
                {activeTab === 'reports' && reportsSubTab === 'secrets_access' &&
                  'See who created, updated, retrieved, or deleted each secret and folder in a resource group/project.'}
                {activeTab === 'reports' && reportsSubTab === 'service_accounts' &&
                  'Every SaaS app and Okta service account across the tenant — including ones since deleted — with who created, assigned, revealed, checked out or rotated it, and when.'}
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

          <SharedEnvironmentNotice />

          {activeTab === 'reports' && reportsSubTab === 'browse' && (
            <ComplianceReports selectedReport={route.reportKey} onSelectReport={key => navigate({ tab: 'reports', reportsSubTab: 'browse', reportKey: key })} />
          )}
          {activeTab === 'reports' && reportsSubTab === 'secrets_access' && <SecretsAccessDashboard />}
          {activeTab === 'reports' && reportsSubTab === 'service_accounts' && <ServiceAccountsDashboard />}
          {activeTab === 'access' && <AccessExplorer subTab={accessSubTab} />}
          {activeTab === 'builder' && <FolderBuilder />}
          {activeTab === 'audit_log' && canAdmin && <AuditLogPage />}

          <Footer />
        </main>
        </AccessModelProvider>
        </EnvironmentScope>
      </div>

      <EnvironmentManagerDialog
        data={environments}
        open={environmentsOpen}
        onOpenChange={next => { setEnvironmentsOpen(next); if (!next) setRestore(null) }}
        isAdmin={whoami?.is_admin}
        canAdmin={canAdmin}
        restore={restore && restore.reopen !== 'orphaned_archives' && restore.reopen !== 'shared_permissions' ? restore : null}
      />
      {canAdmin && <OrphanedArchivesDialog open={orphansOpen} onOpenChange={next => { setOrphansOpen(next); if (!next) setRestore(null) }} />}
      {canAdmin && (
        <SharedPermissionsDialog
          open={sharedPermissionsOpen}
          onOpenChange={next => { setSharedPermissionsOpen(next); if (!next) setRestore(null) }}
          draft={restore?.permissionsDraft && !restore.permissionsDraft.environmentId ? restore.permissionsDraft.settings : undefined}
        />
      )}
      <BannerSettingsDialog open={bannerOpen} onOpenChange={setBannerOpen} />
      <AccessControlDialog open={accessControlOpen} onOpenChange={setAccessControlOpen} />
      <AboutDialog open={aboutOpen} onOpenChange={setAboutOpen} />
    </div>
  )
}
