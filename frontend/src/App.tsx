import { useEffect, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useEnvironments, useUpgradeStatus, useWhoami } from './api/hooks'
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
import { EnvironmentButton } from './components/EnvironmentButton'
import { Footer } from './components/Footer'
import { FolderBuilder } from './components/FolderBuilder'
import { OrphanedArchivesDialog } from './components/OrphanedArchivesDialog'
import { SecretsAccessDashboard } from './components/SecretsAccessDashboard'
import { ServiceAccountsDashboard } from './components/ServiceAccountsDashboard'
import { OktaAdminsReport } from './components/OktaAdminsReport'
import { OverviewPage } from './components/Overview'
import { CrossChecks } from './components/CrossChecks'
import { REPORTS_SUB_TABS, SideNav } from './components/SideNav'
import { UserMenu } from './components/UserMenu'
import { UpgradeNoticeBanner } from './components/UpgradeNoticeBanner'
import { markBundleRequested, rememberRequested } from './utils/upgradeRequested'
import { UpdatesPage, type UpdatesHeader } from './components/UpdatesPage'
import { UpdateKeysPage } from './components/UpdateKeysPage'
import { activeRow, can, environmentScopeKey } from './utils/environmentRows'
import { canAdminFrom } from './utils/whoami'
import { SharedPermissionsDialog } from './components/SharedPermissionsDialog'
import { SharedEnvironmentNotice } from './components/SharedEnvironmentNotice'
import { clearPendingStepUp, readPendingStepUp, stepUpReturnAction, type PendingStepUp } from './utils/stepUp'

// Every navigable view is a hash route (see utils/route.ts) so the browser
// keeps a history entry per in-app navigation -- the mouse back button on
// a compliance report returns to the reports home, not out of the app.
const ROUTE_VOCAB = {
  tabs: ['overview', 'reports', 'access', 'builder', 'audit_log', 'updates', 'update_keys'],
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
  // 5.48.0: the Updates page tells the header what to say in each state (progress, starting) and when it is a full page (confirmation).
  const [updatesHeader, setUpdatesHeader] = useState<UpdatesHeader>({ subtitle: null, fullPage: false })
  // 5.42.0: an Environments change whose step-up approval didn't complete --
  // its screen reopens with the user's input (see utils/stepUp.ts).
  const [restore, setRestore] = useState<Extract<PendingStepUp, { kind: 'environment_change' }> | null>(null)
  const { data: environments, isLoading: environmentsLoading } = useEnvironments()
  const { data: whoami } = useWhoami()
  // UI-06: the Audit Log and banner settings follow what the server will
  // actually serve this caller (verified admin, or a local-mode operator).
  const canAdmin = canAdminFrom(whoami)
  // 5.51.0: archive viewers (view_archive + live_read on the active environment) may open the Overview's counts; the lists of names stay admin-only.
  const activeEnvRow = activeRow(environments)
  const canViewOverview = canAdmin || (!!activeEnvRow && can(activeEnvRow, 'view_archive') && can(activeEnvRow, 'live_read'))
  const isConfigured = !!environments?.active
  const { data: upgradeStatus } = useUpgradeStatus(canAdmin)
  const queryClient = useQueryClient()
  // 5.50.0: the Overview is the home page for administrators; everyone else lands on Compliance Reports.
  useEffect(() => {
    if (whoami && environments && !canViewOverview && activeTab === 'overview') navigate({ tab: 'reports', reportsSubTab: 'browse' })
  }, [whoami, environments, canViewOverview, activeTab, navigate])

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
      if (pending.action === 'upgrade.request') {
        // 5.48.0: an upgrade request the gate just approved (now / schedule / reschedule / cancel / second approval).
        const kind = String(resp.kind ?? '')
        const version = typeof resp.version === 'string' ? resp.version : null
        const OPS: Record<string, string> = { rollback: 'Rollback', restore: 'Restore', clear_failure: 'Clear failure', bundle: 'Support bundle' }
        const label = OPS[kind] ? 'requested' : kind === 'cancel' ? 'cancelled' : resp.awaiting_second_approval ? 'waiting for a second admin'
          : kind === 'schedule' ? 'scheduled' : kind === 'reschedule' ? 'rescheduled' : 'requested'
        if ((kind === 'apply' || kind === 'approve_second') && typeof resp.correlation_id === 'string' && !resp.awaiting_second_approval) {
          rememberRequested({ correlationId: resp.correlation_id, version: version ?? '', approvedAt: new Date().toISOString(), email: whoami?.email ?? null, stepUp: true })
        } else if (['rollback', 'restore', 'clear_failure', 'bundle'].includes(kind) && typeof resp.correlation_id === 'string') {
          rememberRequested({ correlationId: resp.correlation_id, version: '', approvedAt: new Date().toISOString(), email: whoami?.email ?? null, stepUp: true,
            kind: kind as 'rollback' | 'restore' | 'clear_failure' | 'bundle' })
          if (kind === 'bundle') markBundleRequested()
        }
        toast({
          title: OPS[kind] ? `${OPS[kind]}: requested` : kind === 'cancel' ? 'Upgrade request cancelled' : `Upgrade${version ? ` to ${version}` : ''}: ${label}`,
          description: `Approved via step-up MFA at ${new Date().toLocaleString()}.`, variant: 'success',
        })
        setActiveTab('updates')
        for (const key of ['upgrade_status', 'upgrade_notice', 'audit_log']) queryClient.invalidateQueries({ queryKey: [key] })
        return
      }
      const active = typeof resp.active === 'string' ? resp.active : null
      toast({
        title: resp.activated && active ? `Connected to '${active}'` : `${pending.label}: done`,
        description: 'Approved via step-up MFA.',
        variant: 'success',
      })
      for (const key of ['environments', 'shared_permissions', 'orphaned_archives', 'audit_log', 'sync_status', 'upgrade_status']) {
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
    if (restore.reopen === 'updates') { setActiveTab('updates'); setRestore(null) }
    else if (restore.reopen === 'orphaned_archives') setOrphansOpen(true)
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
      <UpgradeNoticeBanner canAdmin={canAdmin} onOpenUpdates={() => setActiveTab('updates')} />
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
          canViewOverview={canViewOverview}
          onOpenBanner={() => setBannerOpen(true)}
          onOpenAccessControl={() => setAccessControlOpen(true)}
          onOpenAbout={() => setAboutOpen(true)}
          onOpenOrphanedArchives={() => setOrphansOpen(true)}
          onOpenSharedPermissions={() => setSharedPermissionsOpen(true)}
          updateCount={upgradeStatus?.check.enabled && upgradeStatus.update_available ? 1 : 0}
        />

        <EnvironmentScope scopeKey={scopeKey}>
        <AccessModelProvider>
        <main className="flex-1 overflow-y-auto px-8 py-6 flex flex-col gap-5">
          {!(activeTab === 'updates' && updatesHeader.fullPage) && (
          <header className="flex items-start justify-between">
            <div>
              <h1 className="text-lg font-semibold text-text">
                {activeTab === 'overview' && 'Overview'}
                {activeTab === 'reports' && reportsSubTab === 'browse' && 'Compliance Reports'}
                {activeTab === 'reports' && reportsSubTab === 'secrets_access' && 'Secrets Access Dashboard'}
                {activeTab === 'reports' && reportsSubTab === 'service_accounts' && 'Service Accounts Dashboard'}
                {activeTab === 'reports' && reportsSubTab === 'okta_admins' && 'Okta Admins'}
                {activeTab === 'reports' && reportsSubTab === 'cross_checks' && 'Cross-checks'}
                {activeTab === 'access' && 'Access Explorer'}
                {activeTab === 'builder' && 'Folder Builder'}
                {activeTab === 'audit_log' && 'Audit Log'}
                {activeTab === 'updates' && 'Updates'}
                {activeTab === 'update_keys' && (<>Updates <span className="text-sm font-normal text-muted">› Release signing keys</span></>)}
              </h1>
              <p className="text-xs text-muted mt-1 max-w-[72ch]">
                {activeTab === 'overview' &&
                  'Okta and OPA privileged access in one place: who can change the gate, who can open the vault, who holds both, and whether the evidence behind it is complete. Counts of people open the list behind them. Home page for administrators and archive viewers; other users land on Compliance Reports.'}
                {activeTab === 'reports' && reportsSubTab === 'browse' &&
                  'Audit evidence with a proposed SOC 2 mapping (other frameworks are planned), generated from OPA + core Okta audit history.'}
                {activeTab === 'reports' && reportsSubTab === 'secrets_access' &&
                  'See who created, updated, retrieved, or deleted each secret and folder in a resource group/project.'}
                {activeTab === 'reports' && reportsSubTab === 'service_accounts' &&
                  'Every SaaS app and Okta service account across the tenant — including ones since deleted — with who created, assigned, revealed, checked out or rotated it, and when.'}
                {activeTab === 'reports' && reportsSubTab === 'okta_admins' &&
                  'Who holds an administrator role in Okta, as of any date there is a snapshot for, and which of them also hold an OPA admin role.'}
                {activeTab === 'reports' && reportsSubTab === 'cross_checks' &&
                  'Questions only a tool that sees both Okta and OPA can answer. Candidates for review, not findings.'}
                {activeTab === 'access' &&
                  'Who can reach what in OPA: resource groups, projects, resources, policies, relationships, users and groups, resolved from the stored OPA scan. Live lookups (last accessed, resource evidence) say so where they appear.'}
                {activeTab === 'builder' &&
                  'Pick or create a resource group and project, build the folder tree, then preview and create.'}
                {activeTab === 'audit_log' &&
                  'Every write action across every environment and user — admin-only, for compliance visibility.'}
                {activeTab === 'updates' &&
                  (updatesHeader.subtitle ?? 'Check for signed releases, upgrade now or on a schedule, and see every upgrade step in the audit log. Admin-only.')}
                {activeTab === 'update_keys' &&
                  'The keys this install trusts for release signatures. A primary signs releases; the offline standby can only sign a revocation that replaces a primary. A primary can never change the standby or undo a revocation.'}
              </p>
            </div>
            <div className="flex items-center gap-3">
              {activeTab === 'access' && environments?.active ? (
                <EnvironmentButton environment={environments.active} onOpen={() => setEnvironmentsOpen(true)} />
              ) : activeTab !== 'overview' && (
                <span className="text-xs text-text-faint">
                  Connected: <span className="text-text-dim font-medium">{environments?.active}</span>
                </span>
              )}
              <UserMenu />
            </div>
          </header>
          )}

          <SharedEnvironmentNotice />

          {activeTab === 'overview' && canViewOverview && <OverviewPage onOpenReports={() => navigate({ tab: 'reports', reportsSubTab: 'browse' })}
            onOpenOktaAdmins={() => navigate({ tab: 'reports', reportsSubTab: 'okta_admins' })} onOpenAccessUsers={() => navigate({ tab: 'access', accessSubTab: 'users' })}
            onOpenServiceAccounts={() => navigate({ tab: 'reports', reportsSubTab: 'service_accounts' })} onOpenEnvironments={() => setEnvironmentsOpen(true)} />}
          {activeTab === 'reports' && reportsSubTab === 'browse' && (
            <ComplianceReports selectedReport={route.reportKey} onSelectReport={key => navigate({ tab: 'reports', reportsSubTab: 'browse', reportKey: key })} />
          )}
          {activeTab === 'reports' && reportsSubTab === 'secrets_access' && <SecretsAccessDashboard />}
          {activeTab === 'reports' && reportsSubTab === 'service_accounts' && <ServiceAccountsDashboard />}
          {activeTab === 'reports' && reportsSubTab === 'okta_admins' && <OktaAdminsReport />}
          {activeTab === 'reports' && reportsSubTab === 'cross_checks' && <CrossChecks />}
          {activeTab === 'access' && <AccessExplorer subTab={accessSubTab} onOpenEnvironments={() => setEnvironmentsOpen(true)} canAdmin={canAdmin} />}
          {activeTab === 'builder' && <FolderBuilder />}
          {activeTab === 'audit_log' && canAdmin && <AuditLogPage />}
          {activeTab === 'updates' && canAdmin && <UpdatesPage onOpenKeys={() => setActiveTab('update_keys')} onHeader={setUpdatesHeader} />}
          {activeTab === 'update_keys' && canAdmin && <UpdateKeysPage onBack={() => setActiveTab('updates')} />}

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
        restore={restore && restore.reopen !== 'orphaned_archives' && restore.reopen !== 'shared_permissions' && restore.reopen !== 'updates' ? restore : null}
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
      <AboutDialog open={aboutOpen} onOpenChange={setAboutOpen} dataLocationNotice={whoami?.data_location_notice} />
    </div>
  )
}
