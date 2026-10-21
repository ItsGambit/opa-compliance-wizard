import { REPO_CHANGELOG_URL, REPO_README_URL } from '../utils/links'
import { RefreshCw } from 'lucide-react'
import { useEnvironments, useSyncStatus, useUpgradeStatus, useVersion, useWhoami } from '../api/hooks'
import { useRefreshActions, useRefreshStatus, useRefreshWatcher } from '../hooks/useRefresh'
import { formatDateTime } from '../utils/format'
import { activeRow, can, refreshReason } from '../utils/environmentRows'
import { completedText, isActive, latestRefresh, requestedParts } from '../utils/refresh'
import { canAdminFrom } from '../utils/whoami'
import { AFFILIATION } from '../utils/brand'

// This project split out of the ItsGambit/Okta monorepo into its own
// standalone repo 2026-09-30 -- these were left pointing at the old
// OPA/Secrets-Wizard/ monorepo path (a real dead link found live, since
// nothing deletes an old repo's README on a split) until fixed here.
// The README itself was later split into a short front-door README plus
// a standalone CHANGELOG.md (public-consumption rewrite) -- the
// Changelog link now points at that file directly instead of a
// #changelog anchor inside README.md, which no longer exists there.

export function Footer() {
  const { data: version } = useVersion()
  const { data: environments } = useEnvironments()
  const { data: whoami } = useWhoami()
  // 5.46.0: admins see a newer release (when the opt-in check found one) here too.
  const { data: upgrade } = useUpgradeStatus(canAdminFrom(whoami))
  const activeEnv = environments?.active ?? undefined  // null (no active env) -> undefined, which the hooks treat as "disabled"
  const { data: syncStatus } = useSyncStatus(activeEnv)
  // 5.42.0: "Sync now" on an environment shared with this user follows what
  // an admin allows shared users (off unless allowed); the server enforces it.
  const active = activeRow(environments)
  const canRefresh = !active || (can(active, 'sync_now') && can(active, 'live_read'))

  // ONE global trigger, not a Refresh button on every report/resource-history view -- every one of those reads the SAME shared
  // audit_store.db archive, so pulling fresh data is inherently one action. 5.51.0: Sync now runs the whole refresh (the OPA scan,
  // the Okta scan and the System Log sync: the same job as the Overview's Refresh); a refresh already running is attached to,
  // never started twice. The server uses this environment's saved ingestion scope, so this can never silently change a user's
  // chosen curated/all setting.
  const { data: refreshStatus } = useRefreshStatus(activeEnv)
  const { start } = useRefreshActions(activeEnv)
  useRefreshWatcher(activeEnv)  // the finish toast and the data reload, once, on every page
  const isSyncing = refreshStatus?.status === 'running'
  const parts = refreshStatus && isSyncing ? requestedParts(refreshStatus) : []
  const endedParts = refreshStatus ? parts.filter(p => !isActive(refreshStatus.parts[p].state)).length : 0
  const syncProgressPercent = parts.length ? Math.max(8, Math.round((endedParts / parts.length) * 100)) : null  // parts finished, not an animated bar
  const latest = latestRefresh(refreshStatus, syncStatus?.sync_state?.last_refresh)
  const reason = !canRefresh && active ? refreshReason(active) : ''

  return (
    <footer className="max-w-4xl mx-auto w-full mt-4 pt-3 border-t border-border text-xs text-text-faint flex flex-wrap items-center justify-center gap-3">
      <span>OPA Compliance Wizard{version && ` v${version.version}`}</span>
      {upgrade?.check.enabled && upgrade.update_available && upgrade.latest && (
        <span className="text-accent">Update available: v{upgrade.latest.version}</span>
      )}
      {activeEnv && (
        <>
          <span aria-hidden="true">·</span>
          {/* Real gap this addresses: with no visible timestamp, there was
              no way to tell whether what's on screen reflects live Okta
              data or a stale archive without opening the buried Environments
              -> Sync settings dialog. "never" (not hidden) is a real,
              meaningful state -- sync_state is genuinely null until the
              first sync for this environment ever completes. */}
          {/* last_sync_completed_at, not the watermark: as of 5.40.2 it is written
              only by a sync that finished successfully (DATA-05), which is what
              "last sync" should mean here. */}
          {latest ? (
            <span>Last refresh: {formatDateTime(latest.finishedAt)} · {latest.failing.length === 0 ? completedText(latest.done, latest.total) : `${completedText(latest.done, latest.total)}; ${latest.failing.join(', ')} did not complete`}</span>
          ) : (
            <span>Last sync: {syncStatus?.sync_state?.last_sync_completed_at ? formatDateTime(syncStatus.sync_state.last_sync_completed_at) : 'never'}</span>
          )}
          {/* aria-disabled, not disabled (WCAG 2.1.1, 1.3.1): the button stays focusable so its reason is read out. */}
          <button
            type="button"
            onClick={() => { if (!isSyncing && canRefresh) void start() }}
            aria-disabled={isSyncing || !canRefresh}
            aria-describedby={reason ? 'footer-sync-reason' : undefined}
            title={reason || (isSyncing ? 'A refresh is running' : 'Refresh: read OPA and Okta again and sync the System Log')}
            className="inline-flex items-center gap-1 hover:text-text-dim aria-disabled:opacity-60 aria-disabled:cursor-not-allowed"
          >
            <RefreshCw size={11} aria-hidden="true" className={isSyncing ? 'animate-spin' : ''} />
            {isSyncing ? 'Syncing…' : 'Sync now'}
          </button>
          {reason && <span id="footer-sync-reason" className="sr-only">{reason}</span>}
          {isSyncing && (
            <span
              className="h-1 w-16 rounded-full bg-bg-hover overflow-hidden"
              role="progressbar"
              aria-label="Refresh progress"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={syncProgressPercent ?? undefined}
              title={syncProgressPercent !== null ? `${syncProgressPercent}%` : undefined}
            >
              <span
                className="h-full block rounded-full bg-accent transition-[width] duration-300"
                style={{ width: `${syncProgressPercent ?? 8}%` }}
              />
            </span>
          )}
        </>
      )}
      <span aria-hidden="true">·</span>
      <a href={REPO_README_URL} target="_blank" rel="noreferrer" className="hover:text-text-dim underline">
        README
      </a>
      <span aria-hidden="true">·</span>
      <a href={REPO_CHANGELOG_URL} target="_blank" rel="noreferrer" className="hover:text-text-dim underline">
        Changelog
      </a>
      <span className="basis-full text-center text-[11px]">{AFFILIATION}</span>
    </footer>
  )
}
