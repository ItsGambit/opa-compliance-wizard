import { useEffect, useRef } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { RefreshCw } from 'lucide-react'
import { useEnvironments, useSyncStatus, useVersion } from '../api/hooks'
import { useSyncJob } from '../hooks/useSyncJob'
import { toast } from '../hooks/useToast'
import { formatDateTime } from '../utils/format'
import { getSyncProgressPercent } from '../utils/syncProgress'

// This project split out of the ItsGambit/Okta monorepo into its own
// standalone repo 2026-09-30 -- these were left pointing at the old
// OPA/Secrets-Wizard/ monorepo path (a real dead link found live, since
// nothing deletes an old repo's README on a split) until fixed here.
const REPO_README_URL = 'https://github.com/ItsGambit/opa-compliance-wizard/blob/main/README.md'
const REPO_CHANGELOG_URL = `${REPO_README_URL}#changelog`

export function Footer() {
  const { data: version } = useVersion()
  const { data: environments } = useEnvironments()
  const activeEnv = environments?.active
  const { data: syncStatus } = useSyncStatus(activeEnv)
  const queryClient = useQueryClient()

  // ONE global sync trigger, not a Refresh button on every report/
  // resource-history view -- every one of those reads the SAME shared
  // audit_store.db archive, so pulling fresh Okta data is inherently one
  // action, not something that needs re-triggering per screen (a real
  // per-view version of this was built and verified working, then
  // deliberately consolidated here instead -- see the plan file). No
  // explicit ingestionScope passed to start() -- the server falls back to
  // this environment's saved schedule scope, so this can never silently
  // change a user's chosen curated/all setting.
  const syncJob = useSyncJob(activeEnv)
  const isSyncing = syncJob.phase === 'starting' || syncJob.phase === 'running'
  // Same real (not animated) percent SyncScheduleDialog's own manual-sync
  // trigger already shows -- see getSyncProgressPercent's docstring. Falls
  // back to the same small fixed value that dialog uses (8%) before the
  // first "fetch" step has landed, rather than showing a stuck 0%.
  const syncProgressPercent = getSyncProgressPercent(syncJob.status?.steps ?? [])
  const prevSyncPhase = useRef(syncJob.phase)
  useEffect(() => {
    if (prevSyncPhase.current !== 'done' && syncJob.phase === 'done') {
      // Broad prefix invalidation, not a specific refetch() -- this
      // updates EVERY currently-mounted report/history view (and this
      // Footer's own "Last Okta import" line) regardless of which one, if
      // any, is on screen right now.
      queryClient.invalidateQueries({ queryKey: ['report'] })
      queryClient.invalidateQueries({ queryKey: ['report_defs'] })
      queryClient.invalidateQueries({ queryKey: ['resource_history'] })
      queryClient.invalidateQueries({ queryKey: ['sync_status'] })
    }
    if (syncJob.phase === 'error' && prevSyncPhase.current !== 'error') {
      toast({ title: 'Sync failed', description: syncJob.error ?? undefined, variant: 'error' })
    }
    prevSyncPhase.current = syncJob.phase
  }, [syncJob.phase, syncJob.error, queryClient])

  return (
    <footer className="max-w-4xl mx-auto w-full mt-4 pt-3 border-t border-border text-xs text-text-faint flex flex-wrap items-center justify-center gap-3">
      <span>OPA Compliance Wizard{version && ` v${version.version}`}</span>
      {activeEnv && (
        <>
          <span aria-hidden="true">·</span>
          {/* Real gap this addresses: with no visible timestamp, there was
              no way to tell whether what's on screen reflects live Okta
              data or a stale archive without opening the buried Environments
              -> Sync settings dialog. "never" (not hidden) is a real,
              meaningful state -- sync_state is genuinely null until the
              first sync for this environment ever completes. */}
          <span>Last Okta import: {syncStatus?.sync_state?.last_synced_at ? formatDateTime(syncStatus.sync_state.last_synced_at) : 'never'}</span>
          <button
            type="button"
            onClick={() => syncJob.start()}
            disabled={isSyncing}
            title="Pull the latest events from live Okta for every report and resource history"
            className="inline-flex items-center gap-1 hover:text-text-dim disabled:opacity-60"
          >
            <RefreshCw size={11} className={isSyncing ? 'animate-spin' : ''} />
            {isSyncing ? 'Syncing…' : 'Sync now'}
          </button>
          {isSyncing && (
            <span className="h-1 w-16 rounded-full bg-bg-hover overflow-hidden" title={syncProgressPercent !== null ? `${syncProgressPercent}%` : undefined}>
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
    </footer>
  )
}
