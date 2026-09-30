import { useEffect, useRef } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { RefreshCw } from 'lucide-react'
import { useEnvironments, useSyncStatus, useVersion } from '../api/hooks'
import { useSyncJob } from '../hooks/useSyncJob'
import { toast } from '../hooks/useToast'
import { formatDateTime } from '../utils/format'

// Points at this project's real GitHub location (OPA/Secrets-Wizard/ inside
// the ItsGambit/Okta repo, not a dedicated repo of its own) -- keep this in
// sync if the project ever moves to its own repo.
const REPO_README_URL = 'https://github.com/ItsGambit/Okta/blob/main/OPA/Secrets-Wizard/README.md'
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
    <footer className="max-w-4xl mx-auto w-full mt-4 pt-3 border-t border-border text-xs text-text-faint flex items-center justify-center gap-3">
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
