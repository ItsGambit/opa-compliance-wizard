import { useEffect, useState } from 'react'
import * as Dialog from '@radix-ui/react-dialog'
import { useQueryClient } from '@tanstack/react-query'
import { CalendarClock, Cloud, FileText, Play, X } from 'lucide-react'
import { importSyncCsv, saveSyncSchedule } from '../api/client'
import { useSyncJob } from '../hooks/useSyncJob'
import { toast } from '../hooks/useToast'
import type { Environment, IngestionScope, SyncSchedule } from '../types'

interface Props {
  env: Environment
}

type FirstRunChoice = 'backfill' | 'csv' | 'fresh'

/** Per-environment compliance-sync settings: enable/disable the daily
 * background sync, ingestion scope (curated vs. everything -- governs
 * what's actually WRITTEN on ingest, not a later filter, see
 * audit_store.py), retention, and a manual "Sync now". On first-ever
 * enable for an environment with no prior sync_state, shows a 3-way
 * choice (live 90-day backfill / CSV import / start fresh) before
 * saving, matching the reviewed mockup exactly. */
export function SyncScheduleDialog({ env }: Props) {
  const [open, setOpen] = useState(false)
  const [firstRunPrompt, setFirstRunPrompt] = useState(false)
  const [firstRunChoice, setFirstRunChoice] = useState<FirstRunChoice>('backfill')
  const [csvPath, setCsvPath] = useState('')
  const queryClient = useQueryClient()
  const job = useSyncJob(env.name)

  const [enabled, setEnabled] = useState(env.sync_schedule.enabled)
  const [runTime, setRunTime] = useState(env.sync_schedule.run_time)
  const [ingestionScope, setIngestionScope] = useState<IngestionScope>(env.sync_schedule.ingestion_scope)
  const [retentionDays, setRetentionDays] = useState<string>(
    env.sync_schedule.retention_days != null ? String(env.sync_schedule.retention_days) : ''
  )
  const [retentionMaxSizeMb, setRetentionMaxSizeMb] = useState<string>(
    env.sync_schedule.retention_max_size_mb != null ? String(env.sync_schedule.retention_max_size_mb) : ''
  )
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (open) {
      setEnabled(env.sync_schedule.enabled)
      setRunTime(env.sync_schedule.run_time)
      setIngestionScope(env.sync_schedule.ingestion_scope)
      setRetentionDays(env.sync_schedule.retention_days != null ? String(env.sync_schedule.retention_days) : '')
      setRetentionMaxSizeMb(
        env.sync_schedule.retention_max_size_mb != null ? String(env.sync_schedule.retention_max_size_mb) : ''
      )
      job.refreshStatus()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, env.sync_schedule])

  const buildConfig = (): SyncSchedule => ({
    enabled,
    run_time: runTime,
    ingestion_scope: ingestionScope,
    retention_days: retentionDays.trim() ? Number(retentionDays) : null,
    retention_max_size_mb: retentionMaxSizeMb.trim() ? Number(retentionMaxSizeMb) : null,
  })

  const doSave = async (config: SyncSchedule) => {
    setSaving(true)
    try {
      await saveSyncSchedule(env.name, config)
      queryClient.invalidateQueries({ queryKey: ['environments'] })
      toast({ title: config.enabled ? 'Daily sync enabled' : 'Daily sync disabled', variant: 'success' })
    } catch (err) {
      toast({ title: 'Could not save sync settings', description: err instanceof Error ? err.message : String(err), variant: 'error' })
    } finally {
      setSaving(false)
    }
  }

  const handleSaveClick = () => {
    const config = buildConfig()
    // Only prompt for a first-run choice when actually turning sync ON
    // for the first time ever (no prior sync_state at all) -- toggling
    // settings on an already-synced environment just saves normally.
    if (config.enabled && job.status?.is_first_sync) {
      setFirstRunPrompt(true)
      return
    }
    doSave(config)
  }

  const handleFirstRunContinue = async () => {
    const config = buildConfig()
    await doSave(config)
    setFirstRunPrompt(false)
    if (firstRunChoice === 'backfill') {
      job.start(config.ingestion_scope)
    } else if (firstRunChoice === 'csv' && csvPath.trim()) {
      setSaving(true)
      try {
        const result = await importSyncCsv(env.name, csvPath.trim(), config.ingestion_scope)
        toast({ title: `Imported ${result.inserted} event(s) from CSV`, variant: 'success' })
        job.refreshStatus()
      } catch (err) {
        toast({ title: 'CSV import failed', description: err instanceof Error ? err.message : String(err), variant: 'error' })
      } finally {
        setSaving(false)
      }
    }
    // 'fresh' -- nothing further to do, tonight's scheduled run starts the archive
  }

  const state = job.status?.sync_state
  const isRunning = job.phase === 'running' || job.phase === 'starting'

  // A backfill walks day-by-day (see audit_store.sync_okta_events) --
  // each "fetch"/"progress" step's detail is "<chunk_since> .. <chunk_until>"
  // ISO timestamps. Real percentage = how far the chunk_until of the most
  // recent step has advanced from the very first step's chunk_since,
  // relative to now -- not a fake/animated bar, an actual measure of the
  // real date window this sync has to cover.
  const fetchSteps = (job.status?.steps ?? []).filter(s => s.key === 'fetch' && s.detail)
  const syncProgressPercent = (() => {
    if (fetchSteps.length === 0) return null
    const firstSince = fetchSteps[0].detail!.split(' .. ')[0]
    const lastUntil = fetchSteps[fetchSteps.length - 1].detail!.split(' .. ')[1]
    const start = new Date(firstSince).getTime()
    const current = new Date(lastUntil).getTime()
    const end = Date.now()
    if (!Number.isFinite(start) || !Number.isFinite(current) || end <= start) return null
    return Math.min(100, Math.round(((current - start) / (end - start)) * 100))
  })()

  return (
    <Dialog.Root open={open} onOpenChange={setOpen}>
      <Dialog.Trigger asChild>
        <button type="button" className="btn-secondary !p-1.5" title="Compliance sync settings">
          <CalendarClock size={12} />
        </button>
      </Dialog.Trigger>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/60 z-40" />
        <Dialog.Content className="card fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-50 w-[30rem] max-h-[85vh] overflow-y-auto p-5">
          <div className="flex items-center justify-between mb-3">
            <Dialog.Title className="text-sm font-semibold text-text">Compliance sync — {env.name}</Dialog.Title>
            <Dialog.Close asChild>
              <button type="button" className="text-text-faint hover:text-text-dim">
                <X size={16} />
              </button>
            </Dialog.Close>
          </div>

          {!firstRunPrompt ? (
            <>
              <div className="flex flex-col gap-3">
                <label className="flex items-center gap-2 text-sm text-text cursor-pointer">
                  <input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} className="accent-accent" />
                  Enable daily sync
                </label>

                <div className="field">
                  <label className="section-label block mb-1">What to ingest</label>
                  <div className="flex flex-col gap-2">
                    <label className="card p-2.5 flex items-start gap-2 cursor-pointer">
                      <input type="radio" checked={ingestionScope === 'curated'} onChange={() => setIngestionScope('curated')} className="mt-0.5" />
                      <div>
                        <div className="text-xs font-medium text-text">Curated events only</div>
                        <div className="text-[0.6875rem] text-text-faint">MFA, lifecycle, PAM access, policy changes. Smallest footprint.</div>
                      </div>
                    </label>
                    <label className="card p-2.5 flex items-start gap-2 cursor-pointer">
                      <input type="radio" checked={ingestionScope === 'all'} onChange={() => setIngestionScope('all')} className="mt-0.5" />
                      <div>
                        <div className="text-xs font-medium text-text">Everything</div>
                        <div className="text-[0.6875rem] text-text-faint">Every Okta System Log event. Maximum flexibility, more storage.</div>
                      </div>
                    </label>
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-2">
                  <div className="field">
                    <label className="section-label block mb-1">Run time (UTC)</label>
                    <input type="time" className="text-input w-full" value={runTime} onChange={e => setRunTime(e.target.value)} />
                  </div>
                  <div className="field">
                    <label className="section-label block mb-1">Retention (days)</label>
                    <input
                      type="number" min="0" placeholder="Forever" className="text-input w-full"
                      value={retentionDays} onChange={e => setRetentionDays(e.target.value)}
                    />
                  </div>
                  <div className="field">
                    <label className="section-label block mb-1">Max size (MB)</label>
                    <input
                      type="number" min="0" placeholder="No limit" className="text-input w-full"
                      value={retentionMaxSizeMb} onChange={e => setRetentionMaxSizeMb(e.target.value)}
                    />
                  </div>
                </div>
                <p className="text-[0.6875rem] text-text-faint">
                  Curated events are never pruned regardless of retention or ingestion scope.
                </p>

                {state && (
                  <div className="card p-2.5 text-xs text-text-dim flex flex-col gap-1">
                    <div>Last synced: {state.last_synced_at ? new Date(state.last_synced_at).toLocaleString() : 'never'}</div>
                    <div>Total events archived: {state.total_events_ingested}</div>
                    {state.last_sync_status === 'error' && <div className="text-loss">Last error: {state.last_sync_error}</div>}
                  </div>
                )}

                {isRunning && (
                  <div className="card p-2.5 flex flex-col gap-1.5">
                    <div className="flex items-center justify-between text-xs text-text">
                      <span className="flex items-center gap-2">
                        <span className="inline-block w-3 h-3 rounded-full border-2 border-accent border-t-transparent animate-spin" />
                        Syncing…
                      </span>
                      {syncProgressPercent !== null && <span className="text-text-faint">{syncProgressPercent}%</span>}
                    </div>
                    <div className="h-1.5 w-full rounded-full bg-bg-hover overflow-hidden">
                      <div
                        className="h-full rounded-full bg-accent transition-[width] duration-300"
                        style={{ width: `${syncProgressPercent ?? 8}%` }}
                      />
                    </div>
                    {fetchSteps.length > 0 && (
                      <div className="text-[0.6875rem] text-text-faint truncate">
                        {fetchSteps[fetchSteps.length - 1].detail}
                      </div>
                    )}
                  </div>
                )}

                {job.phase === 'error' && (
                  <div className="card p-2.5 text-xs text-loss">
                    Sync failed: {job.error ?? job.status?.error ?? 'Unknown error'}
                  </div>
                )}

                {job.phase === 'done' && (
                  <div className="card p-2.5 text-xs text-win">
                    Sync complete — {job.status?.result?.inserted ?? 0} new event(s) archived.
                  </div>
                )}

                <button
                  type="button"
                  className="btn-secondary self-start"
                  disabled={isRunning || !env.name}
                  onClick={() => job.start(ingestionScope)}
                >
                  <Play size={12} /> {isRunning ? 'Syncing…' : 'Sync now'}
                </button>
              </div>

              <div className="flex justify-end gap-2 mt-5">
                <Dialog.Close asChild>
                  <button type="button" className="btn-secondary">Cancel</button>
                </Dialog.Close>
                <button type="button" className="btn-primary" disabled={saving} onClick={handleSaveClick}>
                  Save
                </button>
              </div>
            </>
          ) : (
            <>
              <p className="text-xs text-text-faint mb-4">
                Okta only retains 90 days of System Log history. Choose how to start the archive for{' '}
                <strong>{env.name}</strong> — you can change the ingestion scope later any time.
              </p>
              <div className="flex flex-col gap-2 mb-4">
                <label className="card p-2.5 flex items-start gap-2 cursor-pointer">
                  <input type="radio" checked={firstRunChoice === 'backfill'} onChange={() => setFirstRunChoice('backfill')} className="mt-0.5" />
                  <Cloud size={14} className="mt-0.5 text-text-faint" />
                  <div>
                    <div className="text-xs font-medium text-text">Backfill last 90 days (live)</div>
                    <div className="text-[0.6875rem] text-text-faint">Pulls the full available window from Okta's System Log API.</div>
                  </div>
                </label>
                <label className="card p-2.5 flex items-start gap-2 cursor-pointer">
                  <input type="radio" checked={firstRunChoice === 'csv'} onChange={() => setFirstRunChoice('csv')} className="mt-0.5" />
                  <FileText size={14} className="mt-0.5 text-text-faint" />
                  <div className="flex-1">
                    <div className="text-xs font-medium text-text">Import from a CSV export</div>
                    <div className="text-[0.6875rem] text-text-faint mb-1.5">
                      Already have a System Log CSV export? Ingest it directly — zero API calls.
                    </div>
                    {firstRunChoice === 'csv' && (
                      <input
                        type="text" className="text-input w-full" placeholder="C:\path\to\syslog_export.csv"
                        value={csvPath} onChange={e => setCsvPath(e.target.value)}
                      />
                    )}
                  </div>
                </label>
                <label className="card p-2.5 flex items-start gap-2 cursor-pointer">
                  <input type="radio" checked={firstRunChoice === 'fresh'} onChange={() => setFirstRunChoice('fresh')} className="mt-0.5" />
                  <Play size={14} className="mt-0.5 text-text-faint" />
                  <div>
                    <div className="text-xs font-medium text-text">Start fresh</div>
                    <div className="text-[0.6875rem] text-text-faint">No backfill — accumulates from tonight's first run only.</div>
                  </div>
                </label>
              </div>
              <div className="flex justify-end gap-2">
                <button type="button" className="btn-secondary" onClick={() => setFirstRunPrompt(false)}>Back</button>
                <button
                  type="button"
                  className="btn-primary"
                  disabled={saving || (firstRunChoice === 'csv' && !csvPath.trim())}
                  onClick={handleFirstRunContinue}
                >
                  Continue
                </button>
              </div>
            </>
          )}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}
