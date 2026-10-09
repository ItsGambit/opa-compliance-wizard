import { useState } from 'react'
import * as Dialog from '@radix-ui/react-dialog'
import { useQueryClient } from '@tanstack/react-query'
import { CalendarClock, Cloud, FileText, Play, ShieldCheck } from 'lucide-react'
import { importSyncCsv, resetSyncWatermark, saveSyncSchedule } from '../api/client'
import { useCsvFiles, useWhoami } from '../api/hooks'
import { useIntegrityCheck } from '../hooks/useIntegrityCheck'
import { useSyncJob } from '../hooks/useSyncJob'
import { toast } from '../hooks/useToast'
import type { Environment, IngestionScope, SyncSchedule } from '../types'
import { getSyncProgressPercent } from '../utils/syncProgress'
import { canAdminFrom } from '../utils/whoami'
import { DialogCloseButton } from './DialogCloseButton'
import { IntegrityResultView } from './IntegrityResultView'
import { Select } from './Select'

interface Props {
  env: Environment
}

type FirstRunChoice = 'backfill' | 'csv' | 'fresh'

/** "14:00" (UTC, as the form stores/sends it) -> "= 7:00 AM in your local
 * timezone" -- or a plain explanation if the field is empty/malformed,
 * never a raw "Invalid Date". Recomputed on every render so it always
 * reflects whatever's currently typed, not just the value at mount. */
function formatLocalEquivalent(utcHHMM: string): string {
  const match = /^(\d{2}):(\d{2})$/.exec(utcHHMM)
  if (!match) return 'Enter a time to see your local equivalent.'
  const [, hh, mm] = match
  const today = new Date()
  const utcDate = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate(), Number(hh), Number(mm)))
  const local = utcDate.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' })
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone
  return `= ${local} in your local time (${tz})`
}

/** Per-environment compliance-sync settings: enable/disable the daily
 * background sync, ingestion scope (curated vs. everything -- governs
 * what's actually WRITTEN on ingest, not a later filter, see
 * audit_store.py), retention, and a manual "Sync now". On first-ever
 * enable for an environment with no prior sync_state, shows a 3-way
 * choice (live 90-day backfill / CSV import / start fresh) before
 * saving, matching the reviewed mockup exactly. */
export function SyncScheduleDialog({ env }: Props) {
  const [open, setOpen] = useState(false)
  // The content (and with it the sync-status request and any polling)
  // mounts only while this dialog is open -- the Environments list used to
  // fire one /sync/status request per row as soon as it rendered (UI-07).
  return (
    <Dialog.Root open={open} onOpenChange={setOpen}>
      <Dialog.Trigger asChild>
        <button type="button" className="btn-secondary !p-1.5" title="Compliance sync settings" aria-label={`Compliance sync settings for ${env.name}`}>
          <CalendarClock size={12} aria-hidden="true" />
        </button>
      </Dialog.Trigger>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/60 z-40" />
        <Dialog.Content
          aria-describedby={undefined}
          className="card fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-50 w-[calc(100vw-2rem)] sm:w-[30rem] max-h-[85vh] overflow-y-auto p-5"
        >
          <SyncScheduleContent env={env} />
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}

function SyncScheduleContent({ env }: Props) {
  const [firstRunPrompt, setFirstRunPrompt] = useState(false)
  const [firstRunChoice, setFirstRunChoice] = useState<FirstRunChoice>('backfill')
  // Bare filename, not a full path -- the backend's import_csv route
  // confines csv_path to a bare basename resolved inside PROJECT_ROOT
  // (same _safe_csv_path pattern /api/csv already uses), so this reuses
  // that same file list/picker instead of a free-text path field.
  const [csvFile, setCsvFile] = useState<string | undefined>(undefined)
  const { data: csvFiles } = useCsvFiles()
  const { data: whoami } = useWhoami()
  const queryClient = useQueryClient()
  const job = useSyncJob(env.name)
  const integrity = useIntegrityCheck(env.name)

  // Initialised from the saved schedule each time the dialog opens (this
  // component mounts with it).
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

  // UI-09 / ENG2-04 (external review, 2026-10-05): validate here with the
  // same rules the server enforces (create_secret_folders.py's
  // validate_sync_schedule_config), so a typo is caught before the request
  // and the message names the field. The inputs' min="1" below and this
  // check both exist because the placeholders say "Forever"/"No limit":
  // a user typing 0 means "no limit", and 0 used to be sent as-is, which
  // made the next sync's prune delete every non-curated event.
  const validationError = (): string | null => {
    if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(runTime)) return 'Run time must be a 24-hour HH:MM time (UTC).'
    for (const [label, raw] of [['Retention (days)', retentionDays], ['Max size (MB)', retentionMaxSizeMb]] as const) {
      if (!raw.trim()) continue
      const n = Number(raw)
      if (!Number.isInteger(n) || n < 1) return `${label} must be a whole number of at least 1, or empty for no limit.`
    }
    return null
  }

  const buildConfig = (): SyncSchedule => ({
    enabled,
    run_time: runTime,
    ingestion_scope: ingestionScope,
    retention_days: retentionDays.trim() ? Number(retentionDays) : null,
    retention_max_size_mb: retentionMaxSizeMb.trim() ? Number(retentionMaxSizeMb) : null,
  })

  /** Returns true only if the schedule was actually saved -- the first-run
   * flow must never start a 90-day backfill or a CSV import on the back of
   * a save that failed (it used to: the error was swallowed here and the
   * caller carried on). */
  const doSave = async (config: SyncSchedule): Promise<boolean> => {
    setSaving(true)
    try {
      await saveSyncSchedule(env.name, config)
      queryClient.invalidateQueries({ queryKey: ['environments'] })
      toast({ title: config.enabled ? 'Daily sync enabled' : 'Daily sync disabled', variant: 'success' })
      return true
    } catch (err) {
      toast({ title: 'Could not save sync settings', description: err instanceof Error ? err.message : String(err), variant: 'error' })
      return false
    } finally {
      setSaving(false)
    }
  }

  const handleSaveClick = () => {
    const problem = validationError()
    if (problem) {
      toast({ title: 'Check the sync settings', description: problem, variant: 'error' })
      return
    }
    const config = buildConfig()
    // Only prompt for a first-run choice when actually turning sync ON
    // for the first time ever (no prior sync_state at all) -- toggling
    // settings on an already-synced environment just saves normally.
    if (config.enabled && job.status?.is_first_sync) {
      setFirstRunPrompt(true)
      return
    }
    void doSave(config)
  }

  const handleFirstRunContinue = async () => {
    const config = buildConfig()
    if (!(await doSave(config))) return // keep the prompt open; nothing else may start on a failed save
    setFirstRunPrompt(false)
    if (firstRunChoice === 'backfill') {
      job.start(config.ingestion_scope)
    } else if (firstRunChoice === 'csv' && csvFile) {
      setSaving(true)
      try {
        const result = await importSyncCsv(env.name, csvFile, config.ingestion_scope)
        toast({
          title: `Imported ${result.inserted} event(s) from CSV`,
          description: result.skipped_unparseable
            ? `${result.skipped_unparseable} row(s) had a timestamp that could not be read and were not imported.`
            : undefined,
          variant: result.skipped_unparseable ? 'error' : 'success',
        })
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

  // A backfill walks day-by-day (see audit_store.sync_okta_events) -- see
  // getSyncProgressPercent's own docstring for the real (not animated)
  // percent computation, shared with Footer.tsx's own "Sync now" trigger.
  const fetchSteps = (job.status?.steps ?? []).filter(s => s.key === 'fetch' && s.detail)
  const syncProgressPercent = getSyncProgressPercent(job.status?.steps ?? [])

  return (
    <>
          <div className="flex items-center justify-between mb-3">
            <Dialog.Title className="text-sm font-semibold text-text">Compliance sync — {env.name}</Dialog.Title>
            <DialogCloseButton />
          </div>

          {!firstRunPrompt ? (
            <>
              <div className="flex flex-col gap-3">
                <label className="flex items-center gap-2 text-sm text-text cursor-pointer">
                  <input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} className="accent-accent" />
                  Enable daily sync
                </label>

                <fieldset className="field">
                  <legend className="section-label block mb-1">What to ingest</legend>
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
                </fieldset>

                <div className="grid grid-cols-3 gap-2">
                  <div className="field">
                    <label htmlFor={`${env.id}-run-time`} className="section-label block mb-1">Run time (UTC)</label>
                    <input id={`${env.id}-run-time`} type="time" className="text-input w-full" value={runTime} onChange={e => setRunTime(e.target.value)} />
                    {/* Directly addresses a real mix-up: the "(UTC)" label
                        alone was easy to miss on a native time picker,
                        confirmed live when a 14:00 UTC schedule was
                        entered assuming local time -- showing the
                        equivalent in the viewer's own timezone right next
                        to the input makes the UTC framing impossible to
                        miss without requiring any mental math. */}
                    <p className="text-[0.6875rem] text-text-faint mt-1">
                      {formatLocalEquivalent(runTime)}
                    </p>
                  </div>
                  <div className="field">
                    <label htmlFor={`${env.id}-retention-days`} className="section-label block mb-1">Retention (days)</label>
                    <input
                      id={`${env.id}-retention-days`}
                      type="number" min="1" step="1" placeholder="Forever" className="text-input w-full"
                      value={retentionDays} onChange={e => setRetentionDays(e.target.value)}
                    />
                  </div>
                  <div className="field">
                    <label htmlFor={`${env.id}-retention-mb`} className="section-label block mb-1">Max size (MB)</label>
                    <input
                      id={`${env.id}-retention-mb`}
                      type="number" min="1" step="1" placeholder="No limit" className="text-input w-full"
                      value={retentionMaxSizeMb} onChange={e => setRetentionMaxSizeMb(e.target.value)}
                    />
                  </div>
                </div>
                <p className="text-[0.6875rem] text-text-faint">
                  Curated events are never pruned regardless of retention or ingestion scope. Leave a limit empty for
                  no limit — 0 is not accepted. The size cap counts this environment's own archived event payload.
                </p>

                {job.statusError && (
                  <div className="card p-2.5 text-xs text-loss">Could not load the sync status: {job.statusError}</div>
                )}

                {state && (
                  <div className="card p-2.5 text-xs text-text-dim flex flex-col gap-1">
                    <div>Last successful sync: {state.last_sync_completed_at ? new Date(state.last_sync_completed_at).toLocaleString() : 'never'}</div>
                    <div>Events covered up to: {state.last_synced_at ? new Date(state.last_synced_at).toLocaleString() : '—'}</div>
                    {state.last_import_at && <div>Last CSV import: {new Date(state.last_import_at).toLocaleString()}</div>}
                    <div>Total events archived: {state.total_events_ingested}</div>
                    {state.last_sync_status === 'error' && <div className="text-loss">Last error: {state.last_sync_error}</div>}
                    {/* DATA-03 remedy: an unusable watermark (a poisoned pre-5.40.2
                        CSV import, a clock jump) has exactly one supported way out. */}
                    {state.last_sync_status === 'error' && state.last_sync_error?.includes('watermark') && (
                      <button
                        type="button"
                        className="btn-secondary self-start"
                        disabled={saving || isRunning}
                        onClick={async () => {
                          setSaving(true)
                          try {
                            await resetSyncWatermark(env.name)
                            toast({ title: 'Sync watermark reset', description: 'The next sync will backfill the full 90-day window.', variant: 'success' })
                            job.refreshStatus()
                          } catch (err) {
                            toast({ title: 'Could not reset the watermark', description: err instanceof Error ? err.message : String(err), variant: 'error' })
                          } finally {
                            setSaving(false)
                          }
                        }}
                      >
                        Reset watermark
                      </button>
                    )}
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
                  <Play size={12} aria-hidden="true" /> {isRunning ? 'Syncing…' : 'Sync now'}
                </button>

                {/* FE-15: the evidence-chain check, reachable from the UI. */}
                <div className="card p-2.5 flex flex-col gap-2">
                  <div className="text-xs font-medium text-text flex items-center gap-1.5">
                    <ShieldCheck size={13} aria-hidden="true" /> Evidence chain
                  </div>
                  <p className="text-[0.6875rem] text-text-dim">
                    Checks that this archive's ingestion records still link up end to end.
                    {canAdminFrom(whoami) && ' The deep check also re-reads every sealed event and can take a while on a large archive.'}
                  </p>
                  <div className="flex flex-wrap gap-2">
                    <button
                      type="button"
                      className="btn-secondary text-xs"
                      disabled={integrity.state.phase === 'checking'}
                      onClick={() => integrity.run(false)}
                    >
                      {integrity.state.phase === 'checking' && !integrity.state.deep ? 'Checking…' : 'Verify'}
                    </button>
                    {canAdminFrom(whoami) && (
                      <button
                        type="button"
                        className="btn-secondary text-xs"
                        disabled={integrity.state.phase === 'checking'}
                        onClick={() => integrity.run(true)}
                      >
                        {integrity.state.phase === 'checking' && integrity.state.deep ? 'Deep check running…' : 'Deep check'}
                      </button>
                    )}
                  </div>
                  <IntegrityResultView state={integrity.state} />
                </div>
              </div>

              <div className="flex justify-end gap-2 mt-5">
                <Dialog.Close asChild>
                  <button type="button" className="btn-secondary">Cancel</button>
                </Dialog.Close>
                {/* Save waits for the sync status to have loaded: the first-run
                    prompt keys off is_first_sync, and saving before that answer
                    exists would skip the prompt for a brand-new environment. */}
                <button
                  type="button"
                  className="btn-primary"
                  disabled={saving || !job.statusLoaded}
                  title={!job.statusLoaded ? 'Loading sync status…' : undefined}
                  onClick={handleSaveClick}
                >
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
                      Already have a System Log CSV export? Drop it in the project folder, then pick it below — zero API calls.
                    </div>
                    {firstRunChoice === 'csv' && (
                      <Select
                        value={csvFile}
                        onValueChange={setCsvFile}
                        ariaLabel="System Log CSV file to import"
                        placeholder="Choose a .csv file from the project folder"
                        options={(csvFiles ?? []).map(f => ({ value: f, label: f }))}
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
                  disabled={saving || (firstRunChoice === 'csv' && !csvFile)}
                  onClick={handleFirstRunContinue}
                >
                  Continue
                </button>
              </div>
            </>
          )}
    </>
  )
}
