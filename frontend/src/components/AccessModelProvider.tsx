import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import { fetchAccessModel, ApiError } from '../api/client'
import { useEnvironments } from '../api/hooks'
import { useAccessScanJob } from '../hooks/useAccessScanJob'
import { AccessModelContext, type AccessModelMeta } from '../hooks/useAccessModel'
import { useRefreshStatus } from '../hooks/useRefresh'
import type { AccessModel, AccessModelResponse } from '../types'

/** UI-10 (external review, 2026-10-05): the Access Explorer's model and its job live above the page switch, so they survive tab
 * changes. App mounts this inside the content keyed by the active environment (UI-05), so a different environment always starts empty.
 *
 * 5.51.0: the model comes from the stored OPA scan (GET /api/access/model), so opening the Explorer is instant, also after a restart;
 * the first scan runs only when none was ever stored (404 no_scan). Refresh is the OPA part of the combined refresh. When another
 * screen's refresh (the Overview, the footer's Sync now, the schedule) stores a newer scan, the model is reloaded from the store. */
export function AccessModelProvider({ children }: { children: ReactNode }) {
  const { data: environments } = useEnvironments()
  const environment = environments?.active ?? undefined
  const job = useAccessScanJob()
  const [model, setModel] = useState<AccessModel | null>(null)
  const [meta, setMeta] = useState<AccessModelMeta | null>(null)
  const [loading, setLoading] = useState(false)
  const [loadError, setLoadError] = useState<string | null>(null)
  const started = useRef(false)
  const loadGeneration = useRef(0)
  const { start } = job
  const { data: refreshStatus } = useRefreshStatus(environment)

  // If the provider itself unmounts (or StrictMode simulates it), the pending load is dropped; the next ensureLoaded must start again.
  useEffect(() => () => {
    started.current = false
    loadGeneration.current += 1
  }, [])

  const adopt = useCallback((r: AccessModelResponse) => {
    setModel(r.model)
    setMeta({ built_at: r.built_at, source: r.source, modified_at: r.modified_at })
  }, [])

  useEffect(() => {
    if (job.phase === 'done' && job.result) adopt(job.result)
  }, [job.phase, job.result, adopt])

  const scan = useCallback(() => {
    if (environment) start(environment)
  }, [environment, start])

  const ensureLoaded = useCallback(() => {
    if (started.current || !environment) return
    started.current = true
    loadGeneration.current += 1
    const gen = loadGeneration.current
    setLoading(true)
    setLoadError(null)
    fetchAccessModel()
      .then(r => { if (gen === loadGeneration.current) { adopt(r); setLoading(false) } })
      .catch(err => {
        if (gen !== loadGeneration.current) return
        setLoading(false)
        // No scan was ever stored for this environment: read OPA now. Anything else is shown by the panel as a failed first load.
        if (err instanceof ApiError && err.status === 404 && err.body?.reason === 'no_scan') scan()
        else setLoadError(err instanceof Error ? err.message : String(err))
      })
  }, [environment, adopt, scan])

  const refresh = useCallback(() => {
    if (loadError && !model) {  // the stored scan could not even be opened: try opening it again
      started.current = false
      ensureLoaded()
      return
    }
    started.current = true
    scan()
  }, [scan, loadError, model, ensureLoaded])

  // Another screen's refresh stored a newer OPA scan: show it.
  const builtAt = meta?.built_at
  const jobPhase = job.phase
  useEffect(() => {
    if (!refreshStatus || refreshStatus.status !== 'done' || !started.current || jobPhase === 'starting' || jobPhase === 'running') return
    const part = refreshStatus.parts.opa
    if (part.state !== 'ok' || !part.built_at || !builtAt || part.built_at === builtAt) return
    const gen = loadGeneration.current
    fetchAccessModel().then(r => { if (gen === loadGeneration.current) adopt(r) }).catch(() => {})
  }, [refreshStatus, builtAt, jobPhase, adopt])

  const updateModel = useCallback((update: (m: AccessModel) => AccessModel) => {
    setModel(prev => (prev ? update(prev) : prev))
    setMeta(prev => (prev ? { ...prev, modified_at: new Date().toISOString() } : prev))
  }, [])

  return (
    <AccessModelContext.Provider value={{ job, model, meta, loading, loadError, ensureLoaded, refresh, updateModel }}>
      {children}
    </AccessModelContext.Provider>
  )
}
