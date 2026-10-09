import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import { useAccessBootstrapJob } from '../hooks/useAccessBootstrapJob'
import { AccessModelContext } from '../hooks/useAccessModel'
import type { AccessModel } from '../types'

/** UI-10 (external review, 2026-10-05): the Access Explorer's model and
 * its bootstrap job used to live in AccessExplorer itself, which unmounts
 * on every switch to another page -- coming back re-ran the whole tenant
 * scan (~30 s+, a full sweep of OPA and Okta) and lost local corrections.
 * They live here instead, above the page switch, so they survive tab
 * changes. App mounts this inside the content keyed by the active
 * environment (UI-05), so a different environment always starts empty. The
 * first load still starts only when the Access Explorer is first opened. */
export function AccessModelProvider({ children }: { children: ReactNode }) {
  const job = useAccessBootstrapJob()
  const [model, setModel] = useState<AccessModel | null>(null)
  const started = useRef(false)
  const { start } = job

  // If the provider itself unmounts (or StrictMode simulates it), the job
  // hook has cancelled its request; the next ensureLoaded must start again
  // instead of waiting forever on a start whose answer is discarded.
  useEffect(() => () => { started.current = false }, [])

  useEffect(() => {
    if (job.phase === 'done' && job.result) setModel(job.result)
  }, [job.phase, job.result])

  const ensureLoaded = useCallback(() => {
    if (started.current) return
    started.current = true
    start()
  }, [start])

  const refresh = useCallback(() => {
    started.current = true
    start()
  }, [start])

  const updateModel = useCallback((update: (m: AccessModel) => AccessModel) => {
    setModel(prev => (prev ? update(prev) : prev))
  }, [])

  return (
    <AccessModelContext.Provider value={{ job, model, ensureLoaded, refresh, updateModel }}>
      {children}
    </AccessModelContext.Provider>
  )
}
