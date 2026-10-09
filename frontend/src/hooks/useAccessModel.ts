import { createContext, useContext } from 'react'
import type { AccessModel } from '../types'
import type { useAccessBootstrapJob } from './useAccessBootstrapJob'

type Job = ReturnType<typeof useAccessBootstrapJob>

export interface AccessModelContextValue {
  job: Job
  /** The last successfully loaded model; stays on screen during a refresh. */
  model: AccessModel | null
  /** Starts the first load if nothing has been loaded or started yet. */
  ensureLoaded: () => void
  refresh: () => void
  /** Local correction after a successful "remove from group". */
  updateModel: (update: (model: AccessModel) => AccessModel) => void
}

/** Provided by components/AccessModelProvider (UI-10). */
export const AccessModelContext = createContext<AccessModelContextValue | null>(null)

export function useAccessModel(): AccessModelContextValue {
  const ctx = useContext(AccessModelContext)
  if (!ctx) throw new Error('useAccessModel must be used inside <AccessModelProvider>')
  return ctx
}
