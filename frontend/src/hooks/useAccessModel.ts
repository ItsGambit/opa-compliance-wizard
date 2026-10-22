import { createContext, useContext } from 'react'
import type { AccessModel } from '../types'
import type { useAccessScanJob } from './useAccessScanJob'

type Job = ReturnType<typeof useAccessScanJob>

/** What is known about the scan on screen: when it was read, where it came from, and whether it was corrected since. */
export interface AccessModelMeta {
  built_at: string
  source: 'memory' | 'cache'
  /** Set when a local correction (a user removed from a group) changed the scan after it was read. */
  modified_at: string | null
}

export interface AccessModelContextValue {
  job: Job
  /** The stored (or last scanned) model; stays on screen during a refresh. */
  model: AccessModel | null
  meta: AccessModelMeta | null
  /** True while the stored scan is being opened (before it is known whether one exists). */
  loading: boolean
  /** Why the stored scan could not be opened (nothing was ever scanned in that case), or null. */
  loadError: string | null
  /** Opens the stored scan, or starts the first scan when none was ever stored. Does nothing if that already happened. */
  ensureLoaded: () => void
  /** Reads OPA again (the OPA part of the refresh). */
  refresh: () => void
  /** Stops the refresh that is running. */
  stop: () => void
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
