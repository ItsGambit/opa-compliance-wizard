import { Fragment, useState, type ReactNode } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { removeEnvironmentScopedQueries } from '../api/queryClient'

/** UI-05 (external review, 2026-10-05): everything below is tenant-scoped.
 * When `scopeKey` changes (another environment, or the same environment
 * reconnected to a different OPA team/Okta org), the old tenant's cached
 * queries are removed BEFORE any child renders again, and the children
 * are remounted, so no screen, selection, poll or cached list from the
 * previous tenant survives under the new name.
 *
 * Why during render and not in an effect: a remounted child subscribes to
 * its query in its own effect, which runs before a parent's effect -- it
 * would read the old tenant's still-fresh cache entry, and TanStack does
 * not notify an observer when its query is later removed. This is React's
 * documented "adjust state when a prop changes" pattern: the pass that
 * sees the new key renders nothing and records it; the next pass mounts
 * the children against an empty cache. Removing queries is idempotent, so
 * a StrictMode double render is harmless. */
export function EnvironmentScope({ scopeKey, children }: { scopeKey: string | undefined; children: ReactNode }) {
  const queryClient = useQueryClient()
  const [renderedKey, setRenderedKey] = useState(scopeKey)
  if (scopeKey !== renderedKey) {
    if (renderedKey !== undefined) removeEnvironmentScopedQueries(queryClient)
    setRenderedKey(scopeKey)
    return null
  }
  return <Fragment key={renderedKey ?? ''}>{children}</Fragment>
}
