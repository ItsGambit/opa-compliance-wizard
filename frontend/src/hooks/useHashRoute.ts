import { useCallback, useEffect, useMemo, useState } from 'react'
import { type AppRoute, type RouteVocabulary, parseRoute, routeToHash, sameRoute } from '../utils/route'

/** The app's navigation state, backed by the URL hash (5.40.1).
 *
 * The hash is the single source of truth: `navigate` only writes the
 * hash (which creates a real browser history entry), and the state is
 * re-derived from the hash on every `hashchange` -- the ones the browser
 * fires for Back/Forward included. So the mouse back button on a
 * compliance report returns to the reports home instead of leaving the
 * site, and reload / a pasted link land on the same view.
 *
 * On first render an empty or unknown hash is REPLACED (not pushed) with
 * the canonical default hash, so the initial view doesn't become an
 * extra history entry behind itself. */
export function useHashRoute(vocab: RouteVocabulary) {
  const [route, setRoute] = useState<AppRoute>(() => parseRoute(window.location.hash, vocab))

  useEffect(() => {
    const canonical = routeToHash(parseRoute(window.location.hash, vocab), vocab)
    if (window.location.hash !== canonical) {
      // Normalise without adding a history entry (e.g. "#" or "#/reports"
      // -> "#/reports/browse").
      window.history.replaceState(window.history.state, '', canonical)
    }
    const onHashChange = () =>
      setRoute(prev => {
        const next = parseRoute(window.location.hash, vocab)
        return sameRoute(prev, next) ? prev : next
      })
    window.addEventListener('hashchange', onHashChange)
    return () => window.removeEventListener('hashchange', onHashChange)
  }, [vocab])

  const navigate = useCallback(
    (patch: Partial<AppRoute>) => {
      const next = { ...route, ...patch }
      // Leaving the browse sub-tab (or the reports tab) closes any open
      // report; switching to another tab never carries a stale key along.
      if (next.tab !== 'reports' || next.reportsSubTab !== vocab.reportsSubTabs[0]) next.reportKey = null
      const hash = routeToHash(next, vocab)
      // Pushes a history entry; the hashchange listener above updates
      // `route`. A no-op navigation (same hash) adds nothing.
      if (window.location.hash !== hash) window.location.hash = hash
    },
    [route, vocab]
  )

  return useMemo(() => ({ route, navigate }), [route, navigate])
}
