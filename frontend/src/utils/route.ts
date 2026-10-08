// In-app navigation as URL hash routes (5.40.1). Every tab, sub-tab and
// opened compliance report maps to a hash like:
//   #/reports/browse                 Compliance Reports home
//   #/reports/browse/<report_key>    one report's detail view
//   #/reports/secrets_access         Secrets Access Dashboard
//   #/reports/service_accounts       Service Accounts Dashboard
//   #/access/<sub_tab>               Access Explorer sub-tab
//   #/builder                        Folder Builder
//   #/audit_log                      Audit Log (admin)
// Why: navigation used to live only in React state, so the browser had
// no history entry for anything inside the app -- the mouse "back"
// button on a compliance report left the site entirely instead of
// returning to the reports home. Setting the hash creates a real history
// entry per navigation, and parsing it back (see useHashRoute) makes the
// hash the single source of truth, so Back/Forward, reload and a shared
// link all land on the same view.
//
// Every segment is validated against the known values passed in (never
// trusted raw): an unknown or malformed hash falls back to the default
// view rather than rendering anything derived from the URL. A report
// key is additionally limited to [A-Za-z0-9_.-] and only ever used as a
// lookup key against the server's own report list.

export interface AppRoute {
  tab: string
  reportsSubTab: string
  accessSubTab: string
  /** Only meaningful when tab === 'reports' and reportsSubTab === 'browse'. */
  reportKey: string | null
}

export interface RouteVocabulary {
  tabs: readonly string[]
  reportsSubTabs: readonly string[]
  accessSubTabs: readonly string[]
}

const REPORT_KEY_PATTERN = /^[A-Za-z0-9_.-]{1,64}$/

export function defaultRoute(vocab: RouteVocabulary): AppRoute {
  return { tab: vocab.tabs[0], reportsSubTab: vocab.reportsSubTabs[0], accessSubTab: vocab.accessSubTabs[0], reportKey: null }
}

function segments(hash: string): string[] {
  const path = hash.replace(/^#/, '')
  if (!path.startsWith('/')) return []
  return path
    .slice(1)
    .split('/')
    .filter(Boolean)
    .map(s => {
      try {
        return decodeURIComponent(s)
      } catch {
        return ''
      }
    })
}

/** Parses a location hash into a route, falling back to the default
 * view for anything unknown. Partial hashes fill in defaults for the
 * missing levels (e.g. "#/reports" is the reports home). */
export function parseRoute(hash: string, vocab: RouteVocabulary): AppRoute {
  const route = defaultRoute(vocab)
  const [tab, second, third] = segments(hash)
  if (!tab || !vocab.tabs.includes(tab)) return route
  route.tab = tab
  if (tab === 'reports') {
    if (second && vocab.reportsSubTabs.includes(second)) route.reportsSubTab = second
    // A report key is only read behind an EXPLICIT browse segment -- an
    // unknown sub-tab must not let its trailing segment through as a key.
    if (second === vocab.reportsSubTabs[0] && third && REPORT_KEY_PATTERN.test(third)) route.reportKey = third
  } else if (tab === 'access') {
    if (second && vocab.accessSubTabs.includes(second)) route.accessSubTab = second
  }
  return route
}

/** The canonical hash for a route -- what parseRoute would read back as
 * the same route. Sub-tabs are always written (never implied), so two
 * equal routes always produce an identical hash. */
export function routeToHash(route: AppRoute, vocab: RouteVocabulary): string {
  if (route.tab === 'reports') {
    const base = `#/reports/${encodeURIComponent(route.reportsSubTab)}`
    if (route.reportsSubTab === vocab.reportsSubTabs[0] && route.reportKey) {
      return `${base}/${encodeURIComponent(route.reportKey)}`
    }
    return base
  }
  if (route.tab === 'access') return `#/access/${encodeURIComponent(route.accessSubTab)}`
  return `#/${encodeURIComponent(route.tab)}`
}

export function sameRoute(a: AppRoute, b: AppRoute): boolean {
  return a.tab === b.tab && a.reportsSubTab === b.reportsSubTab && a.accessSubTab === b.accessSubTab && a.reportKey === b.reportKey
}
