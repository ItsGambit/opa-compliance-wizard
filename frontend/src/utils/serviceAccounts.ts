import type { SecretsAccessStatus, ServiceAccountKind, ServiceAccountReportRow, ServiceAccountRotations, ServiceAccountsReport } from '../types'

// Pure helpers behind the Service Accounts Dashboard (5.40.0) -- kept out
// of the component so the filter/summary logic is unit-testable without
// rendering, same split usableEnvironments.ts uses.

export const SERVICE_ACCOUNT_KIND_LABEL: Record<ServiceAccountKind, string> = {
  saas: 'SaaS app',
  okta: 'Okta',
}

export const ALL = 'all'

export interface ServiceAccountFilters {
  kind: typeof ALL | ServiceAccountKind
  status: typeof ALL | SecretsAccessStatus
  resourceGroupId: string // ALL or a real id
  projectId: string // ALL or a real id
}

export const DEFAULT_SERVICE_ACCOUNT_FILTERS: ServiceAccountFilters = {
  kind: ALL,
  status: ALL,
  resourceGroupId: ALL,
  projectId: ALL,
}

/** Applies the structured filters (type / status / resource group /
 * project). A resource-group or project filter necessarily hides rows
 * whose account is no longer in the live roster -- those have no
 * project to match (the backend never guesses one), and the dashboard
 * says so next to the filter rather than silently dropping them. */
export function filterServiceAccountRows(rows: ServiceAccountReportRow[], filters: ServiceAccountFilters): ServiceAccountReportRow[] {
  return rows.filter(row => {
    if (filters.kind !== ALL && row.kind !== filters.kind) return false
    if (filters.status !== ALL && row.status !== filters.status) return false
    if (filters.resourceGroupId !== ALL && row.resource_group_id !== filters.resourceGroupId) return false
    if (filters.projectId !== ALL && row.project_id !== filters.projectId) return false
    return true
  })
}

/** How many accounts the resource-group / project filter is hiding for
 * the one reason it can't help: they are no longer in the live roster,
 * so they have no project to match (never guessed). Respects the other
 * structured filters so the number agrees with what the user would see
 * if they cleared just the scope. */
export function countHiddenByScope(rows: ServiceAccountReportRow[], filters: ServiceAccountFilters): number {
  if (filters.resourceGroupId === ALL && filters.projectId === ALL) return 0
  return rows.filter(
    row =>
      !row.project_id &&
      (filters.kind === ALL || row.kind === filters.kind) &&
      (filters.status === ALL || row.status === filters.status)
  ).length
}

export interface SelectChoice {
  value: string
  label: string
}

/** Resource-group and project choices derived from the rows themselves
 * (no extra API calls -- the roster walk already visited them). Projects
 * are scoped to the selected resource group when one is chosen. Each id
 * appears once, in first-seen (walk) order. */
export function serviceAccountFilterOptions(
  rows: ServiceAccountReportRow[],
  resourceGroupId: string
): { resourceGroups: SelectChoice[]; projects: SelectChoice[] } {
  const resourceGroups = new Map<string, string>()
  const projects = new Map<string, string>()
  for (const row of rows) {
    if (row.resource_group_id && !resourceGroups.has(row.resource_group_id)) {
      resourceGroups.set(row.resource_group_id, row.resource_group_name ?? row.resource_group_id)
    }
    const inScope = resourceGroupId === ALL || row.resource_group_id === resourceGroupId
    if (inScope && row.project_id && !projects.has(row.project_id)) {
      projects.set(row.project_id, row.project_name ?? row.project_id)
    }
  }
  const toChoices = (m: Map<string, string>) => [...m.entries()].map(([value, label]) => ({ value, label }))
  return { resourceGroups: toChoices(resourceGroups), projects: toChoices(projects) }
}

/** Counts for the summary tiles -- computed client-side over whatever is
 * currently shown (the API's own `summary` covers the whole tenant,
 * which is what it should say; the tiles should agree with the table). */
export function summarizeServiceAccounts(rows: ServiceAccountReportRow[]): ServiceAccountsReport['summary'] {
  const summary = { total: rows.length, saas: 0, okta: 0, active: 0, deleted: 0, unknown: 0 }
  for (const row of rows) {
    summary[row.kind] += 1
    summary[row.status] += 1
  }
  return summary
}

/** The second line under an account's name: how it's identified on its
 * own side. SaaS accounts are identified by username within an app
 * instance; Okta accounts by the Okta user they wrap. Both the OPA
 * account id and (SaaS) privileged resource id are shown in the export,
 * not here. */
export function serviceAccountIdentityLine(row: ServiceAccountReportRow): string {
  const parts: string[] = []
  if (row.username) parts.push(row.username)
  if (row.kind === 'saas' && row.app_name) parts.push(row.app_name)
  if (row.kind === 'okta' && row.okta_user_id) parts.push(row.okta_user_id)
  return parts.join(' · ')
}

/** "RG › Project", or an honest placeholder for an account that is no
 * longer in the live roster (its project genuinely isn't knowable from
 * the archive -- see walk_service_account_rosters). */
export function serviceAccountScopeLine(row: ServiceAccountReportRow): string {
  if (!row.resource_group_name && !row.project_name) return ''
  return [row.resource_group_name, row.project_name].filter(Boolean).join(' › ')
}

/** e.g. "14 · 12 SUCCESS, 2 FAILURE" -- totals by outcome, SUCCESS first,
 * then the rest alphabetically so the string is stable. */
export function rotationSummaryLine(rotations: ServiceAccountRotations): string {
  if (rotations.total === 0) return ''
  const outcomes = Object.entries(rotations.by_outcome).sort(([a], [b]) => {
    if (a === 'SUCCESS') return -1
    if (b === 'SUCCESS') return 1
    return a.localeCompare(b)
  })
  const breakdown = outcomes.map(([outcome, n]) => `${n} ${outcome}`).join(', ')
  return outcomes.length > 1 || outcomes[0]?.[0] !== 'SUCCESS'
    ? `${rotations.total} · ${breakdown}`
    : String(rotations.total)
}
