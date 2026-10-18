import type { AccessPolicy, NamedRef, PolicyRule, PolicyRuleResolution, ResourceAccessInfo } from '../types'
import { labelize } from './format'
import { describeCondition, type GrantedRule } from './policy'

/** The Access Explorer shows access RESOURCE-first: one row per resource
 * (a server, an account, a secret ...) instead of one card per policy rule.
 * This module turns the (policy, rule) grants every view already computes
 * (rulesGrantedToGroupIds, rulesGrantedForProject ...) into those rows. No
 * data is dropped: every contributing (policy, rule) stays on the resource
 * as a `GrantLine`. */

/** One (policy, rule) that gives access to a resource. */
export interface GrantLine {
  policy: AccessPolicy
  rule: PolicyRule
  /** The groups through which this view's subject gets this grant. */
  groups: NamedRef[]
  /** Resources the rule also covers that this view does not list
   * (non-zero only when the view filters resolutions, e.g. one project). */
  othersCount: number
}

export interface AccessResource {
  key: string
  /** Section id and title: the rule's resource type ("Servers" ...). */
  typeId: string
  typeLabel: string
  name: string
  /** Short muted qualifier next to the name (project, "selector" ...). */
  hint?: string
  resolution: PolicyRuleResolution
  lines: GrantLine[]
  /** Plain-words actions, de-duplicated across every line. */
  actions: string[]
  /** Conditions, de-duplicated across every line. */
  conditions: string[]
  /** True when at least one way to get this resource needs neither MFA nor
   * an access request (approval). */
  risky: boolean
  viaNames: string[]
  policyNames: string[]
}

// Resource kinds with a verified, working System Log mapping -- see
// create_secret_folders.py's RESOURCE_ACCESS_EVENT_TYPES.
export const TRACKABLE_KINDS = new Set([
  'secret',
  'individual_server_account',
  'individual_managed_saas_app_account',
  'individual_unmanaged_saas_app_account',
  'individual_okta_account',
])

/** UI-12 (external review, 2026-10-05): the state of the per-user "last
 * accessed" lookup, not just its results -- a failed or disabled lookup
 * used to leave every row reading "loading…" forever. */
export type AccessLookup =
  | { status: 'loading' }
  | { status: 'error'; message: string; onRetry: () => void; retrying?: boolean }
  | { status: 'ready'; byId: Map<string, ResourceAccessInfo> }

const PRIVILEGE_PHRASE: Record<string, string> = {
  reveal_password: 'View the password',
  rotate_password: 'Rotate the password',
  password_checkout_ssh: 'Check out the password for SSH',
  password_checkout_rdp: 'Check out the password for RDP',
  principal_account_ssh: 'SSH as a named user',
  principal_account_rdp: 'RDP as a named user',
  checkout_account: 'Check out the account',
}

const SECRET_FLAG_PHRASE: Record<string, string> = {
  list: 'List',
  secret_reveal: 'View secrets',
  secret_create: 'Create secrets',
  secret_update: 'Edit secrets',
  secret_delete: 'Delete secrets',
  folder_create: 'Create folders',
  folder_update: 'Edit folders',
  folder_delete: 'Delete folders',
}

/** Plain-words actions for one rule's privileges. Unknown privilege types
 * fall back to a readable form of their own name, never to nothing; the raw
 * type and flags are still shown in the expanded view. */
export function describeActions(rule: PolicyRule): string[] {
  const out: string[] = []
  for (const p of rule.privileges) {
    if (p.privilege_type === 'secret') {
      for (const f of p.flags) out.push(SECRET_FLAG_PHRASE[f] ?? labelize(f))
      continue
    }
    const base = PRIVILEGE_PHRASE[p.privilege_type] ?? labelize(p.privilege_type)
    if (p.flags.includes('admin_level_permissions') && /^(principal_account_)(ssh|rdp)$/.test(p.privilege_type)) {
      out.push(p.privilege_type.endsWith('ssh') ? 'SSH as admin' : 'RDP as admin')
    } else {
      out.push(base)
    }
  }
  return out
}

/** "Technical" privilege text, exactly what the old rule card showed. */
export function describePrivilegeRaw(p: { privilege_type: string; flags: string[] }): string {
  return `${p.privilege_type}${p.flags.length > 0 ? `: ${p.flags.join(', ')}` : ''}`
}

export function ruleHasApprovalOrMfa(rule: PolicyRule): boolean {
  return rule.conditions.some(c => c.condition_type === 'mfa' || c.condition_type === 'access_request')
}

function slug(text: string): string {
  return text.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'other'
}

function unique<T>(items: T[]): T[] {
  return [...new Set(items)]
}

export interface AggregateOptions {
  /** Which of the policy's groups to credit as "how they get it". */
  groupsFor?: (policy: AccessPolicy) => NamedRef[]
  /** Keep only some of a rule's resolutions (e.g. one project's). A
   * condition (selector) resolution is always kept. */
  includeResolution?: (res: PolicyRuleResolution & { kind: 'resolved' }) => boolean
}

export function aggregateResources(grants: GrantedRule[], options: AggregateOptions = {}): AccessResource[] {
  const groupsFor = options.groupsFor ?? ((policy: AccessPolicy) => policy.principals.user_groups)
  const byKey = new Map<string, AccessResource>()
  for (const { policy, rule } of grants) {
    const typeLabel = rule.resource_type_label || rule.resource_type || 'Other'
    const typeId = slug(typeLabel)
    const kept = rule.resolutions.filter(r => r.kind !== 'resolved' || !options.includeResolution || options.includeResolution(r))
    const othersCount = rule.resolutions.length - kept.length
    for (const res of kept) {
      const key = res.kind === 'resolved' ? `${typeId}|${res.resource_kind}|${res.id}` : `${typeId}|cond|${res.description}`
      let item = byKey.get(key)
      if (!item) {
        const name = res.kind === 'resolved' ? res.name : res.description
        const hint =
          res.kind === 'condition'
            ? 'selector'
            : [res.resource_kind === 'secret_folder' ? 'folder' : null, res.project_name].filter(Boolean).join(' · ') || undefined
        item = {
          key, typeId, typeLabel, name, hint, resolution: res, lines: [], actions: [], conditions: [], risky: false, viaNames: [], policyNames: [],
        }
        byKey.set(key, item)
      }
      if (!item.lines.some(l => l.policy === policy && l.rule === rule)) {
        item.lines.push({ policy, rule, groups: groupsFor(policy), othersCount })
      }
    }
  }
  const out = [...byKey.values()]
  for (const item of out) {
    item.actions = unique(item.lines.flatMap(l => describeActions(l.rule)))
    item.conditions = unique(item.lines.flatMap(l => l.rule.conditions.map(describeCondition)))
    item.risky = item.lines.some(l => !ruleHasApprovalOrMfa(l.rule))
    item.viaNames = unique(item.lines.flatMap(l => l.groups.map(g => g.name)))
    item.policyNames = unique(item.lines.map(l => l.policy.name))
  }
  // Types keep the order in which the grants first mention them; resources
  // sort by name inside their type.
  const typeOrder = new Map<string, number>()
  for (const item of out) if (!typeOrder.has(item.typeId)) typeOrder.set(item.typeId, typeOrder.size)
  out.sort((a, b) => (typeOrder.get(a.typeId)! - typeOrder.get(b.typeId)!) || a.name.localeCompare(b.name))
  return out
}

export interface ResourceSection {
  id: string
  title: string
  resources: AccessResource[]
}

/** Group by resource type, in first-seen order. */
export function sectionsByType(resources: AccessResource[]): ResourceSection[] {
  const sections = new Map<string, ResourceSection>()
  for (const r of resources) {
    let s = sections.get(r.typeId)
    if (!s) {
      s = { id: r.typeId, title: r.typeLabel, resources: [] }
      sections.set(r.typeId, s)
    }
    s.resources.push(r)
  }
  return [...sections.values()]
}

/** "4 servers", "1 secret": lower-cased section title, singular at one. */
export function countLabel(title: string, count: number): string {
  const lower = title.toLowerCase()
  if (count === 1 && lower.endsWith('s') && !lower.endsWith('ss')) return lower.slice(0, -1)
  return lower
}

// ── Last accessed ───────────────────────────────────────────────────────────

export interface TrackTarget {
  id: string
  label: string
}

/** The System Log lookups behind one resource: the account/secret itself,
 * or -- for a folder -- every secret inside it (folder browsing is never
 * logged, reveals reference the secret). */
export function trackTargets(resource: AccessResource): TrackTarget[] {
  const res = resource.resolution
  if (res.kind !== 'resolved') return []
  if (TRACKABLE_KINDS.has(res.resource_kind)) return [{ id: res.access_tracking_id ?? res.id, label: res.name }]
  if (res.resource_kind === 'secret_folder') return (res.child_secrets ?? []).map(c => ({ id: c.id, label: c.name }))
  return []
}

/** The de-duplicated request list the server lookup wants. */
export function trackedRequests(resources: AccessResource[]): { resource_kind: string; resource_id: string }[] {
  const seen = new Map<string, { resource_kind: string; resource_id: string }>()
  for (const r of resources) {
    const res = r.resolution
    if (res.kind !== 'resolved') continue
    if (TRACKABLE_KINDS.has(res.resource_kind)) {
      const id = res.access_tracking_id ?? res.id
      seen.set(id, { resource_kind: res.resource_kind, resource_id: id })
    } else if (res.resource_kind === 'secret_folder') {
      for (const child of res.child_secrets ?? []) seen.set(child.id, { resource_kind: 'secret', resource_id: child.id })
    }
  }
  return [...seen.values()]
}

export type LastUsed =
  | { state: 'used'; at: string }
  | { state: 'never' }
  | { state: 'unknown' }
  | { state: 'untracked' }
  | { state: 'loading' }
  | { state: 'error' }
  /** The view has no lookup at all (service account, or a view that never queries). */
  | { state: 'none' }

export function lastUsedFor(resource: AccessResource, lookup: AccessLookup | undefined): LastUsed {
  const targets = trackTargets(resource)
  if (targets.length === 0) return { state: lookup ? 'untracked' : 'none' }
  if (!lookup) return { state: 'none' }
  if (lookup.status === 'loading') return { state: 'loading' }
  if (lookup.status === 'error') return { state: 'error' }
  const infos = targets.map(t => lookup.byId.get(t.id)).filter((i): i is ResourceAccessInfo => !!i)
  if (infos.length === 0) return { state: 'unknown' }
  if (infos.every(i => !i.supported)) return { state: 'untracked' }
  let latest: string | null = null
  for (const i of infos) {
    for (const e of i.events) {
      if (!latest || new Date(e.published).getTime() > new Date(latest).getTime()) latest = e.published
    }
  }
  if (latest) return { state: 'used', at: latest }
  return infos.some(i => i.supported && i.complete === false) ? { state: 'unknown' } : { state: 'never' }
}
