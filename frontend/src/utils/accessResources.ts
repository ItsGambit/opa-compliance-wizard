import type { AccessPolicy, NamedRef, PolicyRule, PolicyRuleResolution, ResourceAccessInfo } from '../types'
import { labelize } from './format'
import { describeCondition, isPolicyActive, type GrantedRule } from './policy'

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
  /** The policy is switched off: this line gives no access right now. */
  inactive: boolean
}

/** The muted qualifier shown beside a resolved account's name. An Active
 * Directory account shows only its own name in the row (the domain is in the
 * opened row, see ResourceAccessView), so it gets none here. */
export function rowQualifier(res: { resource_kind: string; sub_label?: string | null }): string | null | undefined {
  return res.resource_kind === 'individual_active_directory_account' ? null : res.sub_label
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
  /** True when at least one way to get this resource, through an ACTIVE
   * policy, needs neither MFA nor an access request (approval). An inactive
   * policy gives no access, so it never makes a resource risky. */
  risky: boolean
  /** Every policy behind this resource is inactive: shown, but not in effect. */
  inactiveOnly: boolean
  viaNames: string[]
  policyNames: string[]
  /** The rule selector text(s) that matched this named account (empty for
   * everything else). Searchable and shown in the opened row. */
  selectors: string[]
  /** 5.45.1: for a selector row, why it is not listed by name and the
   * candidate names the resolver found but could not confirm. */
  unresolvedReasons: string[]
  candidates: string[]
  /** Server scopes of a named Active Directory account, and the servers
   * they name; `scopeNotes` says why the servers could not be named. */
  scopes: string[]
  scopeServers: string[]
  scopeNotes: string[]
  /** Notes such as "Matched by OS name (inferred)". */
  matchNotes: string[]
}

/** How many candidate names a selector row shows beside its rule text. */
export const CANDIDATE_PREVIEW = 3

export function candidatePreview(names: string[]): string {
  if (names.length === 0) return ''
  const shown = names.slice(0, CANDIDATE_PREVIEW).join(', ')
  return names.length > CANDIDATE_PREVIEW ? `${shown} +${names.length - CANDIDATE_PREVIEW} more` : shown
}

/** Database and Active Directory access rules are selectors (connections or
 * domains plus account-name conditions), so there is no single account to
 * look up. Each server kind (`database_account`, `active_directory_account`)
 * means "any account of that family this user accessed" and answers under one
 * virtual id. See create_secret_folders.py's *_ANY_ID constants. */
export const DATABASE_ACCOUNT_KIND = 'database_account'
export const DATABASE_ACCOUNT_ANY_ID = 'database_accounts'
export const ACTIVE_DIRECTORY_ACCOUNT_KIND = 'active_directory_account'
export const ACTIVE_DIRECTORY_ACCOUNT_ANY_ID = 'active_directory_accounts'
export const DATABASE_ACCESS_LABEL =
  "Any database account this user accessed (the rule is a selector, so this is not limited to the rule's connection or name pattern)"
export const ACTIVE_DIRECTORY_ACCESS_LABEL =
  "Any Active Directory account this user revealed (the rule is a selector, so not limited to the rule's domain or name pattern)"

const SELECTOR_FAMILIES = [
  { ruleType: 'database_based_resource', kind: DATABASE_ACCOUNT_KIND, anyId: DATABASE_ACCOUNT_ANY_ID, label: DATABASE_ACCESS_LABEL },
  { ruleType: 'active_directory_based_resource', kind: ACTIVE_DIRECTORY_ACCOUNT_KIND, anyId: ACTIVE_DIRECTORY_ACCOUNT_ANY_ID, label: ACTIVE_DIRECTORY_ACCESS_LABEL },
]

/** The account family a selector row (a condition, not one account) tracks
 * as a whole, or undefined for any other row. */
export function selectorFamily(resource: AccessResource) {
  if (resource.resolution.kind !== 'condition') return undefined
  return SELECTOR_FAMILIES.find(f => resource.lines.some(l => l.rule.resource_type === f.ruleType))
}

export function isDatabaseSelector(resource: AccessResource): boolean {
  return selectorFamily(resource)?.kind === DATABASE_ACCOUNT_KIND
}

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

/** A resource's display name: the stored name, else its id; "(deleted)" when
 * the model says the object is in no project any more. A null name used to
 * crash the sort in aggregateResources. */
export function resourceDisplayName(res: { name?: string | null; id: string; missing?: boolean }): string {
  const base = res.name || res.id || 'Unnamed'
  return res.missing ? `${base} (deleted)` : base
}

function shortId(id: string): string {
  return id.length > 8 ? id.slice(0, 8) : id
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
        const name = res.kind === 'resolved' ? resourceDisplayName(res) : res.description
        const hint =
          res.kind === 'condition'
            ? 'selector'
            : [rowQualifier(res), res.resource_kind === 'secret_folder' ? 'folder' : null, res.project_name].filter(Boolean).join(' · ') || undefined
        item = {
          key, typeId, typeLabel, name, hint, resolution: res, lines: [], actions: [], conditions: [], risky: false, inactiveOnly: false, viaNames: [], policyNames: [], selectors: [],
          unresolvedReasons: [], candidates: [], scopes: [], scopeServers: [], scopeNotes: [], matchNotes: [],
        }
        byKey.set(key, item)
      }
      if (res.kind === 'resolved' && res.via_selector && !item.selectors.includes(res.via_selector)) item.selectors.push(res.via_selector)
      const addAll = (list: string[], values: (string | undefined)[]) => {
        for (const v of values) if (v && !list.includes(v)) list.push(v)
      }
      if (res.kind === 'condition') {
        addAll(item.unresolvedReasons, [res.unresolved_reason?.text])
        addAll(item.candidates, res.candidates ?? [])
        addAll(item.scopes, [res.scope_text])
        addAll(item.scopeServers, res.scope_servers ?? [])
      } else {
        addAll(item.scopes, [res.scope_text])
        addAll(item.scopeServers, res.scope_servers ?? [])
        addAll(item.scopeNotes, [res.scope_reason?.text])
        addAll(item.matchNotes, [res.inferred ? 'Matched by OS name (inferred)' : undefined, res.match_note])
      }
      if (!item.lines.some(l => l.policy === policy && l.rule === rule)) {
        item.lines.push({ policy, rule, groups: groupsFor(policy), othersCount, inactive: !isPolicyActive(policy) })
      }
    }
  }
  const out = [...byKey.values()]
  for (const item of out) {
    item.actions = unique(item.lines.flatMap(l => describeActions(l.rule)))
    item.conditions = unique(item.lines.flatMap(l => l.rule.conditions.map(describeCondition)))
    item.inactiveOnly = item.lines.length > 0 && item.lines.every(l => l.inactive)
    item.risky = item.lines.some(l => !l.inactive && !ruleHasApprovalOrMfa(l.rule))
    item.viaNames = unique(item.lines.flatMap(l => l.groups.map(g => g.name)))
    item.policyNames = unique(item.lines.map(l => l.policy.name))
    if (item.resolution.kind === 'condition' && item.candidates.length > 0) {
      item.hint = [item.hint, `possibly: ${candidatePreview(item.candidates)}`].filter(Boolean).join(' · ')
    }
    if (item.inactiveOnly) item.hint = [item.hint, 'inactive policy'].filter(Boolean).join(' · ')
  }
  // Two rows with the same name in one section (two secrets, two accounts
  // ...): the short id tells them apart.
  const sameName = new Map<string, AccessResource[]>()
  for (const item of out) {
    const k = `${item.typeId}|${item.name.toLowerCase()}`
    sameName.set(k, [...(sameName.get(k) ?? []), item])
  }
  for (const group of sameName.values()) {
    if (group.length < 2) continue
    for (const item of group) {
      if (item.resolution.kind === 'resolved') item.hint = [item.hint, `#${shortId(item.resolution.id)}`].filter(Boolean).join(' · ')
    }
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
  /** 'account_selector': the answer lists events per account name, not one resource. */
  kind?: 'account_selector'
}

/** The de-duplicated request list the server lookup wants. */
export interface TrackedRequest {
  resource_kind: string
  resource_id: string
  /** Database / Active Directory / server accounts: lets the server also match
   * the System Log by the exact account name, but only when `name_unique`
   * says no other account of that kind has that name. */
  account_name?: string
  name_unique?: boolean
  /** Server accounts: the server the account is on. */
  server_id?: string
}

/** Why a resource has nothing to look up. 'unknown' = it should be trackable
 * but could not be matched; 'untracked' = the System Log has nothing for it. */
export interface TrackGap {
  state: 'unknown' | 'untracked'
  reason: string
}

export interface Tracking {
  targets: TrackTarget[]
  requests: TrackedRequest[]
  gap?: TrackGap
}

const PLAIN_ID = /^[A-Za-z0-9_-]{1,128}$/

/** A short stable hash (FNV-1a, 32 bit, hex) used to build lookup keys for
 * things that have no id of their own (a server account is "server + user
 * name"; a shared Active Directory account is only a name). Keys must stay
 * plain identifiers, so the server accepts them. */
export function fnvHex(text: string): string {
  let h = 0x811c9dc5
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i)
    h = Math.imul(h, 0x01000193) >>> 0
  }
  return h.toString(16).padStart(8, '0')
}

/** relationship_assignment:secret behaves exactly like a secret granted by a rule. */
function baseKind(kind: string): string {
  return kind.startsWith('relationship_assignment:') ? kind.slice('relationship_assignment:'.length) : kind
}

const SAAS_OKTA_KINDS = new Set(['individual_managed_saas_app_account', 'individual_unmanaged_saas_app_account', 'individual_okta_account'])
const NAMED_ACCOUNT_KINDS = new Set(['individual_database_account', 'individual_active_directory_account'])

export const NOT_TRACKED_REASON = 'The System Log does not record access per resource of this kind.'
export const NO_TRACKING_ID_REASON = 'Could not match this account to the System Log: its tracking id was not found.'
export const UNRESOLVED_FOLDER_REASON = 'This folder was not found in the loaded projects, so the secrets inside it are not known.'
export const EMPTY_FOLDER_REASON = 'This folder is empty, so there is nothing to track.'

/** Everything the lookup needs for one resource, and why when there is nothing. */
export function trackingFor(resource: AccessResource): Tracking {
  const res = resource.resolution
  const family = selectorFamily(resource)
  if (family) {
    return { targets: [{ id: family.anyId, label: family.label, kind: 'account_selector' }], requests: [{ resource_kind: family.kind, resource_id: family.anyId }] }
  }
  if (res.kind !== 'resolved') return { targets: [], requests: [], gap: { state: 'untracked', reason: NOT_TRACKED_REASON } }
  const kind = baseKind(res.resource_kind)
  const label = resourceDisplayName(res)
  const single = (request: TrackedRequest): Tracking => ({ targets: [{ id: request.resource_id, label }], requests: [request] })

  if (kind === 'secret') return single({ resource_kind: 'secret', resource_id: res.id })
  if (kind === 'secret_folder') {
    // No child_secrets key at all = the folder could not be resolved; an empty
    // list = it was found and has no secrets. They are different answers.
    if (res.child_secrets === undefined) return { targets: [], requests: [], gap: { state: 'unknown', reason: UNRESOLVED_FOLDER_REASON } }
    if (res.child_secrets.length === 0) return { targets: [], requests: [], gap: { state: 'untracked', reason: EMPTY_FOLDER_REASON } }
    return {
      targets: res.child_secrets.map(c => ({ id: c.id, label: c.name })),
      requests: res.child_secrets.map(c => ({ resource_kind: 'secret', resource_id: c.id })),
    }
  }
  if (SAAS_OKTA_KINDS.has(kind)) {
    // The Okta-side id (res.id) is never a System Log target, so it is NOT a
    // fallback: without the account's own tracking id there is nothing to match.
    if (!res.access_tracking_id) return { targets: [], requests: [], gap: { state: 'unknown', reason: NO_TRACKING_ID_REASON } }
    return single({ resource_kind: kind, resource_id: res.access_tracking_id })
  }
  if (NAMED_ACCOUNT_KINDS.has(kind)) {
    const id = res.access_tracking_id ?? (PLAIN_ID.test(res.id) ? res.id : `shared-${fnvHex(res.account_name ?? res.id)}`)
    const request: TrackedRequest = { resource_kind: kind, resource_id: id }
    if (res.account_name) {
      request.account_name = res.account_name
      request.name_unique = res.name_unique === true
    }
    return single(request)
  }
  if (kind === 'individual_server_account') {
    const serverId = res.server_id ?? res.id
    if (!PLAIN_ID.test(serverId)) return { targets: [], requests: [], gap: { state: 'untracked', reason: NOT_TRACKED_REASON } }
    if (!res.account_name) return single({ resource_kind: kind, resource_id: serverId })
    return single({
      resource_kind: kind, resource_id: `${serverId}-${fnvHex(res.account_name)}`, server_id: serverId,
      account_name: res.account_name, name_unique: res.name_unique === true,
    })
  }
  return { targets: [], requests: [], gap: { state: 'untracked', reason: NOT_TRACKED_REASON } }
}

/** The System Log lookups behind one resource: the account/secret itself,
 * or -- for a folder -- every secret inside it (folder browsing is never
 * logged, reveals reference the secret). */
export function trackTargets(resource: AccessResource): TrackTarget[] {
  return trackingFor(resource).targets
}

export function trackedRequests(resources: AccessResource[]): TrackedRequest[] {
  const seen = new Map<string, TrackedRequest>()
  for (const r of resources) for (const request of trackingFor(r).requests) seen.set(request.resource_id, request)
  return [...seen.values()]
}

export type LastUsed =
  | {
      state: 'used'
      at: string
      /** Matched events in the window (more than the few the row can list). */
      uses?: number
      windowDays?: number
      eventTypes?: string[]
      /** Selector row: the time is the newest of ANY account of that family. */
      anyAccount?: boolean
      /** A live event newer than the archive's last synced event is included. */
      newerThanSync?: boolean
    }
  | { state: 'never'; windowDays?: number; eventTypes?: string[]; anyAccount?: boolean }
  | { state: 'unknown'; reason?: string }
  /** No event matched by id, but another account shares this account's name and has events: cannot tell which was used. */
  | { state: 'ambiguous' }
  | { state: 'untracked'; reason?: string }
  | { state: 'loading' }
  | { state: 'error' }
  /** The view has no lookup at all (service account, or a view that never queries). */
  | { state: 'none' }

/** Only the defined entries, so a plain answer stays a plain object. */
function defined<T extends object>(o: T): Partial<T> {
  return Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined)) as Partial<T>
}

export function lastUsedFor(resource: AccessResource, lookup: AccessLookup | undefined): LastUsed {
  const tracking = trackingFor(resource)
  const targets = tracking.targets
  if (targets.length === 0) {
    if (!lookup) return { state: 'none' }
    // Only the cases with something specific to say carry a reason.
    if (tracking.gap?.state === 'unknown') return { state: 'unknown', reason: tracking.gap.reason }
    return tracking.gap && tracking.gap.reason !== NOT_TRACKED_REASON ? { state: 'untracked', reason: tracking.gap.reason } : { state: 'untracked' }
  }
  if (!lookup) return { state: 'none' }
  if (lookup.status === 'loading') return { state: 'loading' }
  if (lookup.status === 'error') return { state: 'error' }
  const infos = targets.map(t => lookup.byId.get(t.id)).filter((i): i is ResourceAccessInfo => !!i)
  if (infos.length === 0) return { state: 'unknown' }
  if (infos.every(i => !i.supported)) return { state: 'untracked' }
  const supported = infos.filter(i => i.supported)
  const anyAccount = targets.some(t => t.kind === 'account_selector') || undefined
  const eventTypes = [...new Set(supported.flatMap(i => i.event_types ?? []))]
  const windows = supported.map(i => i.window_days).filter((d): d is number => typeof d === 'number')
  const windowDays = windows.length > 0 ? Math.min(...windows) : undefined
  let latest: string | null = null
  for (const i of infos) {
    for (const e of i.events) {
      if (!latest || new Date(e.published).getTime() > new Date(latest).getTime()) latest = e.published
    }
  }
  if (latest) {
    const counts = supported.map(i => i.uses)
    const uses = counts.every((c): c is number => typeof c === 'number') ? counts.reduce((a, b) => a + b, 0) : undefined
    return {
      state: 'used', at: latest,
      ...defined({
        uses, windowDays, anyAccount,
        eventTypes: eventTypes.length > 0 ? eventTypes : undefined,
        newerThanSync: supported.some(i => i.newer_than_sync) || undefined,
      }),
    }
  }
  if (infos.some(i => i.supported && i.complete === false)) return { state: 'unknown' }
  if (infos.some(i => i.ambiguous)) return { state: 'ambiguous' }
  return { state: 'never', ...defined({ windowDays, anyAccount, eventTypes: eventTypes.length > 0 ? eventTypes : undefined }) }
}
