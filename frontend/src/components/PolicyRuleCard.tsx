import { useState, type ReactNode } from 'react'
import { ChevronDown, ChevronUp } from 'lucide-react'
import type { PolicyRule, PolicyRuleResolution, ResourceAccessInfo } from '../types'
import { describeCondition } from '../utils/policy'
import { formatDateTime } from '../utils/format'

interface Props {
  rule: PolicyRule
  /** Shown when this card appears outside its own policy's detail view
   * (e.g. in the Project/User/Group tabs, where rules from many different
   * policies are listed together) so it's clear which policy granted it. */
  policyName?: string
  /** Only meaningful for resolved resolutions -- see UsersTab, the only
   * current caller that passes this. Omitted everywhere else (Projects/
   * Policies/Groups tabs), since "last accessed by whom" only makes sense
   * once a specific user is in scope. Keyed by resolution.id. */
  accessInfoByResourceId?: Map<string, ResourceAccessInfo>
}

// Resource kinds with a verified, working System Log mapping -- see
// create_secret_folders.py's RESOURCE_ACCESS_EVENT_TYPES. Kept in sync
// with UsersTab's TRACKABLE_KINDS (the only current caller that populates
// accessInfoByResourceId for these kinds).
const TRACKABLE_KINDS = new Set([
  'secret',
  'individual_server_account',
  'individual_managed_saas_app_account',
  'individual_unmanaged_saas_app_account',
  'individual_okta_account',
])

export function Tag({ children }: { children: ReactNode }) {
  return (
    <span className="text-[0.6875rem] font-medium px-1.5 py-0.5 rounded border bg-bg-hover text-text-dim border-border whitespace-nowrap">
      {children}
    </span>
  )
}

function ResourceAccessSummary({ info }: { info: ResourceAccessInfo }) {
  const [expanded, setExpanded] = useState(false)

  if (!info.supported) {
    return <span className="text-text-faint italic">access tracking not available for this resource type</span>
  }
  if (info.events.length === 0) {
    return <span className="text-text-faint">not accessed (or not within the last 90 days)</span>
  }

  const [latest, ...rest] = info.events
  return (
    <span className="inline-flex flex-col gap-0.5">
      <span className="inline-flex items-center gap-1">
        <span>
          last accessed {formatDateTime(latest.published)}
          {latest.request_id && <> · request <code className="text-[0.625rem]">{latest.request_id}</code></>}
        </span>
        {rest.length > 0 && (
          <button
            type="button"
            onClick={() => setExpanded(e => !e)}
            className="text-text-faint hover:text-text-dim"
            title={expanded ? 'Hide earlier accesses' : `Show ${rest.length} earlier access(es)`}
          >
            {expanded ? <ChevronUp size={11} /> : <ChevronDown size={11} />}
          </button>
        )}
      </span>
      {expanded && rest.map((e, i) => (
        <span key={i} className="pl-3 text-text-faint">
          {formatDateTime(e.published)}
          {e.request_id && <> · request <code className="text-[0.625rem]">{e.request_id}</code></>}
        </span>
      ))}
    </span>
  )
}

function FolderAccessSummary({
  childSecrets,
  accessInfoByResourceId,
}: {
  childSecrets: { id: string; name: string }[]
  accessInfoByResourceId: Map<string, ResourceAccessInfo>
}) {
  const [expanded, setExpanded] = useState(false)
  return (
    <span className="inline-flex flex-col gap-0.5">
      <button
        type="button"
        onClick={() => setExpanded(e => !e)}
        className="inline-flex items-center gap-1 text-text-faint hover:text-text-dim"
        title={expanded ? 'Hide secrets' : `Show ${childSecrets.length} secret(s) in this folder`}
      >
        {childSecrets.length} secret{childSecrets.length === 1 ? '' : 's'} in this folder
        {expanded ? <ChevronUp size={11} /> : <ChevronDown size={11} />}
      </button>
      {expanded &&
        childSecrets.map(secret => {
          const info = accessInfoByResourceId.get(secret.id)
          return (
            <div key={secret.id} className="flex items-baseline gap-1.5 pl-3">
              <span className="text-text-dim shrink-0">{secret.name}:</span>
              {info ? <ResourceAccessSummary info={info} /> : <span className="text-text-faint">loading…</span>}
            </div>
          )
        })}
    </span>
  )
}

export function PolicyRuleCard({ rule, policyName, accessInfoByResourceId }: Props) {
  // Narrowed to TRACKABLE_KINDS (not every resolved resource) because
  // that's all UsersTab ever queries access info for -- including anything
  // else here would show a permanent "loading…" for resource kinds nobody
  // asked about, rather than nothing.
  const trackableTargets = rule.resolutions.filter(
    (r): r is PolicyRuleResolution & { kind: 'resolved' } => r.kind === 'resolved' && TRACKABLE_KINDS.has(r.resource_kind)
  )
  // Folder grants have no access event of their own (see
  // create_secret_folders.py's RESOURCE_ACCESS_EVENT_TYPES), but roll up
  // per-secret access for whatever's actually inside the folder. Skipped
  // when empty -- an empty folder has nothing to report.
  const trackableFolders = rule.resolutions.filter(
    (r): r is PolicyRuleResolution & { kind: 'resolved' } =>
      r.kind === 'resolved' && r.resource_kind === 'secret_folder' && (r.child_secrets?.length ?? 0) > 0
  )
  return (
    <div className="card p-3 flex flex-col gap-2">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-text">{rule.name}</span>
          <Tag>{rule.resource_type_label}</Tag>
        </div>
        {policyName && <span className="text-xs text-text-faint">via {policyName}</span>}
      </div>

      <div className="flex flex-col gap-1">
        <span className="section-label">Applies to</span>
        <div className="flex flex-wrap gap-1.5">
          {rule.resolutions.map((res, i) =>
            res.kind === 'resolved' ? (
              <Tag key={i}>
                {res.name}
                {res.project_name
                  ? ` — ${res.project_name}`
                  // relationship_assignment resolutions (see
                  // create_secret_folders.py's
                  // _resolve_relationship_assignment_resources) are
                  // team-wide grants with no project by design -- "(project
                  // unknown)" would wrongly imply a data gap here.
                  : res.resource_kind.startsWith('relationship_assignment:')
                    ? ''
                    : ' (project unknown)'}
                {res.relationship_name && res.assignment_name && (
                  <span className="text-text-faint"> · via {res.relationship_name} → {res.assignment_name}</span>
                )}
              </Tag>
            ) : (
              <span key={i} className="text-xs text-text-faint italic">
                {res.description}
              </span>
            )
          )}
        </div>
      </div>

      {accessInfoByResourceId && (trackableTargets.length > 0 || trackableFolders.length > 0) && (
        <div className="flex flex-col gap-1">
          <span className="section-label">Last accessed (System Log, last 90 days)</span>
          <div className="flex flex-col gap-1 text-[0.6875rem]">
            {trackableTargets.map((res, i) => {
              const info = accessInfoByResourceId.get(res.access_tracking_id ?? res.id)
              return (
                <div key={`s-${i}`} className="flex items-baseline gap-1.5">
                  <span className="text-text-dim shrink-0">{res.name}:</span>
                  {info ? <ResourceAccessSummary info={info} /> : <span className="text-text-faint">loading…</span>}
                </div>
              )
            })}
            {trackableFolders.map((res, i) => (
              <div key={`f-${i}`} className="flex items-baseline gap-1.5">
                <span className="text-text-dim shrink-0">{res.name}:</span>
                <FolderAccessSummary childSecrets={res.child_secrets!} accessInfoByResourceId={accessInfoByResourceId} />
              </div>
            ))}
          </div>
        </div>
      )}

      {rule.privileges.length > 0 && (
        <div className="flex flex-col gap-1">
          <span className="section-label">Privileges</span>
          <div className="flex flex-wrap gap-1.5">
            {rule.privileges.map((p, i) => (
              <Tag key={i}>
                {p.privilege_type}
                {p.flags.length > 0 ? `: ${p.flags.join(', ')}` : ''}
              </Tag>
            ))}
          </div>
        </div>
      )}

      {rule.conditions.length > 0 && (
        <div className="flex flex-col gap-1">
          <span className="section-label">Conditions</span>
          <div className="flex flex-wrap gap-1.5">
            {rule.conditions.map((c, i) => (
              <Tag key={i}>{describeCondition(c)}</Tag>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
