import { useMemo, useState } from 'react'
import { X } from 'lucide-react'
import { useUserResourceAccess } from '../api/hooks'
import { useRemoveUserFromGroup } from '../hooks/useRemoveUserFromGroup'
import type { AccessModel, NamedRef, ResourceAccessInfo } from '../types'
import type { ExportSection } from '../utils/export'
import { grantRows } from '../utils/exportSections'
import { policiesUsingGroup, rulesGrantedToGroupIds } from '../utils/policy'
import { ExportButtons } from './ExportButtons'
import { PolicyRuleCard } from './PolicyRuleCard'
import { Select } from './Select'

interface Props {
  model: AccessModel
  /** Lets this tab remove a group from a user's own `groups` in the
   * already-loaded model, without forcing the ~30s+ full re-bootstrap
   * Access Explorer otherwise only does on an explicit Refresh click --
   * we already know the outcome of a successful removal locally. */
  onUserGroupRemoved: (userId: string, groupId: string) => void
}

// Resource kinds with a verified, working System Log mapping -- see
// create_secret_folders.py's RESOURCE_ACCESS_EVENT_TYPES.
const TRACKABLE_KINDS = new Set([
  'secret',
  'individual_server_account',
  'individual_managed_saas_app_account',
  'individual_unmanaged_saas_app_account',
  'individual_okta_account',
])

/** One group chip, shown wherever a group grants the selected user access
 * -- "already there" info plus a remove action scoped to exactly that
 * group. Removal needs its own confirm step (destructive, same as every
 * other delete in this app) and its own blast-radius warning if the group
 * also backs other policies, mirroring AssignAccessDialog's warning for
 * the opposite direction (adding a group to a policy). */
function GroupAccessChip({
  group,
  userName,
  otherPolicyCount,
  onRemoved,
}: {
  group: NamedRef
  userName: string
  otherPolicyCount: number
  onRemoved: (groupId: string) => void
}) {
  const [confirming, setConfirming] = useState(false)
  const removeMutation = useRemoveUserFromGroup(groupId => {
    setConfirming(false)
    onRemoved(groupId)
  })

  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-center gap-1.5 text-xs text-text-dim bg-bg-hover border border-border rounded px-1.5 py-0.5">
        {group.name}
        <button
          type="button"
          className="text-text-faint hover:text-loss"
          title={`Remove '${userName}' from '${group.name}'`}
          onClick={() => setConfirming(true)}
        >
          <X size={11} />
        </button>
      </div>
      {confirming && (
        <div className="flex items-center gap-2 text-xs text-loss">
          <span>
            Remove '{userName}' from '{group.name}'?
            {otherPolicyCount > 0 && (
              <>
                {' '}
                This group also backs {otherPolicyCount} other polic{otherPolicyCount === 1 ? 'y' : 'ies'} — removing
                takes away that access too, not just this one.
              </>
            )}
          </span>
          <button
            type="button"
            className="btn-danger !py-0.5 !px-2 shrink-0"
            disabled={removeMutation.isPending}
            onClick={() => removeMutation.mutate({ groupId: group.id, userName })}
          >
            {removeMutation.isPending ? 'Removing…' : 'Yes, remove'}
          </button>
          <button
            type="button"
            className="btn-secondary !py-0.5 !px-2 shrink-0"
            disabled={removeMutation.isPending}
            onClick={() => setConfirming(false)}
          >
            Cancel
          </button>
        </div>
      )}
    </div>
  )
}

export function UsersTab({ model, onUserGroupRemoved }: Props) {
  const [userId, setUserId] = useState<string | undefined>(undefined)
  const user = model.users.find(u => u.id === userId)
  const isServiceAccount = user?.user_type === 'service'

  // FIX (external review, 2026-09-30): an inline model.users.map(...) in
  // the JSX below created a brand new array every render regardless of
  // whether model.users actually changed -- on a tenant with a large user
  // count, this defeats the Select component's internal useFuzzyFilter
  // memoization (which keys off array identity) and rebuilds its whole
  // search index on every keystroke/render, not just when the user list
  // itself changes.
  const userOptions = useMemo(
    () => model.users.map(u => ({
      value: u.id,
      label: u.details?.full_name || u.name,
      labelClassName: u.user_type === 'service' ? 'text-warn' : undefined,
    })),
    [model.users]
  )

  const groupIds = useMemo(() => new Set(user?.groups.map(g => g.id) ?? []), [user])
  const grants = useMemo(() => (user ? rulesGrantedToGroupIds(model.policies, groupIds) : []), [model.policies, groupIds, user])

  // Only resource_kinds with a verified, working System Log mapping (see
  // create_secret_folders.py's RESOURCE_ACCESS_EVENT_TYPES) are queried
  // here; everything else is left out entirely, since there's nothing
  // useful to fetch for them yet. secret_folder grants have no event of
  // their own (folder browsing isn't logged, and reveals reference the
  // secret's id, never the folder's), but expand to their child_secrets --
  // queried here as plain "secret" resources so PolicyRuleCard can roll
  // the results back up under the folder. SaaS/Okta account kinds are
  // queried by access_tracking_id (their OPA-internal id), not the
  // displayed id (the Okta-side identifier, never logged as a target) --
  // see that field's comment in types/index.ts.
  const trackedResources = useMemo(() => {
    const seen = new Map<string, { resource_kind: string; resource_id: string }>()
    for (const { rule } of grants) {
      for (const res of rule.resolutions) {
        if (res.kind !== 'resolved') continue
        if (TRACKABLE_KINDS.has(res.resource_kind)) {
          const resourceId = res.access_tracking_id ?? res.id
          seen.set(resourceId, { resource_kind: res.resource_kind, resource_id: resourceId })
        } else if (res.resource_kind === 'secret_folder') {
          for (const child of res.child_secrets ?? []) {
            seen.set(child.id, { resource_kind: 'secret', resource_id: child.id })
          }
        }
      }
    }
    return [...seen.values()]
  }, [grants])

  // A service account (e.g. this dashboard's own) has no Okta identity/
  // email, so the System Log actor lookup behind this can never resolve --
  // skip firing a request known to fail rather than surface an error for
  // something that was never going to work.
  const { data: accessResults } = useUserResourceAccess(user?.id, trackedResources, !isServiceAccount)
  const accessInfoByResourceId = useMemo(() => {
    const map = new Map<string, ResourceAccessInfo>()
    if (accessResults) {
      for (const [resourceId, info] of Object.entries(accessResults)) map.set(resourceId, info)
    }
    return map
  }, [accessResults])

  const exportSectionsForUser: ExportSection[] = useMemo(() => {
    if (!user) return []
    return [
      {
        title: `User: ${user.details?.full_name || user.name}`,
        rows: [
          {
            Email: user.details?.email ?? '',
            Status: user.status ?? '',
            Groups: user.groups.map(g => g.name).join(', '),
          },
        ],
      },
      { title: 'Access Granted', rows: grantRows(grants) },
    ]
  }, [user, grants])

  return (
    <div className="flex flex-col gap-4">
      <div className="card p-3 flex flex-col gap-1">
        <span className="section-label">User</span>
        <Select
          value={userId}
          onValueChange={setUserId}
          placeholder="Select a user"
          options={userOptions}
        />
      </div>

      {user && (
        <>
          <div className="card p-3 flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className={`text-sm font-medium ${isServiceAccount ? 'text-warn' : 'text-text'}`}>
                  {user.details?.full_name || user.name}
                </span>
                {isServiceAccount && (
                  <span className="text-[0.6875rem] font-medium px-1.5 py-0.5 rounded border border-warn/40 bg-warn/10 text-warn whitespace-nowrap">
                    Service account
                  </span>
                )}
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs text-text-faint">{user.status}</span>
                <ExportButtons sections={exportSectionsForUser} filenameBase={`opa-user-${user.name}`} />
              </div>
            </div>
            {user.details?.email && <span className="text-xs text-text-faint">{user.details.email}</span>}
            {isServiceAccount && (
              <span className="text-xs text-text-faint">
                No Okta identity — API-key-only, so "last accessed" (System Log) doesn't apply to it.
              </span>
            )}

            <div className="flex flex-col gap-1">
              <span className="section-label">Groups ({user.groups.length})</span>
              <div className="flex flex-wrap gap-1.5">
                {user.groups.map(g => (
                  <span key={g.id} className="text-xs text-text-dim bg-bg-hover border border-border rounded px-1.5 py-0.5">
                    {g.name}
                  </span>
                ))}
                {user.groups.length === 0 && <span className="text-xs text-text-faint">None</span>}
              </div>
            </div>
          </div>

          <div className="flex flex-col gap-2">
            <span className="section-label">Everything this user has access to (via their groups) ({grants.length})</span>
            {grants.length === 0 && <span className="text-xs text-text-faint">No policy grants access via this user's groups.</span>}
            {grants.map(({ policy, rule }, i) => {
              const matchingGroups = policy.principals.user_groups.filter(g => groupIds.has(g.id))
              return (
                <div key={`${policy.id}-${i}`} className="flex flex-col gap-1.5">
                  {matchingGroups.length > 0 && (
                    <div className="flex flex-wrap items-start gap-2">
                      <span className="text-xs text-text-faint pt-1">Access via:</span>
                      {matchingGroups.map(g => (
                        <GroupAccessChip
                          key={g.id}
                          group={g}
                          userName={user.name}
                          otherPolicyCount={policiesUsingGroup(model.policies, g.id).length - 1}
                          onRemoved={groupId => onUserGroupRemoved(user.id, groupId)}
                        />
                      ))}
                    </div>
                  )}
                  <PolicyRuleCard
                    rule={rule}
                    policyName={policy.name}
                    accessInfoByResourceId={accessInfoByResourceId}
                  />
                </div>
              )
            })}
          </div>
        </>
      )}
    </div>
  )
}
