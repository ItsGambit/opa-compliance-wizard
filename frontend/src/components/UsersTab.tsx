import { useMemo, useRef, useState } from 'react'
import { useUserResourceAccess } from '../api/hooks'
import { useRemoveUserFromGroup } from '../hooks/useRemoveUserFromGroup'
import type { AccessModel, ResourceAccessInfo } from '../types'
import { aggregateResources, trackedRequests, type AccessLookup } from '../utils/accessResources'
import type { ExportSection } from '../utils/export'
import { grantRows } from '../utils/exportSections'
import { policiesUsingGroup, rulesGrantedToGroupIds } from '../utils/policy'
import { ExplorerLayout } from './explorer/ExplorerLayout'
import { GrantsMain } from './explorer/GrantsMain'
import { GroupRemoveControl } from './explorer/GroupRemoveControl'
import { RailGroupsExpander } from './explorer/RailGroupsExpander'
import { CountList, FilterMenu } from './explorer/RailParts'
import { ResourceAccessView } from './explorer/ResourceAccessView'
import { useGrantsExplorer } from './explorer/useGrantsExplorer'
import { ExportButtons } from './ExportButtons'
import { Select } from './Select'

interface Props {
  model: AccessModel
  /** Lets this tab remove a group from a user's own `groups` in the
   * already-loaded model, without forcing the ~30s+ full re-bootstrap
   * Access Explorer otherwise only does on an explicit Refresh click --
   * we already know the outcome of a successful removal locally. */
  onUserGroupRemoved: (userId: string, groupId: string) => void
}

export function UsersTab({ model, onUserGroupRemoved }: Props) {
  const [userId, setUserId] = useState<string | undefined>(undefined)
  // One stable "now" per screen so relative times do not shift while reading.
  const [now] = useState(() => Date.now())
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
      // Not shown, but typed often: e-mail, login name, first/last name.
      keywords: [u.details?.email, u.name, u.details?.first_name, u.details?.last_name].filter((v): v is string => !!v),
      labelClassName: u.user_type === 'service' ? 'text-warn' : undefined,
    })),
    [model.users]
  )

  const groupIds = useMemo(() => new Set(user?.groups.map(g => g.id) ?? []), [user])
  const grants = useMemo(() => (user ? rulesGrantedToGroupIds(model.policies, groupIds) : []), [model.policies, groupIds, user])
  const resources = useMemo(
    () => aggregateResources(grants, { groupsFor: policy => policy.principals.user_groups.filter(g => groupIds.has(g.id)) }),
    [grants, groupIds]
  )

  // Only resource_kinds with a verified, working System Log mapping (see
  // create_secret_folders.py's RESOURCE_ACCESS_EVENT_TYPES) are queried
  // here; everything else is left out entirely. secret_folder grants have
  // no event of their own, but expand to their child_secrets -- queried
  // here as plain "secret" resources. SaaS/Okta account kinds are queried
  // by access_tracking_id (their OPA-internal id), not the displayed id --
  // see that field's comment in types/index.ts.
  const trackedResources = useMemo(() => trackedRequests(resources), [resources])

  // A service account (e.g. this dashboard's own) has no Okta identity/
  // email, so the System Log actor lookup behind this can never resolve --
  // skip firing a request known to fail rather than surface an error for
  // something that was never going to work.
  const accessQuery = useUserResourceAccess(user?.id, trackedResources, !isServiceAccount)
  const { data: accessResults, isError: accessIsError, error: accessError, refetch: refetchAccess, isFetching: accessFetching } = accessQuery
  // UI-12: undefined for a service account (no lookup runs, so no
  // "Last accessed" section), and an explicit error state when it failed.
  const accessLookup = useMemo<AccessLookup | undefined>(() => {
    if (isServiceAccount || !user) return undefined
    if (accessIsError) {
      return { status: 'error', message: accessError instanceof Error ? accessError.message : String(accessError), onRetry: () => { void refetchAccess() }, retrying: accessFetching }
    }
    if (!accessResults) return { status: 'loading' }
    return { status: 'ready', byId: new Map<string, ResourceAccessInfo>(Object.entries(accessResults)) }
  }, [isServiceAccount, user, accessIsError, accessError, refetchAccess, accessFetching, accessResults])

  const ex = useGrantsExplorer({ resources, lookup: accessLookup, resetKey: user?.id ?? '' })

  // Group removal: one mutation for the screen; the confirm step lives in
  // each GroupRemoveControl. The user is remembered at click time.
  const removingUserRef = useRef<string | null>(null)
  const removeMutation = useRemoveUserFromGroup(groupId => {
    if (removingUserRef.current) onUserGroupRemoved(removingUserRef.current, groupId)
  })
  const removeControl = (group: { id: string; name: string }, label: string) => {
    if (!user) return null
    return (
      <GroupRemoveControl
        groupName={group.name}
        userName={user.name}
        label={label}
        otherPolicyCount={policiesUsingGroup(model.policies, group.id).length - 1}
        pending={removeMutation.isPending && removeMutation.variables?.groupId === group.id}
        onConfirm={() => {
          removingUserRef.current = user.id
          removeMutation.mutate({ groupId: group.id, userName: user.name })
        }}
      />
    )
  }

  // Groups that actually back a policy the user gets access through are the
  // ones removal means something for (same rule as before: the old chips
  // only appeared next to a granting policy).
  const grantingGroupIds = useMemo(() => {
    const ids = new Set<string>()
    for (const { policy } of grants) for (const g of policy.principals.user_groups) if (groupIds.has(g.id)) ids.add(g.id)
    return ids
  }, [grants, groupIds])

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

  const rail = (
    <>
      <div className="flex flex-col gap-1">
        <span className="section-label">User</span>
        <Select ariaLabel="User" value={userId} onValueChange={setUserId} placeholder="Select a user" options={userOptions} />
      </div>
      {user && (
        <>
          <div className="flex flex-col gap-1">
            <span className={`xp-rail-title ${isServiceAccount ? '!text-warn' : ''}`}>{user.details?.full_name || user.name}</span>
            <span className="xp-rail-sub">
              {[user.status, user.details?.email].filter(Boolean).join(' · ')}
              {isServiceAccount && <> {user.status || user.details?.email ? '· ' : ''}<span className="text-warn font-medium">Service account</span></>}
            </span>
            {isServiceAccount && (
              <span className="xp-rail-sub">No Okta identity — API-key-only, so "last accessed" (System Log) doesn't apply to it.</span>
            )}
          </div>
          <CountList items={ex.countItems} onSelect={ex.jump} />
          <RailGroupsExpander
            count={user.groups.length}
            label={`group${user.groups.length === 1 ? '' : 's'}`}
            emptyText="None"
            items={user.groups.map(g => ({
              id: g.id,
              name: g.name,
              action: grantingGroupIds.has(g.id) ? removeControl(g, 'Remove') : undefined,
            }))}
          />
          <FilterMenu items={ex.filterItems} active={ex.active} onToggle={ex.toggleFilter} />
          <div className="xp-rail-actions">
            <ExportButtons sections={exportSectionsForUser} filenameBase={`opa-user-${user.name}`} />
          </div>
        </>
      )}
    </>
  )

  return (
    <ExplorerLayout rail={rail} railLabel="User, quick view and filters">
      {!user ? (
        <p className="xp-note">Select a user to see everything they have access to through their groups.</p>
      ) : (
        <GrantsMain
          ex={ex}
          now={now}
          searchLabel="Search this user's access"
          emptyMessage="No policy grants access via this user's groups."
          renderDetail={resource => (
            <ResourceAccessView
              resource={resource}
              lookup={accessLookup}
              now={now}
              renderGroupAction={group => removeControl(group, 'Remove from group')}
            />
          )}
        />
      )}
    </ExplorerLayout>
  )
}
