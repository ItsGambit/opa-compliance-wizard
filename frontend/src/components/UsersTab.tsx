import { useMemo, useRef, useState } from 'react'
import { useUserResourceAccess } from '../api/hooks'
import { useRemoveUserFromGroup } from '../hooks/useRemoveUserFromGroup'
import type { AccessModel, ResourceAccessInfo } from '../types'
import { coverageNote } from '../utils/accessEvidence'
import { aggregateResources, trackedRequests, type AccessLookup } from '../utils/accessResources'
import type { ExportSection } from '../utils/export'
import { visibleAccessSections } from '../utils/exportSections'
import { formatDateTime } from '../utils/format'
import { policiesUsingGroup, rulesGrantedToGroupIds } from '../utils/policy'
import { ExplorerLayout } from './explorer/ExplorerLayout'
import { GrantsMain } from './explorer/GrantsMain'
import { GroupRemoveControl } from './explorer/GroupRemoveControl'
import { RailGroupsExpander } from './explorer/RailGroupsExpander'
import { CountList, FilterMenu } from './explorer/RailParts'
import { ResourceAccessView } from './explorer/ResourceAccessView'
import { UserRail } from './explorer/UserRail'
import { useGrantsExplorer } from './explorer/useGrantsExplorer'
import { ExportButtons } from './ExportButtons'

/** Okta lifecycle flags per OPA user id (cross-check C1), from the newest lookup; absent when none has been run. */
export interface OktaUserFlags {
  capturedAt: string | null
  users: Record<string, { okta_state: string | null; flag: 'inactive' | 'absent' | 'unknown' | null }>
}

interface Props {
  model: AccessModel
  okta?: OktaUserFlags
  /** Lets this tab remove a group from a user's own `groups` in the
   * already-loaded model, without forcing the ~30s+ full re-bootstrap
   * Access Explorer otherwise only does on an explicit Refresh click --
   * we already know the outcome of a successful removal locally. */
  onUserGroupRemoved: (userId: string, groupId: string) => void
}

export function UsersTab({ model, okta, onUserGroupRemoved }: Props) {
  const [userId, setUserId] = useState<string | undefined>(undefined)
  // One stable "now" per screen so relative times do not shift while reading.
  const [now] = useState(() => Date.now())
  const user = model.users.find(u => u.id === userId)
  const isServiceAccount = user?.user_type === 'service'

  const flags = useMemo(() => (okta ? Object.fromEntries(Object.entries(okta.users).map(([id, u]) => [id, u.flag])) : undefined), [okta])

  const oktaFlag = user ? okta?.users[user.id]?.flag ?? null : null
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
    // A user with nothing trackable sends no request at all (so no data ever
    // arrives): that is an empty, finished lookup, not a pending one. Without
    // this the usage filters stayed disabled for such a user.
    if (trackedResources.length === 0) return { status: 'ready', byId: new Map<string, ResourceAccessInfo>() }
    if (!accessResults) return { status: 'loading' }
    return { status: 'ready', byId: new Map<string, ResourceAccessInfo>(Object.entries(accessResults)) }
  }, [isServiceAccount, user, accessIsError, accessError, refetchAccess, accessFetching, accessResults, trackedResources])
  const evidenceNote = useMemo(
    () => (accessResults && trackedResources.length > 0 ? coverageNote(Object.values(accessResults), now) : undefined),
    [accessResults, trackedResources, now]
  )

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
      ...visibleAccessSections(ex.visible, now),
    ]
  }, [user, ex.visible, now])

  const rail = (
    <>
      <UserRail users={model.users} flags={flags} selectedId={userId} onSelect={setUserId} />
      {user && (
        <>
          <div className="flex flex-col gap-1">
            <span className={`xp-rail-title ${isServiceAccount ? '!text-warn' : ''}`}>{user.details?.full_name || user.name}</span>
            <span className="xp-rail-sub">
              {[user.status, user.details?.email].filter(Boolean).join(' · ')}
              {isServiceAccount && <> {user.status || user.details?.email ? '· ' : ''}<span className="text-warn font-medium">Service account</span></>}
            </span>
            {isServiceAccount && (
              <span className="xp-rail-sub">No Okta identity — API-key-only, so "last used" (System Log) doesn't apply to it.</span>
            )}
            {oktaFlag && (
              <span className={`xp-rail-sub ${oktaFlag === 'unknown' ? '' : 'text-warn'}`} role="status">
                {oktaFlag === 'inactive' && <>Okta: this person's Okta user is deprovisioned or suspended, yet they are still an OPA principal. A candidate for review.</>}
                {oktaFlag === 'absent' && <>Okta: no Okta user was found for this person, yet they are still an OPA principal. A candidate for review.</>}
                {oktaFlag === 'unknown' && <>Okta: the status could not be read in the last lookup.</>}
                {okta?.capturedAt && <> Looked up {formatDateTime(okta.capturedAt)}.</>}
              </span>
            )}
            {user.groups_error && (
              <span className="xp-rail-sub text-warn">Groups could not be read for this user, so their access is unknown (not "none").</span>
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
          note={evidenceNote}
          emptyMessage={user.groups_error ? 'Groups could not be read for this user, so it is not known what they can access.' : "No policy grants access via this user's groups."}
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
