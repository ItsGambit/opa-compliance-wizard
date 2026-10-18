import { useMemo, useState } from 'react'
import type { AccessModel } from '../types'
import { aggregateResources } from '../utils/accessResources'
import type { ExportSection } from '../utils/export'
import { grantRows } from '../utils/exportSections'
import { rulesGrantedToGroupIds } from '../utils/policy'
import { Chip } from './explorer/DetailBlocks'
import { ExplorerLayout } from './explorer/ExplorerLayout'
import { GrantsMain } from './explorer/GrantsMain'
import { RailGroupsExpander } from './explorer/RailGroupsExpander'
import { CountList, FilterMenu, RailBlock, RailField } from './explorer/RailParts'
import { ResourceAccessView } from './explorer/ResourceAccessView'
import { useGrantsExplorer } from './explorer/useGrantsExplorer'
import { ExportButtons } from './ExportButtons'
import { Select } from './Select'

interface Props {
  model: AccessModel
}

export function GroupsTab({ model }: Props) {
  const [groupId, setGroupId] = useState<string | undefined>(undefined)
  const [now] = useState(() => Date.now())
  const group = model.groups.find(g => g.id === groupId)

  const members = useMemo(
    () => model.users.filter(u => u.groups.some(g => g.id === groupId)),
    [model.users, groupId]
  )
  const grants = useMemo(
    () => (groupId ? rulesGrantedToGroupIds(model.policies, new Set([groupId])) : []),
    [model.policies, groupId]
  )
  const resources = useMemo(
    () => aggregateResources(grants, { groupsFor: policy => policy.principals.user_groups.filter(g => g.id === groupId) }),
    [grants, groupId]
  )
  const ex = useGrantsExplorer({ resources, resetKey: groupId ?? '' })

  const exportSectionsForGroup: ExportSection[] = useMemo(() => {
    if (!group) return []
    return [
      {
        title: `Group: ${group.name}`,
        rows: [{ Roles: group.roles.join(', '), Members: members.map(u => u.details?.full_name || u.name).join(', ') }],
      },
      { title: 'Access Granted', rows: grantRows(grants) },
    ]
  }, [group, members, grants])

  const rail = (
    <>
      <RailField label="Group">
        <Select ariaLabel="Group" value={groupId} onValueChange={setGroupId} placeholder="Select a group" options={model.groups.map(g => ({ value: g.id, label: g.name }))} />
      </RailField>
      {group && (
        <>
          <div className="flex flex-col gap-1">
            <span className="xp-rail-title">{group.name}</span>
          </div>
          <RailBlock title="RBAC role(s)">
            <p className="xp-note mb-1">Team-level admin roles, not resource access.</p>
            {group.roles.length > 0 ? <div>{group.roles.map(r => <Chip key={r}>{r}</Chip>)}</div> : <span className="xp-note">None</span>}
          </RailBlock>
          <CountList items={ex.countItems} onSelect={ex.jump} />
          <RailGroupsExpander
            count={members.length}
            label={`member${members.length === 1 ? '' : 's'}`}
            emptyText="None found among fetched users"
            items={members.map(u => ({ id: u.id, name: u.details?.full_name || u.name }))}
          />
          <FilterMenu items={ex.filterItems} active={ex.active} onToggle={ex.toggleFilter} />
          <div className="xp-rail-actions">
            <ExportButtons sections={exportSectionsForGroup} filenameBase={`opa-group-${group.name}`} />
          </div>
        </>
      )}
    </>
  )

  return (
    <ExplorerLayout rail={rail} railLabel="Group, quick view and filters">
      {!group ? (
        <p className="xp-note">Select a group to see everything it grants access to.</p>
      ) : (
        <GrantsMain
          ex={ex}
          now={now}
          searchLabel="Search this group's access"
          viaOf={r => r.policyNames}
          emptyMessage="No policy names this group as a principal."
          renderDetail={resource => <ResourceAccessView resource={resource} now={now} />}
        />
      )}
    </ExplorerLayout>
  )
}
