import { useState } from 'react'
import { Plus, RefreshCw } from 'lucide-react'
import { useGroups } from '../api/hooks'
import { useCreateGroup } from '../hooks/useCreateGroup'
import { GroupCreateForm } from './GroupCreateForm'
import { Select } from './Select'

interface Props {
  value: string | undefined
  onChange: (groupId: string) => void
}

export function GroupPicker({ value, onChange }: Props) {
  const { data: groups, isLoading, refetch, isFetching } = useGroups()
  const [creating, setCreating] = useState(false)

  const createMutation = useCreateGroup(group => {
    onChange(group.id)
    setCreating(false)
  })

  if (creating) {
    return <GroupCreateForm mutation={createMutation} onCancel={() => setCreating(false)} />
  }

  return (
    <div className="flex flex-col gap-1">
      <span className="section-label">Group (required — grants access to the new resource group)</span>
      <div className="flex gap-2">
        <Select
          value={value}
          onValueChange={onChange}
          loading={isLoading}
          placeholder="Select a group"
          options={(groups ?? []).map(g => ({ value: g.id, label: g.name }))}
        />
        <button type="button" className="btn-secondary !px-2" title="Refresh groups" onClick={() => refetch()}>
          <RefreshCw size={13} className={isFetching ? 'animate-spin' : ''} />
        </button>
        <button type="button" className="btn-secondary" onClick={() => setCreating(true)}>
          <Plus size={13} /> New Group
        </button>
      </div>
    </div>
  )
}
