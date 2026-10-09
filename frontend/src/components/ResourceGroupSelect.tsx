import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { createResourceGroup } from '../api/client'
import { useResourceGroups } from '../api/hooks'
import { toast } from '../hooks/useToast'
import { GroupPicker } from './GroupPicker'
import { Select } from './Select'

const NEW_SENTINEL = '__new__'

interface Props {
  value: string | undefined
  onChange: (id: string) => void
}

export function ResourceGroupSelect({ value, onChange }: Props) {
  const { data, isLoading, isError } = useResourceGroups()
  const [creating, setCreating] = useState(false)
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [groupId, setGroupId] = useState<string | undefined>(undefined)
  const queryClient = useQueryClient()

  const createMutation = useMutation({
    mutationFn: () => createResourceGroup(name.trim(), description.trim(), groupId ? [groupId] : []),
    onSuccess: (resp) => {
      toast({ title: `Resource group '${resp.resource_group.name}' created`, variant: 'success' })
      queryClient.invalidateQueries({ queryKey: ['resource_groups'] })
      onChange(resp.resource_group.id)
      setCreating(false)
      setName('')
      setDescription('')
      setGroupId(undefined)
    },
    onError: (err: Error) => toast({ title: 'Could not create resource group', description: err.message, variant: 'error' }),
  })

  const handleSelect = (selected: string) => {
    if (selected === NEW_SENTINEL) {
      setCreating(true)
      return
    }
    onChange(selected)
  }

  if (creating) {
    return (
      <div className="card p-3 flex flex-col gap-2 min-w-72">
        <span className="section-label">New resource group</span>
        <input aria-label="New resource group name" value={name} onChange={e => setName(e.target.value)} placeholder="resource group name" className="text-input" />
        <input
          aria-label="New resource group description"
          value={description}
          onChange={e => setDescription(e.target.value)}
          placeholder="description (optional)"
          className="text-input"
        />
        <GroupPicker value={groupId} onChange={setGroupId} />
        <div className="flex gap-2">
          <button
            type="button"
            className="btn-primary"
            disabled={!name.trim() || !groupId || createMutation.isPending}
            onClick={() => createMutation.mutate()}
          >
            {createMutation.isPending ? 'Creating…' : 'Create'}
          </button>
          <button type="button" className="btn-secondary" onClick={() => setCreating(false)}>
            Cancel
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-1">
      <span className="section-label">Resource Group</span>
      <Select ariaLabel="Resource Group"
        value={value}
        onValueChange={handleSelect}
        loading={isLoading}
        placeholder={isError ? 'Failed to load' : 'Select a resource group'}
        options={[
          ...(data ?? []).map(rg => ({ value: rg.id, label: rg.name })),
          { value: NEW_SENTINEL, label: '+ Create new resource group' },
        ]}
      />
    </div>
  )
}
