import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { createProject } from '../api/client'
import { useProjects } from '../api/hooks'
import { toast } from '../hooks/useToast'
import { Select } from './Select'

const NEW_SENTINEL = '__new__'

interface Props {
  resourceGroupId: string | undefined
  value: string | undefined
  onChange: (id: string) => void
}

export function ProjectSelect({ resourceGroupId, value, onChange }: Props) {
  const { data, isLoading, isError } = useProjects(resourceGroupId)
  const [creating, setCreating] = useState(false)
  const [name, setName] = useState('')
  const queryClient = useQueryClient()

  const createMutation = useMutation({
    mutationFn: () => createProject(resourceGroupId!, name.trim()),
    onSuccess: (resp) => {
      toast({ title: `Project '${resp.project.name}' created`, variant: 'success' })
      queryClient.invalidateQueries({ queryKey: ['projects', resourceGroupId] })
      onChange(resp.project.id)
      setCreating(false)
      setName('')
    },
    onError: (err: Error) => toast({ title: 'Could not create project', description: err.message, variant: 'error' }),
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
        <span className="section-label">New project</span>
        <input aria-label="New project" value={name} onChange={e => setName(e.target.value)} placeholder="project name" className="text-input" />
        <div className="flex gap-2">
          <button
            type="button"
            className="btn-primary"
            disabled={!name.trim() || createMutation.isPending}
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
      <span className="section-label">Project</span>
      <Select ariaLabel="Project"
        value={value}
        onValueChange={handleSelect}
        loading={isLoading}
        disabled={!resourceGroupId}
        placeholder={
          !resourceGroupId ? 'Pick a resource group first' : isError ? 'Failed to load' : 'Select a project'
        }
        options={[
          ...(data ?? []).map(p => ({ value: p.id, label: p.name })),
          { value: NEW_SENTINEL, label: '+ Create new project' },
        ]}
      />
    </div>
  )
}
