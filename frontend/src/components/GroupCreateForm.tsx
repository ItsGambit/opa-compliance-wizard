import { useState } from 'react'
import type { UseMutationResult } from '@tanstack/react-query'
import type { CreateGroupResponse } from '../types'

interface Props {
  mutation: UseMutationResult<CreateGroupResponse, Error, { name: string; description: string }>
  onCancel: () => void
  label?: string
}

/** Presentational "create group in Okta" form shared by GroupPicker and
 * AssignAccessDialog. Owns its own name/description input state since
 * that's purely local UI state — the actual create logic lives in
 * useCreateGroup, which callers pass in as `mutation`. */
export function GroupCreateForm({ mutation, onCancel, label = 'New group (created in Okta, pushed into OPA)' }: Props) {
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')

  return (
    <div className="card p-3 flex flex-col gap-2">
      <span className="section-label">{label}</span>
      <input
        value={name}
        onChange={e => setName(e.target.value)}
        placeholder="group name"
        className="text-input"
      />
      <input
        value={description}
        onChange={e => setDescription(e.target.value)}
        placeholder="description (optional)"
        className="text-input"
      />
      <div className="flex gap-2">
        <button
          type="button"
          className="btn-primary"
          disabled={!name.trim() || mutation.isPending}
          onClick={() => mutation.mutate({ name, description })}
        >
          {mutation.isPending ? 'Creating…' : 'Create & Push'}
        </button>
        <button type="button" className="btn-secondary" onClick={onCancel} disabled={mutation.isPending}>
          Cancel
        </button>
      </div>
    </div>
  )
}
