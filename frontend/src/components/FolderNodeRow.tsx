import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2 } from 'lucide-react'
import { deleteFolder } from '../api/client'
import { toast } from '../hooks/useToast'
import type { FolderAccessEntry, FolderNode } from '../types'
import { isValidName } from '../utils/validate'
import { FolderAccessBadge } from './FolderAccessBadge'
import { StatusBadge } from './StatusBadge'

export interface StatusInfo {
  label: string
  variant: 'neutral' | 'exists' | 'new' | 'created' | 'error'
  errorMessage?: string
}

interface Props {
  node: FolderNode
  parentPath: string[]
  statusByPath: Map<string, StatusInfo>
  collisionNames: Set<string>
  folderIdByPath: Map<string, string>
  accessByPath: Map<string, FolderAccessEntry[]>
  resourceGroupId: string | undefined
  projectId: string | undefined
  onAddChild: (parentId: string) => void
  onDelete: (id: string) => void
  onUpdate: (id: string, patch: Partial<Pick<FolderNode, 'name' | 'description'>>) => void
  onAssignAccess: (path: string, folderId: string, folderName: string) => void
}

export function FolderNodeRow({
  node,
  parentPath,
  statusByPath,
  collisionNames,
  folderIdByPath,
  accessByPath,
  resourceGroupId,
  projectId,
  onAddChild,
  onDelete,
  onUpdate,
  onAssignAccess,
}: Props) {
  const [confirmingDelete, setConfirmingDelete] = useState(false)
  const queryClient = useQueryClient()
  const fullPath = [...parentPath, node.name]
  const fullPathKey = fullPath.join('/')
  const status = statusByPath.get(fullPathKey)
  const nameInvalid = node.name.length > 0 && !isValidName(node.name)
  const hasCollision = collisionNames.has(node.name)
  const folderId = folderIdByPath.get(fullPathKey)

  const deleteMutation = useMutation({
    mutationFn: () => deleteFolder(resourceGroupId!, projectId!, folderId!),
    onSuccess: () => {
      toast({ title: `Deleted "${node.name}" from OPA`, variant: 'default' })
      setConfirmingDelete(false)
      queryClient.invalidateQueries({ queryKey: ['security_policies', resourceGroupId] })
      onDelete(node.id)
    },
    onError: (err: Error) => {
      toast({ title: `Could not delete "${node.name}"`, description: err.message, variant: 'error' })
      setConfirmingDelete(false)
    },
  })

  const handleDeleteClick = () => {
    if (!folderId) {
      // Never created in OPA yet — just remove it from the local tree.
      onDelete(node.id)
      return
    }
    setConfirmingDelete(true)
  }

  return (
    <div className="flex flex-col">
      <div className="flex items-center gap-2 py-1" style={{ paddingLeft: `${parentPath.length * 1.5}rem` }}>
        <input
          value={node.name}
          onChange={e => onUpdate(node.id, { name: e.target.value })}
          placeholder="folder-name"
          className={`text-input w-40 ${nameInvalid ? 'border-loss' : hasCollision ? 'border-warn' : ''}`}
        />
        <input
          value={node.description}
          onChange={e => onUpdate(node.id, { description: e.target.value })}
          placeholder="description (optional)"
          className="text-input flex-1 min-w-0"
        />
        {status && <StatusBadge label={status.label} variant={status.variant} />}
        <FolderAccessBadge
          entries={accessByPath.get(fullPathKey)}
          disabled={!folderId}
          onClick={() => folderId && onAssignAccess(fullPathKey, folderId, node.name)}
        />
        <button
          type="button"
          onClick={() => onAddChild(node.id)}
          title="Add subfolder"
          className="btn-secondary !px-1.5 !py-1"
        >
          <Plus size={13} />
        </button>
        <button
          type="button"
          onClick={handleDeleteClick}
          title={folderId ? 'Delete from OPA' : 'Remove'}
          className="btn-secondary !px-1.5 !py-1 hover:!text-loss"
        >
          <Trash2 size={13} />
        </button>
      </div>

      {confirmingDelete && (
        <div
          className="flex items-center gap-2 text-xs text-loss py-1"
          style={{ paddingLeft: `${parentPath.length * 1.5 + 0.25}rem` }}
        >
          Delete "{node.name}" from OPA? This can't be undone.
          <button
            type="button"
            className="btn-danger !py-0.5 !px-2"
            disabled={deleteMutation.isPending}
            onClick={() => deleteMutation.mutate()}
          >
            {deleteMutation.isPending ? 'Deleting…' : 'Yes, delete'}
          </button>
          <button
            type="button"
            className="btn-secondary !py-0.5 !px-2"
            disabled={deleteMutation.isPending}
            onClick={() => setConfirmingDelete(false)}
          >
            Cancel
          </button>
        </div>
      )}

      {nameInvalid && (
        <div className="text-[0.6875rem] text-loss" style={{ paddingLeft: `${parentPath.length * 1.5 + 0.25}rem` }}>
          Only letters, digits, "." "_" "-" are allowed (no spaces, at most 255 characters, not "." or "..").
        </div>
      )}
      {!nameInvalid && hasCollision && (
        <div className="text-[0.6875rem] text-warn" style={{ paddingLeft: `${parentPath.length * 1.5 + 0.25}rem` }}>
          "{node.name}" is used elsewhere in this tree — OPA requires unique names per project.
        </div>
      )}
      {status?.variant === 'error' && status.errorMessage && (
        <div className="text-[0.6875rem] text-loss" style={{ paddingLeft: `${parentPath.length * 1.5 + 0.25}rem` }}>
          {status.errorMessage}
        </div>
      )}

      {node.children.map(child => (
        <FolderNodeRow
          key={child.id}
          node={child}
          parentPath={fullPath}
          statusByPath={statusByPath}
          collisionNames={collisionNames}
          folderIdByPath={folderIdByPath}
          accessByPath={accessByPath}
          resourceGroupId={resourceGroupId}
          projectId={projectId}
          onAddChild={onAddChild}
          onDelete={onDelete}
          onUpdate={onUpdate}
          onAssignAccess={onAssignAccess}
        />
      ))}
    </div>
  )
}
