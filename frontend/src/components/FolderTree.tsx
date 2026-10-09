import { Plus } from 'lucide-react'
import type { FolderAccessEntry, FolderNode } from '../types'
import { addChild, newNode, removeNode, updateNode } from '../utils/tree'
import { FolderNodeRow, type StatusInfo } from './FolderNodeRow'

interface Props {
  nodes: FolderNode[]
  onChange: (nodes: FolderNode[]) => void
  statusByPath: Map<string, StatusInfo>
  collisionNames: Set<string>
  folderIdByPath: Map<string, string>
  accessByPath: Map<string, FolderAccessEntry[]>
  resourceGroupId: string | undefined
  projectId: string | undefined
  /** Named in the "Delete from OPA" confirmation (UI-17). */
  projectName?: string
  onAssignAccess: (path: string, folderId: string, folderName: string) => void
}

export function FolderTree({
  nodes,
  onChange,
  statusByPath,
  collisionNames,
  folderIdByPath,
  accessByPath,
  resourceGroupId,
  projectId,
  projectName,
  onAssignAccess,
}: Props) {
  const handleAddRoot = () => onChange(addChild(nodes, null, newNode()))
  const handleAddChild = (parentId: string) => onChange(addChild(nodes, parentId, newNode()))
  const handleDelete = (id: string) => onChange(removeNode(nodes, id))
  const handleUpdate = (id: string, patch: Partial<Pick<FolderNode, 'name' | 'description'>>) =>
    onChange(updateNode(nodes, id, patch))

  return (
    <div className="card p-3 flex flex-col gap-1">
      {nodes.length === 0 && (
        <div className="text-sm text-text-faint py-6 text-center">No folders yet — add a root folder to start.</div>
      )}
      {nodes.map(node => (
        <FolderNodeRow
          key={node.id}
          node={node}
          parentPath={[]}
          statusByPath={statusByPath}
          collisionNames={collisionNames}
          folderIdByPath={folderIdByPath}
          accessByPath={accessByPath}
          resourceGroupId={resourceGroupId}
          projectId={projectId}
          projectName={projectName}
          onAddChild={handleAddChild}
          onDelete={handleDelete}
          onUpdate={handleUpdate}
          onAssignAccess={onAssignAccess}
        />
      ))}
      <button type="button" onClick={handleAddRoot} className="btn-secondary self-start mt-2">
        <Plus size={13} aria-hidden="true" /> Add root folder
      </button>
    </div>
  )
}
