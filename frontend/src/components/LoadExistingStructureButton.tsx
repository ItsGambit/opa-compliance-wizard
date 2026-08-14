import { useState } from 'react'
import { Download } from 'lucide-react'
import { useLoadExistingFolders } from '../hooks/useLoadExistingFolders'
import { toast } from '../hooks/useToast'
import type { FolderNode } from '../types'

interface Props {
  resourceGroupId: string | undefined
  projectId: string | undefined
  hasUnsavedNodes: boolean
  onLoad: (nodes: FolderNode[], folderIdByPath: Map<string, string>) => void
}

export function LoadExistingStructureButton({ resourceGroupId, projectId, hasUnsavedNodes, onLoad }: Props) {
  const [confirming, setConfirming] = useState(false)

  const loadMutation = useLoadExistingFolders((nodes, folderIdByPath) => {
    setConfirming(false)
    if (nodes.length === 0) {
      toast({ title: 'No existing folders found in this project', variant: 'default' })
    } else {
      toast({
        title: 'Loaded existing folder(s) from this project',
        description: 'OPA only exposes a flat list (no parent/child info) — these appear as root-level; add subfolders under them as needed.',
        variant: 'success',
      })
    }
    onLoad(nodes, folderIdByPath)
  })

  const disabled = !resourceGroupId || !projectId || loadMutation.isPending

  const doLoad = () =>
    loadMutation.mutate(
      { resourceGroupId: resourceGroupId!, projectId: projectId! },
      { onError: (err: Error) => toast({ title: 'Could not load existing structure', description: err.message, variant: 'error' }) }
    )

  const handleClick = () => {
    if (hasUnsavedNodes && !confirming) {
      setConfirming(true)
      return
    }
    doLoad()
  }

  if (confirming) {
    return (
      <div className="flex items-center gap-2 text-xs text-warn">
        Replace the current tree with what's already in this project?
        <button type="button" className="btn-primary !py-0.5 !px-2" onClick={doLoad}>
          Yes, load it
        </button>
        <button type="button" className="btn-secondary !py-0.5 !px-2" onClick={() => setConfirming(false)}>
          Cancel
        </button>
      </div>
    )
  }

  return (
    <button type="button" className="btn-secondary" disabled={disabled} onClick={handleClick}>
      <Download size={13} /> {loadMutation.isPending ? 'Loading…' : 'Load Current Structure'}
    </button>
  )
}
