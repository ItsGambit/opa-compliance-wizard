import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import * as AlertDialog from '@radix-ui/react-alert-dialog'
import { Eye, FolderPlus } from 'lucide-react'
import { execute, preview } from '../api/client'
import { toast } from '../hooks/useToast'
import type { ExecuteResponse, FolderNode, PreviewResponse, Project, ResourceGroup } from '../types'
import { countNodes, flattenTree, treeProblems } from '../utils/tree'

interface Props {
  nodes: FolderNode[]
  resourceGroup: ResourceGroup | undefined
  project: Project | undefined
  onPreviewResult: (resp: PreviewResponse) => void
  onExecuteResult: (resp: ExecuteResponse) => void
}

export function ActionBar({ nodes, resourceGroup, project, onPreviewResult, onExecuteResult }: Props) {
  const [confirmOpen, setConfirmOpen] = useState(false)
  const queryClient = useQueryClient()
  // FE-13: an empty/invalid/duplicate name would plan a different tree
  // than the one on screen ("a//b" drops a level), so it blocks both.
  const problems = treeProblems(nodes)
  const ready = !!resourceGroup && !!project && nodes.length > 0 && problems.length === 0
  const blockedReason = problems.length > 0 ? `Fix the folder names first: ${problems.join(' ')}` : undefined

  const previewMutation = useMutation({
    mutationFn: () => preview(resourceGroup!.id, project!.id, flattenTree(nodes)),
    onSuccess: (resp) => {
      onPreviewResult(resp)
      toast({ title: 'Preview ready', description: `${resp.tree.length} folder(s) planned`, variant: 'default' })
    },
    onError: (err: Error) => toast({ title: 'Preview failed', description: err.message, variant: 'error' }),
  })

  const executeMutation = useMutation({
    mutationFn: () => execute(resourceGroup!.id, project!.id, flattenTree(nodes)),
    onSuccess: (resp) => {
      onExecuteResult(resp)
      queryClient.invalidateQueries({ queryKey: ['secrets_access_report'] })
      const created = resp.results.filter(r => r.status === 'created').length
      const errors = resp.results.filter(r => r.status === 'error').length
      toast({
        title: 'Execute complete',
        description: `Created ${created}, errors ${errors}`,
        variant: errors > 0 ? 'error' : 'success',
      })
    },
    onError: (err: Error) => toast({ title: 'Execute failed', description: err.message, variant: 'error' }),
    onSettled: () => setConfirmOpen(false),
  })

  return (
    <div className="flex items-center gap-2">
      <button
        type="button"
        className="btn-secondary"
        disabled={!ready || previewMutation.isPending}
        title={blockedReason}
        onClick={() => previewMutation.mutate()}
      >
        <Eye size={13} aria-hidden="true" /> {previewMutation.isPending ? 'Previewing…' : 'Preview (dry-run)'}
      </button>

      <AlertDialog.Root open={confirmOpen} onOpenChange={setConfirmOpen}>
        <AlertDialog.Trigger asChild>
          <button type="button" className="btn-primary" disabled={!ready} title={blockedReason}>
            <FolderPlus size={13} aria-hidden="true" /> Create Folders
          </button>
        </AlertDialog.Trigger>
        <AlertDialog.Portal>
          <AlertDialog.Overlay className="fixed inset-0 bg-black/60 z-40" />
          <AlertDialog.Content className="card fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-50 w-[calc(100vw-2rem)] sm:w-96 p-5">
            <AlertDialog.Title className="text-sm font-semibold text-text">Create folders in OPA?</AlertDialog.Title>
            <AlertDialog.Description className="text-xs text-text-faint mt-2 leading-relaxed">
              This will create up to <strong className="text-text-dim">{countNodes(nodes)}</strong> folder(s) in project{' '}
              <strong className="text-text-dim">{project?.name}</strong> under resource group{' '}
              <strong className="text-text-dim">{resourceGroup?.name}</strong>. Folders that already exist are skipped.
              This action calls the real OPA API and cannot be undone from this dashboard.
            </AlertDialog.Description>
            <div className="flex justify-end gap-2 mt-4">
              <AlertDialog.Cancel asChild>
                <button type="button" className="btn-secondary">Cancel</button>
              </AlertDialog.Cancel>
              <button
                type="button"
                className="btn-primary"
                disabled={executeMutation.isPending}
                onClick={() => executeMutation.mutate()}
              >
                {executeMutation.isPending ? 'Creating…' : 'Yes, create folders'}
              </button>
            </div>
          </AlertDialog.Content>
        </AlertDialog.Portal>
      </AlertDialog.Root>
    </div>
  )
}
