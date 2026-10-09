import { useMemo, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useResourceGroups, useProjects, useResourceGroupSecurityPolicies } from '../api/hooks'
import { resolveFolderAccess } from '../utils/folderAccess'
import { ActionBar } from './ActionBar'
import { AssignAccessDialog } from './AssignAccessDialog'
import { CsvFileBar } from './CsvFileBar'
import { FolderTree } from './FolderTree'
import type { StatusInfo } from './FolderNodeRow'
import { LoadExistingStructureButton } from './LoadExistingStructureButton'
import { ResourceGroupSelect } from './ResourceGroupSelect'
import { ProjectSelect } from './ProjectSelect'
import { ResultsPanel } from './ResultsPanel'
import type { ExecuteResponse, FolderNode, PreviewResponse } from '../types'

export function FolderBuilder() {
  const [resourceGroupId, setResourceGroupId] = useState<string | undefined>(undefined)
  const [projectId, setProjectId] = useState<string | undefined>(undefined)
  const [nodes, setNodes] = useState<FolderNode[]>([])
  const [previewResp, setPreviewResp] = useState<PreviewResponse | null>(null)
  const [executeResp, setExecuteResp] = useState<ExecuteResponse | null>(null)
  // Real OPA folder IDs are the one thing this component tracks by path
  // rather than storing on FolderNode itself -- an edit can shift what a
  // path even refers to, so any tree edit clears this and requires a
  // fresh Load/Preview/Execute before "Assign access" is offered again
  // for that folder. Preview/Execute results (merged in below) always
  // win over a stale load, since they're more recent.
  const [loadedFolderIds, setLoadedFolderIds] = useState<Map<string, string>>(new Map())
  const [assigning, setAssigning] = useState<{ path: string; folderId: string; folderName: string } | null>(null)

  const queryClient = useQueryClient()
  const { data: resourceGroups } = useResourceGroups(true)
  const { data: projects } = useProjects(resourceGroupId, true)
  const { data: securityPolicies } = useResourceGroupSecurityPolicies(resourceGroupId, true)

  const resourceGroup = resourceGroups?.find(rg => rg.id === resourceGroupId)
  const project = projects?.find(p => p.id === projectId)

  const clearResults = () => { setPreviewResp(null); setExecuteResp(null) }

  const handleNodesChange = (next: FolderNode[]) => { setNodes(next); clearResults(); setLoadedFolderIds(new Map()) }
  const handleLoadExisting = (next: FolderNode[], folderIdByPath: Map<string, string>) => {
    setNodes(next)
    clearResults()
    setLoadedFolderIds(folderIdByPath)
  }
  // UI-17 (external review, 2026-10-05): folder ids belong to the project
  // they were loaded from. Changing the resource group or project used to
  // keep them, so "Delete from OPA" / "Assign access" sent project A's
  // folder ids against project B. The tree itself stays (it may be meant
  // for the new project too); its rows simply lose those OPA links.
  const handleResourceGroupChange = (id: string) => {
    setResourceGroupId(id); setProjectId(undefined); clearResults(); setLoadedFolderIds(new Map()); setAssigning(null)
  }
  const handleProjectChange = (id: string) => { setProjectId(id); clearResults(); setLoadedFolderIds(new Map()); setAssigning(null) }

  const folderIdByPath = useMemo(() => {
    const map = new Map(loadedFolderIds)
    if (previewResp) {
      for (const t of previewResp.tree) if (t.folder_id) map.set(t.path, t.folder_id)
    }
    if (executeResp) {
      for (const r of executeResp.results) if (r.folder_id) map.set(r.path, r.folder_id)
    }
    return map
  }, [loadedFolderIds, previewResp, executeResp])

  const statusByPath = useMemo(() => {
    const map = new Map<string, StatusInfo>()
    if (executeResp) {
      for (const r of executeResp.results) {
        if (r.status === 'created') map.set(r.path, { label: 'created', variant: 'created' })
        else if (r.status === 'skipped_exists') map.set(r.path, { label: 'exists', variant: 'exists' })
        else map.set(r.path, { label: 'error', variant: 'error', errorMessage: r.error_message })
      }
    } else if (previewResp) {
      for (const t of previewResp.tree) {
        if (t.exists) map.set(t.path, { label: 'exists', variant: 'exists' })
        else if (t.name_in_use_at)
          map.set(t.path, {
            label: 'name in use',
            variant: 'error',
            errorMessage: `A folder with this name already exists at "${t.name_in_use_at}". OPA requires folder names to be unique per project, so creating it here will most likely be refused; it will not be merged with the existing one.`,
          })
        else map.set(t.path, { label: 'will create', variant: 'new' })
      }
    }
    return map
  }, [previewResp, executeResp])

  const collisionNames = useMemo(() => {
    const source = executeResp?.collisions ?? previewResp?.collisions ?? {}
    return new Set(Object.keys(source))
  }, [previewResp, executeResp])

  const accessByPath = useMemo(
    () => resolveFolderAccess(securityPolicies ?? [], folderIdByPath),
    [securityPolicies, folderIdByPath]
  )

  const handleAssignAccess = (path: string, folderId: string, folderName: string) =>
    setAssigning({ path, folderId, folderName })

  const handleAccessSaved = () => {
    queryClient.invalidateQueries({ queryKey: ['security_policies', resourceGroupId] })
    // Who can reach which secret changed (finding from batch 5's review:
    // with a 30 s staleTime nothing else would refresh the dashboard).
    queryClient.invalidateQueries({ queryKey: ['secrets_access_report'] })
  }

  return (
    <div className="flex flex-col gap-5">
      <div className="card p-3 flex flex-wrap items-end gap-4">
        <ResourceGroupSelect value={resourceGroupId} onChange={handleResourceGroupChange} />
        <ProjectSelect resourceGroupId={resourceGroupId} value={projectId} onChange={handleProjectChange} />
        <LoadExistingStructureButton
          resourceGroupId={resourceGroupId}
          projectId={projectId}
          hasUnsavedNodes={nodes.length > 0}
          onLoad={handleLoadExisting}
        />
      </div>

      <CsvFileBar nodes={nodes} onLoad={handleNodesChange} />

      <FolderTree
        nodes={nodes}
        onChange={handleNodesChange}
        statusByPath={statusByPath}
        collisionNames={collisionNames}
        folderIdByPath={folderIdByPath}
        accessByPath={accessByPath}
        resourceGroupId={resourceGroupId}
        projectId={projectId}
        projectName={project?.name}
        onAssignAccess={handleAssignAccess}
      />

      <ResultsPanel preview={previewResp} execute={executeResp} />

      <ActionBar
        nodes={nodes}
        resourceGroup={resourceGroup}
        project={project}
        onPreviewResult={setPreviewResp}
        onExecuteResult={setExecuteResp}
      />

      {assigning && resourceGroupId && projectId && (
        <AssignAccessDialog
          open
          onOpenChange={open => !open && setAssigning(null)}
          resourceGroupId={resourceGroupId}
          projectId={projectId}
          folderId={assigning.folderId}
          folderName={assigning.folderName}
          existingAccess={accessByPath.get(assigning.path)}
          onSaved={handleAccessSaved}
        />
      )}
    </div>
  )
}
