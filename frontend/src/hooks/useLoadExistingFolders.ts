import { useMutation } from '@tanstack/react-query'
import { fetchExistingFolders } from '../api/client'
import type { FolderNode } from '../types'
import { treeFromRows } from '../utils/tree'

/** Shared fetch+convert logic for loading a project's existing (flat) folder
 * list into the tree editor. OPA exposes no parent/child linkage on read, so
 * every existing folder loads as a root-level node — see module docstring
 * fact #2 in create_secret_folders.py for why.
 *
 * onLoad's second argument maps each row's path to its real OPA folder_id
 * (rows without one are omitted) — the caller needs this to know which
 * folders can have a security policy assigned. */
export function useLoadExistingFolders(onLoad: (nodes: FolderNode[], folderIdByPath: Map<string, string>) => void) {
  return useMutation({
    mutationFn: (vars: { resourceGroupId: string; projectId: string }) =>
      fetchExistingFolders(vars.resourceGroupId, vars.projectId),
    onSuccess: (data) => {
      const folderIdByPath = new Map(
        data.rows.filter(r => r.folder_id).map(r => [r.path, r.folder_id as string])
      )
      onLoad(treeFromRows(data.rows), folderIdByPath)
    },
  })
}
