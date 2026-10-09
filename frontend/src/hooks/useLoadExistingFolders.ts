import { useMutation } from '@tanstack/react-query'
import { fetchExistingFolders } from '../api/client'
import type { FolderNode } from '../types'
import { normalizePath, treeFromRows } from '../utils/tree'

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
      // Keyed by the same normalised path the tree is built from (FE-13).
      // Two folders on one path would make "Delete"/"Assign access"
      // ambiguous, so such a path gets no id at all.
      const folderIdByPath = new Map<string, string>()
      const duplicated = new Set<string>()
      for (const r of data.rows) {
        if (!r.folder_id || typeof r.path !== 'string') continue
        const key = normalizePath(r.path)
        if (folderIdByPath.has(key)) duplicated.add(key)
        folderIdByPath.set(key, r.folder_id)
      }
      for (const key of duplicated) folderIdByPath.delete(key)
      onLoad(treeFromRows(data.rows), folderIdByPath)
    },
  })
}
