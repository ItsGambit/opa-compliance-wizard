import type { CsvRow, FolderNode } from '../types'
import { isValidName } from './validate'

// crypto.randomUUID() needs a secure context (https, or localhost -- which
// this app always runs on), so this fallback is essentially unreachable in
// practice. It still gets a monotonic counter on top of the random string
// so that even many IDs generated within the same millisecond (e.g. a CSV
// with hundreds of rows loaded at once) can never collide as React keys.
let fallbackIdCounter = 0

function newId(): string {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) return crypto.randomUUID()
  fallbackIdCounter += 1
  return `${Date.now().toString(36)}-${fallbackIdCounter}-${Math.random().toString(36).slice(2)}`
}

export function newNode(name = '', description = ''): FolderNode {
  return { id: newId(), name, description, children: [] }
}

/** Recursively flattens the tree into CSV-shaped rows (one row per node, any depth). */
export function flattenTree(nodes: FolderNode[], parentPath: string[] = []): CsvRow[] {
  const rows: CsvRow[] = []
  for (const node of nodes) {
    const path = [...parentPath, node.name]
    rows.push({ path: path.join('/'), description: node.description })
    rows.push(...flattenTree(node.children, path))
  }
  return rows
}

/** The one path normalisation both directions use: segments trimmed, empty
 * segments dropped ("a//b " -> "a/b"). FE-13: the folder-id map was keyed
 * by the server's raw path while the tree was built from trimmed segments,
 * so a path with stray spaces lost its OPA id. */
export function normalizePath(path: string): string {
  return path.split('/').map(s => s.trim()).filter(Boolean).join('/')
}

/** Inverse of flattenTree for any tree that passes treeProblems (non-empty,
 * valid, sibling-unique names): builds a nested tree from flat
 * '/'-delimited rows. Rows without a string `path` (a CSV that is not a
 * folder template, e.g. an Okta System Log export) are skipped instead of
 * throwing (FE-11). The last row that names a folder sets its
 * description, even to empty (FE-13). */
export function treeFromRows(rows: CsvRow[]): FolderNode[] {
  const root: FolderNode[] = []

  for (const row of rows) {
    if (typeof row?.path !== 'string') continue
    const segments = normalizePath(row.path).split('/').filter(Boolean)
    if (segments.length === 0) continue

    let level = root
    let builtPath: string[] = []
    segments.forEach((segment, depth) => {
      builtPath = [...builtPath, segment]
      let existing = level.find(n => n.name === segment)
      if (!existing) {
        existing = newNode(segment)
        level.push(existing)
      }
      if (depth === segments.length - 1) {
        existing.description = typeof row.description === 'string' ? row.description : ''
      }
      level = existing.children
    })
  }

  return root
}

export function addChild(nodes: FolderNode[], parentId: string | null, child: FolderNode): FolderNode[] {
  if (parentId === null) return [...nodes, child]
  return nodes.map(node => {
    if (node.id === parentId) return { ...node, children: [...node.children, child] }
    return { ...node, children: addChild(node.children, parentId, child) }
  })
}

export function removeNode(nodes: FolderNode[], id: string): FolderNode[] {
  return nodes
    .filter(node => node.id !== id)
    .map(node => ({ ...node, children: removeNode(node.children, id) }))
}

export function updateNode(nodes: FolderNode[], id: string, patch: Partial<Pick<FolderNode, 'name' | 'description'>>): FolderNode[] {
  return nodes.map(node => {
    if (node.id === id) return { ...node, ...patch }
    return { ...node, children: updateNode(node.children, id, patch) }
  })
}

export function countNodes(nodes: FolderNode[]): number {
  return nodes.reduce((sum, n) => sum + 1 + countNodes(n.children), 0)
}

/** True when every row has a string `path` -- i.e. the file is a folder
 * template (path,description), not some other CSV in the project folder. */
export function looksLikeFolderTemplate(rows: unknown[]): boolean {
  return rows.every(r => typeof r === 'object' && r !== null && typeof (r as { path?: unknown }).path === 'string')
}

/** Why the tree can't be saved / previewed as-is (FE-13): an empty name
 * flattens to "a//b" and silently re-parents its children on reload, and
 * two same-named siblings flatten to one path and merge. Empty when fine. */
export function treeProblems(nodes: FolderNode[]): string[] {
  const problems = new Set<string>()
  const walk = (level: FolderNode[]) => {
    const seen = new Set<string>()
    for (const node of level) {
      if (!node.name.trim()) problems.add('Every folder needs a name.')
      else if (!isValidName(node.name)) problems.add(`"${node.name}" is not a valid folder name.`)
      if (seen.has(node.name)) problems.add(`"${node.name}" appears twice under the same parent.`)
      seen.add(node.name)
      walk(node.children)
    }
  }
  walk(nodes)
  return [...problems]
}
