import type { CsvRow, FolderNode } from '../types'

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

/** Inverse of flattenTree: builds a nested tree from flat '/'-delimited rows. */
export function treeFromRows(rows: CsvRow[]): FolderNode[] {
  const root: FolderNode[] = []

  for (const row of rows) {
    const segments = row.path.split('/').map(s => s.trim()).filter(Boolean)
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
      if (depth === segments.length - 1 && row.description) {
        existing.description = row.description
      }
      level = existing.children
    })
  }

  return root
}

export function findNode(nodes: FolderNode[], id: string): FolderNode | null {
  for (const node of nodes) {
    if (node.id === id) return node
    const found = findNode(node.children, id)
    if (found) return found
  }
  return null
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
