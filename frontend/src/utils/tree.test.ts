/** FE-11 / FE-13: tree utilities. */
import { describe, expect, it } from 'vitest'
import type { CsvRow, FolderNode } from '../types'
import { flattenTree, looksLikeFolderTemplate, newNode, normalizePath, treeFromRows, treeProblems } from './tree'

const strip = (nodes: FolderNode[]): unknown => nodes.map(n => ({ name: n.name, description: n.description, children: strip(n.children) }))

describe('tree utilities', () => {
  it('round-trips a valid tree through flatten -> rows', () => {
    const tree = [
      { ...newNode('apps', 'all apps'), children: [{ ...newNode('web', ''), children: [newNode('prod', 'p')] }, newNode('db', 'd')] },
      newNode('infra', 'i'),
    ]
    expect(strip(treeFromRows(flattenTree(tree)))).toEqual(strip(tree))
  })

  it('skips rows without a string path instead of throwing (FE-11)', () => {
    const rows = [{ description: 'x' }, { path: 5 }, { path: 'a', description: '' }] as unknown as CsvRow[]
    expect(strip(treeFromRows(rows))).toEqual([{ name: 'a', description: '', children: [] }])
  })

  it('lets the last row naming a folder set its description, even to empty', () => {
    const rows: CsvRow[] = [{ path: 'a', description: 'old' }, { path: 'a/b', description: 'b' }, { path: 'a', description: '' }]
    expect(treeFromRows(rows)[0].description).toBe('')
  })

  it('normalises paths the same way in both directions', () => {
    expect(normalizePath(' a / b//c ')).toBe('a/b/c')
  })

  it('reports empty, invalid and duplicate sibling names (FE-13)', () => {
    expect(treeProblems([newNode('ok')])).toEqual([])
    expect(treeProblems([newNode('')])).toEqual(['Every folder needs a name.'])
    expect(treeProblems([newNode('has space')])[0]).toMatch(/not a valid/)
    expect(treeProblems([newNode('a'), newNode('a')])[0]).toMatch(/twice/)
    expect(treeProblems([{ ...newNode('p'), children: [newNode('')] }])).toEqual(['Every folder needs a name.'])
    // same name under different parents is fine for the tree itself
    expect(treeProblems([{ ...newNode('x'), children: [newNode('a')] }, { ...newNode('y'), children: [newNode('a')] }])).toEqual([])
  })

  it('recognises a folder template', () => {
    expect(looksLikeFolderTemplate([{ path: 'a', description: '' }])).toBe(true)
    expect(looksLikeFolderTemplate([{ uuid: 'x', published: 'y' }])).toBe(false)
    expect(looksLikeFolderTemplate([])).toBe(true)
  })
})
