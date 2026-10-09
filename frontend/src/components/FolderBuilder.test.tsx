/** UI-17: changing project drops the OPA folder ids loaded from the old one. */
import { fireEvent, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { renderWithClient } from '../test/renderWithClient'
import type { FolderNode } from '../types'
import { newNode } from '../utils/tree'
import { FolderBuilder } from './FolderBuilder'

vi.mock('../api/hooks', () => ({
  useResourceGroups: () => ({ data: [{ id: 'rg1', name: 'RG' }] }),
  useProjects: () => ({ data: [{ id: 'pA', name: 'Project A' }, { id: 'pB', name: 'Project B' }] }),
  useResourceGroupSecurityPolicies: () => ({ data: [] }),
}))
vi.mock('./ResourceGroupSelect', () => ({
  ResourceGroupSelect: ({ onChange }: { onChange: (id: string) => void }) => <button type="button" onClick={() => onChange('rg1')}>pick rg</button>,
}))
vi.mock('./ProjectSelect', () => ({
  ProjectSelect: ({ onChange }: { onChange: (id: string) => void }) => (
    <>
      <button type="button" onClick={() => onChange('pA')}>pick A</button>
      <button type="button" onClick={() => onChange('pB')}>pick B</button>
    </>
  ),
}))
vi.mock('./LoadExistingStructureButton', () => ({
  LoadExistingStructureButton: ({ onLoad }: { onLoad: (n: FolderNode[], ids: Map<string, string>) => void }) => (
    <button type="button" onClick={() => onLoad([newNode('secrets')], new Map([['secrets', 'folder-in-A']]))}>load existing</button>
  ),
}))
vi.mock('./CsvFileBar', () => ({ CsvFileBar: () => null }))
vi.mock('./ActionBar', () => ({ ActionBar: () => null }))
vi.mock('./AssignAccessDialog', () => ({
  AssignAccessDialog: ({ onSaved }: { onSaved: () => void }) => <button type="button" onClick={onSaved}>save policy</button>,
}))

describe('FolderBuilder', () => {
  it('a project change turns loaded folders back into local-only rows', () => {
    renderWithClient(<FolderBuilder />)
    fireEvent.click(screen.getByText('pick rg'))
    fireEvent.click(screen.getByText('pick A'))
    fireEvent.click(screen.getByText('load existing'))
    expect(screen.getByRole('button', { name: 'Delete secrets from OPA' })).toBeTruthy()
    fireEvent.click(screen.getByText('pick B'))
    expect(screen.queryByRole('button', { name: 'Delete secrets from OPA' })).toBeNull()
    expect(screen.getByRole('button', { name: 'Remove secrets' })).toBeTruthy()
  })

  it('names the project in the delete confirmation', () => {
    renderWithClient(<FolderBuilder />)
    fireEvent.click(screen.getByText('pick rg'))
    fireEvent.click(screen.getByText('pick A'))
    fireEvent.click(screen.getByText('load existing'))
    fireEvent.click(screen.getByRole('button', { name: 'Delete secrets from OPA' }))
    expect(screen.getByText('Project A')).toBeTruthy()
  })

  it('a saved policy refreshes the policy list and the Secrets Access report', () => {
    const { client } = renderWithClient(<FolderBuilder />)
    const spy = vi.spyOn(client, 'invalidateQueries')
    fireEvent.click(screen.getByText('pick rg'))
    fireEvent.click(screen.getByText('pick A'))
    fireEvent.click(screen.getByText('load existing'))
    fireEvent.click(screen.getByTitle('Assign access'))
    fireEvent.click(screen.getByText('save policy'))
    const keys = spy.mock.calls.map(c => (c[0] as { queryKey: string[] }).queryKey[0])
    expect(keys).toEqual(expect.arrayContaining(['security_policies', 'secrets_access_report']))
  })
})
