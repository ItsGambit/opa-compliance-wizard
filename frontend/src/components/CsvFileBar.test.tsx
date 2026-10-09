/** UI-21 / FE-11 / FE-13 in the CSV bar. */
import { fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fetchCsv, fetchCsvFiles, saveCsv } from '../api/client'
import { renderWithClient } from '../test/renderWithClient'
import type { FolderNode } from '../types'
import { newNode } from '../utils/tree'
import { CsvFileBar } from './CsvFileBar'

vi.mock('../api/client', () => ({ fetchCsv: vi.fn(), fetchCsvFiles: vi.fn(), saveCsv: vi.fn() }))
vi.mock('./Select', async () => ({ Select: (await import('../test/MockSelect')).MockSelect }))

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(fetchCsvFiles).mockResolvedValue({ files: ['folders_template.csv', 'okta_export.csv'] })
})

async function pick(file: string) {
  await waitFor(() => expect(document.querySelector('select option[value="okta_export.csv"]')).not.toBeNull())
  fireEvent.change(screen.getByLabelText('Load existing CSV'), { target: { value: file } })
}

describe('CsvFileBar', () => {
  it('asks before a load replaces a tree that has folders', async () => {
    vi.mocked(fetchCsv).mockResolvedValue({ rows: [{ path: 'a', description: '' }] })
    const onLoad = vi.fn()
    renderWithClient(<CsvFileBar nodes={[newNode('mine')]} onLoad={onLoad} />)
    await pick('folders_template.csv')
    fireEvent.click(screen.getByRole('button', { name: /^Load$/ }))
    expect(fetchCsv).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Yes, load it' }))
    await waitFor(() => expect(onLoad).toHaveBeenCalled())
  })

  it('refuses a CSV that is not a folder template', async () => {
    vi.mocked(fetchCsv).mockResolvedValue({ rows: [{ uuid: 'x' }] as never })
    const onLoad = vi.fn()
    renderWithClient(<CsvFileBar nodes={[]} onLoad={onLoad} />)
    await pick('okta_export.csv')
    fireEvent.click(screen.getByRole('button', { name: /^Load$/ }))
    await waitFor(() => expect(fetchCsv).toHaveBeenCalled())
    await new Promise(r => setTimeout(r, 10))
    expect(onLoad).not.toHaveBeenCalled()
  })

  it('asks before overwriting an existing file', async () => {
    vi.mocked(saveCsv).mockResolvedValue({ saved: true, file: 'folders_template.csv', row_count: 1 })
    renderWithClient(<CsvFileBar nodes={[newNode('a')]} onLoad={() => {}} />)
    await pick('folders_template.csv')
    fireEvent.click(screen.getByRole('button', { name: /^Save$/ }))
    expect(saveCsv).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Yes, overwrite' }))
    await waitFor(() => expect(saveCsv).toHaveBeenCalledTimes(1))
  })

  it('saves a new file name without asking', async () => {
    vi.mocked(saveCsv).mockResolvedValue({ saved: true, file: 'new.csv', row_count: 1 })
    renderWithClient(<CsvFileBar nodes={[newNode('a')]} onLoad={() => {}} />)
    await pick('folders_template.csv')
    fireEvent.change(screen.getByLabelText('Save tree to CSV file name'), { target: { value: 'new.csv' } })
    fireEvent.click(screen.getByRole('button', { name: /^Save$/ }))
    await waitFor(() => expect(saveCsv).toHaveBeenCalledWith('new.csv', [{ path: 'a', description: '' }]))
  })

  it('blocks Save while a folder has no name (FE-13)', async () => {
    const nodes: FolderNode[] = [{ ...newNode('a'), children: [newNode('')] }]
    renderWithClient(<CsvFileBar nodes={nodes} onLoad={() => {}} />)
    expect((screen.getByRole('button', { name: /^Save$/ }) as HTMLButtonElement).disabled).toBe(true)
    expect(screen.getByText(/Every folder needs a name/)).toBeTruthy()
  })
})
