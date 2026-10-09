/** UI-10: the model survives leaving and re-entering the Access Explorer. */
import { StrictMode } from 'react'
import { act, render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fetchAccessBootstrapResult, fetchAccessBootstrapStatus, startAccessBootstrap } from '../api/client'
import type { AccessModel } from '../types'
import { AccessExplorer } from './AccessExplorer'
import { AccessModelProvider } from './AccessModelProvider'

vi.mock('../api/client', () => ({
  startAccessBootstrap: vi.fn(), fetchAccessBootstrapStatus: vi.fn(), fetchAccessBootstrapResult: vi.fn(), isSessionExpiredError: () => false,
}))
vi.mock('./ResourceGroupsTab', () => ({ ResourceGroupsTab: () => <div>resource groups view</div> }))
vi.mock('./ExportButtons', () => ({ ExportButtons: () => null }))
vi.mock('../utils/exportSections', () => ({ accessModelExportSections: () => [] }))

beforeEach(() => { vi.clearAllMocks() })

function Shell({ show }: { show: boolean }) {
  return <AccessModelProvider>{show ? <AccessExplorer subTab="resource_groups" /> : <div>other page</div>}</AccessModelProvider>
}

describe('AccessExplorer', () => {
  it('does not re-run the bootstrap after a page switch', async () => {
    vi.mocked(startAccessBootstrap).mockResolvedValue({ started: true, steps: [] })
    vi.mocked(fetchAccessBootstrapStatus).mockResolvedValue({ status: 'done', steps: [], error: null })
    vi.mocked(fetchAccessBootstrapResult).mockResolvedValue({ warnings: [] } as unknown as AccessModel)
    const { rerender } = render(<Shell show />)
    expect(await screen.findByText('resource groups view')).toBeTruthy()
    rerender(<Shell show={false} />)
    rerender(<Shell show />)
    expect(screen.getByText('resource groups view')).toBeTruthy()
    expect(startAccessBootstrap).toHaveBeenCalledTimes(1)
  })

  it('a failed refresh does not leave "Refreshing…" stuck', async () => {
    vi.mocked(startAccessBootstrap).mockResolvedValue({ started: true, steps: [] })
    vi.mocked(fetchAccessBootstrapStatus)
      .mockResolvedValueOnce({ status: 'done', steps: [], error: null })
      .mockResolvedValue({ status: 'error', steps: [], error: 'okta 503' })
    vi.mocked(fetchAccessBootstrapResult).mockResolvedValue({ warnings: [] } as unknown as AccessModel)
    render(<Shell show />)
    await screen.findByText('resource groups view')
    await act(async () => { screen.getByRole('button', { name: /Refresh/ }).click() })
    expect(await screen.findByText('okta 503')).toBeTruthy()
    const refresh = screen.getByRole('button', { name: /Refresh/ }) as HTMLButtonElement
    expect(refresh.disabled).toBe(false)
    expect(refresh.textContent).not.toMatch(/Refreshing/)
    expect(screen.getByText('resource groups view')).toBeTruthy() // previous data still shown
  })

  it('StrictMode: a mount straight onto the Access Explorer still loads (no stuck "Starting…")', async () => {
    vi.mocked(startAccessBootstrap).mockResolvedValue({ started: true, steps: [] })
    vi.mocked(fetchAccessBootstrapStatus).mockResolvedValue({ status: 'done', steps: [], error: null })
    vi.mocked(fetchAccessBootstrapResult).mockResolvedValue({ warnings: [] } as unknown as AccessModel)
    render(<StrictMode><Shell show /></StrictMode>)
    expect(await screen.findByText('resource groups view')).toBeTruthy()
  })
})
