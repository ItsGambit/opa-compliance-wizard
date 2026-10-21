/** UI-10: the model survives leaving and re-entering the Access Explorer. 5.51.0: it opens from the stored OPA scan, says when that
 * scan was read, and its Refresh is the OPA part of the combined refresh. */
import { StrictMode } from 'react'
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError, fetchAccessModel, fetchEnvironments, fetchRefreshStatus, startRefresh } from '../api/client'
import { renderWithClient } from '../test/renderWithClient'
import type { AccessModel, AccessModelResponse, RefreshStatus } from '../types'
import { AccessExplorer } from './AccessExplorer'
import { AccessModelProvider } from './AccessModelProvider'

vi.mock('../api/client', async importOriginal => ({
  ...(await importOriginal<typeof import('../api/client')>()),
  fetchAccessModel: vi.fn(), startRefresh: vi.fn(), fetchRefreshStatus: vi.fn(), fetchEnvironments: vi.fn(),
}))
vi.mock('./ResourceGroupsTab', () => ({ ResourceGroupsTab: () => <div>resource groups view</div> }))
vi.mock('./ExportButtons', () => ({ ExportButtons: () => null }))
vi.mock('../utils/exportSections', () => ({ accessModelExportSections: () => [] }))

const hoursAgo = (h: number) => new Date(Date.now() - h * 3_600_000).toISOString()
const stored = (over: Partial<AccessModelResponse> = {}): AccessModelResponse => ({
  model: { warnings: [] } as unknown as AccessModel, built_at: hoursAgo(6), age_seconds: 21600, source: 'cache', stale: false, very_stale: false,
  counts: { users: 3 }, warnings: 0, modified_at: null, ...over,
})
const status = (over: Partial<RefreshStatus> = {}): RefreshStatus => ({
  status: 'idle', job_id: null, trigger: null, started_at: null, finished_at: null, parts_requested: [], cancel_requested: false, summary: null,
  parts: { opa: { state: 'not_requested' }, okta: { state: 'not_requested' }, log: { state: 'not_requested' } }, ...over,
})
const noScan = () => new ApiError('No stored OPA scan for this environment yet.', 404, { error: 'x', reason: 'no_scan' })

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(fetchEnvironments).mockResolvedValue({ environments: [], active: 'dev' } as never)
  vi.mocked(fetchRefreshStatus).mockResolvedValue(status())
  vi.mocked(startRefresh).mockResolvedValue({ started: true, already_running: false, job_id: 'j1' })
})

function Shell({ show }: { show: boolean }) {
  return <AccessModelProvider>{show ? <AccessExplorer subTab="resource_groups" /> : <div>other page</div>}</AccessModelProvider>
}
const renderShell = (show = true) => renderWithClient(<Shell show={show} />)

describe('AccessExplorer', () => {
  it('opens from the stored scan without starting any job, and says when it was read', async () => {
    vi.mocked(fetchAccessModel).mockResolvedValue(stored())
    renderShell()
    expect(await screen.findByText('resource groups view')).toBeTruthy()
    expect(startRefresh).not.toHaveBeenCalled()
    expect(screen.getByText(/OPA scan as of/)).toBeTruthy()
    expect(screen.getByText(/6 h ago/)).toBeTruthy()
    expect(screen.getByText('Current')).toBeTruthy()
    expect(screen.getByRole('button', { name: /Refresh OPA scan/ })).toBeTruthy()
  })

  it('starts the first scan only when none was ever stored (no_scan), with the full-page panel', async () => {
    vi.mocked(fetchAccessModel).mockRejectedValueOnce(noScan()).mockResolvedValue(stored())
    vi.mocked(fetchRefreshStatus).mockResolvedValue(status({
      status: 'running', job_id: 'j1', parts_requested: ['opa'],
      parts: { opa: { state: 'running', step_defs: [['users', 'Fetching users']], steps: [{ key: 'users', status: 'start', detail: null }] }, okta: { state: 'not_requested' }, log: { state: 'not_requested' } },
    }))
    renderShell()
    expect(await screen.findByText(/No stored OPA scan for this environment yet\./)).toBeTruthy()
    await waitFor(() => expect(startRefresh).toHaveBeenCalledWith('dev', ['opa']))
    expect(await screen.findByText('Fetching users')).toBeTruthy()
  })

  it('does not reopen or rescan after a page switch', async () => {
    vi.mocked(fetchAccessModel).mockResolvedValue(stored())
    const { rerender } = renderShell()
    expect(await screen.findByText('resource groups view')).toBeTruthy()
    rerender(<Shell show={false} />)
    rerender(<Shell show />)
    expect(screen.getByText('resource groups view')).toBeTruthy()
    expect(fetchAccessModel).toHaveBeenCalledTimes(1)
    expect(startRefresh).not.toHaveBeenCalled()
  })

  it('shows an amber "Stale" badge from 24 hours and a red "Very stale" from 7 days', async () => {
    vi.mocked(fetchAccessModel).mockResolvedValue(stored({ built_at: hoursAgo(50) }))
    const { unmount } = renderShell()
    expect(await screen.findByText('Stale · 2 days')).toBeTruthy()
    unmount()
    vi.mocked(fetchAccessModel).mockResolvedValue(stored({ built_at: hoursAgo(24 * 9) }))
    renderShell()
    expect(await screen.findByText('Very stale · 9 days')).toBeTruthy()
  })

  it('Refresh keeps the old scan visible and swaps in the new one when the OPA part is done', async () => {
    vi.mocked(fetchAccessModel).mockResolvedValueOnce(stored({ built_at: hoursAgo(30) })).mockResolvedValue(stored({ built_at: hoursAgo(0.01) }))
    vi.mocked(fetchRefreshStatus)
      .mockResolvedValueOnce(status())
      .mockResolvedValueOnce(status({ status: 'running', job_id: 'j1', parts_requested: ['opa'], parts: { opa: { state: 'running', step_defs: [['users', 'Fetching users']], steps: [] }, okta: { state: 'not_requested' }, log: { state: 'not_requested' } } }))
      .mockResolvedValue(status({ status: 'done', job_id: 'j1', parts_requested: ['opa'], parts: { opa: { state: 'ok' }, okta: { state: 'not_requested' }, log: { state: 'not_requested' } } }))
    renderShell()
    await screen.findByText('Stale · 1 day')
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: /Refresh OPA scan/ })) })
    expect(await screen.findByText(/Showing the OPA scan as of/)).toBeTruthy()
    expect(screen.getByText('resource groups view')).toBeTruthy()  // the old data stays while refreshing
    expect(await screen.findByText('Current', undefined, { timeout: 4000 })).toBeTruthy()  // swapped in place
    expect(screen.queryByText('Stale · 1 day')).toBeNull()
    expect(startRefresh).toHaveBeenCalledWith('dev', ['opa'])
  })

  it('a refused refresh keeps the previous scan, shows the server\'s message and names the scan that is still shown; the label does not change', async () => {
    const built = hoursAgo(6)
    vi.mocked(fetchAccessModel).mockResolvedValue(stored({ built_at: built }))
    vi.mocked(fetchRefreshStatus)
      .mockResolvedValueOnce(status())
      .mockResolvedValue(status({ status: 'done', job_id: 'j1', parts_requested: ['opa'], parts: {
        opa: { state: 'refused', message: 'OPA refused the service key for projects (HTTP 403). The previous scan is kept.' }, okta: { state: 'not_requested' }, log: { state: 'not_requested' } } }))
    renderShell()
    await screen.findByText('resource groups view')
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: /Refresh OPA scan/ })) })
    expect(await screen.findByText(/OPA refused the service key for projects \(HTTP 403\)/)).toBeTruthy()
    expect(screen.getByText(/Refresh failed:/)).toBeTruthy()
    expect(screen.getByText(/is still shown\./)).toBeTruthy()
    expect(screen.getByText('resource groups view')).toBeTruthy()
    const label = screen.getByText(/OPA scan as of/).parentElement!
    expect(within(label).getByText('Current')).toBeTruthy()
    const refresh = screen.getByRole('button', { name: /Refresh OPA scan/ })
    expect(refresh.getAttribute('aria-disabled')).toBe('false')
  })

  it('the as-of explanation is attached to the label and the button (not only a title), and "Edited since the scan" shows after a local correction', async () => {
    vi.mocked(fetchAccessModel).mockResolvedValue(stored({ modified_at: new Date().toISOString() }))
    renderShell()
    await screen.findByText('resource groups view')
    const button = screen.getByRole('button', { name: /Refresh OPA scan/ })
    const help = document.getElementById(button.getAttribute('aria-describedby')!)!
    expect(help.textContent).toMatch(/read from the stored scan/)
    expect(screen.getByText('Edited since the scan')).toBeTruthy()
  })

  it('a stored scan that cannot be opened is a failed first load with a way to retry, and it does not start a scan', async () => {
    vi.mocked(fetchAccessModel).mockRejectedValueOnce(new ApiError('The stored scan could not be read.', 502)).mockResolvedValue(stored())
    renderShell()
    expect(await screen.findByText(/The stored scan could not be read\./)).toBeTruthy()
    expect(startRefresh).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: /Try again/ }))
    expect(await screen.findByText('resource groups view')).toBeTruthy()
  })

  it('StrictMode: a mount straight onto the Access Explorer still loads (no stuck "Opening…")', async () => {
    vi.mocked(fetchAccessModel).mockResolvedValue(stored())
    renderWithClient(<StrictMode><Shell show /></StrictMode>)
    expect(await screen.findByText('resource groups view')).toBeTruthy()
  })
})
