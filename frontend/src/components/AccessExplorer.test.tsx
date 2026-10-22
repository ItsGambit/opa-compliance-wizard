/** UI-10: the model survives leaving and re-entering the Access Explorer. 5.51.0: it opens from the stored OPA scan, says when that
 * scan was read, and its Refresh is the OPA part of the combined refresh. */
import { StrictMode } from 'react'
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError, cancelRefresh, fetchAccessModel, fetchEnvironments, fetchRefreshStatus, fetchSyncStatus, startRefresh } from '../api/client'
import { renderWithClient } from '../test/renderWithClient'
import type { AccessModel, AccessModelResponse, RefreshStatus } from '../types'
import { AccessExplorer } from './AccessExplorer'
import { AccessModelProvider } from './AccessModelProvider'

vi.mock('../api/client', async importOriginal => ({
  ...(await importOriginal<typeof import('../api/client')>()),
  fetchAccessModel: vi.fn(), startRefresh: vi.fn(), fetchRefreshStatus: vi.fn(), fetchEnvironments: vi.fn(), fetchSyncStatus: vi.fn(), cancelRefresh: vi.fn(),
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

const toolbarRefresh = () => screen.getAllByRole('button', { name: /Refresh OPA scan/ }).at(-1)!  // the stale banner has one too (first)

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(fetchEnvironments).mockResolvedValue({ environments: [], active: 'dev' } as never)
  vi.mocked(fetchRefreshStatus).mockResolvedValue(status())
  vi.mocked(fetchSyncStatus).mockResolvedValue({ status: 'idle', steps: [], error: null, sync_state: null, is_first_sync: false })
  vi.mocked(startRefresh).mockResolvedValue({ started: true, already_running: false, job_id: 'j1' })
})

function Shell({ show }: { show: boolean }) {
  return <AccessModelProvider>{show ? <AccessExplorer subTab="resource_groups" onOpenEnvironments={() => {}} /> : <div>other page</div>}</AccessModelProvider>
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
    expect(toolbarRefresh()).toBeTruthy()
  })

  it('starts the first scan only when none was ever stored (no_scan), with the full-page panel', async () => {
    vi.mocked(fetchAccessModel).mockRejectedValueOnce(noScan()).mockResolvedValue(stored())
    vi.mocked(fetchRefreshStatus).mockResolvedValue(status({
      status: 'running', job_id: 'j1', parts_requested: ['opa'],
      parts: { opa: { state: 'running', step_defs: [['users', 'Fetching users']], steps: [{ key: 'users', status: 'start', detail: null }] }, okta: { state: 'not_requested' }, log: { state: 'not_requested' } },
    }))
    renderShell()
    expect(await screen.findByText(/No stored OPA scan for this environment yet\./)).toBeTruthy()
    await waitFor(() => expect(startRefresh).toHaveBeenCalledWith('dev', ['opa'], 'explorer'))
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
    await act(async () => { fireEvent.click(toolbarRefresh()) })
    expect(await screen.findByText(/Showing the OPA scan as of/)).toBeTruthy()
    expect(screen.getByText('resource groups view')).toBeTruthy()  // the old data stays while refreshing
    expect(await screen.findByText('Current', undefined, { timeout: 4000 })).toBeTruthy()  // swapped in place
    expect(screen.queryByText('Stale · 1 day')).toBeNull()
    expect(startRefresh).toHaveBeenCalledWith('dev', ['opa'], 'explorer')
  })

  it('a refused refresh keeps the previous scan, shows the server\'s message and names the scan that is still shown; the label does not change', async () => {
    const built = hoursAgo(6)
    vi.mocked(fetchAccessModel).mockResolvedValue(stored({ built_at: built }))
    vi.mocked(fetchRefreshStatus)
      .mockResolvedValueOnce(status())
      .mockResolvedValue(status({ status: 'done', job_id: 'j1', parts_requested: ['opa'], parts: {
        opa: { state: 'refused', audit_line: 'access_scan.failed (OpaApiError: 403)', steps: [{ key: 'users', status: 'start', detail: null }], step_defs: [['resource_groups', 'Fetching resource groups'], ['users', 'Fetching users'], ['projects', 'Fetching projects']], message: 'OPA refused the service key when listing projects (HTTP 403). Nothing was changed: the scan from 21 Oct 2026, 02:20 UTC is still shown and stored. To fix: open Environments and check the service key; it needs read access to the team\'s users, groups, projects and policies. Then retry.' }, okta: { state: 'not_requested' }, log: { state: 'not_requested' } } }))
    renderShell()
    await screen.findByText('resource groups view')
    await act(async () => { fireEvent.click(toolbarRefresh()) })
    // the panel leads with the outcome: title, bold what-happened sentence, nothing changed, "To fix:", then the buttons and the audit line
    expect(await screen.findByText('Refresh refused')).toBeTruthy()
    expect(screen.getByText('OPA refused the service key when listing projects', { selector: 'strong' })).toBeTruthy()
    const text = screen.getByTestId('failure-text').textContent!
    expect(text).toMatch(/^OPA refused the service key when listing projects \(HTTP 403\)\. Nothing was changed: the scan from .* is still shown and stored\. To fix: open Environments/)
    expect(screen.getByText('To fix:', { selector: 'strong' })).toBeTruthy()
    const panel = screen.getByTestId('failure-text').parentElement!
    const order = ['Refresh refused', 'failure-text', 'Retry', 'Open Environments', 'Dismiss', 'Audit Log: access_scan.failed (OpaApiError: 403)']
    const html = panel.textContent!
    expect(order.filter(x => x !== 'failure-text').map(x => html.indexOf(x))).toEqual([...order.filter(x => x !== 'failure-text').map(x => html.indexOf(x))].sort((a, b) => a - b))
    expect(panel.className).not.toMatch(/overflow-y|max-h/)  // never a scroll box that hides the message
    expect(within(panel).queryByText('Fetching projects')).toBeNull()  // steps that never started are not listed
    expect(screen.getByText('resource groups view')).toBeTruthy()
    const label = screen.getByText(/OPA scan as of/).parentElement!
    expect(within(label).getByText('Current')).toBeTruthy()
    expect(toolbarRefresh().getAttribute('aria-disabled')).toBe('false')
  })

  it('Refresh OPA scan while a job without the OPA part runs shows the server\'s busy message and keeps the old scan and label (not "done")', async () => {
    const built = hoursAgo(30)
    vi.mocked(fetchAccessModel).mockResolvedValue(stored({ built_at: built }))
    vi.mocked(startRefresh).mockRejectedValue(new ApiError('A refresh of System Log is running. The OPA scan can start when it finishes.', 409, { error: 'x', reason: 'busy_other_parts' }))
    renderShell()
    await screen.findByText('Stale · 1 day')
    await act(async () => { fireEvent.click(toolbarRefresh()) })
    expect((await screen.findByTestId('failure-text')).textContent).toBe('A refresh of System Log is running. The OPA scan can start when it finishes.')
    expect(screen.getByText('Refresh not started')).toBeTruthy()  // nothing was started and nothing was lost: not "Refresh failed"
    expect(screen.queryByText('Refresh failed')).toBeNull()
    expect(screen.queryByRole('button', { name: 'Open Environments' })).toBeNull()
    expect(screen.getByText('Stale · 1 day')).toBeTruthy()  // the label did not change
    expect(fetchAccessModel).toHaveBeenCalledTimes(1)  // nothing was fetched as if a scan had finished
  })

  it('the as-of explanation is attached to the label and the button (not only a title), and "Edited since the scan" shows after a local correction', async () => {
    vi.mocked(fetchAccessModel).mockResolvedValue(stored({ modified_at: new Date().toISOString() }))
    renderShell()
    await screen.findByText('resource groups view')
    const button = toolbarRefresh()
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

  it('a stale scan shows the warning bar with the age, why the scheduled refresh did not read OPA, and what to do', async () => {
    vi.mocked(fetchAccessModel).mockResolvedValue(stored({ built_at: hoursAgo(50) }))
    vi.mocked(fetchSyncStatus).mockResolvedValue({ status: 'idle', steps: [], error: null, is_first_sync: false, sync_state: { last_refresh: { scheduled: {
      finished_at: '2026-10-21T02:20:00.000Z', parts: { opa: { state: 'timed_out', message: 'Stopped after 45 minutes. The previous data is kept. Try again.' } } } } } } as never)
    renderShell()
    const bar = (await screen.findByText(/This OPA scan is 2 days old\./)).closest('div')!
    await waitFor(() => expect(bar.textContent).toMatch(/The scheduled refresh on .*2026 did not finish its OPA part \(Stopped after 45 minutes\)\./))
    expect(bar.textContent).toMatch(/Policies, groups and memberships may have changed since .*2026/)
    expect(within(bar).getByRole('button', { name: 'Refresh OPA scan' })).toBeTruthy()
    expect(within(bar).queryByRole('link', { name: /Audit Log entry/ })).toBeNull()  // the Audit Log is for administrators
  })

  it('no warning bar for a current scan; the toolbar says Export CSV and Export Markdown and the footnote names the scan', async () => {
    vi.mocked(fetchAccessModel).mockResolvedValue(stored())
    renderShell()
    await screen.findByText('resource groups view')
    expect(screen.queryByText(/This OPA scan is/)).toBeNull()
    expect(screen.getByText(/Policy grants come from the stored OPA scan \(.*2026.*\)\. "Last accessed" and "Resource evidence" read the archive/)).toBeTruthy()
  })

  it('while refreshing the bottom panel has a progress bar, Stop and the sentence that the scan stays on screen', async () => {
    vi.mocked(fetchAccessModel).mockResolvedValue(stored({ built_at: hoursAgo(6) }))
    vi.mocked(fetchRefreshStatus).mockResolvedValueOnce(status()).mockResolvedValue(status({ status: 'running', job_id: 'j1', parts_requested: ['opa'], parts: {
      opa: { state: 'running', step_defs: [['a', 'Resource groups'], ['b', 'Groups'], ['c', 'Users'], ['d', 'Projects']], steps: [{ key: 'a', status: 'done', detail: '4' }, { key: 'b', status: 'start', detail: null }] },
      okta: { state: 'not_requested' }, log: { state: 'not_requested' } } }))
    vi.mocked(cancelRefresh).mockResolvedValue({ cancelling: true, job_id: 'j1' })
    renderShell()
    await screen.findByText('Current')
    await act(async () => { fireEvent.click(toolbarRefresh()) })
    const bar = await screen.findByRole('progressbar', { name: 'Scan progress' })
    expect(bar.getAttribute('aria-valuenow')).toBe('25')
    expect(screen.getByText(/stays on screen until the new one finishes\./)).toBeTruthy()
    expect(screen.getByText('Users')).toBeTruthy()  // the whole list while it runs (the mockup's panel)
    fireEvent.click(screen.getByRole('button', { name: 'Stop' }))
    await waitFor(() => expect(cancelRefresh).toHaveBeenCalledWith('dev'))
  })

  it('a value hidden before storing has its own line and is not reported as an unreadable section', async () => {
    vi.mocked(fetchAccessModel).mockResolvedValue(stored({ model: { warnings: [
      { section: 'gateways', status: 403, message: 'gateways: not available to this service key (HTTP 403); shown as empty.' },
      { section: 'redacted values', status: 'redacted', message: '1 value under name fields looked like a credential and was removed from the stored scan.' },
    ] } as unknown as AccessModel }))
    renderShell()
    await screen.findByText('resource groups view')
    const incomplete = screen.getByText(/Some sections are incomplete/).parentElement!
    expect(incomplete.textContent).toContain('gateways')
    expect(incomplete.textContent).not.toContain('looked like a credential')
    expect(screen.getByText('1 value under name fields looked like a credential and was removed from the stored scan.')).toBeTruthy()
  })
})
