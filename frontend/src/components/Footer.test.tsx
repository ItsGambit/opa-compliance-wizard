/** UI-07 / 5.42.0: Sync now on a shared environment follows what an admin allows shared users. */
import { fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fetchEnvironments, fetchRefreshStatus, fetchSyncStatus, fetchUpgradeStatus, fetchVersion, fetchWhoami, startRefresh, startSync } from '../api/client'
import type { RefreshStatus } from '../types'
import { renderWithClient } from '../test/renderWithClient'
import type { Environment } from '../types'
import { makeStatus, NEWER } from '../test/upgradeFixtures'
import { Footer } from './Footer'

vi.mock('../api/client', () => ({
  fetchEnvironments: vi.fn(), fetchSyncStatus: vi.fn(), fetchVersion: vi.fn(), fetchWhoami: vi.fn(), fetchUpgradeStatus: vi.fn(), startSync: vi.fn(), isSessionExpiredError: () => false, onSessionRestored: () => () => {},
  fetchRefreshStatus: vi.fn(), startRefresh: vi.fn(),
}))

const env = (o: Partial<Environment>): Environment => ({
  id: 'e1', name: 'team', base_domain: '', team_name: '', key_id: '', okta_url: '', has_okta_token: true,
  sync_schedule: {} as Environment['sync_schedule'], shared: true, is_own: false, addressable: true, ...o,
})

const IDLE: RefreshStatus = {
  status: 'idle', job_id: null, trigger: null, started_at: null, finished_at: null, parts_requested: [], cancel_requested: false, summary: null,
  parts: { opa: { state: 'not_requested' }, okta: { state: 'not_requested' }, log: { state: 'not_requested' } },
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(fetchRefreshStatus).mockResolvedValue(IDLE)
  vi.mocked(startRefresh).mockResolvedValue({ started: true, already_running: false, job_id: 'j1' })
  vi.mocked(fetchVersion).mockResolvedValue({ version: '5.40.7' })
  vi.mocked(fetchWhoami).mockResolvedValue({ email: 'a@example.com', is_local: false, is_admin: false })
  vi.mocked(fetchSyncStatus).mockResolvedValue({ status: 'idle', steps: [], error: null, sync_state: null, is_first_sync: false })
})

describe('Footer', () => {
  it('disables Sync now (with the reason) on an environment shared with this user', async () => {
    vi.mocked(fetchEnvironments).mockResolvedValue({ environments: [env({})], active: 'team', active_id: 'e1' })
    renderWithClient(<Footer />)
    const btn = (await screen.findByRole('button', { name: /Sync now/ })) as HTMLButtonElement
    // aria-disabled and still focusable (WCAG 2.1.1): the reason is read out through aria-describedby, and clicking does nothing
    expect(btn.getAttribute('aria-disabled')).toBe('true')
    expect(btn.disabled).toBe(false)
    expect(btn.title).toMatch(/an admin hasn't allowed shared users to run its sync on 'team'/)
    expect(document.getElementById(btn.getAttribute('aria-describedby')!)!.textContent).toMatch(/Refreshing needs the Sync now permission on this environment.*an admin hasn't allowed shared users to run its sync on 'team'/)
    fireEvent.click(btn)
    expect(startRefresh).not.toHaveBeenCalled()
  })

  it('follows the server-reported permission on a shared environment (5.42.0)', async () => {
    const permissions = Object.fromEntries(
      ['view_archive', 'live_read', 'tenant_write', 'import_csv', 'reset_watermark', 'sync_settings'].map(k => [k, { value: 'deny', source: 'default' }]),
    ) as NonNullable<Environment['permissions']>
    vi.mocked(fetchEnvironments).mockResolvedValue({
      environments: [env({ permissions: { ...permissions, sync_now: { value: 'allow', source: 'override' } } })],
      active: 'team', active_id: 'e1',
    })
    renderWithClient(<Footer />)
    const btn = (await screen.findByRole('button', { name: /Sync now/ })) as HTMLButtonElement
    expect(btn.getAttribute('aria-disabled')).toBe('true')  // sync_now allowed, but a refresh also reads OPA live: live_read is denied
    expect(btn.title).toMatch(/Live read permission/)
  })

  it('enables it on the user’s own environment', async () => {
    vi.mocked(fetchEnvironments).mockResolvedValue({ environments: [env({ is_own: true, shared: false })], active: 'team', active_id: 'e1' })
    renderWithClient(<Footer />)
    const btn = (await screen.findByRole('button', { name: /Sync now/ })) as HTMLButtonElement
    expect(btn.getAttribute('aria-disabled')).toBe('false')
  })

  it('Sync now runs the FULL refresh (all three parts) through the refresh route and never calls the legacy sync/start route', async () => {
    vi.mocked(fetchEnvironments).mockResolvedValue({ environments: [env({ is_own: true, shared: false })], active: 'team', active_id: 'e1' })
    renderWithClient(<Footer />)
    fireEvent.click(await screen.findByRole('button', { name: /Sync now/ }))
    await waitFor(() => expect(startRefresh).toHaveBeenCalledTimes(1))
    expect(startRefresh).toHaveBeenCalledWith('team', undefined)  // no `parts`: the server runs every part
    expect(startSync).not.toHaveBeenCalled()
  })

  it('while a refresh runs the button attaches (no second job) and the footer says it is syncing', async () => {
    vi.mocked(fetchEnvironments).mockResolvedValue({ environments: [env({ is_own: true, shared: false })], active: 'team', active_id: 'e1' })
    vi.mocked(fetchRefreshStatus).mockResolvedValue({
      ...IDLE, status: 'running', job_id: 'j7', trigger: 'manual', started_at: new Date().toISOString(), parts_requested: ['opa', 'okta', 'log'],
      parts: { opa: { state: 'running' }, okta: { state: 'pending' }, log: { state: 'ok' } },
    })
    renderWithClient(<Footer />)
    const btn = await screen.findByRole('button', { name: /Syncing…/ })
    expect(btn.getAttribute('aria-disabled')).toBe('true')
    fireEvent.click(btn)
    expect(startRefresh).not.toHaveBeenCalled()
    const bar = screen.getByRole('progressbar', { name: 'Refresh progress' })
    expect(bar.getAttribute('aria-valuenow')).toBe('33')  // one of three parts has ended
  })

  it('shows the last refresh and its outcome, not only the last System Log sync', async () => {
    vi.mocked(fetchEnvironments).mockResolvedValue({ environments: [env({ is_own: true, shared: false })], active: 'team', active_id: 'e1' })
    vi.mocked(fetchSyncStatus).mockResolvedValue({
      status: 'idle', steps: [], error: null, is_first_sync: false,
      sync_state: { last_sync_completed_at: '2026-10-21T02:14:00.000Z', last_refresh: { scheduled: {
        finished_at: '2026-10-21T02:20:00.000Z', trigger: 'scheduled', parts: { opa: { state: 'ok' }, log: { state: 'ok' }, okta: { state: 'refused' } } } } },
    } as never)
    renderWithClient(<Footer />)
    const line = await screen.findByText(/Last refresh /)
    expect(line.textContent).toMatch(/^Last refresh .*2026.* · 2 of 3 parts completed$/)  // one short line; the detail is in the tooltip and the description
    expect(line.getAttribute('title')).toBe('Okta scan did not complete')
    expect(document.getElementById(line.getAttribute('aria-describedby')!)!.textContent).toBe('Okta scan did not complete')
    expect(screen.queryByText(/Last sync:/)).toBeNull()
  })

  it('without any refresh record it still says when the System Log last synced', async () => {
    vi.mocked(fetchEnvironments).mockResolvedValue({ environments: [env({ is_own: true, shared: false })], active: 'team', active_id: 'e1' })
    renderWithClient(<Footer />)
    expect(await screen.findByText(/Last sync: never/)).toBeTruthy()
  })

  it('tells an admin about a newer release (only when the opt-in check found one)', async () => {
    vi.mocked(fetchEnvironments).mockResolvedValue({ environments: [env({ is_own: true, shared: false })], active: 'team', active_id: 'e1' })
    vi.mocked(fetchWhoami).mockResolvedValue({ email: 'a@example.com', is_local: false, is_admin: true, can_admin: true })
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(makeStatus({ ...NEWER, installed_version: '5.40.7' }))
    renderWithClient(<Footer />)
    expect(await screen.findByText('Update available: v5.48.0')).toBeTruthy()
  })

  it('a non-admin is never asked about updates', async () => {
    vi.mocked(fetchEnvironments).mockResolvedValue({ environments: [env({ is_own: true, shared: false })], active: 'team', active_id: 'e1' })
    renderWithClient(<Footer />)
    await screen.findByRole('button', { name: /Sync now/ })
    expect(fetchUpgradeStatus).not.toHaveBeenCalled()
  })
})
