/** UI-07 / 5.42.0: Sync now on a shared environment follows what an admin allows shared users. */
import { screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fetchEnvironments, fetchSyncStatus, fetchUpgradeStatus, fetchVersion, fetchWhoami } from '../api/client'
import { renderWithClient } from '../test/renderWithClient'
import type { Environment } from '../types'
import { makeStatus, NEWER } from '../test/upgradeFixtures'
import { Footer } from './Footer'

vi.mock('../api/client', () => ({
  fetchEnvironments: vi.fn(), fetchSyncStatus: vi.fn(), fetchVersion: vi.fn(), fetchWhoami: vi.fn(), fetchUpgradeStatus: vi.fn(), startSync: vi.fn(), isSessionExpiredError: () => false, onSessionRestored: () => () => {},
}))

const env = (o: Partial<Environment>): Environment => ({
  id: 'e1', name: 'team', base_domain: '', team_name: '', key_id: '', okta_url: '', has_okta_token: true,
  sync_schedule: {} as Environment['sync_schedule'], shared: true, is_own: false, addressable: true, ...o,
})

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(fetchVersion).mockResolvedValue({ version: '5.40.7' })
  vi.mocked(fetchWhoami).mockResolvedValue({ email: 'a@example.com', is_local: false, is_admin: false })
  vi.mocked(fetchSyncStatus).mockResolvedValue({ status: 'idle', steps: [], error: null, sync_state: null, is_first_sync: false })
})

describe('Footer', () => {
  it('disables Sync now (with the reason) on an environment shared with this user', async () => {
    vi.mocked(fetchEnvironments).mockResolvedValue({ environments: [env({})], active: 'team', active_id: 'e1' })
    renderWithClient(<Footer />)
    const btn = (await screen.findByRole('button', { name: /Sync now/ })) as HTMLButtonElement
    expect(btn.disabled).toBe(true)
    expect(btn.title).toMatch(/an admin hasn't allowed shared users to run its sync on 'team'/)
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
    expect(btn.disabled).toBe(false)
  })

  it('enables it on the user’s own environment', async () => {
    vi.mocked(fetchEnvironments).mockResolvedValue({ environments: [env({ is_own: true, shared: false })], active: 'team', active_id: 'e1' })
    renderWithClient(<Footer />)
    const btn = (await screen.findByRole('button', { name: /Sync now/ })) as HTMLButtonElement
    expect(btn.disabled).toBe(false)
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
