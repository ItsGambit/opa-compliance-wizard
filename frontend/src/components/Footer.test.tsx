/** UI-07: Sync now is the environment owner's action. */
import { screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fetchEnvironments, fetchSyncStatus, fetchVersion } from '../api/client'
import { renderWithClient } from '../test/renderWithClient'
import type { Environment } from '../types'
import { Footer } from './Footer'

vi.mock('../api/client', () => ({
  fetchEnvironments: vi.fn(), fetchSyncStatus: vi.fn(), fetchVersion: vi.fn(), startSync: vi.fn(), isSessionExpiredError: () => false, onSessionRestored: () => () => {},
}))

const env = (o: Partial<Environment>): Environment => ({
  id: 'e1', name: 'team', base_domain: '', team_name: '', key_id: '', okta_url: '', has_okta_token: true,
  sync_schedule: {} as Environment['sync_schedule'], shared: true, is_own: false, addressable: true, ...o,
})

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(fetchVersion).mockResolvedValue({ version: '5.40.7' })
  vi.mocked(fetchSyncStatus).mockResolvedValue({ status: 'idle', steps: [], error: null, sync_state: null, is_first_sync: false })
})

describe('Footer', () => {
  it('disables Sync now (with the reason) on an environment shared with this user', async () => {
    vi.mocked(fetchEnvironments).mockResolvedValue({ environments: [env({})], active: 'team', active_id: 'e1' })
    renderWithClient(<Footer />)
    const btn = (await screen.findByRole('button', { name: /Sync now/ })) as HTMLButtonElement
    expect(btn.disabled).toBe(true)
    expect(btn.title).toMatch(/Only the owner of 'team'/)
  })

  it('enables it on the user’s own environment', async () => {
    vi.mocked(fetchEnvironments).mockResolvedValue({ environments: [env({ is_own: true, shared: false })], active: 'team', active_id: 'e1' })
    renderWithClient(<Footer />)
    const btn = (await screen.findByRole('button', { name: /Sync now/ })) as HTMLButtonElement
    expect(btn.disabled).toBe(false)
  })
})
