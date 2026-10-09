/** UI-07: the sync dialog loads status only once opened; FE-15: the
 * evidence-chain check is offered (deep only to admins). */
import { fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fetchCsvFiles, fetchIntegrity, fetchSyncStatus, fetchWhoami } from '../api/client'
import { renderWithClient } from '../test/renderWithClient'
import type { Environment } from '../types'
import { SyncScheduleDialog } from './SyncScheduleDialog'

vi.mock('../api/client', () => ({
  fetchSyncStatus: vi.fn(), fetchCsvFiles: vi.fn(), fetchWhoami: vi.fn(), fetchIntegrity: vi.fn(),
  startSync: vi.fn(), saveSyncSchedule: vi.fn(), importSyncCsv: vi.fn(), resetSyncWatermark: vi.fn(), isSessionExpiredError: () => false, onSessionRestored: () => () => {},
}))

const env = {
  id: 'e1', name: 'dev', base_domain: '', team_name: '', key_id: '', okta_url: '', has_okta_token: true, shared: false, is_own: true,
  sync_schedule: { enabled: false, run_time: '02:00', ingestion_scope: 'curated', retention_days: null, retention_max_size_mb: null },
} as Environment

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(fetchSyncStatus).mockResolvedValue({ status: 'idle', steps: [], error: null, sync_state: null, is_first_sync: false })
  vi.mocked(fetchCsvFiles).mockResolvedValue({ files: [] })
})

describe('SyncScheduleDialog', () => {
  it('fires no status request until opened', async () => {
    vi.mocked(fetchWhoami).mockResolvedValue({ email: null, is_local: true, is_admin: false, can_admin: true })
    renderWithClient(<SyncScheduleDialog env={env} />)
    await new Promise(r => setTimeout(r, 10))
    expect(fetchSyncStatus).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Compliance sync settings for dev' }))
    await waitFor(() => expect(fetchSyncStatus).toHaveBeenCalledWith('dev'))
    expect(screen.getByLabelText('Run time (UTC)')).toBeTruthy()
    expect(screen.getByLabelText('Retention (days)')).toBeTruthy()
  })

  it('runs the evidence-chain check; the deep check is offered to admins only', async () => {
    vi.mocked(fetchWhoami).mockResolvedValue({ email: 'u@x', is_local: false, is_admin: false, can_admin: false })
    vi.mocked(fetchIntegrity).mockResolvedValue({ valid: true, manifest_count: 4, broken_at: null, reason: null })
    renderWithClient(<SyncScheduleDialog env={env} />)
    fireEvent.click(screen.getByRole('button', { name: 'Compliance sync settings for dev' }))
    await screen.findByText('Evidence chain')
    expect(screen.queryByRole('button', { name: 'Deep check' })).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Verify' }))
    expect(await screen.findByText(/Intact: 4 ingestion record/)).toBeTruthy()
  })
})
