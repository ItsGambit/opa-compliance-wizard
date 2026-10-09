/** DATA-12 admin UI: list orphaned archives; purge only after typed confirmation. */
import { fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fetchOrphanedArchives, purgeOrphanedArchive } from '../api/client'
import { renderWithClient } from '../test/renderWithClient'
import { OrphanedArchivesDialog } from './OrphanedArchivesDialog'

vi.mock('../api/client', () => ({ fetchOrphanedArchives: vi.fn(), purgeOrphanedArchive: vi.fn() }))

const ID = '3f2a9c1e-0000-4000-8000-000000000001'
beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(fetchOrphanedArchives).mockResolvedValue({ archives: [{
    environment_id: ID, event_count: 1200, bytes: 2_500_000, oldest_published: '2026-07-01T00:00:00Z',
    newest_published: '2026-09-30T00:00:00Z', manifest_count: 14,
  }] })
})

describe('OrphanedArchivesDialog', () => {
  it('lists an orphan with its size and lets nothing be purged until the id prefix is typed', async () => {
    vi.mocked(purgeOrphanedArchive).mockResolvedValue({ purged: ID, events: 1200, ingestion_manifests: 14 })
    renderWithClient(<OrphanedArchivesDialog open onOpenChange={() => {}} />)
    expect(await screen.findByText(ID)).toBeTruthy()
    expect(screen.getByText(/1,200 event\(s\) · 2.4 MB · 14 manifest\(s\)/)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: /Purge…/ }))
    const purge = screen.getByRole('button', { name: 'Purge archive' }) as HTMLButtonElement
    expect(purge.disabled).toBe(true)
    const input = screen.getByLabelText(/to confirm/)
    fireEvent.change(input, { target: { value: '3f2a9c1f' } })
    expect(purge.disabled).toBe(true)
    fireEvent.change(input, { target: { value: '3f2a9c1e' } })
    expect(purge.disabled).toBe(false)
    fireEvent.click(purge)
    await waitFor(() => expect(purgeOrphanedArchive).toHaveBeenCalledWith(ID))
    expect(purgeOrphanedArchive).toHaveBeenCalledTimes(1)
  })

  it('Cancel leaves the archive alone', async () => {
    renderWithClient(<OrphanedArchivesDialog open onOpenChange={() => {}} />)
    await screen.findByText(ID)
    fireEvent.click(screen.getByRole('button', { name: /Purge…/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByRole('button', { name: 'Purge archive' })).toBeNull()
    expect(purgeOrphanedArchive).not.toHaveBeenCalled()
  })

  it('shows an empty state and a load error', async () => {
    vi.mocked(fetchOrphanedArchives).mockResolvedValueOnce({ archives: [] })
    const { unmount } = renderWithClient(<OrphanedArchivesDialog open onOpenChange={() => {}} />)
    expect(await screen.findByText(/No orphaned archives/)).toBeTruthy()
    unmount()
    vi.mocked(fetchOrphanedArchives).mockRejectedValueOnce(new Error('Admin access required'))
    renderWithClient(<OrphanedArchivesDialog open onOpenChange={() => {}} />)
    expect(await screen.findByText('Admin access required')).toBeTruthy()
  })

  it('does not fetch while closed', () => {
    renderWithClient(<OrphanedArchivesDialog open={false} onOpenChange={() => {}} />)
    expect(fetchOrphanedArchives).not.toHaveBeenCalled()
  })
})
