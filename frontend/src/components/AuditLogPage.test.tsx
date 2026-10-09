/** UI-13: audit log paging, keys and Refresh guard. */
import { fireEvent, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { backfillMfaLogEvents, fetchAuditLog } from '../api/client'
import { renderWithClient } from '../test/renderWithClient'
import type { AuditLogEntry } from '../types'
import { AuditLogPage } from './AuditLogPage'

vi.mock('../api/client', () => ({ fetchAuditLog: vi.fn(), backfillMfaLogEvents: vi.fn() }))

const entry = (i: number, ts = '2026-10-01T00:00:00Z'): AuditLogEntry =>
  ({ timestamp: ts, action: 'sync.manual_start', actor_email: null, actor_sub: null, details: { n: i } } as unknown as AuditLogEntry)

let consoleError: ReturnType<typeof vi.spyOn>
beforeEach(() => { vi.clearAllMocks(); consoleError = vi.spyOn(console, 'error') })
afterEach(() => { consoleError.mockRestore() })

describe('AuditLogPage', () => {
  it('same-second entries render without key collisions; Load more appends by offset', async () => {
    vi.mocked(fetchAuditLog).mockImplementation(async (_limit, offset) => ({
      entries: offset === 0 ? Array.from({ length: 50 }, (_, i) => entry(i)) : [entry(49), entry(50), entry(51)],
    }))
    renderWithClient(<AuditLogPage />)
    await screen.findAllByText('sync.manual_start')
    expect(screen.getAllByText('sync.manual_start')).toHaveLength(50)
    expect(consoleError.mock.calls.some((c: unknown[]) => String(c[0]).includes('same key'))).toBe(false)
    fireEvent.click(screen.getByRole('button', { name: 'Load more' }))
    await waitFor(() => expect(screen.getAllByText('sync.manual_start')).toHaveLength(52))
    expect(fetchAuditLog).toHaveBeenLastCalledWith(51, 49) // one entry of overlap, checked
    expect(screen.queryByRole('button', { name: 'Load more' })).toBeNull() // last page was short
  })

  it('Refresh runs one backfill at a time', async () => {
    vi.mocked(fetchAuditLog).mockResolvedValue({ entries: [entry(1)] })
    let release!: (v: { updated_count: number }) => void
    vi.mocked(backfillMfaLogEvents).mockImplementation(() => new Promise(r => { release = r }))
    renderWithClient(<AuditLogPage />)
    await screen.findByText('sync.manual_start')
    const refresh = screen.getByRole('button', { name: /Refresh/ })
    fireEvent.click(refresh)
    fireEvent.click(refresh)
    fireEvent.click(refresh)
    expect(backfillMfaLogEvents).toHaveBeenCalledTimes(1)
    expect((screen.getByRole('button', { name: /Refresh/ }) as HTMLButtonElement).disabled).toBe(true)
    release({ updated_count: 0 })
    await waitFor(() => expect((screen.getByRole('button', { name: /Refresh/ }) as HTMLButtonElement).disabled).toBe(false))
  })

  it('says the search covers only the loaded entries', async () => {
    vi.mocked(fetchAuditLog).mockResolvedValue({ entries: Array.from({ length: 50 }, (_, i) => entry(i)) })
    renderWithClient(<AuditLogPage />)
    await screen.findAllByText('sync.manual_start')
    fireEvent.change(screen.getByLabelText('Search the loaded audit log entries'), { target: { value: 'sync' } })
    expect(screen.getByText(/Searching the 50 most recent entries loaded/)).toBeTruthy()
  })

  it('new activity between pages reloads the list instead of duplicating an entry', async () => {
    let shifted = false
    vi.mocked(fetchAuditLog).mockImplementation(async (_limit, offset) => {
      const base = shifted ? [entry(-1), ...Array.from({ length: 52 }, (_, i) => entry(i))] : Array.from({ length: 52 }, (_, i) => entry(i))
      return { entries: !offset ? base.slice(0, 50) : base.slice(offset, offset + 51) }
    })
    renderWithClient(<AuditLogPage />)
    await screen.findAllByText('sync.manual_start')
    shifted = true
    fireEvent.click(screen.getByRole('button', { name: 'Load more' }))
    await waitFor(() => expect(fetchAuditLog).toHaveBeenLastCalledWith(50, 0)) // reloaded from the newest
    expect(screen.getAllByText('sync.manual_start')).toHaveLength(50)
  })

  it('Refresh that hits a shift between its pages reloads once more instead of failing silently', async () => {
    let calls = 0
    vi.mocked(backfillMfaLogEvents).mockResolvedValue({ updated_count: 0 })
    vi.mocked(fetchAuditLog).mockImplementation(async (_limit, offset) => {
      calls += 1
      const base = Array.from({ length: 52 }, (_, i) => entry(i))
      if (!offset) return { entries: base.slice(0, 50) }
      // the first older-page read during the refresh is shifted
      return calls === 4 ? { entries: [entry(-5), entry(50)] } : { entries: base.slice(offset, offset + 51) }
    })
    renderWithClient(<AuditLogPage />)
    await screen.findAllByText('sync.manual_start')
    fireEvent.click(screen.getByRole('button', { name: 'Load more' }))
    await waitFor(() => expect(screen.getAllByText('sync.manual_start')).toHaveLength(52))
    fireEvent.click(screen.getByRole('button', { name: /Refresh/ }))
    await waitFor(() => expect((screen.getByRole('button', { name: /Refresh/ }) as HTMLButtonElement).disabled).toBe(false))
    expect(screen.queryByText(/Could not load the audit log/)).toBeNull()
    expect(screen.getAllByText('sync.manual_start').length).toBeGreaterThanOrEqual(50)
  })
})
