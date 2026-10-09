/** UI-04 / UI-14 on the reports home. */
import { fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fetchEnvironments, fetchReportDefs, fetchSyncStatus, runReport } from '../api/client'
import { renderWithClient } from '../test/renderWithClient'
import { exportSections } from '../utils/export'
import { ComplianceReports } from './ComplianceReports'

vi.mock('../api/client', () => ({
  fetchEnvironments: vi.fn(), fetchReportDefs: vi.fn(), fetchSyncStatus: vi.fn(), runReport: vi.fn(),
}))
vi.mock('../utils/export', () => ({ exportSections: vi.fn() }))
const toastSpy = vi.fn()
vi.mock('../hooks/useToast', () => ({ toast: (m: unknown) => toastSpy(m) }))

const DEFS = [
  { key: 'mfa_enforcement', label: 'MFA', description: 'd', control: 'CC6', count: 3 },
  { key: 'provisioning', label: 'Provisioning', description: 'd', control: 'CC6', count: 1 },
]

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(fetchEnvironments).mockResolvedValue({ environments: [], active: 'dev', active_id: 'e1' })
  vi.mocked(fetchSyncStatus).mockResolvedValue({ status: 'idle', steps: [], error: null, sync_state: null, is_first_sync: false })
})

describe('ComplianceReports', () => {
  it('a failed report list is an error with Retry, not "Loading reports…" forever', async () => {
    vi.mocked(fetchReportDefs).mockRejectedValue(new Error('No environment named dev'))
    renderWithClient(<ComplianceReports selectedReport={null} onSelectReport={() => {}} />)
    expect(await screen.findByText('No environment named dev')).toBeTruthy()
    expect(screen.queryByText('Loading reports…')).toBeNull()
  })

  it('labels the card counts as all-time', async () => {
    vi.mocked(fetchReportDefs).mockResolvedValue({ reports: DEFS as never })
    renderWithClient(<ComplianceReports selectedReport={null} onSelectReport={() => {}} />)
    expect((await screen.findAllByText('events, all time')).length).toBe(2)
  })

  it('Export all downloads nothing if any report failed, and names the failures', async () => {
    vi.mocked(fetchReportDefs).mockResolvedValue({ reports: DEFS as never })
    vi.mocked(runReport).mockImplementation(async key => {
      if (key === 'provisioning') throw new Error('502 upstream')
      return { rows: [], total: 0, truncated: false } as never
    })
    renderWithClient(<ComplianceReports selectedReport={null} onSelectReport={() => {}} />)
    await screen.findAllByText('events, all time')
    fireEvent.click(screen.getByRole('button', { name: /Export all/ }))
    await waitFor(() => expect(toastSpy).toHaveBeenCalledWith(expect.objectContaining({ title: 'Export failed — nothing was downloaded', description: expect.stringContaining('Provisioning (502 upstream)') })))
    expect(exportSections).not.toHaveBeenCalled()
  })

  it('Export all writes one file when every report loaded', async () => {
    vi.mocked(fetchReportDefs).mockResolvedValue({ reports: DEFS as never })
    vi.mocked(runReport).mockResolvedValue({ rows: [], total: 0, truncated: false } as never)
    renderWithClient(<ComplianceReports selectedReport={null} onSelectReport={() => {}} />)
    await screen.findAllByText('events, all time')
    fireEvent.click(screen.getByRole('button', { name: /Export all/ }))
    await waitFor(() => expect(exportSections).toHaveBeenCalledTimes(1))
    expect(vi.mocked(exportSections).mock.calls[0][2]).toBe('opa-compliance-reports-all')
  })

  it('a card export failure is a toast, and the button is busy while it runs', async () => {
    vi.mocked(fetchReportDefs).mockResolvedValue({ reports: [DEFS[0]] as never })
    let reject!: (e: Error) => void
    vi.mocked(runReport).mockImplementation(() => new Promise((_, r) => { reject = r }))
    renderWithClient(<ComplianceReports selectedReport={null} onSelectReport={() => {}} />)
    const btn = await screen.findByRole('button', { name: 'Export MFA as CSV' })
    fireEvent.click(btn)
    await waitFor(() => expect((btn as HTMLButtonElement).disabled).toBe(true))
    reject(new Error('timeout'))
    await waitFor(() => expect(toastSpy).toHaveBeenCalledWith(expect.objectContaining({ title: 'Could not export "MFA"' })))
    expect(exportSections).not.toHaveBeenCalled()
  })
})
