/** UI-04 / UI-14 on the reports home. */
import { fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fetchEnvironments, fetchReportCsv, fetchReportDefs, fetchSyncStatus, runReport } from '../api/client'
import { utcDaysAgo, utcToday } from '../hooks/useReportDateRange'
import { renderWithClient } from '../test/renderWithClient'
import { downloadBlob, exportSections } from '../utils/export'
import { ComplianceReports } from './ComplianceReports'

vi.mock('../api/client', () => ({
  fetchEnvironments: vi.fn(), fetchReportDefs: vi.fn(), fetchSyncStatus: vi.fn(), runReport: vi.fn(), fetchReportCsv: vi.fn(),
}))
vi.mock('../utils/export', () => ({ exportSections: vi.fn(), downloadBlob: vi.fn() }))
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
    vi.mocked(fetchReportCsv).mockImplementation(() => new Promise((_, r) => { reject = r }))
    renderWithClient(<ComplianceReports selectedReport={null} onSelectReport={() => {}} />)
    const btn = await screen.findByRole('button', { name: 'Export MFA as CSV' })
    fireEvent.click(btn)
    await waitFor(() => expect((btn as HTMLButtonElement).disabled).toBe(true))
    reject(new Error('timeout'))
    await waitFor(() => expect(toastSpy).toHaveBeenCalledWith(expect.objectContaining({ title: 'Could not export "MFA"', description: 'timeout', variant: 'error' })))
    expect(downloadBlob).not.toHaveBeenCalled()
  })

  it('a card export downloads the server file for the last 90 UTC days and says so on the button', async () => {
    vi.mocked(fetchReportDefs).mockResolvedValue({ reports: [DEFS[0]] as never })
    const blob = new Blob(['x'])
    vi.mocked(fetchReportCsv).mockResolvedValue({ blob, rows: 4812 })
    renderWithClient(<ComplianceReports selectedReport={null} onSelectReport={() => {}} />)
    const btn = await screen.findByRole('button', { name: 'Export MFA as CSV' })
    const from = utcDaysAgo(90)
    const to = utcToday()
    expect(btn.getAttribute('title')).toContain(`every event from ${from} to ${to} (UTC, the last 90 days)`)
    fireEvent.click(btn)
    await waitFor(() => expect(downloadBlob).toHaveBeenCalledTimes(1))
    expect(fetchReportCsv).toHaveBeenCalledWith('dev', 'mfa_enforcement', from, to)
    expect(downloadBlob).toHaveBeenCalledWith(`opa-report-mfa_enforcement-${from}-to-${to}.csv`, blob)
    // The count in the toast is the server's: complete, with no "incomplete" path left.
    expect(toastSpy).toHaveBeenCalledWith(expect.objectContaining({ title: 'Exported "MFA"', description: expect.stringContaining('4,812 events') }))
    expect(toastSpy).not.toHaveBeenCalledWith(expect.objectContaining({ title: expect.stringContaining('incomplete') }))
    expect(runReport).not.toHaveBeenCalled()      // nothing is written from a capped list
    expect(exportSections).not.toHaveBeenCalled()
  })

  it('Export all writes nothing and says why, before any file, when a report list is cut at the limit', async () => {
    vi.mocked(fetchReportDefs).mockResolvedValue({ reports: DEFS as never })
    vi.mocked(runReport).mockImplementation(async key => (
      key === 'provisioning' ? { rows: new Array(1000).fill({}), total: 4812, truncated: true } : { rows: [], total: 0, truncated: false }) as never)
    renderWithClient(<ComplianceReports selectedReport={null} onSelectReport={() => {}} />)
    await screen.findAllByText('events, all time')
    fireEvent.click(screen.getByRole('button', { name: /Export all/ }))
    await waitFor(() => expect(toastSpy).toHaveBeenCalledWith(expect.objectContaining({
      title: 'Export all stopped — nothing was downloaded',
      description: expect.stringContaining('Provisioning has 4,812 events and only 1,000 can be listed here'),
      variant: 'error',
    })))
    expect(exportSections).not.toHaveBeenCalled()
  })

  it('Export all shows an error when the request itself fails', async () => {
    vi.mocked(fetchReportDefs).mockResolvedValue({ reports: DEFS as never })
    vi.mocked(runReport).mockImplementation(() => { throw new Error('offline') })
    renderWithClient(<ComplianceReports selectedReport={null} onSelectReport={() => {}} />)
    await screen.findAllByText('events, all time')
    fireEvent.click(screen.getByRole('button', { name: /Export all/ }))
    await waitFor(() => expect(toastSpy).toHaveBeenCalledWith(expect.objectContaining({ title: 'Export failed — nothing was downloaded', description: 'offline', variant: 'error' })))
    expect(exportSections).not.toHaveBeenCalled()
  })

  it('groups by the server-derived control: the two moved reports sit under Access Controls', async () => {
    const defs = [
      { key: 'api_token_lifecycle', label: 'API Token Lifecycle', description: 'd', control: 'CC6', controls: [{ framework: 'soc2', id: 'CC6.1', status: 'proposed' }], mapping_status: 'proposed', count: 1 },
      { key: 'credential_rotation', label: 'Credential Rotation', description: 'd', control: 'CC6', controls: [{ framework: 'soc2', id: 'CC6.1', status: 'proposed' }], mapping_status: 'proposed', count: 1 },
      { key: 'policy_modifications', label: 'Policy Modifications', description: 'd', control: 'CC8', count: 1 },
    ]
    vi.mocked(fetchReportDefs).mockResolvedValue({ reports: defs as never })
    renderWithClient(<ComplianceReports selectedReport={null} onSelectReport={() => {}} />)
    const access = (await screen.findByText('Access Controls — CC6')).parentElement as HTMLElement
    expect(access.textContent).toContain('API Token Lifecycle')
    expect(access.textContent).toContain('Credential Rotation')
    expect(access.textContent).not.toContain('Policy Modifications')
    const change = screen.getByText('Change Management — CC8').parentElement as HTMLElement
    expect(change.textContent).toContain('Policy Modifications')
    expect(change.textContent).not.toContain('Credential Rotation')
  })
})
