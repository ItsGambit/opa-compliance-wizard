/** Review finding 9: an invalid range says so; it does not show the old
 * rows as "loading" forever. */
import { fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fetchReportCsv, runReport } from '../api/client'
import { renderWithClient } from '../test/renderWithClient'
import type { ComplianceReportDef } from '../types'
import { downloadBlob, exportSections } from '../utils/export'
import { ComplianceReportDetail } from './ComplianceReportDetail'

vi.mock('../api/client', () => ({ runReport: vi.fn(), fetchReportCsv: vi.fn() }))
vi.mock('../utils/export', () => ({ exportSections: vi.fn(), downloadBlob: vi.fn() }))
const toastSpy = vi.fn()
vi.mock('../hooks/useToast', () => ({ toast: (m: unknown) => toastSpy(m) }))

beforeEach(() => {
  vi.clearAllMocks()
})

const row = { uuid: 'u1', user: 'alice', actor_alternate_id: null, action: 'did', event_type: 'e', timestamp: '2026-10-01T00:00:00Z', resource: '', resource_type: '', resource_type_detail: '', resource_id: '', resource_alternate_id: '', outcome: 'SUCCESS', outcome_reason: '', client_ip: '', client_geo: '', request_id: '' }
const def = { key: 'mfa', label: 'MFA', description: 'd', control: 'CC6' } as ComplianceReportDef

describe('ComplianceReportDetail', () => {
  it('From after To: no query, no stale rows, a clear message', async () => {
    vi.mocked(runReport).mockResolvedValue({ rows: [row], total: 1, truncated: false } as never)
    renderWithClient(<ComplianceReportDetail def={def} environment="dev" onBack={() => {}} />)
    expect(await screen.findByText('alice')).toBeTruthy()
    fireEvent.change(screen.getByLabelText('From (UTC day)'), { target: { value: '2999-01-01' } })
    expect(await screen.findByText('Fix the date range to see events.')).toBeTruthy()
    expect(screen.queryByText('alice')).toBeNull()
    expect(screen.queryByText(/rows below are from the previous range/)).toBeNull()
    expect(runReport).toHaveBeenCalledTimes(1)
  })

  it('shows the mapped controls as a proposed mapping, in words', () => {
    vi.mocked(runReport).mockResolvedValue({ rows: [], total: 0, truncated: false } as never)
    const mapped = {
      ...def, controls: [{ framework: 'soc2', id: 'CC6.2', status: 'proposed' }, { framework: 'soc2', id: 'CC6.3', status: 'proposed' }],
      mapping_status: 'proposed',
    } as ComplianceReportDef
    renderWithClient(<ComplianceReportDetail def={mapped} environment="dev" onBack={() => {}} />)
    expect(screen.getByText('Proposed mapping')).toBeTruthy()
    expect(screen.getByText('SOC 2 CC6.2')).toBeTruthy()
    expect(screen.getByText('SOC 2 CC6.3')).toBeTruthy()
    expect(screen.getByText('Suggested by this project; not reviewed by an auditor.')).toBeTruthy()
  })

  it('shows the methodology under "How this is calculated" and the known limits in view', () => {
    vi.mocked(runReport).mockResolvedValue({ rows: [], total: 0, truncated: false } as never)
    const mapped = {
      ...def, controls: [{ framework: 'soc2', id: 'CC6.1', status: 'proposed' }], mapping_status: 'proposed',
      methodology: 'What it shows: MFA events.', known_limits: ['Revocations are not part of this report.', 'Second limit.'],
    } as ComplianceReportDef
    renderWithClient(<ComplianceReportDetail def={mapped} environment="dev" onBack={() => {}} />)
    expect(screen.getByText('How this is calculated')).toBeTruthy()
    expect(screen.getByText('What it shows: MFA events.')).toBeTruthy()
    expect(screen.getByText('Known limits')).toBeTruthy()
    expect(screen.getByText('Revocations are not part of this report.')).toBeTruthy()
    expect(screen.getByText('Second limit.')).toBeTruthy()
  })

  it('shows no mapping block when an older server sends no controls', () => {
    vi.mocked(runReport).mockResolvedValue({ rows: [], total: 0, truncated: false } as never)
    renderWithClient(<ComplianceReportDetail def={def} environment="dev" onBack={() => {}} />)
    expect(screen.queryByTestId('mapped-controls')).toBeNull()
  })

  describe('exports (5.53.0)', () => {
    it('CSV downloads the server file for the date range on screen, not the rows on screen', async () => {
      vi.mocked(runReport).mockResolvedValue({ rows: [row], total: 1, truncated: false } as never)
      const blob = new Blob(['x'])
      vi.mocked(fetchReportCsv).mockResolvedValue({ blob, rows: 1 })
      renderWithClient(<ComplianceReportDetail def={def} environment="dev" onBack={() => {}} />)
      await screen.findByText('alice')
      fireEvent.change(screen.getByLabelText('From (UTC day)'), { target: { value: '2026-01-05' } })
      fireEvent.change(screen.getByLabelText('To (UTC day, inclusive)'), { target: { value: '2026-02-06' } })
      const btn = await screen.findByRole('button', { name: /Export CSV/ })
      await waitFor(() => expect((btn as HTMLButtonElement).disabled).toBe(false))
      expect(btn.getAttribute('title')).toContain('every event from 2026-01-05 to 2026-02-06 (UTC)')
      fireEvent.click(btn)
      await waitFor(() => expect(downloadBlob).toHaveBeenCalledWith('opa-report-mfa-2026-01-05-to-2026-02-06.csv', blob))
      expect(fetchReportCsv).toHaveBeenCalledWith('dev', 'mfa', '2026-01-05', '2026-02-06')
    })

    it('a failed CSV export is an error, and nothing is saved', async () => {
      vi.mocked(runReport).mockResolvedValue({ rows: [row], total: 1, truncated: false } as never)
      vi.mocked(fetchReportCsv).mockRejectedValue(new Error('The end date is in the future (dates are UTC)'))
      renderWithClient(<ComplianceReportDetail def={def} environment="dev" onBack={() => {}} />)
      await screen.findByText('alice')
      fireEvent.click(await screen.findByRole('button', { name: /Export CSV/ }))
      await waitFor(() => expect(toastSpy).toHaveBeenCalledWith(expect.objectContaining({
        title: 'Could not export "MFA"', description: 'The end date is in the future (dates are UTC)', variant: 'error',
      })))
      expect(downloadBlob).not.toHaveBeenCalled()
    })

    it('CSV is blocked, with the reason, while the date range is invalid', async () => {
      vi.mocked(runReport).mockResolvedValue({ rows: [row], total: 1, truncated: false } as never)
      renderWithClient(<ComplianceReportDetail def={def} environment="dev" onBack={() => {}} />)
      await screen.findByText('alice')
      fireEvent.change(screen.getByLabelText('From (UTC day)'), { target: { value: '2999-01-01' } })
      const btn = (await screen.findByRole('button', { name: /Export CSV/ })) as HTMLButtonElement
      expect(btn.disabled).toBe(true)
      expect(btn.getAttribute('title')).toBe('Fix the date range first')
    })

    it('a capped list says so: the CSV has every event, the Markdown only the rows on screen, in the file too', async () => {
      vi.mocked(runReport).mockResolvedValue({ rows: [row], total: 4812, truncated: true } as never)
      renderWithClient(<ComplianceReportDetail def={def} environment="dev" onBack={() => {}} />)
      await screen.findByText('alice')
      expect(screen.getAllByText(/The CSV export above has every event in the range/).length).toBe(1)
      expect(screen.getByRole('note').textContent).toContain('Markdown has only the newest 1 of 4,812 events on screen. The CSV has every event in the range.')
      fireEvent.click(screen.getByRole('button', { name: /Markdown/ }))
      expect(exportSections).toHaveBeenCalledTimes(1)
      const [sections, format] = vi.mocked(exportSections).mock.calls[0]
      expect(format).toBe('md')
      expect(sections[0].title).toBe('MFA (newest 1 of 4,812 events in the range)')
    })

    it('no capped-list CSV path is left: the page never writes a CSV from its own rows', async () => {
      vi.mocked(runReport).mockResolvedValue({ rows: [row], total: 4812, truncated: true } as never)
      renderWithClient(<ComplianceReportDetail def={def} environment="dev" onBack={() => {}} />)
      await screen.findByText('alice')
      for (const call of vi.mocked(exportSections).mock.calls) expect(call[1]).not.toBe('csv')
      expect(toastSpy).not.toHaveBeenCalledWith(expect.objectContaining({ title: expect.stringContaining('incomplete') }))
    })
  })
})
