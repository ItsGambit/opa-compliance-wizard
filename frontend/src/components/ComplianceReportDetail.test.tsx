/** Review finding 9: an invalid range says so; it does not show the old
 * rows as "loading" forever. */
import { fireEvent, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { runReport } from '../api/client'
import { renderWithClient } from '../test/renderWithClient'
import type { ComplianceReportDef } from '../types'
import { ComplianceReportDetail } from './ComplianceReportDetail'

vi.mock('../api/client', () => ({ runReport: vi.fn() }))

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
})
