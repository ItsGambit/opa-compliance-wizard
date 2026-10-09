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
})
