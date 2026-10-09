/** UI-04 / UI-18 / UI-19 in the shared report table. */
import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import type { ComplianceReportRow } from '../types'
import { ReportRowsTable } from './ReportRowsTable'

const row = (uuid: string, outcome: string): ComplianceReportRow => ({
  uuid, user: 'u', actor_alternate_id: null, action: 'a', event_type: 'e', timestamp: '2026-10-01T00:00:00.000Z',
  resource: 'r', resource_type: '', resource_type_detail: '', resource_id: '', resource_alternate_id: '', outcome,
  outcome_reason: '', client_ip: '', client_geo: '', request_id: '',
} as ComplianceReportRow)

describe('ReportRowsTable', () => {
  it('UI-04: a failed load shows the error and Retry, never the empty message', () => {
    const onRetry = vi.fn()
    render(<ReportRowsTable rows={[]} isLoading={false} emptyMessage="No events found" error={new Error('No environment named dev')} onRetry={onRetry} />)
    expect(screen.queryByText('No events found')).toBeNull()
    expect(screen.getByText('No environment named dev')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(onRetry).toHaveBeenCalled()
  })

  it('UI-18: an outcome filter the new rows no longer contain is cleared', () => {
    const { rerender } = render(<ReportRowsTable rows={[row('1', 'SUCCESS'), row('2', 'FAILURE')]} isLoading={false} emptyMessage="none" />)
    const select = screen.getByLabelText('Filter by outcome') as HTMLSelectElement
    fireEvent.change(select, { target: { value: 'FAILURE' } })
    expect(screen.getAllByText('FAILURE').length).toBeGreaterThan(0)
    rerender(<ReportRowsTable rows={[row('3', 'SUCCESS')]} isLoading={false} emptyMessage="none" />)
    expect((screen.getByLabelText('Filter by outcome') as HTMLSelectElement).value).toBe('')
    expect(screen.queryByText('No rows match the current filters.')).toBeNull()
  })

  it('says when the rows are the previous range while a new one loads', () => {
    render(<ReportRowsTable rows={[row('1', 'SUCCESS')]} isLoading={false} emptyMessage="none" stale />)
    expect(screen.getByText(/rows below are from the previous range/)).toBeTruthy()
  })

  it('labels every filter control', () => {
    render(<ReportRowsTable rows={[row('1', 'SUCCESS')]} isLoading={false} emptyMessage="none" />)
    for (const l of ['Filter by user', 'Filter by action', 'Filter by affected resource', 'Filter by outcome']) expect(screen.getByLabelText(l)).toBeTruthy()
  })
})
