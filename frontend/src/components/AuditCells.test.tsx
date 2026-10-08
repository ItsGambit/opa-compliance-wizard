/** Covers the shared AuditCell / AuditHistoryCell (5.40.0): the outcome
 * rendering added for the Service Accounts Dashboard must show a
 * non-success outcome, stay silent on SUCCESS, and change nothing for a
 * Secrets entry that carries no outcome at all. */
import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { AuditCell, AuditHistoryCell } from './AuditCells'

const base = { by: 'Alex Example', at: '2026-10-01T00:00:00.000Z', request_id: 'req-1' }

describe('AuditCell', () => {
  it('renders a dash for no entry', () => {
    render(<AuditCell entry={null} />)
    expect(screen.getByText('—')).toBeTruthy()
  })

  it('shows a non-success outcome with its reason as a tooltip', () => {
    render(<AuditCell entry={{ ...base, outcome: 'FAILURE', outcome_reason: 'example reason' }} />)
    const outcome = screen.getByText(/FAILURE/)
    expect(outcome.getAttribute('title')).toBe('example reason')
    expect(screen.getByText('req-1')).toBeTruthy()
  })

  it('stays silent on SUCCESS and on a Secrets entry with no outcome field', () => {
    const { container, rerender } = render(<AuditCell entry={{ ...base, outcome: 'SUCCESS' }} />)
    expect(container.textContent).not.toContain('SUCCESS')
    rerender(<AuditCell entry={base} />)
    expect(container.textContent).toContain('Alex Example')
    expect(container.textContent).not.toMatch(/FAILURE|DEFERRED|SUCCESS/)
  })
})

describe('AuditHistoryCell', () => {
  it('shows only the newest entry until expanded, then the rest', () => {
    render(
      <AuditHistoryCell
        entries={[
          { ...base, by: 'Newest' },
          { ...base, by: 'Older', outcome: 'DEFERRED' },
        ]}
      />
    )
    expect(screen.getByText(/Newest/)).toBeTruthy()
    expect(screen.queryByText(/Older/)).toBeNull()
    fireEvent.click(screen.getByTitle('Show 1 earlier entry'))
    expect(screen.getByText(/Older/)).toBeTruthy()
    expect(screen.getByText(/DEFERRED/)).toBeTruthy()
  })

  it('uses a custom renderer when given', () => {
    render(<AuditHistoryCell entries={[base]} renderEntry={e => <span>custom {e.by}</span>} />)
    expect(screen.getByText('custom Alex Example')).toBeTruthy()
  })
})
