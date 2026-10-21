/** The refresh progress card: states in words, one live announcement per part outcome (M2), collapse after a minute. */
import { act, fireEvent, render, screen, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import type { RefreshPart, RefreshStatus } from '../types'
import { RefreshProgressCard } from './RefreshProgressCard'

const base = (over: Partial<RefreshStatus> = {}): RefreshStatus => ({
  status: 'running', job_id: 'j1', trigger: 'manual', started_at: '2026-10-21T08:41:00.000Z', finished_at: null, parts_requested: ['opa', 'okta', 'log'],
  cancel_requested: false, summary: null,
  parts: { opa: { state: 'running', started_at: '2026-10-21T08:41:00.000Z', step_defs: [['users', 'Fetching users'], ['groups', 'Fetching groups']], steps: [{ key: 'users', status: 'done', detail: '212' }, { key: 'groups', status: 'start', detail: null }] },
    log: { state: 'running', started_at: '2026-10-21T08:41:00.000Z' }, okta: { state: 'pending', sub: { admins: { state: 'pending' }, principal_status: { state: 'waiting' } } } },
  ...over,
})
const withParts = (s: RefreshStatus, p: Partial<RefreshStatus['parts']>, over: Partial<RefreshStatus> = {}): RefreshStatus => ({ ...s, ...over, parts: { ...s.parts, ...p } as RefreshStatus['parts'] })
const noop = { canRun: true, onRetry: vi.fn(), onStop: vi.fn() }
const NOW = new Date('2026-10-21T08:43:12.000Z').getTime()
const live = () => screen.getByTestId('refresh-live').textContent

describe('RefreshProgressCard', () => {
  it('shows each part with its state in words and the steps with their state as text, not only colour (M5)', () => {
    render(<RefreshProgressCard status={base()} now={NOW} {...noop} />)
    const card = screen.getByRole('region', { name: 'Refresh progress' })
    expect(within(card).getAllByText('Running').length).toBe(2)
    expect(within(card).getByText('Waiting')).toBeTruthy()
    expect(within(card).getByText(/done:/, { selector: '.sr-only' })).toBeTruthy()
    expect(within(card).getByText(/running:/, { selector: '.sr-only' })).toBeTruthy()
    expect(within(card).getAllByText(/not started:/, { selector: '.sr-only' }).length).toBe(2)
    expect(within(card).getAllByText('2 min 12 s', { selector: 'div' }).length).toBe(2)  // OPA scan and System Log have run that long
  })

  it('announces a part once, when it ends, and the summary at the end: never every step (M2)', () => {
    const { rerender } = render(<RefreshProgressCard status={base()} now={NOW} {...noop} />)
    expect(live()).toBe('')
    const step = withParts(base(), { opa: { ...(base().parts.opa as RefreshPart), steps: [{ key: 'users', status: 'done', detail: '212' }, { key: 'groups', status: 'done', detail: '31' }] } })
    rerender(<RefreshProgressCard status={step} now={NOW} {...noop} />)
    expect(live()).toBe('')  // a step finishing is not announced
    const logDone = withParts(base(), { log: { state: 'ok', events_new: 3 } })
    rerender(<RefreshProgressCard status={logDone} now={NOW} {...noop} />)
    expect(live()).toBe('System Log completed.')
    rerender(<RefreshProgressCard status={withParts(logDone, { opa: { state: 'ok' } })} now={NOW} {...noop} />)
    expect(live()).toBe('OPA scan completed.')  // only the part that just ended
    const refused = withParts(logDone, { opa: { state: 'ok' }, okta: { state: 'refused', message: 'Okta refused the admin-role read.' } }, { status: 'done', finished_at: '2026-10-21T08:48:00.000Z', summary: '2 of 3 parts completed; Okta scan refused.' })
    rerender(<RefreshProgressCard status={refused} now={NOW} {...noop} />)
    expect(live()).toBe('Okta scan refused. Okta refused the admin-role read. Refresh finished: 2 of 3 parts completed.')
    rerender(<RefreshProgressCard status={refused} now={NOW + 1000} {...noop} />)
    expect(live()).toBe('Okta scan refused. Okta refused the admin-role read. Refresh finished: 2 of 3 parts completed.')  // not repeated
  })

  it('attaching to a job that already ended does not announce what is already on screen', () => {
    const done = withParts(base(), { opa: { state: 'ok' }, log: { state: 'ok' }, okta: { state: 'ok' } }, { status: 'done', finished_at: '2026-10-21T08:42:00.000Z' })
    render(<RefreshProgressCard status={done} now={NOW} {...noop} />)
    expect(live()).toBe('')
  })

  it('a failed row keeps its message and offers Retry this part for that part only; Stop appears only while running', () => {
    const onRetry = vi.fn()
    const failed = withParts(base(), { opa: { state: 'ok' }, log: { state: 'ok' }, okta: { state: 'error', message: 'Okta did not answer.' } }, { status: 'done', finished_at: '2026-10-21T08:43:00.000Z' })
    render(<RefreshProgressCard status={failed} now={NOW} canRun onRetry={onRetry} onStop={vi.fn()} />)
    expect(screen.getByText('Okta did not answer.')).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Stop' })).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: /Retry this part/ }))
    expect(onRetry).toHaveBeenCalledWith('okta')
    expect(screen.getAllByRole('button', { name: /Retry this part/ }).length).toBe(1)
  })

  it('a viewer who may not run it gets no Retry and no Stop', () => {
    const failed = withParts(base(), { opa: { state: 'error', message: 'x' } }, { status: 'done', finished_at: '2026-10-21T08:43:00.000Z' })
    render(<RefreshProgressCard status={failed} now={NOW} canRun={false} onRetry={vi.fn()} onStop={vi.fn()} />)
    expect(screen.queryByRole('button', { name: /Retry this part/ })).toBeNull()
    render(<RefreshProgressCard status={base()} now={NOW} canRun={false} onRetry={vi.fn()} onStop={vi.fn()} />)
    expect(screen.queryByRole('button', { name: 'Stop' })).toBeNull()
  })

  it('collapses to one line a minute after it finished, and Details reopens it', () => {
    const done = withParts(base(), { opa: { state: 'ok' }, log: { state: 'ok' }, okta: { state: 'ok' } }, { status: 'done', finished_at: '2026-10-21T08:42:00.000Z' })
    const { rerender } = render(<RefreshProgressCard status={done} now={new Date('2026-10-21T08:42:30.000Z').getTime()} {...noop} />)
    expect(screen.queryByRole('button', { name: 'Details' })).toBeNull()  // still the full card
    rerender(<RefreshProgressCard status={done} now={new Date('2026-10-21T08:43:30.000Z').getTime()} {...noop} />)
    expect(screen.getByText(/all 3 parts completed/)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Details' }))
    expect(screen.getByText('OPA scan')).toBeTruthy()
  })

  it('"completed with N unreadable sections" is spelled out, and a stopped or timed-out part says so', () => {
    const s = withParts(base(), { opa: { state: 'ok', warnings: 2 }, log: { state: 'timed_out', message: 'Stopped after 90 minutes. The previous data is kept.' }, okta: { state: 'cancelled', message: 'Stopped by an administrator; previous data kept.' } }, { status: 'done', finished_at: '2026-10-21T08:43:00.000Z' })
    render(<RefreshProgressCard status={s} now={NOW} {...noop} />)
    expect(screen.getByText('Completed with 2 unreadable sections')).toBeTruthy()
    expect(screen.getByText('Timed out')).toBeTruthy()
    expect(screen.getByText('Stopped')).toBeTruthy()
  })

  it('renders nothing for an idle server', () => {
    const idle = { ...base(), status: 'idle' as const, job_id: null }
    const { container } = render(<RefreshProgressCard status={idle} {...noop} />)
    expect(container.innerHTML).toBe('')
    act(() => {})
  })
})
