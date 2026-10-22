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
    expect(screen.getByText(/OPA scan, System Log and Okta scan all completed/)).toBeTruthy()  // what ran, not only a count
    expect(screen.getByText(/Refresh finished .*\(1 min 00 s\)/)).toBeTruthy()  // with how long it took
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

  it('Retry this part: its name has no stray space and its target is at least 24 px high (U18); rows are one column under 900 px (U16)', () => {
    const failed = withParts(base(), { opa: { state: 'error', message: 'x' } }, { status: 'done', finished_at: '2026-10-21T08:43:00.000Z' })
    const { container } = render(<RefreshProgressCard status={failed} environment="prod-example" now={NOW} {...noop} />)
    const retry = screen.getByRole('button', { name: 'Retry this part: OPA scan' })
    expect(retry.className).toMatch(/min-h-6/)
    const row = container.querySelector('div.grid')!
    expect(row.className).toMatch(/min-\[900px\]:grid-cols-/)
    expect(row.className).not.toMatch(/(^| )sm:grid-cols/)
  })

  it('leads with the environment, who started it and how long it took; the running card explains the two lanes and holds Stop under the line', () => {
    const running = { ...base(), started_by: 'you' } as RefreshStatus
    const { rerender } = render(<RefreshProgressCard status={running} environment="prod-example" now={NOW} {...noop} />)
    expect(screen.getByText('Refreshing prod-example')).toBeTruthy()
    expect(screen.getByText(/by you · OPA scan and System Log run side by side; the Okta scan follows the log so the two do not share Okta's rate budget\./)).toBeTruthy()
    const done = withParts(running, { opa: { state: 'ok' }, log: { state: 'ok' }, okta: { state: 'ok' } }, { status: 'done', finished_at: '2026-10-21T08:43:12.000Z' })
    rerender(<RefreshProgressCard status={done} environment="prod-example" now={NOW} {...noop} />)
    expect(screen.getByText('Refresh of prod-example finished')).toBeTruthy()
    expect(screen.getByText(/by you · finished .* \(2 min 12 s\) · Audit Log: refresh\.completed/)).toBeTruthy()
  })

  it('the collapsed line says what was read: new events and principals', () => {
    const done = withParts(base(), { opa: { state: 'ok', counts: { users: 214 } }, log: { state: 'ok', events_new: 3412 }, okta: { state: 'ok' } }, { status: 'done', finished_at: '2026-10-21T08:41:30.000Z' })
    render(<RefreshProgressCard status={done} environment="prod-example" now={NOW} {...noop} />)
    expect(screen.getByText(/all completed · 3,412 new events · 214 principals/)).toBeTruthy()
  })
})
