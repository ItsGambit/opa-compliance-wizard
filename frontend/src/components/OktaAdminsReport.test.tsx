import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fetchConfigSnapshotDiff, fetchConfigSnapshots, fetchEnvironments, fetchOktaAdminsReport, logOktaAdminsExport, startOktaCapture } from '../api/client'
import { okReport, REFUSED_MESSAGE, snapshot } from '../test/oktaFixtures'
import { renderWithClient } from '../test/renderWithClient'
import * as toasts from '../hooks/useToast'
import { OktaAdminsReport } from './OktaAdminsReport'

vi.mock('../api/client', () => ({
  fetchEnvironments: vi.fn(), fetchOktaAdminsReport: vi.fn(), fetchConfigSnapshots: vi.fn(), fetchConfigSnapshotDiff: vi.fn(),
  fetchConfigSnapshotExport: vi.fn(), startOktaCapture: vi.fn(), logOktaAdminsExport: vi.fn(),
}))
vi.mock('./Select', async () => ({ Select: (await import('../test/MockSelect')).MockSelect }))
vi.mock('../utils/export', async orig => ({ ...(await orig<typeof import('../utils/export')>()), exportSections: vi.fn(), downloadTextFile: vi.fn() }))

const snaps = [
  { ...snapshot, snapshot_id: 7, kind: 'okta_admins', source_endpoint: null, meta: null },
  { ...snapshot, snapshot_id: 5, captured_at: '2026-10-01T00:00:00.000Z', kind: 'okta_admins', source_endpoint: null, meta: null },
  { ...snapshot, snapshot_id: 4, captured_at: '2026-09-30T00:00:00.000Z', status: 'refused' as const, item_count: 0, kind: 'okta_admins', source_endpoint: null, meta: { error_code: 'E0000006' } },
]

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(fetchEnvironments).mockResolvedValue({ environments: [], active: 'dev' } as never)
  vi.mocked(fetchConfigSnapshots).mockResolvedValue({ snapshots: snaps } as never)
  vi.mocked(fetchOktaAdminsReport).mockResolvedValue(okReport())
  vi.mocked(logOktaAdminsExport).mockResolvedValue({ logged: true })
})

describe('OktaAdminsReport', () => {
  it('shows the admins, scope, time-bound access and evidence, with the separation-of-duties card', async () => {
    renderWithClient(<OktaAdminsReport />)
    expect(await screen.findByText('Alex Example')).toBeTruthy()
    expect(screen.getAllByText('Super administrator').length).toBeGreaterThan(0)
    expect(screen.getByText('Groups: Support')).toBeTruthy()
    expect(screen.getByText(/Time-bound until/)).toBeTruthy()
    expect(screen.getByText(/Granted .*2026.* by boss@example.com/)).toBeTruthy()
    expect(screen.getAllByText('Before the archive began').length).toBe(2)  // the active and the removed row
    const sod = screen.getByRole('region', { name: 'Separation of duties' })
    expect(within(sod).getByText('pam_admin')).toBeTruthy()
    expect(within(sod).getByText(/Candidates for review, not findings/)).toBeTruthy()
    expect(screen.getAllByText('removed').length).toBeGreaterThan(0)
  })

  it('says exactly why a refused read has no data, and shows no table', async () => {
    vi.mocked(fetchOktaAdminsReport).mockResolvedValue(okReport({ state: 'refused', message: REFUSED_MESSAGE, rows: [], as_of_snapshot: null }))
    renderWithClient(<OktaAdminsReport />)
    expect(await screen.findByText(REFUSED_MESSAGE)).toBeTruthy()
    expect(screen.queryByRole('table', { name: /admins/i })).toBeNull()
    expect((screen.getByRole('button', { name: /CSV/ }) as HTMLButtonElement).disabled).toBe(true)
  })

  it('invites the first capture when none exists', async () => {
    vi.mocked(fetchOktaAdminsReport).mockResolvedValue(okReport({ state: 'never_captured', message: 'No capture of the Okta admin list has been taken for this environment yet.', rows: [], as_of_snapshot: null }))
    renderWithClient(<OktaAdminsReport />)
    expect(await screen.findByText(/No capture of the Okta admin list/)).toBeTruthy()
    expect(screen.getByText(/at most every\s+six hours/)).toBeTruthy()
  })

  it('keeps showing the last good snapshot with the refusal when a newer capture was refused', async () => {
    vi.mocked(fetchOktaAdminsReport).mockResolvedValue(okReport({ message: REFUSED_MESSAGE }))
    renderWithClient(<OktaAdminsReport />)
    expect(await screen.findByText(/The data below is the last successful snapshot/)).toBeTruthy()
    expect(screen.getByText('Alex Example')).toBeTruthy()
  })

  it('starts a capture and refetches', async () => {
    vi.mocked(startOktaCapture).mockResolvedValue({ started: true, already_running: false })
    renderWithClient(<OktaAdminsReport />)
    await screen.findByText('Alex Example')
    fireEvent.click(screen.getByRole('button', { name: /Capture now/ }))
    await waitFor(() => expect(startOktaCapture).toHaveBeenCalledWith('dev', 'okta_admins'))
    await waitFor(() => expect(vi.mocked(fetchOktaAdminsReport).mock.calls.length).toBeGreaterThan(1))
  })

  it('lists the daily sealed OPA access state as its own history, asked for by kind', async () => {
    renderWithClient(<OktaAdminsReport />)
    await screen.findByText('Alex Example')
    const region = await screen.findByRole('region', { name: 'Daily OPA access state' })
    expect(within(region).getByText(/Opening, comparing or exporting one needs the Live read permission/)).toBeTruthy()
    expect(within(region).getAllByText('sealed').length).toBeGreaterThan(0)
    expect(vi.mocked(fetchConfigSnapshots).mock.calls.map(c => c[1])).toEqual(expect.arrayContaining(['okta_admins', 'opa_access_state']))
  })

  it('says when the capture that is already running was started', async () => {
    const spy = vi.spyOn(toasts, 'toast')
    vi.mocked(startOktaCapture).mockResolvedValue({ started: false, already_running: true, started_at: '2026-10-21T08:41:00.000Z' })
    renderWithClient(<OktaAdminsReport />)
    await screen.findByText('Alex Example')
    fireEvent.click(screen.getByRole('button', { name: /Capture now/ }))
    await waitFor(() => expect(spy).toHaveBeenCalled())
    expect(spy.mock.calls[0][0].title).toMatch(/^A capture is already running \(started .*2026.*\)$/)
  })

  it('disables the button while a capture is running and reports a failed one', async () => {
    vi.mocked(fetchOktaAdminsReport).mockResolvedValue(okReport({ capture: { status: 'running', kind: 'okta_admins' } }))
    renderWithClient(<OktaAdminsReport />)
    const button = await screen.findByRole('button', { name: /Reading Okta/ })
    expect((button as HTMLButtonElement).disabled).toBe(true)
  })

  it('filters by status and role and searches', async () => {
    renderWithClient(<OktaAdminsReport />)
    await screen.findByText('Alex Example')
    fireEvent.change(screen.getByLabelText('Status'), { target: { value: 'removed' } })
    expect(screen.queryByText('Alex Example')).toBeNull()
    fireEvent.change(screen.getByLabelText('Status'), { target: { value: '__all__' } })
    fireEvent.change(screen.getByLabelText('Role'), { target: { value: 'HELP_DESK_ADMIN' } })
    expect(screen.queryByText('Alex Example')).toBeNull()
    expect(screen.getByText('Sam Sample')).toBeTruthy()
    fireEvent.change(screen.getByLabelText('Role'), { target: { value: '__all__' } })
    fireEvent.change(screen.getByLabelText('Search admins'), { target: { value: 'zzzzzz' } })
    expect(await screen.findByText(/No rows match/)).toBeTruthy()
  })

  it('exports and records the export in the audit log', async () => {
    const { exportSections } = await import('../utils/export')
    renderWithClient(<OktaAdminsReport />)
    await screen.findByText('Alex Example')
    fireEvent.click(screen.getByRole('button', { name: /CSV/ }))
    expect(exportSections).toHaveBeenCalledWith(expect.any(Array), 'csv', 'opa-okta-admins')
    await waitFor(() => expect(logOktaAdminsExport).toHaveBeenCalledWith('dev', 'csv', undefined))
  })

  it('lists snapshots including a refused one, and compares two', async () => {
    vi.mocked(fetchConfigSnapshotDiff).mockResolvedValue({
      kind: 'okta_admins', older: snaps[1], newer: snaps[0], added: [{ key: 'user:1', object: { login: 'new@example.com' } }],
      removed: [{ key: 'user:2', object: { login: 'gone@example.com' } }], changed: [{ key: 'user:3', fields: ['roles'], before: { login: 'c@example.com' }, after: { login: 'c@example.com' } }], unchanged: 5,
    } as never)
    renderWithClient(<OktaAdminsReport />)
    const history = await screen.findByRole('region', { name: 'Snapshot history' })
    expect(await within(history).findByText('refused by Okta')).toBeTruthy()
    fireEvent.change(within(history).getByLabelText('Older snapshot'), { target: { value: '5' } })
    fireEvent.change(within(history).getByLabelText('Newer snapshot'), { target: { value: '7' } })
    expect(await within(history).findByText(/1 added, 1 removed, 1 changed, 5 unchanged/)).toBeTruthy()
    expect(within(history).getByText(/new@example.com/)).toBeTruthy()
    expect(within(history).getByText(/gone@example.com/)).toBeTruthy()
    expect(within(history).getByText(/c@example.com \(roles\)/)).toBeTruthy()
  })
})
