import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { cancelRefresh, fetchEnvironments, fetchOverview, fetchPeopleList, fetchRefreshStatus, startOktaCapture, startRefresh, startSync } from '../api/client'
import type { RefreshStatus } from '../types'
import { overview } from '../test/oktaFixtures'
import { renderWithClient } from '../test/renderWithClient'
import { OverviewPage } from './Overview'

vi.mock('../api/client', () => ({
  fetchEnvironments: vi.fn(), fetchOverview: vi.fn(), fetchPeopleList: vi.fn(), startOktaCapture: vi.fn(), startSync: vi.fn(), fetchReportDefs: vi.fn(), fetchIntegrity: vi.fn(),
  fetchRefreshStatus: vi.fn(), startRefresh: vi.fn(), cancelRefresh: vi.fn(),
}))
vi.mock('./Select', async () => ({ Select: (await import('../test/MockSelect')).MockSelect }))
vi.mock('./ExportButtons', () => ({ ExportButtons: ({ filenameBase }: { filenameBase: string }) => <div>export {filenameBase}</div> }))

const IDLE: RefreshStatus = {
  status: 'idle', job_id: null, trigger: null, started_at: null, finished_at: null, parts_requested: [], cancel_requested: false, summary: null,
  parts: { opa: { state: 'not_requested' }, okta: { state: 'not_requested' }, log: { state: 'not_requested' } },
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(fetchEnvironments).mockResolvedValue({ environments: [], active: 'prod-example' } as never)
  vi.mocked(fetchOverview).mockResolvedValue(overview())
  vi.mocked(fetchRefreshStatus).mockResolvedValue(IDLE)
  vi.mocked(startRefresh).mockResolvedValue({ started: true, already_running: false, job_id: 'j1' })
})

describe('OverviewPage', () => {
  it('shows the sources strip, the paragraph, the tiles and every section', async () => {
    renderWithClient(<OverviewPage onOpenReports={vi.fn()} />)
    expect(await screen.findByText(/14 people hold an Okta admin role/)).toBeTruthy()
    const strip = screen.getByRole('region', { name: 'Where the figures come from' })
    expect(within(strip).getByText(/412 days held/)).toBeTruthy()
    expect(within(strip).getByText('Intact')).toBeTruthy()
    for (const name of ['Key figures']) expect(screen.getByRole('list', { name })).toBeTruthy()
    expect(screen.getByRole('region', { name: /Cross-checks/ })).toBeTruthy()
    expect(screen.getByRole('region', { name: /Okta sign-ins and MFA/ })).toBeTruthy()
    expect(screen.getByRole('region', { name: 'Inventory over time' })).toBeTruthy()
    expect(screen.getByRole('region', { name: 'Evidence readiness' })).toBeTruthy()
  })

  it('a count opens the named list in a drawer (fetched only then) and says it is audited', async () => {
    vi.mocked(fetchOverview).mockResolvedValue(overview({ tiles: { ...overview().tiles, left_okta: { people: 3, accounts: 1, state: 'ok', effective_known: true } } }))
    vi.mocked(fetchPeopleList).mockResolvedValue({ list: 'c1', state: 'ok', message: null, snapshot: null, people: [
      { source: 'opa_user', opa_id: 'u1', name: 'person1@example.com', email: 'person1@example.com', okta_state: 'DEPROVISIONED', okta_id: null, okta_login: null, flag: 'inactive', opa_roles: [], opa_powerful_roles: [], footprint: { groups: 1, policies: 1, resources: 4 } },
    ] } as never)
    renderWithClient(<OverviewPage onOpenReports={vi.fn()} />)
    await screen.findByText(/14 people hold/)
    expect(fetchPeopleList).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: /Open the list: Left Okta, still in OPA/ }))
    expect((await screen.findAllByText('person1@example.com')).length).toBeGreaterThan(0)
    expect(screen.getByText(/Opening it is recorded in the Audit Log/)).toBeTruthy()
    expect(fetchPeopleList).toHaveBeenCalledWith('prod-example', 'c1', undefined)
  })

  it('shows an Okta read the token cannot make as not readable, not as zero', async () => {
    vi.mocked(fetchOverview).mockResolvedValue(overview({
      okta_admins: { state: 'refused', message: 'Your Okta token cannot read admin role assignments.', count: null, by_role: {}, time_bound: null, snapshot: null },
      tiles: { ...overview().tiles, okta_people: 0, both: null },
      cross_checks: [{ ...overview().cross_checks[1], state: 'refused', message: 'Your Okta token cannot read admin role assignments.', result: { state: 'refused', people: null } }],
    }))
    renderWithClient(<OverviewPage onOpenReports={vi.fn()} />)
    expect((await screen.findAllByText('Not readable')).length).toBeGreaterThan(0)
    expect(screen.getAllByText(/cannot read admin role assignments/).length).toBeGreaterThan(0)
  })

  it('lists what is stale or failing before the figures', async () => {
    vi.mocked(fetchOverview).mockResolvedValue(overview({ attention: [{ kind: 'sync', text: 'Archive sync has not succeeded for 3 day(s).' }] }))
    renderWithClient(<OverviewPage onOpenReports={vi.fn()} />)
    expect(await screen.findByText(/Archive sync has not succeeded for 3 day/)).toBeTruthy()
  })

  it('has one split Refresh control; the three old buttons are gone', async () => {
    renderWithClient(<OverviewPage onOpenReports={vi.fn()} />)
    await screen.findByText(/14 people hold/)
    expect(screen.getByRole('button', { name: /^Refresh$/ })).toBeTruthy()
    expect(screen.getByRole('button', { name: 'More refresh options' })).toBeTruthy()
    for (const gone of [/Sync now/, /Take a snapshot now/, /Reload the Overview/]) expect(screen.queryByRole('button', { name: gone })).toBeNull()
    expect(startSync).not.toHaveBeenCalled()
  })

  it('Refresh runs every part by default; the menu runs a single part; Verify the chain is in the menu', async () => {
    renderWithClient(<OverviewPage onOpenReports={vi.fn()} />)
    await screen.findByText(/14 people hold/)
    fireEvent.click(screen.getByRole('button', { name: /^Refresh$/ }))
    await waitFor(() => expect(startRefresh).toHaveBeenCalledWith('prod-example', undefined))
    fireEvent.click(screen.getByRole('button', { name: 'More refresh options' }))
    fireEvent.click(await screen.findByRole('menuitem', { name: /OPA scan only/ }))
    await waitFor(() => expect(startRefresh).toHaveBeenLastCalledWith('prod-example', ['opa']))
    fireEvent.click(screen.getByRole('button', { name: 'More refresh options' }))
    expect(await screen.findByRole('menuitem', { name: /Verify the chain/ })).toBeTruthy()
    expect(screen.queryByRole('menuitem', { name: /Build sign-in figures/ })).toBeNull()  // only while not built
  })

  it('a viewer without Sync now gets an aria-disabled control that explains why (focusable, reason read out), and clicking does nothing', async () => {
    vi.mocked(fetchEnvironments).mockResolvedValue({
      environments: [{ id: 'e1', name: 'prod-example', is_own: false, shared: true, addressable: true, base_domain: '', team_name: '', key_id: '', okta_url: '', has_okta_token: true,
        sync_schedule: {}, permissions: { live_read: { value: 'allow', source: 'default' }, sync_now: { value: 'deny', source: 'default' } } }],
      active: 'prod-example', active_id: 'e1',
    } as never)
    renderWithClient(<OverviewPage onOpenReports={vi.fn()} />)
    await screen.findByText(/14 people hold/)
    const btn = await screen.findByRole('button', { name: /^Refresh$/ })
    await waitFor(() => expect(btn.getAttribute('aria-disabled')).toBe('true'))
    expect((btn as HTMLButtonElement).disabled).toBe(false)  // still focusable
    const reasonId = btn.getAttribute('aria-describedby')!
    expect(document.getElementById(reasonId)!.textContent).toMatch(/Refreshing needs the Sync now permission on this environment/)
    fireEvent.click(btn)
    expect(startRefresh).not.toHaveBeenCalled()
  })

  it('shows the progress rows from the status, keeps a refused row\'s message with Retry this part, and Retry runs only that part', async () => {
    vi.mocked(fetchRefreshStatus).mockResolvedValue({
      status: 'done', job_id: 'j9', trigger: 'manual', started_at: new Date(Date.now() - 60_000).toISOString(), finished_at: new Date().toISOString(),
      parts_requested: ['opa', 'okta', 'log'], cancel_requested: false, summary: '2 of 3 parts completed; Okta scan refused.',
      parts: {
        opa: { state: 'ok', message: 'Scanned 3 users.', counts: { users: 3 }, step_defs: [['users', 'Fetching users']], steps: [{ key: 'users', status: 'done', detail: '3' }] },
        log: { state: 'ok', message: '12 new events stored.', events_new: 12 },
        okta: { state: 'refused', message: 'Okta refused the admin-role read.', sub: { admins: { state: 'refused', message: 'refused' }, inventory: { state: 'ok' } } },
      },
    } as RefreshStatus)
    renderWithClient(<OverviewPage onOpenReports={vi.fn()} />)
    const card = await screen.findByRole('region', { name: 'Refresh progress' })
    expect(within(card).getByText('Refused')).toBeTruthy()
    expect(within(card).getAllByText('Completed').length).toBe(2)
    expect(within(card).getByText('Okta refused the admin-role read.')).toBeTruthy()
    fireEvent.click(within(card).getByRole('button', { name: /Retry this part/ }))
    await waitFor(() => expect(startRefresh).toHaveBeenCalledWith('prod-example', ['okta']))
  })

  it('a running refresh disables the control and offers Stop, which calls the server', async () => {
    vi.mocked(fetchRefreshStatus).mockResolvedValue({
      status: 'running', job_id: 'j2', trigger: 'manual', started_at: new Date().toISOString(), finished_at: null, parts_requested: ['opa', 'okta', 'log'],
      cancel_requested: false, summary: null,
      parts: { opa: { state: 'running', started_at: new Date().toISOString(), step_defs: [['users', 'Fetching users']], steps: [{ key: 'users', status: 'start', detail: null }] }, log: { state: 'ok', events_new: 1 }, okta: { state: 'pending' } },
    } as RefreshStatus)
    vi.mocked(cancelRefresh).mockResolvedValue({ cancelling: true, job_id: 'j2' })
    renderWithClient(<OverviewPage onOpenReports={vi.fn()} />)
    const main = await screen.findByRole('button', { name: /Refreshing…/ })
    expect(main.getAttribute('aria-disabled')).toBe('true')
    fireEvent.click(main)
    expect(startRefresh).not.toHaveBeenCalled()
    fireEvent.click(await screen.findByRole('button', { name: 'Stop' }))
    await waitFor(() => expect(cancelRefresh).toHaveBeenCalledWith('prod-example'))
  })

  it('says plainly when no OPA scan is stored yet, and with a schedule says when the daily refresh runs', async () => {
    const base = overview()
    vi.mocked(fetchOverview).mockResolvedValue({ ...base, sources: { ...base.sources, opa_model: { loaded: false, refreshed_at: null, principals_effective: null, built_at: null, source: 'none' },
      refresh: { schedule: { enabled: true, run_time: '02:00' }, last_scheduled: null, last_manual: null } } })
    renderWithClient(<OverviewPage onOpenReports={vi.fn()} />)
    await screen.findByText(/14 people hold/)
    expect(screen.getByText(/No OPA scan stored yet\. Select/)).toBeTruthy()
    expect(screen.getByText(/or wait for the daily refresh at 02:00 UTC/)).toBeTruthy()
  })

  it('shows the stored scan with its time and an amber stale badge from 24 hours', async () => {
    const base = overview()
    const builtAt = new Date(Date.now() - 50 * 3_600_000).toISOString()
    vi.mocked(fetchOverview).mockResolvedValue({ ...base, sources: { ...base.sources, opa_model: { loaded: true, refreshed_at: builtAt, principals_effective: 212, built_at: builtAt, source: 'cache', stale: true, counts: { users: 3 }, warnings_count: 0, modified_at: null } } })
    renderWithClient(<OverviewPage onOpenReports={vi.fn()} />)
    await screen.findByText(/14 people hold/)
    const strip = screen.getByRole('region', { name: 'Where the figures come from' })
    expect(within(strip).getByText(/Stale · 2 days/)).toBeTruthy()
    expect(within(strip).getByText(/212 principals with effective access/)).toBeTruthy()
  })

  it('offers to build the sign-in figures when they have not been built', async () => {
    vi.mocked(fetchOverview).mockResolvedValue(overview({ signins_mfa: { state: 'not_built', message: 'The sign-in and MFA figures have not been built from the archive yet.', weeks: [] } }))
    renderWithClient(<OverviewPage onOpenReports={vi.fn()} />)
    fireEvent.click(await screen.findByRole('button', { name: /Build from the archive/ }))
    await waitFor(() => expect(startOktaCapture).toHaveBeenCalledWith('prod-example', 'mfa_aggregates'))
    fireEvent.click(screen.getByRole('button', { name: 'More refresh options' }))
    fireEvent.click(await screen.findByRole('menuitem', { name: /Build sign-in figures from the archive/ }))
    await waitFor(() => expect(startOktaCapture).toHaveBeenCalledTimes(2))
  })

  it('changing the as-of date reloads from that snapshot', async () => {
    renderWithClient(<OverviewPage onOpenReports={vi.fn()} />)
    await screen.findByText(/14 people hold/)
    fireEvent.change(screen.getByLabelText('As of'), { target: { value: '2026-10-02T00:00:00.000Z' } })
    await waitFor(() => expect(fetchOverview).toHaveBeenLastCalledWith('prod-example', '2026-10-02T00:00:00.000Z', undefined))
  })

  it('labels a capped Okta count as a lower bound', async () => {
    const base = overview()
    vi.mocked(fetchOverview).mockResolvedValue({ ...base, inventory: { ...base.inventory, problems: [{ series: 'okta.users', state: 'capped' }] } })
    renderWithClient(<OverviewPage onOpenReports={vi.fn()} />)
    await screen.findByText(/14 people hold/)
    const inv = screen.getByRole('region', { name: 'Inventory over time' })
    expect(within(inv).getByText(/lower bound, stopped at 50,000/, { selector: 'span.sr-only' })).toBeTruthy()
    expect(within(inv).getByText(/a lower bound, counting stopped at 50,000/)).toBeTruthy()
    expect(within(inv).getByText(/≥/)).toBeTruthy()
  })

  it('selects the inventory series from a row', async () => {
    renderWithClient(<OverviewPage onOpenReports={vi.fn()} />)
    await screen.findByText(/14 people hold/)
    const inv = screen.getByRole('region', { name: 'Inventory over time' })
    fireEvent.click(within(inv).getByRole('button', { name: 'Users' }))
    expect(within(inv).getByText(/Users \(Okta\), per daily snapshot/)).toBeTruthy()
  })
})
