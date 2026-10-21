import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fetchEnvironments, fetchOverview, fetchPeopleList, startOktaCapture, startSync } from '../api/client'
import { overview } from '../test/oktaFixtures'
import { renderWithClient } from '../test/renderWithClient'
import { OverviewPage } from './Overview'

vi.mock('../api/client', () => ({
  fetchEnvironments: vi.fn(), fetchOverview: vi.fn(), fetchPeopleList: vi.fn(), startOktaCapture: vi.fn(), startSync: vi.fn(), fetchReportDefs: vi.fn(), fetchIntegrity: vi.fn(),
}))
vi.mock('./Select', async () => ({ Select: (await import('../test/MockSelect')).MockSelect }))
vi.mock('./ExportButtons', () => ({ ExportButtons: ({ filenameBase }: { filenameBase: string }) => <div>export {filenameBase}</div> }))

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(fetchEnvironments).mockResolvedValue({ environments: [], active: 'prod-example' } as never)
  vi.mocked(fetchOverview).mockResolvedValue(overview())
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

  it('the sources actions call the server', async () => {
    vi.mocked(startSync).mockResolvedValue({ started: true, already_running: false })
    vi.mocked(startOktaCapture).mockResolvedValue({ started: true, already_running: false })
    renderWithClient(<OverviewPage onOpenReports={vi.fn()} />)
    await screen.findByText(/14 people hold/)
    fireEvent.click(screen.getByRole('button', { name: /Sync now/ }))
    await waitFor(() => expect(startSync).toHaveBeenCalledWith('prod-example'))
    fireEvent.click(screen.getByRole('button', { name: /Take a snapshot now/ }))
    await waitFor(() => expect(startOktaCapture).toHaveBeenCalledWith('prod-example', 'okta_admins'))
    expect(startOktaCapture).toHaveBeenCalledWith('prod-example', 'inventory_counts')
  })

  it('offers to build the sign-in figures when they have not been built', async () => {
    vi.mocked(fetchOverview).mockResolvedValue(overview({ signins_mfa: { state: 'not_built', message: 'The sign-in and MFA figures have not been built from the archive yet.', weeks: [] } }))
    renderWithClient(<OverviewPage onOpenReports={vi.fn()} />)
    fireEvent.click(await screen.findByRole('button', { name: /Build from the archive/ }))
    await waitFor(() => expect(startOktaCapture).toHaveBeenCalledWith('prod-example', 'mfa_aggregates'))
  })

  it('changing the as-of date reloads from that snapshot', async () => {
    renderWithClient(<OverviewPage onOpenReports={vi.fn()} />)
    await screen.findByText(/14 people hold/)
    fireEvent.change(screen.getByLabelText('As of'), { target: { value: '2026-10-02T00:00:00.000Z' } })
    await waitFor(() => expect(fetchOverview).toHaveBeenLastCalledWith('prod-example', '2026-10-02T00:00:00.000Z', undefined))
  })

  it('selects the inventory series from a row', async () => {
    renderWithClient(<OverviewPage onOpenReports={vi.fn()} />)
    await screen.findByText(/14 people hold/)
    const inv = screen.getByRole('region', { name: 'Inventory over time' })
    fireEvent.click(within(inv).getByRole('button', { name: 'Users' }))
    expect(within(inv).getByText(/Users \(Okta\), per daily snapshot/)).toBeTruthy()
  })
})
