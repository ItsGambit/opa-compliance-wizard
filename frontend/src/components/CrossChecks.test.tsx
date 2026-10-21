import { fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fetchCrossChecks, fetchEnvironments, startOktaCapture } from '../api/client'
import { c1Card, snapshot } from '../test/oktaFixtures'
import { renderWithClient } from '../test/renderWithClient'
import type { CrossChecksResponse } from '../types'
import { CrossChecks } from './CrossChecks'

vi.mock('../api/client', () => ({ fetchEnvironments: vi.fn(), fetchCrossChecks: vi.fn(), startOktaCapture: vi.fn() }))
vi.mock('./ExportButtons', () => ({ ExportButtons: () => <div>export</div> }))

const response = (card = c1Card()): CrossChecksResponse => ({ cards: [card], user_flags: { snapshot, users: {} }, capture: { status: 'idle' } })

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(fetchEnvironments).mockResolvedValue({ environments: [], active: 'dev' } as never)
})

describe('CrossChecks', () => {
  it('lists the candidates with Okta status, flags and OPA admin roles', async () => {
    vi.mocked(fetchCrossChecks).mockResolvedValue(response())
    renderWithClient(<CrossChecks />)
    expect(await screen.findByText('alex@example.com')).toBeTruthy()
    expect(screen.getAllByText('Inactive in Okta').length).toBeGreaterThan(0)  // the tile and the row badge
    expect(screen.getAllByText('Not found in Okta').length).toBeGreaterThan(0)
    expect(screen.getByText('pam_admin')).toBeTruthy()
    expect(screen.getByText('no Okta user with login svc-okta or e-mail svc@example.com')).toBeTruthy()
    expect(screen.getByText(/1 OPA service user\(s\) have no Okta identity/)).toBeTruthy()
  })

  it('says so when every principal is active', async () => {
    vi.mocked(fetchCrossChecks).mockResolvedValue(response(c1Card({ rows: [], counts: { checked: 3, inactive_in_okta: 0, absent_in_okta: 0, unreadable: 0, active: 3 } })))
    renderWithClient(<CrossChecks />)
    expect(await screen.findByText(/Every OPA principal that was looked up is active in Okta/)).toBeTruthy()
  })

  it('shows a refused lookup as refused, not as zero', async () => {
    vi.mocked(fetchCrossChecks).mockResolvedValue(response(c1Card({ state: 'refused', message: 'Your Okta token cannot read users; the lifecycle cross-check needs a token whose admin can view users.', rows: [], counts: {} })))
    renderWithClient(<CrossChecks />)
    expect(await screen.findByText(/cannot read users/)).toBeTruthy()
    expect(screen.queryByText('Checked')).toBeNull()
  })

  it('needs the OPA roster, and runs the lookup when it has it', async () => {
    vi.mocked(fetchCrossChecks).mockResolvedValue(response(c1Card({ state: 'never_run', message: 'Run the lookup to compare each OPA principal with its Okta user.', rows: [], counts: {}, inputs: { okta_snapshot: null, opa_roster_loaded: false } })))
    renderWithClient(<CrossChecks />)
    expect(await screen.findByText(/roster is not loaded in this session/)).toBeTruthy()
    expect((screen.getByRole('button', { name: /Run lookup/ }) as HTMLButtonElement).disabled).toBe(true)
  })

  it('starts the principal lookup', async () => {
    vi.mocked(fetchCrossChecks).mockResolvedValue(response(c1Card({ state: 'never_run', rows: [], counts: {} })))
    vi.mocked(startOktaCapture).mockResolvedValue({ started: true, already_running: false })
    renderWithClient(<CrossChecks />)
    fireEvent.click(await screen.findByRole('button', { name: /Run lookup/ }))
    await waitFor(() => expect(startOktaCapture).toHaveBeenCalledWith('dev', 'opa_principal_status'))
  })
})
