/** UI-07 / UI-16 / UI-19 / UI-22 in the Environments dialog. */
import { fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError, activateEnvironment, saveEnvironment, setEnvironmentShared } from '../api/client'
import { renderWithClient } from '../test/renderWithClient'
import type { Environment, EnvironmentsResponse } from '../types'
import { EnvironmentManagerDialog } from './EnvironmentManagerDialog'

vi.mock('../api/client', async importOriginal => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    activateEnvironment: vi.fn(),
    deleteEnvironment: vi.fn(),
    saveEnvironment: vi.fn(),
    setEnvironmentShared: vi.fn(),
  }
})
vi.mock('./SyncScheduleDialog', () => ({ SyncScheduleDialog: ({ env }: { env: Environment }) => <button type="button">sync {env.id}</button> }))

const SCHEDULE = { enabled: false, run_time: '02:00', ingestion_scope: 'curated', retention_days: null, retention_max_size_mb: null } as Environment['sync_schedule']
const env = (id: string, name: string, o: Partial<Environment> = {}): Environment => ({
  id, name, base_domain: 'x.example', team_name: 't', key_id: 'k123456789', okta_url: '', has_okta_token: false,
  sync_schedule: SCHEDULE, shared: false, is_own: true, addressable: true, ...o,
})

function renderDialog(data: EnvironmentsResponse, isAdmin = false) {
  return renderWithClient(<EnvironmentManagerDialog data={data} open onOpenChange={() => {}} isAdmin={isAdmin} />)
}

beforeEach(() => { vi.clearAllMocks() })

describe('EnvironmentManagerDialog', () => {
  it('admin view with two same-named rows: one active badge, no Activate or sync controls on the foreign row', () => {
    const data: EnvironmentsResponse = {
      environments: [env('mine', 'prod'), env('theirs', 'prod', { is_own: false, addressable: false }), env('other', 'dev')],
      active: 'prod', active_id: 'mine',
    }
    renderDialog(data, true)
    expect(screen.getAllByText('active')).toHaveLength(1)
    expect(screen.queryAllByRole('button', { name: 'Activate prod' })).toHaveLength(0)
    expect(screen.getByRole('button', { name: 'Activate dev' })).toBeTruthy()
    expect(screen.queryByText('sync theirs')).toBeNull()
    expect(screen.getByText('sync mine')).toBeTruthy()
    expect(screen.getByText(/Another user's private environment/)).toBeTruthy()
  })

  it('a shared-with-me row is activatable but has no sync controls', () => {
    renderDialog({ environments: [env('s', 'team', { is_own: false, shared: true })], active: null, active_id: null })
    expect(screen.getByRole('button', { name: 'Activate team' })).toBeTruthy()
    expect(screen.queryByText('sync s')).toBeNull()
  })

  it('Activate sends the row id', async () => {
    vi.mocked(activateEnvironment).mockResolvedValue({ activated: true, active: 'dev' })
    renderDialog({ environments: [env('d1', 'dev')], active: null, active_id: null })
    fireEvent.click(screen.getByRole('button', { name: 'Activate dev' }))
    await waitFor(() => expect(activateEnvironment).toHaveBeenCalledWith('dev', 'd1'))
  })

  it('making an environment shared asks first; making it private does not', async () => {
    vi.mocked(setEnvironmentShared).mockResolvedValue({ name: 'dev', shared: true })
    renderDialog({ environments: [env('d1', 'dev'), env('d2', 'qa', { shared: true })], active: 'dev', active_id: 'd1' })
    fireEvent.click(screen.getByRole('button', { name: /Sharing for dev: private/ }))
    expect(setEnvironmentShared).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Yes, share' }))
    await waitFor(() => expect(setEnvironmentShared).toHaveBeenCalledWith('dev', true, 'd1'))
    fireEvent.click(screen.getByRole('button', { name: /Sharing for qa: shared/ }))
    await waitFor(() => expect(setEnvironmentShared).toHaveBeenCalledWith('qa', false, 'd2'))
  })

  it('a fresh form does not show the previous attempt’s error', async () => {
    vi.mocked(saveEnvironment).mockRejectedValue(new ApiError('bad secret', 502, { error: 'bad secret' }))
    renderDialog({ environments: [env('d1', 'dev')], active: 'dev', active_id: 'd1' })
    fireEvent.click(screen.getByRole('button', { name: 'Edit dev' }))
    fireEvent.click(screen.getByRole('button', { name: 'Save & Reconnect' }))
    await screen.findByText('bad secret', { selector: '[role=alert]' })
    fireEvent.click(screen.getByRole('button', { name: 'Close the form' }))
    fireEvent.click(screen.getByRole('button', { name: /Add environment/ }))
    expect(screen.queryByText('bad secret', { selector: '[role=alert]' })).toBeNull()
  })

  it('"Saved, but could not connect" closes the form and refreshes the list', async () => {
    vi.mocked(saveEnvironment).mockRejectedValue(new ApiError('Saved, but could not connect: 401', 502, { error: 'Saved, but could not connect: 401', saved: true }))
    const { client } = renderDialog({ environments: [env('d1', 'dev')], active: 'dev', active_id: 'd1' })
    const spy = vi.spyOn(client, 'invalidateQueries')
    fireEvent.click(screen.getByRole('button', { name: 'Edit dev' }))
    fireEvent.click(screen.getByRole('button', { name: 'Save & Reconnect' }))
    await waitFor(() => expect(spy).toHaveBeenCalledWith({ queryKey: ['environments'] }))
    expect(screen.queryByRole('button', { name: 'Save & Reconnect' })).toBeNull()
  })

  it('labels every form field and the close buttons (UI-19)', () => {
    renderDialog({ environments: [], active: null, active_id: null })
    fireEvent.click(screen.getByRole('button', { name: /Add environment/ }))
    for (const label of ['Label', 'Base Domain', 'Team Name', 'Key ID', 'Key Secret', 'Okta URL', 'Okta API Token']) {
      expect(screen.getByLabelText(label)).toBeTruthy()
    }
    expect(screen.getByRole('button', { name: 'Close' })).toBeTruthy()
  })
})
