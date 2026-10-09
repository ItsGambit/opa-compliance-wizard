/** UI-07 / UI-16 / UI-19 / UI-22 in the Environments dialog. */
import { fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError, activateEnvironment, saveEnvironment, setEnvironmentShared } from '../api/client'
import { renderWithClient } from '../test/renderWithClient'
import type { Environment, EnvironmentsResponse } from '../types'
import { EnvironmentManagerDialog } from './EnvironmentManagerDialog'
import { beginStepUp } from '../utils/stepUp'

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
vi.mock('../utils/stepUp', async importOriginal => {
  const actual = await importOriginal<typeof import('../utils/stepUp')>()
  return { ...actual, beginStepUp: vi.fn() }
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


describe('EnvironmentManagerDialog -- step-up MFA (5.42.0)', () => {
  it('a hosted save goes to MFA with the form input but never its secrets', async () => {
    vi.mocked(saveEnvironment).mockResolvedValue({ step_up_required: true, action_id: 'act1', action: 'environment.upsert' })
    renderDialog({ environments: [env('d1', 'dev')], active: 'dev', active_id: 'd1' })
    fireEvent.click(screen.getByRole('button', { name: 'Edit dev' }))
    fireEvent.change(screen.getByLabelText('Key Secret'), { target: { value: 'TOP-SECRET' } })
    fireEvent.change(screen.getByLabelText('Base Domain'), { target: { value: 'new.example' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save & Reconnect' }))
    await waitFor(() => expect(beginStepUp).toHaveBeenCalled())
    const [actionId, pending] = vi.mocked(beginStepUp).mock.calls[0]
    expect(actionId).toBe('act1')
    expect(JSON.stringify(pending)).not.toContain('TOP-SECRET')
    expect(pending.kind === 'environment_change' && pending.environmentDraft?.base_domain).toBe('new.example')
  })

  it('reopens a not-applied edit with the user’s input', () => {
    const restore = {
      kind: 'environment_change' as const, action: 'environment.upsert', label: "Save environment 'dev'", startedAt: Date.now(),
      environmentDraft: { id: 'd1', name: 'dev', base_domain: 'typed.example', team_name: 't', key_id: 'k', okta_url: '' },
    }
    renderWithClient(<EnvironmentManagerDialog data={{ environments: [env('d1', 'dev')], active: 'dev', active_id: 'd1' }}
      open onOpenChange={() => {}} restore={restore} />)
    expect((screen.getByLabelText('Base Domain') as HTMLInputElement).value).toBe('typed.example')
    expect((screen.getByLabelText('Key Secret') as HTMLInputElement).value).toBe('')
    expect(screen.getByText(/Your earlier input is restored/)).toBeTruthy()
  })

  it('a hosted share/unshare goes to MFA', async () => {
    vi.mocked(setEnvironmentShared).mockResolvedValue({ step_up_required: true, action_id: 'act2', action: 'environment.share' })
    renderDialog({ environments: [env('d2', 'qa', { shared: true })], active: 'qa', active_id: 'd2' })
    fireEvent.click(screen.getByRole('button', { name: /Sharing for qa: shared/ }))
    await waitFor(() => expect(beginStepUp).toHaveBeenCalledWith('act2', expect.objectContaining({ label: "Make 'qa' private" })))
  })

  it('a shared row lists what the user may and may not do; admins get the per-environment editor', () => {
    const allow = { value: 'allow', source: 'built_in' } as const
    const deny = { value: 'deny', source: 'default' } as const
    const shared = env('s', 'team', {
      is_own: false, shared: true,
      permissions: { view_archive: allow, live_read: allow, tenant_write: deny, import_csv: allow, reset_watermark: allow, sync_now: deny, sync_settings: deny },
    })
    renderDialog({ environments: [shared], active: null, active_id: null })
    expect(screen.getByText(/Not allowed for shared users: changes in OPA \/ Okta, Sync now, sync settings/)).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Shared permissions for team' })).toBeNull()
  })
})
