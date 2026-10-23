/** 5.53.0: unlocking mid-edit (or from a locked dialog) keeps the unsaved input, never the secrets, and reopens the same dialog. */
import { act, cleanup, fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import {
  fetchAccessControl, fetchOrphanedArchives, fetchSettingsEnvironments, fetchSettingsStatus, fetchSharedPermissions, startSettingsUnlock,
} from '../api/client'
import { renderWithClient } from '../test/renderWithClient'
import type { SettingsEnvironment, SettingsStatus, SharedPermissionsResponse } from '../types'
import { readPendingStepUp, restoreFromUnlock } from '../utils/stepUp'
import { AccessControlDialog } from './AccessControlDialog'
import { EnvironmentManagerDialog } from './EnvironmentManagerDialog'
import { OrphanedArchivesDialog } from './OrphanedArchivesDialog'
import { SharedPermissionsDialog } from './SharedPermissionsDialog'

vi.mock('../api/client', async importOriginal => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual, fetchSettingsStatus: vi.fn(), fetchSettingsEnvironments: vi.fn(), startSettingsUnlock: vi.fn(), fetchAccessControl: vi.fn(),
    fetchSharedPermissions: vi.fn(), fetchOrphanedArchives: vi.fn(),
  }
})
vi.mock('../utils/stepUp', async importOriginal => {
  const actual = await importOriginal<typeof import('../utils/stepUp')>()
  return { ...actual, beginStepUp: (id: string, pending: Parameters<typeof actual.beginStepUp>[1]) => actual.beginStepUp(id, pending, () => {}) }
})
vi.mock('../hooks/useToast', () => ({ toast: vi.fn() }))
vi.mock('./SyncScheduleDialog', () => ({ SyncScheduleDialog: () => null }))

const hosted = (unlocked: boolean): SettingsStatus => ({
  mode: 'hosted', mfa: true, unlocked, unlocked_until: null, seconds_left: unlocked ? 300 : 0, local_notice: null,
})
const LOCAL: SettingsStatus = { mode: 'local', mfa: false, unlocked: true, unlocked_until: null, seconds_left: 0, local_notice: 'No MFA in local mode.' }
const SECRET = 'TOP-SECRET-VALUE'
const stored = () => sessionStorage.getItem('opa.pendingStepUp') ?? ''

beforeEach(() => {
  sessionStorage.clear()
  vi.clearAllMocks()
  vi.mocked(startSettingsUnlock).mockResolvedValue({ step_up_required: true, action_id: 'act-r', action: 'settings.unlock' })
})

/** Window runs out while the dialog is open: the dialog stays, the user presses Verify with Okta. */
async function lapseAndVerify(client: { refetchQueries: (f: { queryKey: unknown[] }) => Promise<void> }) {
  vi.mocked(fetchSettingsStatus).mockResolvedValue(hosted(false))
  await act(async () => { await client.refetchQueries({ queryKey: ['settings_status'] }) })
  fireEvent.click(await screen.findByRole('button', { name: 'Verify with Okta' }))
  await waitFor(() => expect(stored()).not.toBe(''))
}

describe('the draft survives a Settings unlock', () => {
  it('Environments: the form input comes back in the same dialog; the secrets are never stored', async () => {
    const env = { id: 'd1', name: 'dev', base_domain: 'x.example', team_name: 't', key_id: 'k1', okta_url: '', has_okta_token: false, shared: false, is_own: true, addressable: true,
      sync_schedule: { enabled: false, run_time: '02:00', ingestion_scope: 'curated', retention_days: null, retention_max_size_mb: null } } as SettingsEnvironment
    vi.mocked(fetchSettingsStatus).mockResolvedValue(hosted(true))
    vi.mocked(fetchSettingsEnvironments).mockResolvedValue({ environments: [env], active: 'dev', active_id: 'd1' })
    const { client, unmount } = renderWithClient(<EnvironmentManagerDialog open onOpenChange={() => {}} />)
    fireEvent.click(await screen.findByRole('button', { name: 'Edit dev' }))
    fireEvent.change(screen.getByLabelText('Base Domain'), { target: { value: 'typed.example' } })
    fireEvent.change(screen.getByLabelText('Key Secret'), { target: { value: SECRET } })
    fireEvent.change(screen.getByLabelText('Okta API Token'), { target: { value: SECRET + '-2' } })
    await lapseAndVerify(client)
    expect(stored()).not.toContain('TOP-SECRET')
    const pending = readPendingStepUp()
    expect(pending).toMatchObject({ kind: 'settings_unlock', reopen: 'environments', environmentDraft: { id: 'd1', name: 'dev', base_domain: 'typed.example' } })
    unmount(); cleanup()
    // back from the gate: the same dialog reopens with the input put back
    const restore = restoreFromUnlock(pending as Parameters<typeof restoreFromUnlock>[0])
    expect(restore?.reopen).toBe('environments')
    vi.mocked(fetchSettingsStatus).mockResolvedValue(LOCAL)
    renderWithClient(<EnvironmentManagerDialog open onOpenChange={() => {}} restore={restore} />)
    expect(await screen.findByDisplayValue('typed.example')).toBeTruthy()
    expect((screen.getByLabelText('Key Secret') as HTMLInputElement).value).toBe('')
  })

  it('Shared permissions: the chosen values come back', async () => {
    const data = {
      capabilities: [{ key: 'live_read', label: 'Live read queries', description: 'd', builtin: 'allow' }, { key: 'sync_now', label: 'Run Sync now', description: 'd', builtin: 'deny' }],
      defaults: { live_read: { value: 'allow', source: 'built_in', updated_at: null, updated_by: null }, sync_now: { value: 'deny', source: 'built_in', updated_at: null, updated_by: null } },
      environments: {},
    } as unknown as SharedPermissionsResponse
    vi.mocked(fetchSharedPermissions).mockResolvedValue(data)
    vi.mocked(fetchSettingsStatus).mockResolvedValue(hosted(true))
    const { client, unmount } = renderWithClient(<SharedPermissionsDialog open onOpenChange={() => {}} />)
    const sync = (await screen.findByLabelText('Run Sync now')) as HTMLSelectElement
    fireEvent.change(sync, { target: { value: 'allow' } })
    await lapseAndVerify(client)
    const pending = readPendingStepUp()
    expect(pending).toMatchObject({ kind: 'settings_unlock', reopen: 'shared_permissions', permissionsDraft: { settings: { sync_now: 'allow' } } })
    unmount(); cleanup()
    const restore = restoreFromUnlock(pending as Parameters<typeof restoreFromUnlock>[0])
    vi.mocked(fetchSettingsStatus).mockResolvedValue(LOCAL)
    renderWithClient(<SharedPermissionsDialog open onOpenChange={() => {}} draft={restore?.permissionsDraft?.settings} />)
    await waitFor(async () => expect(((await screen.findByLabelText('Run Sync now')) as HTMLSelectElement).value).toBe('allow'))
  })

  it('Access control: the group ids come back', async () => {
    vi.mocked(fetchAccessControl).mockResolvedValue({ admin_group_id: null, user_group_id: null, restrict_login: false })
    vi.mocked(fetchSettingsStatus).mockResolvedValue(hosted(true))
    const { client, unmount } = renderWithClient(<AccessControlDialog open onOpenChange={() => {}} />)
    const admin = (await screen.findByLabelText('Admin Group ID')) as HTMLInputElement
    await new Promise(r => setTimeout(r, 20))
    fireEvent.change(admin, { target: { value: '00gTYPED' } })
    await lapseAndVerify(client)
    const pending = readPendingStepUp()
    expect(pending).toMatchObject({ kind: 'settings_unlock', reopen: 'access_control', accessControlDraft: { admin_group_id: '00gTYPED' } })
    unmount(); cleanup()
    const restore = restoreFromUnlock(pending as Parameters<typeof restoreFromUnlock>[0])
    vi.mocked(fetchSettingsStatus).mockResolvedValue(LOCAL)
    renderWithClient(<AccessControlDialog open onOpenChange={() => {}} draft={restore?.accessControlDraft} />)
    expect(await screen.findByDisplayValue('00gTYPED')).toBeTruthy()
  })

  it('Orphaned archives: unlocking from the locked dialog names this dialog to reopen', async () => {
    vi.mocked(fetchOrphanedArchives).mockResolvedValue({ archives: [] })
    vi.mocked(fetchSettingsStatus).mockResolvedValue(hosted(false))
    renderWithClient(<OrphanedArchivesDialog open onOpenChange={() => {}} />)
    fireEvent.click(await screen.findByRole('button', { name: 'Continue with Okta' }))
    await waitFor(() => expect(stored()).not.toBe(''))
    const pending = readPendingStepUp()
    expect(pending).toMatchObject({ kind: 'settings_unlock', reopen: 'orphaned_archives' })
    expect(restoreFromUnlock(pending as Parameters<typeof restoreFromUnlock>[0])?.reopen).toBe('orphaned_archives')
    expect(fetchOrphanedArchives).not.toHaveBeenCalled()
  })

  it('a stored draft never holds a secret even if a caller hands one over', async () => {
    const { beginStepUp } = await vi.importActual<typeof import('../utils/stepUp')>('../utils/stepUp')
    beginStepUp('a', {
      kind: 'settings_unlock', startedAt: Date.now(), reopen: 'environments',
      environmentDraft: { name: 'dev', base_domain: 'b', team_name: 't', key_id: 'k', okta_url: '', key_secret: SECRET, okta_api_token: SECRET } as never,
    }, () => {})
    expect(stored()).not.toContain('TOP-SECRET')
    expect(stored()).toContain('"base_domain":"b"')
  })
})
