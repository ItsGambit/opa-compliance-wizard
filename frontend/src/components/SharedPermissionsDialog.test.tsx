/** 5.42.0: the admin's global defaults for shared environments. */
import { fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fetchSharedPermissions, saveSharedPermissions } from '../api/client'
import { renderWithClient } from '../test/renderWithClient'
import type { SharedPermissionsResponse } from '../types'
import { beginStepUp } from '../utils/stepUp'
import { SharedPermissionsDialog } from './SharedPermissionsDialog'

vi.mock('../api/client', async importOriginal => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return { ...actual, fetchSharedPermissions: vi.fn(), saveSharedPermissions: vi.fn() }
})
vi.mock('../utils/stepUp', async importOriginal => {
  const actual = await importOriginal<typeof import('../utils/stepUp')>()
  return { ...actual, beginStepUp: vi.fn() }
})

const DATA: SharedPermissionsResponse = {
  capabilities: [
    { key: 'live_read', label: 'Live read queries', description: 'Reads with the owner’s credentials.', builtin: 'allow' },
    { key: 'sync_now', label: 'Run Sync now', description: 'Starts a sync.', builtin: 'deny' },
  ] as SharedPermissionsResponse['capabilities'],
  defaults: {
    live_read: { value: 'allow', source: 'built_in', updated_at: null, updated_by: null },
    sync_now: { value: 'allow', source: 'default', updated_at: 'x', updated_by: 'admin@example.com' },
  } as SharedPermissionsResponse['defaults'],
  environments: {},
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(fetchSharedPermissions).mockResolvedValue(DATA)
})

describe('SharedPermissionsDialog', () => {
  it('shows each capability as a labelled choice with its value and source; saves only what changed, via MFA', async () => {
    renderWithClient(<SharedPermissionsDialog open onOpenChange={() => {}} />)
    const live = (await screen.findByLabelText('Live read queries')) as HTMLSelectElement
    const sync = screen.getByLabelText('Run Sync now') as HTMLSelectElement
    expect(live.value).toBe('inherit')
    expect(sync.value).toBe('allow')
    expect(screen.getByText(/from the global default/)).toBeTruthy()
    expect(screen.getByText(/from the built-in default/)).toBeTruthy()
    const save = screen.getByRole('button', { name: /Verify & Save/ }) as HTMLButtonElement
    expect(save.disabled).toBe(true)
    fireEvent.change(live, { target: { value: 'deny' } })
    expect(save.disabled).toBe(false)
    vi.mocked(saveSharedPermissions).mockResolvedValue({ step_up_required: true, action_id: 'a1', action: 'shared_permissions.update' })
    fireEvent.click(save)
    await waitFor(() => expect(saveSharedPermissions).toHaveBeenCalledWith({ live_read: 'deny' }))
    await waitFor(() => expect(beginStepUp).toHaveBeenCalledWith('a1', expect.objectContaining({ reopen: 'shared_permissions' })))
  })
})
