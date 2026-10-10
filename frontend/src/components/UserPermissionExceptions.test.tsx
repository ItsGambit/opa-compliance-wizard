/** 5.43.0: per-user exceptions on one environment (admin-only). */
import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError, saveSharedPermissions } from '../api/client'
import { renderWithClient } from '../test/renderWithClient'
import type { Environment, SharedPermissionsResponse } from '../types'
import { beginStepUp } from '../utils/stepUp'
import { groupGrants, mainAddressOnly, orgLabel } from '../utils/sharedPermissions'
import { UserPermissionExceptions } from './UserPermissionExceptions'

vi.mock('../api/client', async importOriginal => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return { ...actual, saveSharedPermissions: vi.fn() }
})
vi.mock('../utils/stepUp', async importOriginal => {
  const actual = await importOriginal<typeof import('../utils/stepUp')>()
  return { ...actual, beginStepUp: vi.fn() }
})

const PERSONAL = 'https://login.example.org'
const WORK = 'https://work.example.com/oauth2/default'
const ENV = { id: 'e1', name: 'dev' } as Environment

function data(grants: SharedPermissionsResponse['environments'][string]['grants'] = []): SharedPermissionsResponse {
  return {
    capabilities: [
      { key: 'live_read', label: 'Live read queries', description: 'Reads.', builtin: 'allow' },
      { key: 'sync_now', label: 'Run Sync now', description: 'Starts a sync.', builtin: 'deny' },
    ] as SharedPermissionsResponse['capabilities'],
    defaults: {} as SharedPermissionsResponse['defaults'],
    environments: {
      e1: {
        name: 'dev', shared: true, overrides: {}, grants,
        effective: {
          live_read: { value: 'allow', source: 'built_in' }, sync_now: { value: 'deny', source: 'built_in' },
        } as SharedPermissionsResponse['environments'][string]['effective'],
      },
    },
    identities: [
      { issuer: PERSONAL, subject: '00uME', email: 'me@example.org', last_seen_at: 'x' },
      { issuer: WORK, subject: '00uME', email: 'me@work.example.com', last_seen_at: 'x' },
    ],
  }
}

beforeEach(() => vi.clearAllMocks())

describe('UserPermissionExceptions', () => {
  it('picks a user the gates have seen (by e-mail and org) and saves only their exception, via MFA', async () => {
    renderWithClient(<UserPermissionExceptions env={ENV} data={data()} />)
    expect(screen.getByText('No user has an exception here.')).toBeTruthy()
    const picker = screen.getByLabelText('User') as HTMLSelectElement
    // Same Okta user id in two orgs = two different users, told apart by org.
    expect(within(picker).getByText('me@example.org — login.example.org · 00uME')).toBeTruthy()
    expect(within(picker).getByText('me@work.example.com — work.example.com · 00uME')).toBeTruthy()
    fireEvent.change(picker, { target: { value: `${PERSONAL} 00uME` } })
    const sync = screen.getByLabelText('Run Sync now') as HTMLSelectElement
    expect(sync.value).toBe('inherit')
    expect(screen.getByText(/Inherit — this environment \(not allowed\)/)).toBeTruthy()
    const save = screen.getByRole('button', { name: /Verify & save the exceptions/ }) as HTMLButtonElement
    expect(save.disabled).toBe(true)
    fireEvent.change(sync, { target: { value: 'allow' } })
    vi.mocked(saveSharedPermissions).mockResolvedValue({ step_up_required: true, action_id: 'a1', action: 'shared_permissions.update' })
    fireEvent.click(save)
    await waitFor(() => expect(saveSharedPermissions).toHaveBeenCalledWith(
      { sync_now: 'allow' }, 'e1', { issuer: PERSONAL, subject: '00uME' }))
    await waitFor(() => expect(beginStepUp).toHaveBeenCalledWith('a1', expect.objectContaining({
      reopen: 'environments',
      permissionsDraft: { environmentId: 'e1', user: { issuer: PERSONAL, subject: '00uME' }, settings: { live_read: 'inherit', sync_now: 'allow' } },
    })))
  })

  it('lists existing exceptions per user and edits them', () => {
    const grants = [{ issuer: PERSONAL, subject: '00uME', email: 'me@example.org', capability: 'sync_now' as const, value: 'allow' as const }]
    renderWithClient(<UserPermissionExceptions env={ENV} data={data(grants)} />)
    const list = screen.getByRole('list', { name: 'Users with exceptions on dev' })
    expect(within(list).getByText('me@example.org')).toBeTruthy()
    expect(within(list).getByText('Run Sync now: allowed')).toBeTruthy()
    fireEvent.click(within(list).getByRole('button', { name: 'Edit the exceptions for me@example.org' }))
    expect((screen.getByLabelText('Run Sync now') as HTMLSelectElement).value).toBe('allow')
    expect(screen.getByText(/this user’s exception/)).toBeTruthy()
  })

  it('accepts a user entered by hand only in the shapes the server accepts', async () => {
    renderWithClient(<UserPermissionExceptions env={ENV} data={{ ...data(), identities: [] }} />)
    expect(screen.getByText(/users who have signed in since this version/)).toBeTruthy()
    fireEvent.change(screen.getByLabelText('User'), { target: { value: '__manual__' } })
    const issuer = screen.getByLabelText(/Okta issuer/) as HTMLInputElement
    const subject = screen.getByLabelText('Okta user id') as HTMLInputElement
    fireEvent.change(issuer, { target: { value: 'http://login.example.org' } })
    fireEvent.change(subject, { target: { value: '00uME' } })
    expect(screen.queryByLabelText('Run Sync now')).toBeNull()
    expect(issuer.getAttribute('aria-invalid')).toBe('true')
    fireEvent.change(issuer, { target: { value: ` ${PERSONAL} ` } })
    expect(screen.queryByLabelText('Run Sync now')).toBeNull()  // not until it's committed
    fireEvent.click(screen.getByRole('button', { name: 'Use this user' }))
    fireEvent.change(screen.getByLabelText('Run Sync now'), { target: { value: 'allow' } })
    // Editing the id afterwards doesn't wipe the chosen settings.
    fireEvent.change(subject, { target: { value: '00uME2' } })
    expect((screen.getByLabelText('Run Sync now') as HTMLSelectElement).value).toBe('allow')
    fireEvent.change(subject, { target: { value: '00uME' } })
    vi.mocked(saveSharedPermissions).mockResolvedValue({ changed: [] })
    fireEvent.click(screen.getByRole('button', { name: /Verify & save the exceptions/ }))
    await waitFor(() => expect(saveSharedPermissions).toHaveBeenCalledWith(
      { sync_now: 'allow' }, 'e1', { issuer: PERSONAL, subject: '00uME' }))
  })

  it('restores an exception whose MFA approval did not complete', () => {
    renderWithClient(<UserPermissionExceptions env={ENV} data={data()}
      draftUser={{ issuer: WORK, subject: '00uME' }} draft={{ live_read: 'deny', sync_now: 'inherit' }} />)
    expect((screen.getByLabelText('User') as HTMLSelectElement).value).toBe(`${WORK} 00uME`)
    expect((screen.getByLabelText('Live read queries') as HTMLSelectElement).value).toBe('deny')
    expect((screen.getByRole('button', { name: /Verify & save the exceptions/ }) as HTMLButtonElement).disabled).toBe(false)
  })

  it('is not offered by an older server that would ignore the user', () => {
    const old = data()
    delete old.environments.e1.grants
    const { container } = renderWithClient(<UserPermissionExceptions env={ENV} data={old} />)
    expect(container.textContent).toBe('')
  })

  it('names the main address when the second site refuses an admin screen', () => {
    expect((mainAddressOnly(new ApiError('Request failed with status 403', 403)) as Error).message).toMatch(/main login address/)
    const serverRefusal = new ApiError('Admin access required', 403, { error: 'Admin access required' })
    expect(mainAddressOnly(serverRefusal)).toBe(serverRefusal)
  })

  it('helpers', () => {
    expect(orgLabel(WORK)).toBe('work.example.com')
    expect(groupGrants([
      { issuer: PERSONAL, subject: 'a', email: null, capability: 'sync_now', value: 'allow' },
      { issuer: PERSONAL, subject: 'a', email: null, capability: 'live_read', value: 'deny' },
      { issuer: WORK, subject: 'a', email: null, capability: 'sync_now', value: 'deny' },
    ]).map(g => [g.user.issuer, g.grants.length])).toEqual([[PERSONAL, 2], [WORK, 1]])
  })
})
