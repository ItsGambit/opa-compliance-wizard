/** Users view: the reference Access Explorer layout (rail + sections + rows). */
import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { removeUserFromGroup } from '../api/client'
import { useUserResourceAccess } from '../api/hooks'
import { exampleModel, exampleUser } from '../test/accessFixtures'
import { renderWithClient } from '../test/renderWithClient'
import type { AccessModel } from '../types'
import { UsersTab } from './UsersTab'

vi.mock('../api/client', () => ({ removeUserFromGroup: vi.fn() }))
vi.mock('../api/hooks', () => ({ useUserResourceAccess: vi.fn() }))
vi.mock('./Select', async () => ({ Select: (await import('../test/MockSelect')).MockSelect }))
vi.mock('./ExportButtons', () => ({ ExportButtons: ({ filenameBase }: { filenameBase: string }) => <div>export {filenameBase}</div> }))

const lookupResult = (data: unknown) => ({ data, isError: false, error: null, refetch: vi.fn(), isFetching: false })

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(useUserResourceAccess).mockReturnValue(lookupResult(undefined) as never)
  vi.mocked(removeUserFromGroup).mockResolvedValue({ group_id: 'g1' } as never)
})

function open(model: AccessModel = exampleModel, onRemoved = vi.fn()) {
  renderWithClient(<UsersTab model={model} onUserGroupRemoved={onRemoved} />)
  fireEvent.change(screen.getByLabelText('User'), { target: { value: 'u1' } })
  return onRemoved
}

describe('UsersTab', () => {
  it('asks for a user first', () => {
    renderWithClient(<UsersTab model={exampleModel} onUserGroupRemoved={vi.fn()} />)
    expect(screen.getByText(/Select a user to see everything/)).toBeTruthy()
  })

  it('shows the identity, per-type counts, groups and the sections', () => {
    open()
    const rail = screen.getByRole('complementary')
    expect(within(rail).getAllByText('Example Admin').length).toBeGreaterThan(0)
    expect(within(rail).getByText(/ACTIVE · admin@example.test/)).toBeTruthy()
    expect(within(rail).getByRole('button', { name: /2\s*servers/ })).toBeTruthy()
    expect(within(rail).getByRole('button', { name: /3\s*managed saas app accounts/i })).toBeTruthy()
    expect(within(rail).getByRole('button', { name: /3\s*groups/ })).toBeTruthy()
    expect(screen.getByText('lab-linux-example-01')).toBeTruthy()
    expect(screen.getByText('opa-user-admin@example.test', { exact: false })).toBeTruthy()
  })

  it('a row shows what they can do, how they get it and last used, and expands inline', () => {
    vi.mocked(useUserResourceAccess).mockReturnValue(lookupResult({
      s1: { resource_kind: 'x', supported: true, events: [] },
    }) as never)
    open()
    const row = screen.getByRole('button', { name: /lab-linux-example-01/ })
    expect(row.textContent).toContain('View the password')
    expect(row.textContent).toContain('Example-All-Users')
    expect(row.textContent).toContain('Not tracked') // servers have no System Log mapping
    fireEvent.click(row)
    const detail = screen.getByRole('region', { name: 'Details for lab-linux-example-01' })
    expect(within(detail).getByText('How they get it')).toBeTruthy()
    expect(within(detail).getByText(/MFA required/)).toBeTruthy()
  })

  it('removes the user from a group only after the confirm step, with the blast-radius warning', async () => {
    const onRemoved = open()
    fireEvent.click(screen.getByRole('button', { name: /lab-linux-example-01/ }))
    const detail = screen.getByRole('region', { name: 'Details for lab-linux-example-01' })
    fireEvent.click(within(detail).getByRole('button', { name: 'Remove from group admin@example.test from Example-All-Users' }))
    expect(removeUserFromGroup).not.toHaveBeenCalled()
    // Example-All-Users backs two policies in the fixture: one other
    expect(within(detail).getByText(/also backs 1 other policy/)).toBeTruthy()
    fireEvent.click(within(detail).getByRole('button', { name: 'Yes, remove' }))
    await waitFor(() => expect(removeUserFromGroup).toHaveBeenCalledWith('g1', 'admin@example.test'))
    await waitFor(() => expect(onRemoved).toHaveBeenCalledWith('u1', 'g1'))
  })

  it('the rail groups list offers Remove only for groups that grant something, same confirm step', async () => {
    const onRemoved = open()
    const rail = screen.getByRole('complementary')
    fireEvent.click(within(rail).getByRole('button', { name: /3\s*groups/ }))
    // g3 (Example-No-Policy) backs no policy: listed, but not removable here
    expect(within(rail).getByText('Example-No-Policy')).toBeTruthy()
    expect(within(rail).getAllByRole('button', { name: /^Remove admin@example.test from/ }).length).toBe(2)
    fireEvent.click(within(rail).getByRole('button', { name: 'Remove admin@example.test from Example-Linux-Admins' }))
    fireEvent.click(within(rail).getByRole('button', { name: 'Yes, remove' }))
    await waitFor(() => expect(removeUserFromGroup).toHaveBeenCalledWith('g2', 'admin@example.test'))
    await waitFor(() => expect(onRemoved).toHaveBeenCalled())
  })

  it('a service account has no last-accessed lookup and says why', () => {
    const model = { ...exampleModel, users: [{ ...exampleUser, user_type: 'service' as const }] } as AccessModel
    open(model)
    expect(screen.getByText(/No Okta identity/)).toBeTruthy()
    expect(vi.mocked(useUserResourceAccess).mock.calls.at(-1)?.[2]).toBe(false)
    expect(screen.queryByRole('checkbox', { name: /Used in the last 90 days/ })).toBeNull()
  })

  it('says so when no policy grants anything', () => {
    const model = { ...exampleModel, policies: [] } as unknown as AccessModel
    open(model)
    expect(screen.getByText("No policy grants access via this user's groups.")).toBeTruthy()
  })
})
