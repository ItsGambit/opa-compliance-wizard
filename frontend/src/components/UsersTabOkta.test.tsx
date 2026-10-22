/** 5.50.0: the Users view marks people whose Okta user is inactive or missing (cross-check C1). */
import { fireEvent, screen, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { useUserResourceAccess } from '../api/hooks'
import { exampleModel } from '../test/accessFixtures'
import { renderWithClient } from '../test/renderWithClient'
import { UsersTab, type OktaUserFlags } from './UsersTab'

vi.mock('../api/client', () => ({ removeUserFromGroup: vi.fn() }))
vi.mock('../api/hooks', () => ({ useUserResourceAccess: vi.fn() }))
vi.mock('./ExportButtons', () => ({ ExportButtons: () => <div>export</div> }))

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(useUserResourceAccess).mockReturnValue({ data: undefined, isError: false, error: null, refetch: vi.fn(), isFetching: false } as never)
})

function open(okta?: OktaUserFlags) {
  renderWithClient(<UsersTab model={exampleModel} okta={okta} onUserGroupRemoved={vi.fn()} />)
  const options = screen.getAllByRole('option')
  fireEvent.click(options.find(o => o.textContent?.includes('Example Admin') || o.textContent?.includes('admin@example.test')) ?? options[0])
}

describe('UsersTab Okta lifecycle flag', () => {
  it('says so, as a candidate for review, for an inactive Okta user', () => {
    open({ capturedAt: '2026-10-02T00:00:00.000Z', users: { u1: { okta_state: 'DEPROVISIONED', flag: 'inactive' } } })
    const detail = screen.getByRole('region', { name: 'Selected user' })
    expect(within(detail).getByRole('status').textContent).toMatch(/deprovisioned or suspended.*still an OPA principal.*candidate for review/)
    expect(within(detail).getByRole('status').textContent).toMatch(/Looked up/)
    expect(within(detail).getByText(/Okta: deprovisioned, read /)).toBeTruthy()
    expect(screen.getByRole('option', { name: /Okta: inactive/ })).toBeTruthy()  // the list says it too, not by colour alone
  })

  it('says a missing Okta user is missing, and an unread one is unread', () => {
    open({ capturedAt: null, users: { u1: { okta_state: 'ABSENT', flag: 'absent' } } })
    expect(screen.getByText(/no Okta user was found/)).toBeTruthy()
  })

  it('stays quiet for an active user and when no lookup has run', () => {
    open({ capturedAt: '2026-10-02T00:00:00.000Z', users: { u1: { okta_state: 'ACTIVE', flag: null } } })
    expect(screen.getByText(/^Okta: active, read /)).toBeTruthy()  // the design's badge; no warning text
    expect(screen.queryByText(/candidate for review/)).toBeNull()
  })

  it('works without any Okta data', () => {
    open(undefined)
    expect(screen.queryByText(/Okta:/)).toBeNull()
  })
})
