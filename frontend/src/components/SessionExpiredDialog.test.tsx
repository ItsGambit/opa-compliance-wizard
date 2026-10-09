/** FE-05: one sign-in prompt when the gate refuses requests. */
import { act, fireEvent, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { fetchEnvironments } from '../api/client'
import { renderWithClient } from '../test/renderWithClient'
import { SessionExpiredDialog } from './SessionExpiredDialog'

afterEach(() => { vi.unstubAllGlobals() })

describe('SessionExpiredDialog', () => {
  it('opens once when requests hit the login gate, and Continue closes it', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ type: 'opaqueredirect', status: 0, ok: false }))
    renderWithClient(<SessionExpiredDialog />)
    expect(screen.queryByText('Your session has expired')).toBeNull()
    await act(async () => {
      await Promise.allSettled([fetchEnvironments(), fetchEnvironments(), fetchEnvironments()])
    })
    expect(screen.getAllByText('Your session has expired')).toHaveLength(1)
    const open = vi.fn()
    vi.stubGlobal('open', open)
    fireEvent.click(screen.getByRole('button', { name: 'Sign in in a new tab' }))
    expect(open).toHaveBeenCalledWith('/login', '_blank', 'noopener')
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }))
    expect(screen.queryByText('Your session has expired')).toBeNull()
  })
})
