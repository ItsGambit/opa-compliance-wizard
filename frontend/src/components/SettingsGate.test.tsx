/** 5.53.0: the Settings/Updates unlock gate. The server decides everything; these tests cover what the screen says in each state. */
import { act, fireEvent, screen, waitFor } from '@testing-library/react'
import { useState } from 'react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError, fetchSettingsStatus, lockSettings, startSettingsUnlock } from '../api/client'
import { renderWithClient } from '../test/renderWithClient'
import type { SettingsStatus } from '../types'
import { beginStepUp } from '../utils/stepUp'
import { SettingsGate } from './SettingsGate'

vi.mock('../api/client', async importOriginal => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return { ...actual, fetchSettingsStatus: vi.fn(), startSettingsUnlock: vi.fn(), lockSettings: vi.fn() }
})
vi.mock('../utils/stepUp', async importOriginal => {
  const actual = await importOriginal<typeof import('../utils/stepUp')>()
  return { ...actual, beginStepUp: vi.fn() }
})
vi.mock('../hooks/useToast', () => ({ toast: vi.fn() }))

const hosted = (o: Partial<SettingsStatus> = {}): SettingsStatus => ({
  mode: 'hosted', mfa: true, unlocked: false, unlocked_until: null, seconds_left: 0, local_notice: null, ...o,
})
const LOCAL: SettingsStatus = { mode: 'local', mfa: false, unlocked: true, unlocked_until: null, seconds_left: 0, local_notice: 'No MFA in local mode. This is the server wording.' }

function Body() {
  const [text, setText] = useState('')
  return <input aria-label="draft" value={text} onChange={e => setText(e.target.value)} />
}

function renderGate(onNotNow = vi.fn(), area: 'settings' | 'updates' = 'settings') {
  return { onNotNow, ...renderWithClient(<SettingsGate area={area} reopen={area === 'updates' ? 'updates' : 'access_control'} what="Access control" onNotNow={onNotNow}><Body /></SettingsGate>) }
}

beforeEach(() => { vi.clearAllMocks() })

describe('SettingsGate', () => {
  it('locked: a prompt with Continue and Not now, and nothing behind it is mounted', async () => {
    vi.mocked(fetchSettingsStatus).mockResolvedValue(hosted())
    const { onNotNow } = renderGate()
    expect(await screen.findByText('Unlock Access control with MFA')).toBeTruthy()
    expect(screen.getByText(/The unlock lasts 10 minutes, and every save still asks again/)).toBeTruthy()
    expect(screen.queryByLabelText('draft')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Not now' }))
    expect(onNotNow).toHaveBeenCalled()
    expect(startSettingsUnlock).not.toHaveBeenCalled()
  })

  it('unlocking: the button is disabled while the request is prepared, then the page goes to the gate for settings_unlock', async () => {
    vi.mocked(fetchSettingsStatus).mockResolvedValue(hosted())
    let resolve!: (v: { step_up_required: true; action_id: string; action: string }) => void
    vi.mocked(startSettingsUnlock).mockReturnValue(new Promise(r => { resolve = r }))
    renderGate(vi.fn(), 'updates')
    fireEvent.click(await screen.findByRole('button', { name: 'Continue with Okta' }))
    const busy = (await screen.findByRole('button', { name: 'Preparing…' })) as HTMLButtonElement
    expect(busy.disabled).toBe(true)
    expect((screen.getByRole('button', { name: 'Not now' }) as HTMLButtonElement).disabled).toBe(true)
    await act(async () => { resolve({ step_up_required: true, action_id: 'act-1', action: 'settings.unlock' }) })
    await waitFor(() => expect(beginStepUp).toHaveBeenCalled())
    const [actionId, pending] = vi.mocked(beginStepUp).mock.calls[0]
    expect(actionId).toBe('act-1')
    expect(pending).toMatchObject({ kind: 'settings_unlock', reopen: 'updates' })
    expect(typeof (pending as { startedAt: number }).startedAt).toBe('number')
  })

  it('unlocked: shows the time left from the server and lets the user lock now (back to the prompt)', async () => {
    vi.mocked(fetchSettingsStatus).mockResolvedValue(hosted({ unlocked: true, seconds_left: 545, unlocked_until: '2099-01-01T00:00:00Z' }))
    vi.mocked(lockSettings).mockResolvedValue({ locked: true })
    renderGate()
    expect(await screen.findByText('Unlocked · 9 min left')).toBeTruthy()
    expect(screen.getByLabelText('draft')).toBeTruthy()
    vi.mocked(fetchSettingsStatus).mockResolvedValue(hosted())
    fireEvent.click(screen.getByRole('button', { name: 'Lock now' }))
    await waitFor(() => expect(lockSettings).toHaveBeenCalled())
    expect(await screen.findByText('Unlock Access control with MFA')).toBeTruthy()
    expect(screen.queryByLabelText('draft')).toBeNull()
  })

  it('the last minute turns the pill to a short warning and moves nothing else', async () => {
    vi.mocked(fetchSettingsStatus).mockResolvedValue(hosted({ unlocked: true, seconds_left: 45 }))
    renderGate()
    const pill = await screen.findByText(/Expires in \d+ s/)
    expect(pill.className).toContain('text-warn')
    expect(screen.getByLabelText('draft')).toBeTruthy()
    expect(screen.getByText('Settings unlock expires in under a minute.')).toBeTruthy()
    expect(beginStepUp).not.toHaveBeenCalled()    // no auto-redirect
  })

  it('locked again mid-edit: the form stays mounted with what was typed, and Unlock is offered', async () => {
    vi.mocked(fetchSettingsStatus).mockResolvedValue(hosted({ unlocked: true, seconds_left: 300 }))
    const { client } = renderGate()
    const box = (await screen.findByLabelText('draft')) as HTMLInputElement
    fireEvent.change(box, { target: { value: 'half-typed group id' } })
    vi.mocked(fetchSettingsStatus).mockResolvedValue(hosted())      // the window ran out (or was ended elsewhere)
    await act(async () => { await client.refetchQueries({ queryKey: ['settings_status'] }) })
    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toContain('Settings locked again')
    expect(alert.textContent).toContain('a save asks for its own MFA anyway')
    expect((screen.getByLabelText('draft') as HTMLInputElement).value).toBe('half-typed group id')
    expect(screen.queryByText('Unlock Access control with MFA')).toBeNull()
    vi.mocked(startSettingsUnlock).mockResolvedValue({ step_up_required: true, action_id: 'act-2', action: 'settings.unlock' })
    fireEvent.click(screen.getByRole('button', { name: 'Verify with Okta' }))
    await waitFor(() => expect(beginStepUp).toHaveBeenCalledWith('act-2', expect.objectContaining({ kind: 'settings_unlock', reopen: 'access_control' })))
  })

  it('a save elsewhere that renewed the window brings the pill back', async () => {
    vi.mocked(fetchSettingsStatus).mockResolvedValue(hosted({ unlocked: true, seconds_left: 300 }))
    const { client } = renderGate()
    await screen.findByLabelText('draft')
    vi.mocked(fetchSettingsStatus).mockResolvedValue(hosted())
    await act(async () => { await client.refetchQueries({ queryKey: ['settings_status'] }) })
    await screen.findByText(/Settings locked again/)
    vi.mocked(fetchSettingsStatus).mockResolvedValue(hosted({ unlocked: true, seconds_left: 600 }))
    await act(async () => { await client.refetchQueries({ queryKey: ['settings_status'] }) })
    expect(await screen.findByText('Unlocked · 10 min left')).toBeTruthy()
    expect(screen.queryByText(/Settings locked again/)).toBeNull()
  })

  it('local mode: no prompt, no pill, the server’s notice above the content', async () => {
    vi.mocked(fetchSettingsStatus).mockResolvedValue(LOCAL)
    renderGate()
    expect(await screen.findByLabelText('draft')).toBeTruthy()
    expect(screen.getByRole('note').textContent).toContain('No MFA in local mode. This is the server wording.')
    expect(screen.queryByRole('button', { name: 'Continue with Okta' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Lock now' })).toBeNull()
    expect(fetchSettingsStatus).toHaveBeenCalledWith('settings')
  })

  it('asks the server about the right area', async () => {
    vi.mocked(fetchSettingsStatus).mockResolvedValue(LOCAL)
    renderGate(vi.fn(), 'updates')
    await screen.findByLabelText('draft')
    expect(fetchSettingsStatus).toHaveBeenCalledWith('updates')
  })

  it('says so when it cannot tell, with a Retry (never a silent open)', async () => {
    vi.mocked(fetchSettingsStatus).mockRejectedValue(new ApiError('boom', 500, { error: 'boom' }))
    renderGate()
    expect(await screen.findByText('Could not check whether Settings is unlocked')).toBeTruthy()
    expect(screen.queryByLabelText('draft')).toBeNull()
  })
})
