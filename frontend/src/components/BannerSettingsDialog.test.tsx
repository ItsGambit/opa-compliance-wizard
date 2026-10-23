/** A background refetch of the banner must not wipe an edit in progress. */
import { act, fireEvent, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { fetchBanner, saveBanner } from '../api/client'
import { beginStepUp } from '../utils/stepUp'
import { renderWithClient } from '../test/renderWithClient'
import { BannerSettingsDialog } from './BannerSettingsDialog'

vi.mock('../api/client', () => ({ fetchBanner: vi.fn(), saveBanner: vi.fn(), isStepUpRequired: (v: unknown) => typeof v === 'object' && v !== null && (v as { step_up_required?: boolean }).step_up_required === true }))
vi.mock('../utils/stepUp', () => ({ beginStepUp: vi.fn() }))

describe('BannerSettingsDialog', () => {
  it('seeds once per opening, not on every refetch', async () => {
    vi.mocked(fetchBanner).mockResolvedValue({ enabled: true, message: 'server text', variant: 'info', dismissible: true })
    const { client } = renderWithClient(<BannerSettingsDialog open onOpenChange={() => {}} />)
    const box = (await screen.findByDisplayValue('server text')) as HTMLTextAreaElement
    fireEvent.change(box, { target: { value: 'my draft' } })
    vi.mocked(fetchBanner).mockResolvedValue({ enabled: true, message: 'someone else', variant: 'info', dismissible: true })
    await act(async () => { await client.refetchQueries({ queryKey: ['banner'] }) })
    await new Promise(r => setTimeout(r, 10))
    expect((screen.getByLabelText('Message') as HTMLTextAreaElement).value).toBe('my draft')
  })
})

describe('BannerSettingsDialog -- step-up MFA (5.53.0)', () => {
  it('a hosted save goes to MFA first, carrying the typed banner so a cancelled approval loses nothing', async () => {
    vi.mocked(fetchBanner).mockResolvedValue({ enabled: false, message: '', variant: 'warning', dismissible: true })
    vi.mocked(saveBanner).mockResolvedValue({ step_up_required: true, action_id: 'act-b', action: 'banner.update' })
    renderWithClient(<BannerSettingsDialog open onOpenChange={() => {}} />)
    await screen.findByLabelText('Show banner')
    await new Promise(r => setTimeout(r, 20))      // the stored banner seeds the form once it has loaded
    fireEvent.click(screen.getByLabelText('Show banner'))
    fireEvent.change(screen.getByLabelText('Message'), { target: { value: 'Planned work tonight' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await vi.waitFor(() => expect(beginStepUp).toHaveBeenCalled())
    const [actionId, pending] = vi.mocked(beginStepUp).mock.calls[0]
    expect(actionId).toBe('act-b')
    expect(pending).toMatchObject({
      kind: 'environment_change', action: 'banner.update', reopen: 'banner',
      bannerDraft: { enabled: true, message: 'Planned work tonight', variant: 'warning', dismissible: true },
    })
  })

  it('reopens with the draft of an approval that did not complete, not the stored banner', async () => {
    vi.mocked(fetchBanner).mockResolvedValue({ enabled: false, message: 'stored', variant: 'info', dismissible: true })
    renderWithClient(<BannerSettingsDialog open onOpenChange={() => {}} draft={{ enabled: true, message: 'typed before MFA', variant: 'danger', dismissible: false }} />)
    expect(await screen.findByDisplayValue('typed before MFA')).toBeTruthy()
  })
})
