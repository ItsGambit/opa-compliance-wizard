/** A background refetch of the banner must not wipe an edit in progress. */
import { act, fireEvent, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { fetchBanner } from '../api/client'
import { renderWithClient } from '../test/renderWithClient'
import { BannerSettingsDialog } from './BannerSettingsDialog'

vi.mock('../api/client', () => ({ fetchBanner: vi.fn(), saveBanner: vi.fn() }))

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
