/** UI-11: dismissing one announcement hides only that one. */
import { act, fireEvent, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fetchBanner } from '../api/client'
import { renderWithClient } from '../test/renderWithClient'
import type { BannerConfig } from '../types'
import { AnnouncementBanner } from './AnnouncementBanner'

vi.mock('../api/client', () => ({ fetchBanner: vi.fn() }))

beforeEach(() => { sessionStorage.clear(); vi.clearAllMocks() })

async function setup(banner: BannerConfig) {
  vi.mocked(fetchBanner).mockResolvedValue(banner)
  const r = renderWithClient(<AnnouncementBanner />)
  await screen.findByText(banner.message)
  return r.client
}

async function publish(client: ReturnType<typeof renderWithClient>['client'], banner: BannerConfig) {
  vi.mocked(fetchBanner).mockResolvedValue(banner)
  await act(async () => { await client.refetchQueries({ queryKey: ['banner'] }) })
}

describe('AnnouncementBanner', () => {
  it('a new message shows after the previous one was dismissed', async () => {
    const client = await setup({ enabled: true, message: 'Maintenance tonight', variant: 'info', dismissible: true })
    fireEvent.click(screen.getByRole('button', { name: 'Dismiss announcement' }))
    expect(screen.queryByText('Maintenance tonight')).toBeNull()
    await publish(client, { enabled: true, message: 'Incident in progress', variant: 'danger', dismissible: true })
    expect(await screen.findByText('Incident in progress')).toBeTruthy()
  })

  it('a non-dismissible message always shows, even after a dismissal', async () => {
    const client = await setup({ enabled: true, message: 'A', variant: 'info', dismissible: true })
    fireEvent.click(screen.getByRole('button', { name: 'Dismiss announcement' }))
    await publish(client, { enabled: true, message: 'A', variant: 'warning', dismissible: false })
    expect(await screen.findByText('A')).toBeTruthy()
  })

  it('the dismissed message stays dismissed when refetched unchanged', async () => {
    const client = await setup({ enabled: true, message: 'A', variant: 'info', dismissible: true })
    fireEvent.click(screen.getByRole('button', { name: 'Dismiss announcement' }))
    await publish(client, { enabled: true, message: 'A', variant: 'info', dismissible: true })
    await new Promise(r => setTimeout(r, 20))
    expect(screen.queryByText('A')).toBeNull()
  })
})
