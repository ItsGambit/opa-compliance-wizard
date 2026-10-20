/** 5.48.0, artboard 11: upgrade events in the audit log, and the support-bundle download on the failed one. */
import { screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fetchAuditLog } from '../api/client'
import { renderWithClient } from '../test/renderWithClient'
import type { AuditLogEntry } from '../types'
import { AuditLogPage } from './AuditLogPage'

vi.mock('../api/client', async importOriginal => ({
  ...(await importOriginal<typeof import('../api/client')>()), fetchAuditLog: vi.fn(), backfillMfaLogEvents: vi.fn(),
}))

const NAME = 'ocw-support-5.46.0-to-5.48.0-20261021T023158Z-k4q9.tar.gz'
const E = (action: string, details: Record<string, unknown>, actor: string | null = null, ts = '2026-10-21T02:31:00Z'): AuditLogEntry =>
  ({ timestamp: ts, action, actor_email: actor, actor_sub: null, details, client_ip: null, user_agent: null } as AuditLogEntry)

beforeEach(() => vi.clearAllMocks())

describe('upgrade events', () => {
  it('a failed upgrade offers the bundle as a download; other rows do not', async () => {
    vi.mocked(fetchAuditLog).mockResolvedValue({ entries: [
      E('upgrade.failed', { trigger: 'ocw-updater', correlation_id: 'upg-7f3a9c2e', reason_code: 'health_healthz', bundle: { name: NAME, size: 1_800_000, sha256: 'ab' } }),
      E('upgrade.rolled_back', { trigger: 'ocw-updater', correlation_id: 'upg-7f3a9c2e', bundle: null }),
      E('upgrade.requested', { correlation_id: 'upg-7f3a9c2e', step_up_verified: true }, 'admin@example.com'),
    ] })
    renderWithClient(<AuditLogPage />)
    await screen.findByText('upgrade.failed')
    const links = screen.getAllByRole('link', { name: /Download support bundle/ }) as HTMLAnchorElement[]
    expect(links).toHaveLength(1)
    expect(links[0].getAttribute('href')).toBe(`/api/upgrade/bundle?name=${NAME}`)
    expect(links[0].textContent).toContain('1.7 MB')
    expect(screen.getByText(/Redacted · e-mails, subjects, hosts, env names, secrets/)).toBeTruthy()
    expect(screen.getByText(/Nothing is sent automatically/)).toBeTruthy()
    expect(screen.getAllByText('ocw-updater (server)')).toHaveLength(2)
    expect(screen.getAllByText('admin@example.com').length).toBeGreaterThan(0)
  })

  it('a bundle name that is not a bundle file name gets no link', async () => {
    vi.mocked(fetchAuditLog).mockResolvedValue({ entries: [E('upgrade.failed', { trigger: 'ocw-updater', bundle: { name: '../../etc/passwd', size: 1 } })] })
    renderWithClient(<AuditLogPage />)
    await screen.findByText('upgrade.failed')
    expect(screen.queryByRole('link', { name: /Download support bundle/ })).toBeNull()
  })

  it('the scheduler\'s own rows are labelled as the scheduler', async () => {
    vi.mocked(fetchAuditLog).mockResolvedValue({ entries: [E('upgrade.missed', { correlation_id: 'upg-1', reason_code: 'app_not_running' })] })
    renderWithClient(<AuditLogPage />)
    await screen.findByText('upgrade.missed')
    expect(screen.getByText('scheduler (server)')).toBeTruthy()
  })
})
