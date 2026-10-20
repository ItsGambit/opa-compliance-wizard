/** 5.46.0: the notify-only Updates screen and banner. */
import { fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fetchAuditLog, fetchUpgradeStatus, saveUpgradeSettings } from '../api/client'
import { renderWithClient } from '../test/renderWithClient'
import type { UpgradeStatus } from '../types'
import { AuditLogPage } from './AuditLogPage'
import { UpdateBanner } from './UpdateBanner'
import { describeCheckFailure } from '../utils/upgrade'
import { UpdatesDialog } from './UpdatesDialog'

vi.mock('../api/client', () => ({
  fetchUpgradeStatus: vi.fn(),
  saveUpgradeSettings: vi.fn(),
  fetchAuditLog: vi.fn(),
  backfillMfaLogEvents: vi.fn(),
}))
vi.mock('../hooks/useToast', () => ({ toast: vi.fn() }))

function status(over: Partial<UpgradeStatus> = {}): UpgradeStatus {
  return {
    installed_version: '5.46.0',
    check: { enabled: true, source: 'setting', env_locked: false, env_invalid_value: null, prompt_needed: false, share_version: false, mirror: false },
    latest: null,
    update_available: false,
    last_check: { at: '2026-10-20T12:00:00Z', status: 'ok', code: 'ok', next_at: '2026-10-21T12:00:00Z', consecutive_failures: 0, failing_since: null },
    signing_keys: { pinned: true, serial: 0, error: null },
    ...over,
  }
}
const newer = {
  latest: { version: '5.47.0', published_at: '2026-10-19T08:00:00Z', release_url: 'https://github.com/example/example/releases/tag/v5.47.0', signed_artifact: true },
  update_available: true,
}

beforeEach(() => { sessionStorage.clear(); vi.clearAllMocks() })

function open() {
  return renderWithClient(<UpdatesDialog open onOpenChange={() => {}} />)
}

describe('UpdatesDialog', () => {
  it('asks once, says exactly what is sent, and sends nothing until the admin agrees', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(status({
      check: { enabled: false, source: 'default_off', env_locked: false, env_invalid_value: null, prompt_needed: true, share_version: false, mirror: false },
    }))
    vi.mocked(saveUpgradeSettings).mockResolvedValue(status())
    open()
    await screen.findByText('Turn on the daily update check?')
    expect(screen.getByText(/nothing about your tenant, users or/i)).toBeTruthy()
    expect(saveUpgradeSettings).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Turn on' }))
    await waitFor(() => expect(saveUpgradeSettings).toHaveBeenCalledWith({ enabled: true }))
  })

  it('"Keep it off" answers the prompt without enabling anything', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(status({
      check: { enabled: false, source: 'default_off', env_locked: false, env_invalid_value: null, prompt_needed: true, share_version: false, mirror: false },
    }))
    vi.mocked(saveUpgradeSettings).mockResolvedValue(status())
    open()
    fireEvent.click(await screen.findByRole('button', { name: 'Keep it off' }))
    await waitFor(() => expect(saveUpgradeSettings).toHaveBeenCalledWith({ enabled: false }))
  })

  it('shows the install command, release notes link and signing note for a newer signed release', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(status(newer))
    open()
    await screen.findByText(/Version 5.47.0 is available/)
    expect(screen.getByText('server/deploy.sh --release 5.47.0')).toBeTruthy()
    const link = screen.getByRole('link', { name: 'Read the release notes' }) as HTMLAnchorElement
    expect(link.href).toContain('github.com')
    expect(link.rel).toContain('noopener')
    expect(screen.getByText(/never installs|does not install anything/i)).toBeTruthy()
  })

  it('refuses to suggest installing a release that has no signed download', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(status({ ...newer, latest: { ...newer.latest, signed_artifact: false } }))
    open()
    await screen.findByText(/no signed download attached/i)
    expect(screen.queryByText(/server\/deploy.sh --release/)).toBeNull()
  })

  it('reports failed checks in plain words, and no pinned key as a normal state', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(status({
      last_check: { at: '2026-10-20T12:00:00Z', status: 'error', code: 'network', next_at: null, consecutive_failures: 3, failing_since: '2026-10-19T12:00:00Z' },
      signing_keys: { pinned: false, serial: 0, error: null },
    }))
    open()
    await screen.findByText(/last 3 checks failed/i)
    expect(screen.getByText(/could not be reached/)).toBeTruthy()
    expect(screen.getByText(/No release signing key is pinned/)).toBeTruthy()
    expect(screen.getByText(/existing installs are unaffected/i)).toBeTruthy()
  })

  it('a check locked by the server environment cannot be changed here', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(status({
      check: { enabled: false, source: 'env_off', env_locked: true, env_invalid_value: null, prompt_needed: false, share_version: false, mirror: false },
    }))
    open()
    await screen.findByText(/set by this server's configuration/i)
    expect(screen.queryByRole('button', { name: /Turn/ })).toBeNull()
  })

  it('a damaged key list is shown as an error', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(status({ signing_keys: { pinned: false, serial: null, error: 'file is damaged' } }))
    open()
    expect((await screen.findByRole('alert')).textContent).toContain('file is damaged')
  })

  it('share-version is a separate, explicit switch', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(status())
    vi.mocked(saveUpgradeSettings).mockResolvedValue(status())
    open()
    fireEvent.click(await screen.findByRole('checkbox'))
    await waitFor(() => expect(saveUpgradeSettings).toHaveBeenCalledWith({ share_version: true }))
  })

  it('has a sentence for every failure code', () => {
    for (const code of ['network', 'timeout', 'truncated', 'redirect_refused', 'bad_url', 'http_429', 'http_500', null]) {
      expect(describeCheckFailure(code).length).toBeGreaterThan(10)
    }
  })
})

describe('UpdateBanner', () => {
  it('shows for admins when a newer release exists, and a dismissal lasts for that version only', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(status(newer))
    const { client } = renderWithClient(<UpdateBanner canAdmin onOpenUpdates={() => {}} />)
    await screen.findByText(/Version 5.47.0 is available/)
    fireEvent.click(screen.getByRole('button', { name: 'Dismiss update notice' }))
    expect(screen.queryByText(/Version 5.47.0 is available/)).toBeNull()
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(status({ ...newer, latest: { ...newer.latest, version: '5.48.0' } }))
    await client.refetchQueries({ queryKey: ['upgrade_status'] })
    expect(await screen.findByText(/Version 5.48.0 is available/)).toBeTruthy()
  })

  it('is absent for non-admins (no request is even made), when off, or when up to date', async () => {
    renderWithClient(<UpdateBanner canAdmin={false} onOpenUpdates={() => {}} />)
    expect(fetchUpgradeStatus).not.toHaveBeenCalled()
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(status({ ...newer, check: { ...status().check, enabled: false } }))
    const off = renderWithClient(<UpdateBanner canAdmin onOpenUpdates={() => {}} />)
    await waitFor(() => expect(fetchUpgradeStatus).toHaveBeenCalled())
    expect(off.container.textContent).toBe('')
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(status())
    const same = renderWithClient(<UpdateBanner canAdmin onOpenUpdates={() => {}} />)
    await waitFor(() => expect(fetchUpgradeStatus).toHaveBeenCalledTimes(2))
    expect(same.container.textContent).toBe('')
  })
})

describe('Audit log', () => {
  it('shows update-check events as server events and a failed check or refusal in the failure style', async () => {
    vi.mocked(fetchAuditLog).mockResolvedValue({
      entries: [
        { timestamp: '2026-10-20T12:00:00Z', action: 'upgrade.check', actor_email: null, actor_sub: null, details: { result: 'failed', reason: 'network' } },
        { timestamp: '2026-10-20T11:00:00Z', action: 'upgrade.settings', actor_email: 'cli:operator', actor_sub: null, details: { via: 'cli' } },
      ],
    } as never)
    const { container } = renderWithClient(<AuditLogPage />)
    await screen.findByText('upgrade.check')
    expect(screen.getByText('server (updates)')).toBeTruthy()
    expect(container.querySelector('.border-l-loss')).toBeTruthy()
    expect(screen.getByText('cli:operator')).toBeTruthy()
  })
})
