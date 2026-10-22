/** 5.46.0: the Updates page (artboards 01-03), the Keys page (12), the banners, the nav count and the brand surfaces. */
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { checkUpgradeNow, fetchAuditLog, fetchUpgradeNotice, fetchUpgradeStatus, fetchVersion, fetchWhoami, saveUpgradeSettings } from '../api/client'
import { renderWithClient } from '../test/renderWithClient'
import { makeStatus, makeUpgrade, NEWER, RELEASE_KEY, STANDBY_KEY } from '../test/upgradeFixtures'
import type { AuditLogEntry } from '../types'
import { beginStepUp } from '../utils/stepUp'
import { describeCheckFailure, formatBytes, updateState } from '../utils/upgrade'
import { AboutDialog } from './AboutDialog'
import { AuditLogPage } from './AuditLogPage'
import { Brand, BrandMark } from './Brand'
import { SideNav } from './SideNav'
import { UpgradeNoticeBanner } from './UpgradeNoticeBanner'
import { describeKeyEvent, UpdateKeysPage } from './UpdateKeysPage'
import { UpdatesPage } from './UpdatesPage'

vi.mock('../api/client', async importOriginal => ({
  ...(await importOriginal<typeof import('../api/client')>()),
  fetchUpgradeStatus: vi.fn(), saveUpgradeSettings: vi.fn(), checkUpgradeNow: vi.fn(), fetchAuditLog: vi.fn(), backfillMfaLogEvents: vi.fn(),
  fetchWhoami: vi.fn(), fetchVersion: vi.fn(), reviewUpgrade: vi.fn(), requestUpgrade: vi.fn(), fetchUpgradeNotice: vi.fn(), isStepUpRequired: (v: unknown) => typeof v === 'object' && v !== null && (v as { step_up_required?: boolean }).step_up_required === true,
}))
vi.mock('../hooks/useToast', () => ({ toast: vi.fn() }))
vi.mock('../utils/stepUp', () => ({ beginStepUp: vi.fn() }))

beforeAll(() => {
  window.matchMedia = ((query: string) => ({
    matches: true, media: query, onchange: null, addEventListener: () => {}, removeEventListener: () => {},
    addListener: () => {}, removeListener: () => {}, dispatchEvent: () => false,
  })) as unknown as typeof window.matchMedia
})

beforeEach(() => {
  sessionStorage.clear()
  vi.clearAllMocks()
  vi.mocked(fetchWhoami).mockResolvedValue({ email: 'admin@example.com', is_local: false, is_admin: true, can_admin: true })
  vi.mocked(fetchVersion).mockResolvedValue({ version: '5.46.0' })
})

const FIRST_RUN = makeStatus({
  check: { ...makeStatus().check, enabled: false, source: 'default_off', prompt_needed: true, frequency: null },
  last_check: { ...makeStatus().last_check, at: null, status: null, code: null, next_at: null },
})

describe('Updates page', () => {
  it('01 up to date: status, check settings and the keys summary', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(makeStatus({ latest: { ...NEWER.latest, version: '5.46.0' } }))
    renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    expect(await screen.findByText('Up to date')).toBeTruthy()
    expect(screen.getByText('Installed version')).toBeTruthy()
    expect(screen.getByText('Update check')).toBeTruthy()
    expect(screen.getByText('Release signing keys')).toBeTruthy()
    expect(screen.getByText('Not shared (off)')).toBeTruthy()
    expect(screen.getByRole('button', { name: /Check now/ })).toBeTruthy()
    expect(screen.queryByText('Enable the update check?')).toBeNull()
  })

  it('02 first run: says what is sent and never sent, offers Daily/Manual/Off, sends nothing until saved', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(FIRST_RUN)
    vi.mocked(saveUpgradeSettings).mockResolvedValue(makeStatus())
    renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    await screen.findByText('Enable the update check?')
    expect(screen.getByText('What the check sends')).toBeTruthy()
    expect(screen.getByText('What it never sends')).toBeTruthy()
    expect(screen.getByText(/Your tenant, environment names, users/)).toBeTruthy()
    const [daily, manual, off] = screen.getAllByRole('radio') as HTMLInputElement[]
    expect([daily.checked, manual.checked, off.checked]).toEqual([true, false, false])
    expect((screen.getByRole('checkbox') as HTMLInputElement).checked).toBe(false)   // share-version is off by default
    expect(screen.queryByRole('button', { name: /Check now/ })).toBeNull()           // nothing to check yet
    expect(screen.queryByText('Release signing keys')).toBeNull()                    // as drawn
    expect(saveUpgradeSettings).not.toHaveBeenCalled()
    fireEvent.click(manual)
    fireEvent.click(screen.getByRole('button', { name: /Save with MFA/ }))
    await waitFor(() => expect(saveUpgradeSettings).toHaveBeenCalledWith({ frequency: 'manual', share_version: false }))
  })

  it('02 hosted save hands the approval to the step-up flow and returns to the Updates page', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(FIRST_RUN)
    vi.mocked(saveUpgradeSettings).mockResolvedValue({ step_up_required: true, action_id: 'a'.repeat(20), action: 'upgrade.settings' })
    renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    fireEvent.click(await screen.findByRole('button', { name: /Save with MFA/ }))
    await waitFor(() => expect(beginStepUp).toHaveBeenCalled())
    const [id, pending] = vi.mocked(beginStepUp).mock.calls[0]
    expect(id).toBe('a'.repeat(20))
    expect(pending).toMatchObject({ kind: 'environment_change', action: 'upgrade.settings', reopen: 'updates' })
  })

  it('02 local mode has no MFA: the button says Save', async () => {
    vi.mocked(fetchWhoami).mockResolvedValue({ email: null, is_local: true, is_admin: false, can_admin: true })
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(FIRST_RUN)
    renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    expect(await screen.findByRole('button', { name: 'Save' })).toBeTruthy()
    expect(screen.queryByRole('button', { name: /MFA/ })).toBeNull()
  })

  it('02 Not now keeps it off and shows a one-line reminder instead', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(FIRST_RUN)
    renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    fireEvent.click(await screen.findByRole('button', { name: 'Not now' }))
    expect(screen.getByText(/stays off until you choose/)).toBeTruthy()
    expect(saveUpgradeSettings).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: /Enable the update check/ }))
    expect(screen.getByText('Enable the update check?')).toBeTruthy()
  })

  it('03 update available, updater not installed: version, signed badge, key, size, notes, install command; Upgrade/Schedule are disabled', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(makeStatus({ ...NEWER, upgrade: makeUpgrade({ updater: { ready: false, reason: 'updater_not_installed', activator: null, message: 'This server does not use the privileged updater (no upgrade inbox). Run server/install.sh once.' } }) }))
    renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    expect(await screen.findByText('5.48.0 is available')).toBeTruthy()
    // Mockup 03 (owner, 2026-10-20): the available card replaces the installed-version card.
    expect(screen.queryByText('Installed version')).toBeNull()
    expect(screen.getByText('Signed download attached')).toBeTruthy()
    expect(screen.getAllByText(RELEASE_KEY.key_id).length).toBeGreaterThan(0)
    expect(screen.getByText(/14\.8 MB/)).toBeTruthy()
    expect(screen.getByText('server/deploy.sh --release 5.48.0')).toBeTruthy()
    expect(screen.getByText('5.48.0 — Example release')).toBeTruthy()
    expect((screen.getByRole('button', { name: /Upgrade now/ }) as HTMLButtonElement).disabled).toBe(true)
    expect((screen.getByRole('button', { name: /Schedule/ }) as HTMLButtonElement).disabled).toBe(true)
    expect(screen.getByText(/does not use the privileged updater/)).toBeTruthy()
    const link = screen.getByRole('link', { name: 'release notes' }) as HTMLAnchorElement
    expect(link.rel).toContain('noopener')
  })

  it('03 an unsigned release is never offered for install', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(makeStatus({ ...NEWER, latest: { ...NEWER.latest, signed_artifact: false } }))
    renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    await screen.findByText('No signed download')
    expect(screen.queryByText(/deploy.sh --release/)).toBeNull()
    expect(screen.getByText(/has no signed download attached/)).toBeTruthy()
  })

  it('failed checks are explained in plain words; an env-locked check cannot be changed here', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(makeStatus({
      last_check: { ...makeStatus().last_check, status: 'error', code: 'network', consecutive_failures: 3, failing_since: '2026-10-18T09:00:00Z' },
      check: { ...makeStatus().check, env_locked: true, source: 'env_on' },
    }))
    renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    await screen.findByText('Last check failed')
    expect(screen.getByText(/last 3 checks failed/)).toBeTruthy()
    expect(screen.getByText(/could not be reached/, { selector: 'p' })).toBeTruthy()
    expect(screen.getByText(/Set by this server's configuration/)).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Change…' })).toBeNull()
  })

  it('Change… opens the same form, and Check now runs one check', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(makeStatus())
    vi.mocked(checkUpgradeNow).mockResolvedValue(makeStatus())
    renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    fireEvent.click(await screen.findByRole('button', { name: 'Change…' }))
    expect(screen.getAllByRole('radio')).toHaveLength(3)
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    fireEvent.click(screen.getByRole('button', { name: /Check now/ }))
    await waitFor(() => expect(checkUpgradeNow).toHaveBeenCalled())
  })

  it('no pinned key and a damaged key list are shown, not hidden', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(makeStatus({ signing_keys: { pinned: false, serial: 0, error: null, keys: [] } }))
    const { unmount } = renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    expect(await screen.findByText(/No release signing key is pinned/)).toBeTruthy()
    unmount()
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(makeStatus({ signing_keys: { pinned: false, serial: null, error: 'file is damaged', keys: [] } }))
    renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    expect((await screen.findByRole('alert')).textContent).toContain('file is damaged')
  })
})

const REVOKED = makeStatus({
  signing_keys: {
    pinned: true, serial: 1, error: null,
    keys: [
      { ...RELEASE_KEY, key_id: '9A1F57C0B3E8D4C2' }, STANDBY_KEY,
      { ...RELEASE_KEY, status: 'revoked', revoked_at: '2026-10-19T09:00:00Z' },
    ],
  },
  revocation: {
    serial: 1, issued_at: '2026-10-19T09:00:00Z', applied_at: '2026-10-19T09:00:00Z', reason: 'key compromise suspected',
    advisory_url: 'https://example.com/advisory', revoked: [RELEASE_KEY.key_id], added: ['9A1F57C0B3E8D4C2'], signed_by: STANDBY_KEY.key_id, source: 'release_assets',
  },
})

describe('Keys page (artboard 12)', () => {
  it('shows the revocation card, the key table (revoked key struck through) and the key history', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(REVOKED)
    vi.mocked(fetchAuditLog).mockResolvedValue({ entries: [
      { timestamp: '2026-10-19T09:00:00Z', actor_email: null, actor_sub: null, action: 'upgrade.key_revoked',
        details: { revoked: [RELEASE_KEY.key_id], reason: 'key compromise suspected', signed_by: STANDBY_KEY.key_id } },
      { timestamp: '2026-10-18T09:00:00Z', actor_email: null, actor_sub: null, action: 'upgrade.check', details: {} },
    ] as AuditLogEntry[] })
    renderWithClient(<UpdateKeysPage onBack={() => {}} />)
    expect(await screen.findByText('Revocation applied')).toBeTruthy()
    expect(screen.getByText('A signing key was revoked')).toBeTruthy()
    expect(screen.getByText(/What this means for you/i)).toBeTruthy()
    expect(screen.getByRole('link', { name: 'https://example.com/advisory' })).toBeTruthy()
    const rows = screen.getAllByRole('row')
    expect(rows[1].textContent).toContain('9A1F57C0B3E8D4C2')        // active primary first, standby second, revoked last
    expect(rows[3].textContent).toContain('Revoked')
    expect(rows[3].textContent).toContain('refused forever')
    await waitFor(() => expect(screen.getAllByText('upgrade.key_revoked').length).toBe(2))   // the card's audit line and the history row
    expect(screen.queryByText('upgrade.check')).toBeNull()           // only key events in the key history
  })

  it('without a revocation there is no red card', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(makeStatus())
    vi.mocked(fetchAuditLog).mockResolvedValue({ entries: [] })
    renderWithClient(<UpdateKeysPage onBack={() => {}} />)
    await screen.findByText('Pinned keys')
    expect(screen.queryByText('Revocation applied')).toBeNull()
    expect(screen.getByText(/No key changes have been recorded/)).toBeTruthy()
  })

  it('describes every key event in words', () => {
    const e = (action: string, details: Record<string, unknown>) => ({ timestamp: '', actor_email: null, actor_sub: null, action, details }) as AuditLogEntry
    expect(describeKeyEvent(e('upgrade.key_added', { added: ['AA'], signed_by: 'BB' }))).toContain('added')
    expect(describeKeyEvent(e('upgrade.key_list_installed', { version: '5.47.0', signed_by: 'BB' }))).toContain('5.47.0')
    expect(describeKeyEvent(e('upgrade.key_revocation_rejected', { reason: 'bad_signature' }))).toContain('rejected')
  })
})

describe('The one banner (artboards 03, 07, 08a, 10 and 12)', () => {
  it('available for admins, dismissible; a revocation (red) takes the place of it and stays; one banner at a time', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue({ ...makeStatus({ ...NEWER }), revocation: REVOKED.revocation })
    vi.mocked(fetchUpgradeNotice).mockResolvedValue({ kind: 'available', version: '5.48.0' })
    const open = vi.fn()
    renderWithClient(<UpgradeNoticeBanner canAdmin onOpenUpdates={open} />)
    expect((await screen.findByRole('alert')).textContent).toContain('revoked')
    expect(screen.queryByText(/is available/)).toBeNull()                       // never two
    fireEvent.click(screen.getByRole('button', { name: 'Review on the Updates page' }))
    expect(open).toHaveBeenCalled()
  })

  it('available, in the mockup words, when there is no revocation; dismissed for the session', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(makeStatus({ ...NEWER }))
    vi.mocked(fetchUpgradeNotice).mockResolvedValue({ kind: 'available', version: '5.48.0' })
    renderWithClient(<UpgradeNoticeBanner canAdmin onOpenUpdates={() => {}} />)
    expect(await screen.findByText('Version 5.48.0 of OPA Compliance Wizard is available. Admins can review and upgrade from the Updates page.')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Dismiss announcement' }))
    expect(screen.queryByText(/is available/)).toBeNull()
  })

  it('a running or failed upgrade beats a revocation notice', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue({ ...makeStatus({ ...NEWER }), revocation: REVOKED.revocation })
    vi.mocked(fetchUpgradeNotice).mockResolvedValue({ kind: 'running', version: '5.48.0', started_at: '2026-10-21T02:30:00Z' })
    renderWithClient(<UpgradeNoticeBanner canAdmin onOpenUpdates={() => {}} />)
    expect(await screen.findByText(/Upgrade to 5.48.0 in progress/)).toBeTruthy()
    expect(screen.queryByText(/revoked/)).toBeNull()
  })

  it('no status request for non-admins, and nothing when there is nothing to say', async () => {
    vi.mocked(fetchUpgradeNotice).mockResolvedValue({ kind: 'none' })
    const r = renderWithClient(<UpgradeNoticeBanner canAdmin={false} />)
    await waitFor(() => expect(fetchUpgradeNotice).toHaveBeenCalled())
    expect(fetchUpgradeStatus).not.toHaveBeenCalled()
    expect(r.container.textContent).toBe('')
  })
})

describe('Navigation and brand', () => {
  function nav(extra: { updateCount?: number; canAdmin?: boolean } = {}) {
    const noop = () => {}
    return render(
      <SideNav activeTab="updates" onTabChange={noop} accessSubTabs={[]} accessSubTab="" onAccessSubTabChange={noop}
        reportsSubTab="browse" onReportsSubTabChange={noop} onOpenEnvironments={noop} onOpenBanner={noop}
        onOpenAccessControl={noop} onOpenAbout={noop} canAdmin {...extra} />,
    )
  }

  it('Updates is a top-level admin item with a count badge; no badge at zero; hidden for non-admins', () => {
    const { unmount } = nav({ updateCount: 1 })
    expect(screen.getAllByText('Updates').length).toBeGreaterThan(0)
    expect(screen.getByLabelText('1 available').textContent).toBe('1')
    unmount()
    const again = nav({ updateCount: 0 })
    expect(screen.queryByLabelText('1 available')).toBeNull()
    again.unmount()
    nav({ canAdmin: false })
    expect(screen.queryAllByText('Updates')).toHaveLength(0)
  })

  it('the sidebar brand row is the mark and the wordmark only; the lockup carries the tagline', () => {
    nav()
    expect(screen.getByText('OPA Compliance Wizard')).toBeTruthy()
    expect(screen.queryByText('Evidence for OPA audits')).toBeNull()
    expect(screen.getByRole('img', { name: /mark/i })).toBeTruthy()
    render(<Brand variant="lockup" tagline="Evidence for OPA audits" mark={<BrandMark size={10} />} />)
    expect(screen.getByText('Evidence for OPA audits')).toBeTruthy()
  })

  it('About has the lockup with the tagline, the product sentence and the affiliation line, and no secrets-folder framing', () => {
    render(<AboutDialog open onOpenChange={() => {}} />)
    expect(screen.getByText('Evidence for OPA audits')).toBeTruthy()
    expect(screen.getByText(/produces audit evidence for Okta Privileged Access \(OPA\) tenants/)).toBeTruthy()
    expect(screen.getByText(/Not affiliated with or endorsed by Okta, Inc\. Okta and Okta Privileged Access are trademarks of Okta, Inc\./)).toBeTruthy()
    expect(screen.queryByText(/secret folders/i)).toBeNull()
    expect(screen.queryByText(/other users of this computer may read/)).toBeNull()  // no notice unless the server sends one
  })

  it('About shows the one-line notice when the Windows data folder is readable by other users of the computer', () => {
    render(<AboutDialog open onOpenChange={() => {}} dataLocationNotice="The archive is in a location other users of this computer may read: C:\\ProgramData\\opa. Move it with OPA_DATA_DIR." />)
    expect(screen.getByRole('status').textContent).toMatch(/other users of this computer may read: .*Move it with OPA_DATA_DIR/)
  })
})

describe('Audit log rows for update events (artboard 11)', () => {
  it('system events get the accent border and no empty IP/agent rows; failures are red; human rows are plain', async () => {
    vi.mocked(fetchAuditLog).mockResolvedValue({ entries: [
      { timestamp: '2026-10-20T12:00:00Z', actor_email: null, actor_sub: null, action: 'upgrade.check', details: { outcome: 'failed', result: 'failed: network', correlation_id: 'upd-1' } },
      { timestamp: '2026-10-20T11:00:00Z', actor_email: null, actor_sub: null, action: 'upgrade.key_revoked', details: { revoked: ['AA'], correlation_id: 'upd-2' } },
      { timestamp: '2026-10-20T10:00:00Z', actor_email: 'admin@example.com', actor_sub: 's', action: 'upgrade.settings', details: { frequency: 'daily' }, client_ip: '203.0.113.9' },
    ] as AuditLogEntry[] })
    const { container } = renderWithClient(<AuditLogPage />)
    await screen.findByText('upgrade.key_revoked')
    expect(container.querySelectorAll('.border-l-loss')).toHaveLength(1)
    expect(container.querySelectorAll('.border-l-accent')).toHaveLength(1)
    expect(screen.getByText('scheduler (server)')).toBeTruthy()
    expect(screen.getByText('update check (server)')).toBeTruthy()
    expect(screen.getAllByText('Client IP')).toHaveLength(1)           // only the human row shows it
    expect(screen.getByText('203.0.113.9')).toBeTruthy()
  })
})

describe('Updates page: a stored latest release older than the installed one (5.52.0)', () => {
  const OLD = { ...NEWER.latest, version: '5.45.0' }

  it('says the check predates the installed version and offers Check now', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(makeStatus({
      installed_version: '5.46.0', installed_at: '2026-10-20T03:00:00Z', latest: OLD, update_available: false,
      last_check: { ...makeStatus().last_check, at: '2026-10-19T09:00:00Z' },
    }))
    renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    expect(await screen.findByText('Not checked since upgrade')).toBeTruthy()
    expect(screen.getByText(/Not checked since this version was installed/)).toBeTruthy()
    expect(screen.queryByText('Up to date')).toBeNull()
    expect(screen.queryByText(/no newer release/)).toBeNull()
    expect(screen.getByRole('button', { name: /Check now/ })).toBeTruthy()
  })

  it('after a check made once this version was installed, says up to date as of that check and what it saw', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(makeStatus({
      installed_version: '5.46.0', installed_at: '2026-10-18T03:00:00Z', latest: OLD, update_available: false,
      last_check: { ...makeStatus().last_check, at: '2026-10-19T09:00:00Z' },
    }))
    renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    expect(await screen.findByText('Up to date')).toBeTruthy()
    expect(screen.getByText(/Up to date as of the last check \(.*\); the last check saw 5\.45\.0\./)).toBeTruthy()
    expect(screen.queryByText(/Not checked since this version was installed/)).toBeNull()
  })

  it('leaves an equal or newer stored latest alone', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(makeStatus({ latest: { ...NEWER.latest, version: '5.46.0' } }))
    renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    expect(await screen.findByText('Up to date')).toBeTruthy()
    expect(screen.getByText(/no newer release/)).toBeTruthy()
  })
})

describe('helpers', () => {
  it('maps status to the badge state, sizes and failure codes', () => {
    expect(updateState(FIRST_RUN)).toBe('not_enabled')
    expect(updateState(makeStatus({ check: { ...makeStatus().check, enabled: false, frequency: 'off' } }))).toBe('off')
    expect(updateState(makeStatus({ ...NEWER }))).toBe('update_available')
    expect(updateState(makeStatus())).toBe('up_to_date')
    expect(updateState(makeStatus({ installed_version: '5.46.0', installed_at: '2026-10-20T03:00:00Z', latest: { ...NEWER.latest, version: '5.45.0' } }))).toBe('stale')
    expect(updateState(makeStatus({ installed_version: '5.46.0', installed_at: '2026-10-18T03:00:00Z', latest: { ...NEWER.latest, version: '5.45.0' } }))).toBe('up_to_date')
    expect(updateState(makeStatus({ last_check: { ...makeStatus().last_check, at: null } }))).toBe('waiting')
    expect(formatBytes(15_500_000)).toBe('14.8 MB')
    expect(formatBytes(null)).toBe('')
    for (const code of ['network', 'timeout', 'truncated', 'redirect_refused', 'bad_url', 'http_429', 'http_500', null]) {
      expect(describeCheckFailure(code).length).toBeGreaterThan(10)
    }
  })
})
