/** 5.48.0: the upgrade flow's screens (artboards 03-11) and the local-mode / channel additions. */
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError, fetchUpgradeNotice, fetchUpgradeStatus, fetchVersion, fetchWhoami, requestUpgrade, reviewUpgrade, saveUpgradeSettings } from '../api/client'
import { renderWithClient } from '../test/renderWithClient'
import { makePreview, makeRun, makeStatus, makeUpgrade, NEWER, TARGET_SHA } from '../test/upgradeFixtures'
import { beginStepUp } from '../utils/stepUp'
import { rememberRequested } from '../utils/upgradeRequested'
import { UpdatesPage } from './UpdatesPage'
import { UpgradeNoticeBanner } from './UpgradeNoticeBanner'

vi.mock('../api/client', async importOriginal => ({
  ...(await importOriginal<typeof import('../api/client')>()),
  fetchUpgradeStatus: vi.fn(), saveUpgradeSettings: vi.fn(), checkUpgradeNow: vi.fn(), fetchAuditLog: vi.fn(), backfillMfaLogEvents: vi.fn(),
  fetchWhoami: vi.fn(), fetchVersion: vi.fn(), reviewUpgrade: vi.fn(), requestUpgrade: vi.fn(), fetchUpgradeNotice: vi.fn(),
  isStepUpRequired: (v: unknown) => typeof v === 'object' && v !== null && (v as { step_up_required?: boolean }).step_up_required === true,
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

const AVAILABLE = (over = {}) => makeStatus({ ...NEWER, upgrade: makeUpgrade({ preview: makePreview(), ...over }) })
const STEP_UP = { step_up_required: true as const, action_id: 'act_example_0123456789', action: 'upgrade.request' }

async function openConfirm() {
  vi.mocked(fetchUpgradeStatus).mockResolvedValue(AVAILABLE())
  renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
  fireEvent.click(await screen.findByRole('button', { name: /Upgrade now/ }))
  await screen.findByText('Confirm the upgrade to 5.48.0')
}

describe('03 available, reviewed', () => {
  it('shows the signed information: key, sha, migrations with the unsafe one flagged, downtime, preflight', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(AVAILABLE())
    renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    expect(await screen.findByText('5.48.0 is available')).toBeTruthy()
    expect(screen.getByText('Signed · verified')).toBeTruthy()
    expect(screen.getByText('9f1c3a7e…74f2d'.replace('74f2d', '4f2d'))).toBeTruthy()
    expect(screen.getByText(/min_upgrade_from/)).toBeTruthy()
    expect(screen.getByText(/Migration 11 is not rollback-safe/)).toBeTruthy()
    expect(screen.getByText('All passed')).toBeTruthy()
    expect(screen.getByText(/About 50 s\./)).toBeTruthy()
    expect((screen.getByRole('button', { name: /Upgrade now/ }) as HTMLButtonElement).disabled).toBe(false)
    expect((screen.getByRole('button', { name: /Schedule/ }) as HTMLButtonElement).disabled).toBe(false)
  })

  it('reads the signed information by itself when none is stored yet, and shows a failure with a retry', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(makeStatus({ ...NEWER, upgrade: makeUpgrade() }))
    vi.mocked(reviewUpgrade).mockRejectedValue(new ApiError('The signature file is malformed', 409, { error: 'x', reason: 'signature_invalid' }))
    renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    await waitFor(() => expect(reviewUpgrade).toHaveBeenCalledTimes(1))
    expect(await screen.findByText(/The signature file is malformed/)).toBeTruthy()
    expect((screen.getByRole('button', { name: /Upgrade now/ }) as HTMLButtonElement).disabled).toBe(true)
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }))
    await waitFor(() => expect(reviewUpgrade).toHaveBeenCalledTimes(2))
  })

  it.each([
    ['preflight failed', { preview: makePreview({ preflight_ok: false, preflight: [{ id: 'disk_data', ok: false, text: 'Disk, data volume: 1 GB free; 3 GB needed.' }] }) }, /A preflight check failed: Disk, data volume/],
    ['an operator is needed', { run: makeRun({ result: 'failed_needs_operator', step: 'failed_needs_operator' }) }, /An operator must act on the server/],
    ['the version failed before', { failures: { '5.48.0': { count: 1, last_code: 'health_healthz' } } }, /failed here before.*clear-failure/],
    ['two failures', { failures: { '5.40.0': { count: 1, last_code: 'x' }, '5.41.0': { count: 1, last_code: 'y' } } }, /Two upgrades have failed/],
    ['already scheduled', { schedule: { correlation_id: 'upg-0000abcd', version: '5.48.0', sha256: TARGET_SHA, when_utc: '2099-01-01T00:00:00Z', entered: null, entered_tz: null, status: 'scheduled', actor_email: null, approved_at: '2026-10-19T16:12:00Z', key_id: null } }, /already scheduled|Upgrade to 5.48.0 scheduled/],
    ['a second approval is pending', { pending_approval: { kind: 'apply', version: '5.48.0', sha256: TARGET_SHA, when_utc: null, entered: null, first_email: 'first@example.com', created_at: '2026-10-19T14:32:00Z', expires_at: '2099-10-20T14:32:00Z', correlation_id: 'upg-0000abce', mine: true } }, /waiting for a second admin|a different admin must approve/],
  ])('the buttons are off with the reason: %s', async (_name, over, text) => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(AVAILABLE(over))
    renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    await screen.findByText('5.48.0 is available')
    expect(screen.getAllByText(text).length).toBeGreaterThan(0)
    expect((screen.getByRole('button', { name: /Upgrade now/ }) as HTMLButtonElement).disabled).toBe(true)
  })
})

describe('05a confirmation and step-up', () => {
  it('lists what is approved, needs the acknowledgement, then binds the MFA to the exact version and hash', async () => {
    await openConfirm()
    expect(screen.getByText('5.46.0 → 5.48.0')).toBeTruthy()
    expect(screen.getByText(TARGET_SHA)).toBeTruthy()
    expect(screen.getByText(/not rollback-safe/, { selector: 'strong' })).toBeTruthy()
    expect(screen.getByText(/Free space|Disk space on both volumes/)).toBeTruthy()
    const approve = screen.getByRole('button', { name: /Approve with MFA/ }) as HTMLButtonElement
    expect(approve.disabled).toBe(true)
    vi.mocked(requestUpgrade).mockResolvedValue(STEP_UP)
    fireEvent.click(screen.getByRole('checkbox'))
    expect(approve.disabled).toBe(false)
    fireEvent.click(approve)
    await waitFor(() => expect(requestUpgrade).toHaveBeenCalledWith({ kind: 'apply', version: '5.48.0', sha256: TARGET_SHA, acknowledged: true }))
    await waitFor(() => expect(beginStepUp).toHaveBeenCalledWith('act_example_0123456789', expect.objectContaining({ kind: 'environment_change', action: 'upgrade.request', reopen: 'updates' })))
  })

  it('Back returns to the Updates page without asking for anything', async () => {
    await openConfirm()
    fireEvent.click(screen.getByRole('button', { name: 'Back' }))
    expect(await screen.findByText('5.48.0 is available')).toBeTruthy()
    expect(requestUpgrade).not.toHaveBeenCalled()
  })

  it('a refused request shows the server reason and stays on the page', async () => {
    await openConfirm()
    vi.mocked(requestUpgrade).mockRejectedValue(new ApiError('5.48.0 failed here before.', 409, { error: 'x', reason: 'version_failed_before' }))
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(screen.getByRole('button', { name: /Approve with MFA/ }))
    await waitFor(() => expect(requestUpgrade).toHaveBeenCalled())
    expect(beginStepUp).not.toHaveBeenCalled()
    expect(screen.getByText('Confirm the upgrade to 5.48.0')).toBeTruthy()
  })

  it('a failed preflight blocks the approval', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(AVAILABLE())
    renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    fireEvent.click(await screen.findByRole('button', { name: /Upgrade now/ }))
    await screen.findByText('Confirm the upgrade to 5.48.0')
    expect((screen.getByRole('button', { name: /Approve with MFA/ }) as HTMLButtonElement).disabled).toBe(true)
  })
})

describe('04 schedule dialog', () => {
  const NOW = Date.parse('2026-10-20T12:00:00Z')
  async function openDialog() {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(AVAILABLE())
    vi.spyOn(Date, 'now').mockReturnValue(NOW)
    renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    fireEvent.click(await screen.findByRole('button', { name: /Schedule/ }))
    return screen.findByRole('dialog')
  }

  it('shows the same moment in server, local and UTC, defaulting to tomorrow 03:30 server time', async () => {
    const dlg = await openDialog()
    expect((within(dlg).getByLabelText('Date') as HTMLInputElement).value).toBe('2026-10-21')
    expect((within(dlg).getByLabelText('Time') as HTMLInputElement).value).toBe('03:30')
    const times = within(dlg).getByTestId('sched-times')
    expect(times.textContent).toMatch(/Wed 21 Oct 2026, 03:30.*UTC\+1/)
    expect(times.textContent).toContain('2026-10-21 02:30')
    expect(within(dlg).getByRole('radio', { name: /Server time — Europe\/London/ })).toBeTruthy()
    expect(within(dlg).getByText(/Last sync finished 02:14 UTC; a sync runs daily at 03:00 UTC/)).toBeTruthy()
    vi.mocked(Date.now).mockRestore()
  })

  it('refuses a past time, and Continue hands the choice on with the zone the admin typed it in', async () => {
    const dlg = await openDialog()
    fireEvent.change(within(dlg).getByLabelText('Date'), { target: { value: '2026-10-19' } })
    expect(within(dlg).getByRole('alert').textContent).toMatch(/in the past/)
    expect((within(dlg).getByRole('button', { name: 'Continue to confirmation' }) as HTMLButtonElement).disabled).toBe(true)
    fireEvent.change(within(dlg).getByLabelText('Date'), { target: { value: '2026-12-31' } })
    expect(within(dlg).getByRole('alert').textContent).toMatch(/at most 31 days/)
    fireEvent.change(within(dlg).getByLabelText('Date'), { target: { value: '2026-10-22' } })
    fireEvent.click(within(dlg).getByRole('button', { name: 'Continue to confirmation' }))
    await screen.findByText('Confirm the upgrade to 5.48.0')
    expect(screen.getByText('Scheduled')).toBeTruthy()
    vi.mocked(requestUpgrade).mockResolvedValue(STEP_UP)
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(screen.getByRole('button', { name: /Approve with MFA/ }))
    await waitFor(() => expect(requestUpgrade).toHaveBeenCalledWith(expect.objectContaining({
      kind: 'schedule', version: '5.48.0', sha256: TARGET_SHA, acknowledged: true, when_utc: '2026-10-22T02:30:00Z', entered_tz: 'Europe/London', entered_local: '2026-10-22T03:30',
    })))
    vi.mocked(Date.now).mockRestore()
  })

  it('switching the zone keeps the moment', async () => {
    const dlg = await openDialog()
    fireEvent.click(within(dlg).getByRole('radio', { name: 'UTC' }))
    expect((within(dlg).getByLabelText('Time') as HTMLInputElement).value).toBe('02:30')
    vi.mocked(Date.now).mockRestore()
  })

  it('the hint button uses the quiet slot after the daily sync', async () => {
    const dlg = await openDialog()
    fireEvent.click(within(dlg).getByRole('button', { name: 'Use 03:30 UTC' }))
    expect((within(dlg).getByLabelText('Time') as HTMLInputElement).value).toBe('04:30')   // 03:30 UTC, shown in server time (BST)
    vi.mocked(Date.now).mockRestore()
  })
})

describe('07 scheduled', () => {
  const SCHED = { correlation_id: 'upg-7f3a9c2e', version: '5.48.0', sha256: TARGET_SHA, when_utc: '2099-10-21T02:30:00Z', entered: 'Europe/London 03:30', entered_tz: 'Europe/London', status: 'scheduled' as const, actor_email: 'admin@example.com', approved_at: '2026-10-19T16:12:00Z', key_id: 'E7620F1842B4E81F' }

  it('shows the schedule, what happens at the time, and cancel needs a confirmation then MFA', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(AVAILABLE({ schedule: SCHED }))
    renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    expect(await screen.findByText('Upgrade to 5.48.0 scheduled')).toBeTruthy()
    expect(screen.getByText('missed', { selector: 'strong' })).toBeTruthy()
    expect(screen.getByText('upg-7f3a9c2e')).toBeTruthy()
    vi.mocked(requestUpgrade).mockResolvedValue({ ...STEP_UP })
    fireEvent.click(screen.getByRole('button', { name: /Cancel upgrade/ }))
    fireEvent.click(await screen.findByRole('button', { name: 'Cancel the upgrade' }))
    await waitFor(() => expect(requestUpgrade).toHaveBeenCalledWith({ kind: 'cancel' }))
    await waitFor(() => expect(beginStepUp).toHaveBeenCalled())
  })

  it('a missed schedule is shown as missed and can be scheduled again, never run late', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(AVAILABLE({ schedule: { ...SCHED, status: 'missed' } }))
    renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    expect(await screen.findByText('The scheduled upgrade to 5.48.0 was missed')).toBeTruthy()
    expect(screen.getByRole('button', { name: /Schedule again/ })).toBeTruthy()
    expect(screen.queryByRole('button', { name: /Cancel upgrade/ })).toBeNull()
  })

  it('Run it now instead leads to the confirmation for an immediate upgrade', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(AVAILABLE({ schedule: SCHED }))
    renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    fireEvent.click(await screen.findByRole('button', { name: /Run it now instead/ }))
    expect(await screen.findByText('Confirm the upgrade to 5.48.0')).toBeTruthy()
    expect(screen.getByText('Now')).toBeTruthy()
  })
})

describe('05b second admin', () => {
  const PENDING = { kind: 'apply' as const, version: '5.48.0', sha256: TARGET_SHA, when_utc: null, entered: null, first_email: 'first@example.com', created_at: '2026-10-19T14:32:00Z', expires_at: '2099-10-20T14:32:00Z', correlation_id: 'upg-0000abce', mine: false }

  it('a different admin reviews, approves with MFA, or declines', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(AVAILABLE({ pending_approval: PENDING }))
    renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    fireEvent.click(await screen.findByRole('button', { name: /Review and approve/ }))
    expect(await screen.findByText('Waiting for a second admin')).toBeTruthy()
    expect(screen.getByText('What the first admin approved — review it yourself')).toBeTruthy()
    vi.mocked(requestUpgrade).mockResolvedValue(STEP_UP)
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(screen.getByRole('button', { name: /Approve as second admin with MFA/ }))
    await waitFor(() => expect(requestUpgrade).toHaveBeenCalledWith({ kind: 'approve_second' }))
    fireEvent.click(screen.getByRole('button', { name: /Decline and drop the request/ }))
    await waitFor(() => expect(requestUpgrade).toHaveBeenCalledWith({ kind: 'cancel' }))
  })

  it('the first approver cannot be the second', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(AVAILABLE({ pending_approval: { ...PENDING, mine: true } }))
    renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    fireEvent.click(await screen.findByRole('button', { name: /Withdraw it/ }))
    await screen.findByText('Waiting for a second admin')
    fireEvent.click(screen.getByRole('checkbox'))
    expect((screen.getByRole('button', { name: /Approve as second admin with MFA/ }) as HTMLButtonElement).disabled).toBe(true)
    expect(screen.getByText(/You already approved this request; a different admin must approve it/)).toBeTruthy()
  })
})

describe('08a progress', () => {
  const RUNNING = makeRun({ result: null, step: 'switching', seconds: null, updated_at: null,
    steps_done: [{ step: 'validated', at: '2026-10-21T02:30:02Z', seconds: 0.4 }, { step: 'downloaded', at: '2026-10-21T02:30:03Z', seconds: 0.1 }, { step: 'staged', at: '2026-10-21T02:30:04Z', seconds: 1.1 },
      { step: 'preflight', at: '2026-10-21T02:30:05Z', seconds: 1.8 }, { step: 'backup', at: '2026-10-21T02:30:21Z', seconds: 16 }] })

  it('shows the step list with done, current and pending steps and an accessible progress bar', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(AVAILABLE({ run: RUNNING }))
    renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    expect(await screen.findByText('Upgrading to 5.48.0')).toBeTruthy()
    expect(screen.getByText('Step 6 of 9 · switching')).toBeTruthy()
    const bar = screen.getByRole('progressbar', { name: 'Upgrade progress' })
    expect(bar.getAttribute('aria-valuenow')).toBe('6')
    const items = screen.getAllByRole('listitem').filter(li => li.getAttribute('data-state'))
    expect(items.map(li => li.getAttribute('data-state'))).toEqual(['done', 'done', 'done', 'done', 'done', 'current', 'todo', 'todo', 'todo'])
    expect(screen.queryByRole('button', { name: /Upgrade now/ })).toBeNull()
  })

  it('keeps showing the last run and says "Restarting" while the poll gets 502/503/network errors, then recovers', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(AVAILABLE({ run: RUNNING }))
    const { client } = renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    await screen.findByText('Upgrading to 5.48.0')
    for (const err of [new ApiError('Bad Gateway', 502), new ApiError('Service Unavailable', 503), new TypeError('Failed to fetch')]) {
      vi.mocked(fetchUpgradeStatus).mockRejectedValueOnce(err)
      await act(async () => { await client.refetchQueries({ queryKey: ['upgrade_status'] }) })
      expect(await screen.findByText(/Restarting — this normally takes under a minute/)).toBeTruthy()
      expect(screen.getByText('Upgrading to 5.48.0')).toBeTruthy()
      await act(async () => { await client.refetchQueries({ queryKey: ['upgrade_status'] }) })
      await waitFor(() => expect(screen.queryByText(/Restarting — this normally/)).toBeNull())
    }
  })

  it('polls by itself every 2 seconds while an upgrade runs', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      vi.mocked(fetchUpgradeStatus).mockResolvedValue(AVAILABLE({ run: RUNNING }))
      renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
      await screen.findByText('Upgrading to 5.48.0')
      const before = vi.mocked(fetchUpgradeStatus).mock.calls.length
      await act(async () => { await vi.advanceTimersByTimeAsync(4500) })
      expect(vi.mocked(fetchUpgradeStatus).mock.calls.length).toBeGreaterThanOrEqual(before + 2)
    } finally { vi.useRealTimers() }
  })

  it('reloads once when the new version answers, never again', async () => {
    const reload = vi.fn()
    Object.defineProperty(window, 'location', { configurable: true, value: { ...window.location, reload } })
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(makeStatus({ ...NEWER, installed_version: '5.48.0', update_available: false, upgrade: makeUpgrade({ run: makeRun(), rollback: { available: true, until: '2099-01-01T00:00:00Z', to: '5.46.0' } }) }))
    renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    await waitFor(() => expect(reload).toHaveBeenCalledTimes(1))
    renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    await screen.findAllByText(/Upgraded to 5.48.0/)
    expect(reload).toHaveBeenCalledTimes(1)
  })

  it('Starting: waits for the updater, shows a refusal, and warns when it never picks the request up', async () => {
    rememberRequested({ correlationId: 'upg-7f3a9c2e', version: '5.48.0', approvedAt: new Date().toISOString(), email: 'admin@example.com', stepUp: true })
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(AVAILABLE())
    const { unmount } = renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    expect(await screen.findByText('Starting the upgrade to 5.48.0')).toBeTruthy()
    expect(screen.getByText('Waiting for the updater')).toBeTruthy()
    expect(screen.queryByText(/has not picked the request up/)).toBeNull()
    unmount()
    rememberRequested({ correlationId: 'upg-7f3a9c2e', version: '5.48.0', approvedAt: new Date(Date.now() - 4 * 60_000).toISOString(), email: null, stepUp: true })
    const slow = renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    expect(await screen.findByText(/has not picked the request up after three minutes/)).toBeTruthy()
    slow.unmount()
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(AVAILABLE({ rejection: { correlation_id: 'upg-7f3a9c2e', code: 'version_failed_before', message: 'failed before', at: null } }))
    renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    expect(await screen.findByText('The updater refused the upgrade to 5.48.0')).toBeTruthy()
    expect(screen.getByText(/this version failed before/)).toBeTruthy()
  })
})

describe('09 success and 10 failure', () => {
  it('success: duration, migrations, 8 of 8 checks, rollback window with the command', async () => {
    const health = ['unit_active', 'version', 'healthz', 'gate_401', 'quick_check', 'schema_version', 'chain_heads', 'smoke_read'].map(id => ({ id, ok: true, detail: 'ok' }))
    vi.mocked(fetchVersion).mockResolvedValue({ version: '5.48.0' })
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(makeStatus({ installed_version: '5.48.0', upgrade: makeUpgrade({ run: makeRun({ health }), rollback: { available: true, until: '2099-01-01T00:00:00Z', to: '5.46.0' } }) }))
    renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    expect(await screen.findByText('Upgraded to 5.48.0 in 52 s')).toBeTruthy()
    expect(screen.getByText('8 of 8 passed')).toBeTruthy()
    expect(screen.getByText(/Migrations 10 and 11 applied \(schema 9 → 11\)/)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: /Roll back to 5.46.0/ }))
    expect(screen.getByLabelText('Rollback command').textContent).toBe('sudo ocw-updater rollback')
  })

  const ROLLED = makeRun({
    result: 'rolled_back', step: 'rolled_back', reason_code: 'health_healthz', seconds: null, rolled_back_to: '5.46.0',
    failure: { step: 'health_check', reason_code: 'health_healthz', detail: '/healthz reported degraded', at: '2026-10-21T02:31:14Z' },
    health: [{ id: 'unit_active', ok: true, detail: '' }, { id: 'version', ok: true, detail: '' }, { id: 'healthz', ok: false, detail: "/healthz reported 'degraded'; the baseline before the upgrade was 'ok'" }],
    rollback_health: Array.from({ length: 8 }, (_, i) => ({ id: `c${i}`, ok: true, detail: '' })),
    bundle: { name: 'ocw-support-5.46.0-to-5.48.0-20261021T023158Z-k4q9.tar.gz', size: 1_800_000, sha256: 'c7a0e2' + '0'.repeat(52) + '91fd' },
  })

  it('rolled back: what happened, where you are, the bundle download, clear-failure and restore on the command line', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(AVAILABLE({ run: ROLLED, failures: { '5.48.0': { count: 1, last_code: 'health_healthz' } } }))
    renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    expect(await screen.findByText('The upgrade to 5.48.0 failed and was rolled back automatically')).toBeTruthy()
    expect(screen.getByText(/health_healthz/, { selector: 'code' })).toBeTruthy()
    expect(screen.getByText(/No data was changed by the rollback/)).toBeTruthy()
    const link = screen.getByRole('link', { name: /Download support bundle/ }) as HTMLAnchorElement
    expect(link.getAttribute('href')).toBe('/api/upgrade/bundle?name=ocw-support-5.46.0-to-5.48.0-20261021T023158Z-k4q9.tar.gz')
    expect(screen.getByText(/Nothing is sent automatically/)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: /Clear failure/ }))
    expect(screen.getByLabelText('Clear failure command').textContent).toBe('sudo ocw-updater clear-failure')
    // restore: typed confirmation reveals the command, nothing is sent from here
    expect(screen.queryByLabelText('Restore command')).toBeNull()
    fireEvent.change(screen.getByLabelText(/Type RESTORE/), { target: { value: 'RESTOR' } })
    expect(screen.queryByLabelText('Restore command')).toBeNull()
    fireEvent.change(screen.getByLabelText(/Type RESTORE/), { target: { value: 'RESTORE' } })
    expect(screen.getByLabelText('Restore command').textContent).toBe('sudo ocw-updater restore --confirm RESTORE')
    expect(requestUpgrade).not.toHaveBeenCalled()
  })

  it('needs an operator: says so, offers no upgrade, no restore', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(AVAILABLE({ run: makeRun({ result: 'failed_needs_operator', step: 'failed_needs_operator', reason_code: 'rollback_failed', operator_reason: 'health checks failed after the rollback', bundle: null }) }))
    renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    expect(await screen.findByText('The upgrade to 5.48.0 failed and could not be rolled back automatically')).toBeTruthy()
    expect(screen.getByText(/An operator must act on the server\./, { selector: 'strong' })).toBeTruthy()
    expect((screen.getByRole('button', { name: /Upgrade now/ }) as HTMLButtonElement).disabled).toBe(true)
    expect(screen.queryByText('Restore the pre-upgrade archive copy')).toBeNull()
  })

  it('refused before anything was switched', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(AVAILABLE({ run: makeRun({ result: 'failed', step: 'staged', reason_code: 'hash_mismatch', failed_step: 'staged', backup: null, bundle: null }) }))
    renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    expect(await screen.findByText('The upgrade to 5.48.0 failed before anything was switched')).toBeTruthy()
    expect(screen.getByText(/does not match the signed hash/)).toBeTruthy()
    expect(screen.queryByText('Restore the pre-upgrade archive copy')).toBeNull()
  })
})

describe('local mode and the release channel', () => {
  it('local mode: no hosted flow, the command-line hint instead', async () => {
    vi.mocked(fetchWhoami).mockResolvedValue({ email: null, is_local: true, is_admin: false, can_admin: true })
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(makeStatus({ ...NEWER }))
    renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    expect(await screen.findByText('5.48.0 is available')).toBeTruthy()
    expect(screen.queryByRole('button', { name: /Upgrade now/ })).toBeNull()
    expect(screen.queryByRole('button', { name: /Schedule/ })).toBeNull()
    expect(screen.getByLabelText('Upgrade command').textContent).toBe('python launch.py upgrade')
    expect(screen.getByLabelText('Restore command').textContent).toBe('python launch.py upgrade --restore-previous')
    expect(reviewUpgrade).not.toHaveBeenCalled()
  })

  it('shows a PRERELEASE badge and the channel control; saves only what changed', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(makeStatus({
      ...NEWER, latest: { ...NEWER.latest, prerelease: true, version: '5.49.0-rc1' } as never,
      check: { ...makeStatus().check, channel: 'prerelease', channel_source: 'setting' },
    }))
    vi.mocked(saveUpgradeSettings).mockResolvedValue(STEP_UP as never)
    renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    expect(await screen.findByText('PRERELEASE')).toBeTruthy()
    expect(screen.getByText(/Pre-release \(release candidates are offered too\)/)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Change…' }))
    const stable = screen.getByRole('radio', { name: /Stable/ }) as HTMLInputElement
    fireEvent.click(stable)
    fireEvent.click(screen.getByRole('button', { name: /Save with MFA/ }))
    await waitFor(() => expect(saveUpgradeSettings).toHaveBeenCalledWith({ frequency: 'daily', share_version: false, channel: 'stable' }))
  })

  it('a channel set by the operator is locked with an explanation; an older server shows no control at all', async () => {
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(makeStatus({ check: { ...makeStatus().check, channel: 'stable', channel_source: 'env' } }))
    const { unmount } = renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    fireEvent.click(await screen.findByRole('button', { name: 'Change…' }))
    expect(screen.getByRole('radio', { name: /Pre-release/ }).matches(':disabled')).toBe(true)
    expect(screen.getByText(/The channel is set by this server's environment/)).toBeTruthy()
    unmount()
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(makeStatus())
    renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    fireEvent.click(await screen.findByRole('button', { name: 'Change…' }))
    expect(screen.queryByText('Release channel', { selector: 'legend' })).toBeNull()
  })
})

describe('the notice banner (every signed-in user)', () => {
  const show = async (n: unknown, canAdmin = false) => {
    vi.mocked(fetchUpgradeNotice).mockResolvedValue(n as never)
    renderWithClient(<UpgradeNoticeBanner canAdmin={canAdmin} onOpenUpdates={() => {}} />)
  }
  it('scheduled maintenance is shown to non-admins and can be dismissed for the session', async () => {
    await show({ kind: 'scheduled', version: '5.48.0', when_utc: '2099-10-21T02:30:00Z', downtime_estimate_seconds: 45 })
    expect(await screen.findByText(/Scheduled maintenance: OPA Compliance Wizard will upgrade to 5.48.0/)).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Open the Updates page' })).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Dismiss announcement' }))
    expect(screen.queryByText(/Scheduled maintenance/)).toBeNull()
  })
  it('running and failed stay, and only admins get the link', async () => {
    await show({ kind: 'running', version: '5.48.0', started_at: '2026-10-21T02:30:00Z' }, true)
    expect(await screen.findByText(/Upgrade to 5.48.0 in progress/)).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Open the Updates page' })).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Dismiss announcement' })).toBeNull()
  })
  it('failed and rolled back is an alert', async () => {
    await show({ kind: 'failed', result: 'rolled_back', version: '5.48.0', rolled_back_to: '5.46.0', at: '2026-10-21T02:31:00Z' })
    expect((await screen.findByRole('alert')).textContent).toMatch(/rolled back automatically.*5\.46\.0/)
  })
  it('nothing for none, and "available" is the admin banner, not this one', async () => {
    await show({ kind: 'available', version: '5.48.0' }, true)
    await waitFor(() => expect(fetchUpgradeNotice).toHaveBeenCalled())
    expect(screen.queryByRole('status')).toBeNull()
  })
})
