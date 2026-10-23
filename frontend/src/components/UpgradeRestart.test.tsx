/** 5.53.0: the upgrade's steps stay on screen through the restart, and the page shows the result before it reloads. */
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError, fetchAuditLog, fetchUpgradeNotice, fetchUpgradeStatus, fetchVersion, fetchWhoami } from '../api/client'
import { renderWithClient } from '../test/renderWithClient'
import { makePreview, makeRun, makeStatus, makeUpgrade, NEWER } from '../test/upgradeFixtures'
import type { UpgradeNotice, UpgradeNoticeRun } from '../types'
import { UpdatesPage } from './UpdatesPage'

vi.mock('../api/client', async importOriginal => ({
  ...(await importOriginal<typeof import('../api/client')>()),
  fetchUpgradeStatus: vi.fn(), checkUpgradeNow: vi.fn(), fetchAuditLog: vi.fn(), backfillMfaLogEvents: vi.fn(),
  fetchWhoami: vi.fn(), fetchVersion: vi.fn(), reviewUpgrade: vi.fn(), fetchUpgradeNotice: vi.fn(),
}))
vi.mock('../hooks/useToast', () => ({ toast: vi.fn() }))

beforeAll(() => {
  window.matchMedia = ((query: string) => ({
    matches: true, media: query, onchange: null, addEventListener: () => {}, removeEventListener: () => {},
    addListener: () => {}, removeListener: () => {}, dispatchEvent: () => false,
  })) as unknown as typeof window.matchMedia
})

const IDS = ['validated', 'downloaded', 'staged', 'preflight', 'backup', 'switching', 'restarting', 'health_check', 'completed']
const stepsDone = (n: number) => IDS.slice(0, n).map((step, i) => ({ step, at: `2026-10-21T02:30:${String(2 + i * 5).padStart(2, '0')}Z`, seconds: 3 + i }))
const HEALTH_IDS = ['unit_active', 'version', 'healthz', 'gate_401', 'quick_check', 'schema_version', 'chain_heads', 'smoke_read']
const HEALTH = HEALTH_IDS.map(id => ({ id, ok: true, detail: '' }))

const RESTARTING = makeRun({ result: null, step: 'restarting', seconds: null, updated_at: '2026-10-21T02:30:40Z', steps_done: stepsDone(6), health: [] })
const COMPLETED = makeRun({ result: 'completed', step: 'completed', seconds: 52, updated_at: '2026-10-21T02:30:54Z', steps_done: stepsDone(9), health: HEALTH })
const statusWith = (run: ReturnType<typeof makeRun>, installed: string) =>
  makeStatus({ ...NEWER, installed_version: installed, update_available: false, upgrade: makeUpgrade({ run, preview: makePreview(), rollback: { available: true, until: '2099-01-01T00:00:00Z', to: '5.46.0' } }) })
const noticeRun = (over: Partial<UpgradeNoticeRun> = {}): UpgradeNoticeRun => ({
  correlation_id: 'upg-7f3a9c2e', action: 'apply', version_from: '5.46.0', version_to: '5.48.0', step: 'restarting', result: null, reason_code: null, failed_step: null,
  started_at: '2026-10-21T02:30:02Z', updated_at: '2026-10-21T02:30:40Z', seconds: null, rolled_back_to: null, step_started_at: '2026-10-21T02:30:35Z',
  steps_done: stepsDone(6), health: null, ...over,
})
const notice = (run: UpgradeNoticeRun | null): UpgradeNotice => ({ kind: 'running', version: '5.48.0', started_at: '2026-10-21T02:30:02Z', run } as UpgradeNotice)

beforeEach(() => {
  sessionStorage.clear()
  localStorage.clear()
  vi.clearAllMocks()
  vi.mocked(fetchWhoami).mockResolvedValue({ email: 'admin@example.com', is_local: false, is_admin: true, can_admin: true })
  vi.mocked(fetchVersion).mockResolvedValue({ version: '5.46.0' })           // this browser loaded the OLD interface
  vi.mocked(fetchUpgradeNotice).mockResolvedValue({ kind: 'none' } as UpgradeNotice)
  vi.mocked(fetchAuditLog).mockResolvedValue({ entries: [] })
})

/** Advance fake time in whole seconds, one act() each, so React commits between the ticks (the countdown re-arms itself after every render). */
async function seconds(n: number) {
  for (let i = 0; i < n; i++) await act(async () => { await vi.advanceTimersByTimeAsync(1000) })
}

const states = () => screen.getAllByRole('listitem').filter(li => li.getAttribute('data-state')).map(li => li.getAttribute('data-state'))

describe('through the restart', () => {
  it('keeps the steps while the status fails, then shows the result with from → to, every step and the health checks, and reloads only on request', async () => {
    const reload = vi.fn()
    Object.defineProperty(window, 'location', { configurable: true, value: { ...window.location, reload } })
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      let polls = 0
      vi.mocked(fetchUpgradeStatus).mockImplementation(async () => {
        polls += 1
        if (polls === 1) return statusWith(RESTARTING, '5.46.0')                                // first answer: still the old process
        if (polls <= 4) throw new ApiError('Service Unavailable', 503)                           // the restart: nothing answers for a while
        if (polls === 5) throw new TypeError('Failed to fetch')
        return statusWith(COMPLETED, '5.48.0')                                                   // the new version answers
      })
      renderWithClient(<UpdatesPage onOpenKeys={() => {}} reloadAfterSeconds={Infinity} />)
      await screen.findByText('Upgrading to 5.48.0')
      expect(states()).toEqual(['done', 'done', 'done', 'done', 'done', 'done', 'current', 'todo', 'todo'])

      await seconds(2)                                                                           // the poll fails
      expect((await screen.findAllByText(/Restarting — this normally takes under a minute/)).length).toBeGreaterThan(0)
      expect(screen.getByText('Upgrading to 5.48.0')).toBeTruthy()                               // the steps are still there, not a bare spinner
      expect(states()).toEqual(['done', 'done', 'done', 'done', 'done', 'done', 'current', 'todo', 'todo'])
      expect(screen.queryByText(/Upgraded to/)).toBeNull()

      await seconds(9)                                                                           // more failures, then the new version answers
      expect(await screen.findByRole('heading', { name: /Upgraded to 5\.48\.0 in 52 seconds/ })).toBeTruthy()
      expect(screen.getByText('5.46.0 → 5.48.0')).toBeTruthy()
      expect(screen.getAllByText('8 of 8 passed').length).toBeGreaterThan(0)
      expect(states()).toEqual(Array(9).fill('done'))
      const steps = screen.getAllByRole('listitem').filter(li => li.getAttribute('data-state'))
      expect(within(steps[6]).getByText(/Restarting/)).toBeTruthy()
      expect(steps[6].textContent).toMatch(/\d\d:\d\d:\d\d · 9 s/)                              // each step carries its time and duration
      expect(reload).not.toHaveBeenCalled()                                                      // the result is on screen first

      fireEvent.click(screen.getByRole('button', { name: 'Reload on 5.48.0 now' }))
      expect(reload).toHaveBeenCalledTimes(1)
    } finally { vi.useRealTimers() }
  })

  it('reloads by itself after the visible countdown, once', async () => {
    const reload = vi.fn()
    Object.defineProperty(window, 'location', { configurable: true, value: { ...window.location, reload } })
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(statusWith(COMPLETED, '5.48.0'))
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      renderWithClient(<UpdatesPage onOpenKeys={() => {}} reloadAfterSeconds={3} />)
      await screen.findByRole('heading', { name: /Upgraded to 5\.48\.0/ })
      expect(screen.getByText(/Reloading by itself in \d s/)).toBeTruthy()
      expect(reload).not.toHaveBeenCalled()
      await seconds(4)
      expect(reload).toHaveBeenCalledTimes(1)
      await seconds(5)
      expect(reload).toHaveBeenCalledTimes(1)
    } finally { vi.useRealTimers() }
  })

  it('"Keep this summary open" stops the automatic reload', async () => {
    const reload = vi.fn()
    Object.defineProperty(window, 'location', { configurable: true, value: { ...window.location, reload } })
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(statusWith(COMPLETED, '5.48.0'))
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      renderWithClient(<UpdatesPage onOpenKeys={() => {}} reloadAfterSeconds={3} />)
      await screen.findByRole('heading', { name: /Upgraded to 5\.48\.0/ })
      fireEvent.click(screen.getByRole('button', { name: 'Keep this summary open' }))
      await seconds(6)
      expect(reload).not.toHaveBeenCalled()
      expect(screen.getByText(/still runs the old version until you reload/)).toBeTruthy()
    } finally { vi.useRealTimers() }
  })

  it('no summary and no reload once this browser already runs the new version: the ordinary success page shows, with every step', async () => {
    vi.mocked(fetchVersion).mockResolvedValue({ version: '5.48.0' })
    vi.mocked(fetchUpgradeStatus).mockResolvedValue(statusWith(COMPLETED, '5.48.0'))
    renderWithClient(<UpdatesPage onOpenKeys={() => {}} reloadAfterSeconds={0} />)
    expect((await screen.findAllByText(/Upgraded to 5\.48\.0/)).length).toBeGreaterThan(0)
    expect(screen.queryByRole('button', { name: /Reload on/ })).toBeNull()
    expect(screen.getByText('Every step, with its time')).toBeTruthy()
  })
})

describe('Updates locked while the upgrade runs (403 settings_locked)', () => {
  const locked = () => new ApiError('Unlock Settings with MFA to view this.', 403, { reason: 'settings_locked', step_up_required: true } as never)

  it('shows the steps from the progress-only notice, says the page is locked, and does not call it a failure', async () => {
    vi.mocked(fetchUpgradeStatus).mockRejectedValue(locked())
    vi.mocked(fetchUpgradeNotice).mockResolvedValue(notice(noticeRun()))
    renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
    expect(await screen.findByText('Upgrading to 5.48.0')).toBeTruthy()
    expect(states()).toEqual(['done', 'done', 'done', 'done', 'done', 'done', 'current', 'todo', 'todo'])
    expect(screen.getByText(/Updates locked again/)).toBeTruthy()
    expect(screen.queryByText(/Could not load the update status/)).toBeNull()
    expect(screen.queryByText(/failed|rolled back/i)).toBeNull()
  })

  it('moves on with the notice (health checks included) and ends in the result, still without the status', async () => {
    const reload = vi.fn()
    Object.defineProperty(window, 'location', { configurable: true, value: { ...window.location, reload } })
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      vi.mocked(fetchUpgradeStatus).mockRejectedValue(locked())
      let n = 0
      vi.mocked(fetchUpgradeNotice).mockImplementation(async () => {
        n += 1
        if (n === 1) return notice(noticeRun())
        if (n === 2) return notice(noticeRun({ step: 'health_check', updated_at: '2026-10-21T02:30:46Z', steps_done: stepsDone(7), health: HEALTH.slice(0, 3) }))
        return notice(noticeRun({ step: 'completed', result: 'completed', seconds: 52, updated_at: '2026-10-21T02:30:54Z', steps_done: stepsDone(9), health: HEALTH }))
      })
      renderWithClient(<UpdatesPage onOpenKeys={() => {}} reloadAfterSeconds={Infinity} />)
      await screen.findByText('Upgrading to 5.48.0')
      await seconds(2)
      await waitFor(() => expect(states()).toEqual(['done', 'done', 'done', 'done', 'done', 'done', 'done', 'current', 'todo']))
      expect(screen.getAllByText(/Eight checks|Service unit active/).length).toBeGreaterThan(0)
      await seconds(2)
      expect(await screen.findByRole('heading', { name: /Upgraded to 5\.48\.0 in 52 seconds/ })).toBeTruthy()
      expect(screen.getAllByText('8 of 8 passed').length).toBeGreaterThan(0)
      expect(states()).toEqual(Array(9).fill('done'))
    } finally { vi.useRealTimers() }
  })

  it('after the status was seen once, a lock keeps the detailed steps and the notice only moves them on', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      let polls = 0
      vi.mocked(fetchUpgradeStatus).mockImplementation(async () => {
        polls += 1
        if (polls === 1) return statusWith(makeRun({ ...RESTARTING, steps_done: stepsDone(6).map(s => ({ ...s, detail: { current: '5.48.0' } })) }), '5.46.0')
        throw locked()
      })
      vi.mocked(fetchUpgradeNotice).mockResolvedValue(notice(noticeRun({ step: 'health_check', updated_at: '2026-10-21T02:30:46Z', steps_done: stepsDone(7) })))
      renderWithClient(<UpdatesPage onOpenKeys={() => {}} />)
      await screen.findByText('Upgrading to 5.48.0')
      await seconds(2)
      await waitFor(() => expect(states()).toEqual(['done', 'done', 'done', 'done', 'done', 'done', 'done', 'current', 'todo']))
      expect(screen.getByText(/Updates locked again/)).toBeTruthy()
      expect(screen.getByText(/Maintenance page in place; current → releases\/5\.48\.0/)).toBeTruthy()   // the detail from the earlier status survives
    } finally { vi.useRealTimers() }
  })
})
