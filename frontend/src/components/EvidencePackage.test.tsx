/** 5.53.0: the Evidence package page, step by step, and the MFA round trip that keeps the period and the acknowledgement. */
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { checkEvidencePackage, fetchEnvironments, fetchEvidencePackage, prepareEvidencePackage } from '../api/client'
import { renderWithClient } from '../test/renderWithClient'
import type { EvidenceCoverage, EvidenceJob } from '../types'
import { readPendingStepUp } from '../utils/stepUp'
import { EvidencePackage } from './EvidencePackage'

vi.mock('../api/client', async importOriginal => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return { ...actual, fetchEnvironments: vi.fn(), checkEvidencePackage: vi.fn(), prepareEvidencePackage: vi.fn(), fetchEvidencePackage: vi.fn() }
})
vi.mock('../utils/stepUp', async importOriginal => {
  const actual = await importOriginal<typeof import('../utils/stepUp')>()
  return { ...actual, beginStepUp: (id: string, pending: Parameters<typeof actual.beginStepUp>[1]) => actual.beginStepUp(id, pending, () => {}) }
})

const COV: EvidenceCoverage = {
  period: { start: '2026-07-01', end: '2026-09-30' }, days: 92, has_coverage: true, coverage_pct: 97.8, covered_days: 90,
  counts: { covered_with_events: 80, covered_zero_events: 8, not_covered: 2, pruned_by_retention: 2, before_archive: 0, after_data_as_of: 0 },
  gap_days_total: 2, gap_ranges: [['2026-08-10', '2026-08-11']], gap_ranges_total: 1,
  zero_days_total: 8, zero_ranges: [['2026-07-04', '2026-07-05']], zero_ranges_total: 1,
  pruned_days_total: 2, pruned_ranges: [['2026-07-01', '2026-07-02']], pruned_ranges_total: 1, before_archive_days: 0, after_data_as_of_days: 0,
  needs_acknowledgement: true, archive_start_date: '2026-06-01', data_as_of: '2026-10-22T02:00:00.000Z', pruned_basis: 'recorded',
  limits: ['Pruned days rest on a recorded run.'], events_in_period: 1200, chain_head: 'f'.repeat(64),
  controls: [
    { framework: 'soc2', control_id: 'CC6.1', mapping_status: 'proposed', reports: ['mfa_enforcement', 'pam_secrets'], rows: 40, status: 'events_present' },
    { framework: 'soc2', control_id: 'CC8.1', mapping_status: 'proposed', reports: ['policy_modifications'], rows: 0, status: 'zero_events_in_period' },
  ],
}
const NO_GAPS: EvidenceCoverage = { ...COV, needs_acknowledgement: false, gap_days_total: 0, gap_ranges: [], gap_ranges_total: 0, counts: { ...COV.counts, not_covered: 0 } }

const DONE: EvidenceJob = {
  job_id: 'job-1', status: 'done', stage: 'Done', progress: 1, environment: 'dev', period: COV.period, gaps_acknowledged: true,
  started_at: 't', finished_at: 't', expires_at: 't2', seconds_left: 900, window_seconds: 900, error: null, reason: null,
  result: { sha256: 'a'.repeat(64), bytes: 5_242_880, chain_head: 'b'.repeat(64), events: 1200, report_rows: 900, coverage_pct: 97.8, gap_days: 2, zero_days: 8,
    pruned_days: 2, built_at: '2026-10-23T10:00:00.000Z', seconds: 4, data_as_of: null, verifier_sha256: 'c'.repeat(64), filename: 'evidence-package-dev.zip' },
}

function env(over: Record<string, unknown> = {}) {
  return { environments: [{ id: 'env-1', name: 'dev', shared: false, is_own: true, addressable: true, ...over }], active: 'dev', active_id: 'env-1' }
}

beforeEach(() => {
  sessionStorage.clear()
  vi.clearAllMocks()
  vi.mocked(fetchEnvironments).mockResolvedValue(env() as never)
  vi.mocked(checkEvidencePackage).mockResolvedValue(COV)
})

async function toCoverage() {
  fireEvent.click(await screen.findByRole('button', { name: 'Continue' }))                       // framework -> period
  fireEvent.click(screen.getByRole('button', { name: 'Check coverage' }))                         // period -> coverage
  await screen.findByText(/Coverage: 97.8% of 92 days/)
}

describe('the steps', () => {
  it('step 1 offers SOC 2, with ISO 27001 and SOX shown disabled as not available yet; the step heading takes focus on each step', async () => {
    renderWithClient(<EvidencePackage />)
    expect((await screen.findByRole('radio', { name: /SOC 2/ }) as HTMLInputElement).checked).toBe(true)
    for (const name of ['ISO 27001', 'SOX']) expect((screen.getByRole('radio', { name: new RegExp(name) }) as HTMLInputElement).disabled).toBe(true)
    expect(screen.getAllByText('Not available yet').length).toBe(2)
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }))
    const h = await screen.findByRole('heading', { name: /Step 2 of 6: Period/ })
    await waitFor(() => expect(document.activeElement).toBe(h))
  })

  it('step 2: presets fill UTC dates, custom dates are validated, nothing is checked until asked', async () => {
    renderWithClient(<EvidencePackage />)
    fireEvent.click(await screen.findByRole('button', { name: 'Continue' }))
    expect(screen.getByText(/UTC calendar days/)).toBeTruthy()
    fireEvent.click(screen.getByRole('radio', { name: 'Last 12 months' }))
    const start = screen.getByLabelText(/Start \(UTC date\)/) as HTMLInputElement
    expect(start.value).toMatch(/^\d{4}-\d{2}-\d{2}$/)
    fireEvent.change(start, { target: { value: '2999-01-01' } })
    expect((screen.getByRole('radio', { name: 'Custom dates' }) as HTMLInputElement).checked).toBe(true)
    expect(screen.getByRole('alert').textContent).toMatch(/after the end date|future/)
    expect((screen.getByRole('button', { name: 'Check coverage' }) as HTMLButtonElement).disabled).toBe(true)
    expect(checkEvidencePackage).not.toHaveBeenCalled()
  })

  it('step 3 states coverage as text, lists the gap days, and Continue waits for the acknowledgement', async () => {
    renderWithClient(<EvidencePackage />)
    await toCoverage()
    expect(checkEvidencePackage).toHaveBeenCalledWith('dev', expect.objectContaining({ start: expect.any(String) }), 'env-1')
    expect(screen.getByText('Gap: not covered').nextSibling?.textContent).toMatch(/2 days \(2026-08-10 to 2026-08-11\)/)
    expect(screen.getByText('Pruned by retention').nextSibling?.textContent).toMatch(/not gaps/)
    expect(screen.getByText('Covered, zero events').nextSibling?.textContent).toMatch(/8 days/)
    expect(screen.getByRole('status').textContent).toMatch(/2 days not covered \(gaps\)/)
    const next = screen.getByRole('button', { name: 'Continue' }) as HTMLButtonElement
    expect(next.disabled).toBe(true)
    const box = screen.getByRole('checkbox', { name: /no record of reading 2 days of this period \(2026-08-10 to 2026-08-11\).*may be missing/ })
    fireEvent.click(box)
    expect(next.disabled).toBe(false)
  })

  it('with no gaps there is nothing to acknowledge; with no coverage at all it cannot continue', async () => {
    vi.mocked(checkEvidencePackage).mockResolvedValue(NO_GAPS)
    const { unmount } = renderWithClient(<EvidencePackage />)
    await toCoverage()
    expect(screen.queryByRole('checkbox')).toBeNull()
    expect((screen.getByRole('button', { name: 'Continue' }) as HTMLButtonElement).disabled).toBe(false)
    unmount(); cleanup()
    vi.mocked(checkEvidencePackage).mockResolvedValue({ ...COV, has_coverage: false, covered_days: 0, coverage_pct: 0, needs_acknowledgement: false })
    renderWithClient(<EvidencePackage />)
    fireEvent.click(await screen.findByRole('button', { name: 'Continue' }))
    fireEvent.click(screen.getByRole('button', { name: 'Check coverage' }))
    expect((await screen.findByRole('status')).textContent).toMatch(/^No coverage/)
    expect((screen.getByRole('button', { name: 'Continue' }) as HTMLButtonElement).disabled).toBe(true)
  })

  it('step 4 previews the control matrix with the proposed label', async () => {
    renderWithClient(<EvidencePackage />)
    await toCoverage()
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }))
    await screen.findByRole('heading', { name: /Step 4 of 6: Control matrix/ })
    const table = screen.getByRole('table')
    expect(table.textContent).toContain('SOC 2 CC6.1')
    expect(table.textContent).toContain('mfa_enforcement, pam_secrets')
    expect(table.textContent).toContain('0 (none in the period)')
    expect(table.textContent?.match(/Proposed/g)?.length).toBe(2)
  })
})

describe('local mode: build, progress, result', () => {
  it('builds at once, announces progress, then shows the download with the 15-minute window, sha256 and chain head', async () => {
    vi.mocked(checkEvidencePackage).mockResolvedValue(NO_GAPS)
    vi.mocked(prepareEvidencePackage).mockResolvedValue({ job_id: 'job-1', status: 'running', environment: 'dev', period: COV.period })
    let calls = 0
    vi.mocked(fetchEvidencePackage).mockImplementation(async () => (++calls < 2
      ? { ...DONE, status: 'running', stage: 'Writing events', progress: 0.55, result: undefined, seconds_left: null }
      : DONE))
    renderWithClient(<EvidencePackage />)
    await toCoverage()
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }))     // matrix
    fireEvent.click(await screen.findByRole('button', { name: 'Continue' }))                                      // build
    fireEvent.click(await screen.findByRole('button', { name: 'Build the package' }))
    await waitFor(() => expect(prepareEvidencePackage).toHaveBeenCalledWith('dev', expect.any(Object), false, 'env-1'))
    const live = await screen.findByText(/Writing events \(55%\)/)
    expect(live.closest('[aria-live="polite"]')).toBeTruthy()
    expect(screen.getByLabelText('Build progress')).toBeTruthy()
    const link = (await screen.findByRole('link', { name: /Download the package/ }, { timeout: 4000 })) as HTMLAnchorElement
    expect(link.getAttribute('href')).toBe('/api/evidence_packages/job-1/download')
    expect(screen.getByText(/15 minutes after it was built: 15 minutes left/)).toBeTruthy()
    expect(screen.getByText('a'.repeat(64))).toBeTruthy()
    expect(screen.getByText('b'.repeat(64))).toBeTruthy()
    expect(screen.getByText(/Compare these two values with the server's build log/)).toBeTruthy()
    expect(screen.getByRole('link', { name: /Package format and checking steps/ })).toBeTruthy()
    await waitFor(() => expect(document.activeElement?.tagName).toBe('H2'))
  })

  it('a failed build says why, in text', async () => {
    vi.mocked(checkEvidencePackage).mockResolvedValue(NO_GAPS)
    vi.mocked(prepareEvidencePackage).mockResolvedValue({ job_id: 'job-2', status: 'running', environment: 'dev', period: COV.period })
    vi.mocked(fetchEvidencePackage).mockResolvedValue({ ...DONE, job_id: 'job-2', status: 'error', result: undefined, error: 'The package would be larger than the limit.', reason: 'size_limit' })
    renderWithClient(<EvidencePackage />)
    await toCoverage()
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Continue' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Build the package' }))
    expect((await screen.findByRole('alert')).textContent).toMatch(/was not built: The package would be larger than the limit/)
  })

  it('a refusal at start (a build is running) stays on the build step with the reason', async () => {
    vi.mocked(checkEvidencePackage).mockResolvedValue(NO_GAPS)
    vi.mocked(prepareEvidencePackage).mockRejectedValue(new Error('Another evidence package is being built on this server.'))
    renderWithClient(<EvidencePackage />)
    await toCoverage()
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Continue' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Build the package' }))
    expect((await screen.findByRole('alert')).textContent).toMatch(/Another evidence package is being built/)
    expect(screen.getByRole('button', { name: 'Build the package' })).toBeTruthy()
  })
})

describe('hosted mode: the MFA step-up keeps the period, the acknowledgement and the environment', () => {
  it('starts the step-up with an evidence_package record and builds nothing yet', async () => {
    vi.mocked(prepareEvidencePackage).mockResolvedValue({ step_up_required: true, action_id: 'act-1', action: 'evidence_package.build' })
    renderWithClient(<EvidencePackage />)
    await toCoverage()
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Continue' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Build the package' }))
    await waitFor(() => expect(readPendingStepUp()).not.toBeNull())
    const pending = readPendingStepUp()
    expect(pending).toMatchObject({ kind: 'evidence_package', environmentId: 'env-1', gapsAcknowledged: true, period: { start: expect.any(String), end: expect.any(String) } })
    expect(prepareEvidencePackage).toHaveBeenCalledWith('dev', expect.any(Object), true, 'env-1')
    expect(fetchEvidencePackage).not.toHaveBeenCalled()
  })

  it('after the approved save the page reopens at the build with the started job (inputs restored)', async () => {
    vi.mocked(fetchEvidencePackage).mockResolvedValue(DONE)
    renderWithClient(<EvidencePackage resume={{ environmentId: 'env-1', period: COV.period, gapsAcknowledged: true, jobId: 'job-1' }} />)
    expect(await screen.findByRole('link', { name: /Download the package/ })).toBeTruthy()
    expect(fetchEvidencePackage).toHaveBeenCalledWith('job-1')
  })

  it('when the save did not start a build, the page reopens at the coverage check with the same period and the acknowledgement kept', async () => {
    renderWithClient(<EvidencePackage resume={{ environmentId: 'env-1', period: COV.period, gapsAcknowledged: true, error: 'This approval was already used or abandoned.' }} />)
    await screen.findByText(/Coverage: 97.8% of 92 days/)
    expect(checkEvidencePackage).toHaveBeenCalledWith('dev', COV.period, 'env-1')
    expect(screen.getByText(/Period 2026-07-01 to 2026-09-30 \(UTC\)/)).toBeTruthy()
    expect(screen.getByRole('alert').textContent).toMatch(/was not built: This approval was already used or abandoned/)
  })

  it('a restored period is recognised as a custom one and the dates are not replaced', async () => {
    vi.mocked(fetchEvidencePackage).mockResolvedValue({ ...DONE, status: 'running', result: undefined, seconds_left: null })
    renderWithClient(<EvidencePackage resume={{ environmentId: 'env-1', period: { start: '2026-02-01', end: '2026-02-20' }, gapsAcknowledged: false, jobId: 'job-9' }} />)
    expect(await screen.findByLabelText('Build progress')).toBeTruthy()
  })
})

describe('permission', () => {
  it('a shared user who may not build is told so and given no controls', async () => {
    vi.mocked(fetchEnvironments).mockResolvedValue(env({
      is_own: false, shared: true,
      permissions: { view_archive: { value: 'allow', source: 'built_in' }, build_evidence_package: { value: 'deny', source: 'built_in' } },
    }) as never)
    renderWithClient(<EvidencePackage />)
    expect(await screen.findByText(/not available to you on 'dev'/)).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Continue' })).toBeNull()
  })
})
