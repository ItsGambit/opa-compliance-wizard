import { useEffect, useMemo, useRef, useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { AlertTriangle, CheckCircle2, Download, Info } from 'lucide-react'
import { checkEvidencePackage, evidencePackageDownloadUrl, fetchEvidencePackage, isStepUpRequired, prepareEvidencePackage } from '../api/client'
import { useEnvironments } from '../api/hooks'
import type { EvidenceCoverage, EvidenceJobStarted, EvidencePeriod } from '../types'
import { activeRow, can, permissionReason } from '../utils/environmentRows'
import {
  coverageHeadline, coverageLines, dayCount, gapAcknowledgementLabel, minutesLeftText, periodError, presetPeriod, utcToday,
  type PeriodPreset,
} from '../utils/evidencePackage'
import { REPO_EVIDENCE_FORMAT_URL, REPO_EVIDENCE_GUIDE_URL } from '../utils/links'
import { beginStepUp } from '../utils/stepUp'
import { ErrorNotice } from './ErrorNotice'
import { StatusBadge } from './StatusBadge'

/** What App.tsx hands back after the MFA round trip: the inputs the person had (period, acknowledgement), the build the approved
 * save started (jobId), or why it did not start (error). */
export interface EvidenceResume {
  environmentId: string
  period: EvidencePeriod
  gapsAcknowledged: boolean
  jobId?: string
  error?: string
}

interface Props {
  resume?: EvidenceResume | null
  onResumeConsumed?: () => void
}

const STEPS = ['Framework', 'Period', 'Coverage check', 'Control matrix', 'Build', 'Result'] as const
type Step = 1 | 2 | 3 | 4 | 5 | 6

function inferPreset(period: EvidencePeriod): PeriodPreset {
  if (period.start === presetPeriod('last_quarter').start && period.end === presetPeriod('last_quarter').end) return 'last_quarter'
  if (period.start === presetPeriod('last_12_months').start && period.end === presetPeriod('last_12_months').end) return 'last_12_months'
  return 'custom'
}

/** The evidence package page (5.53.0): framework, period, coverage check, control matrix, build, result. One step at a time;
 * every step heading takes focus when the step changes, progress is announced in a live region, and every state is text. */
export function EvidencePackage({ resume, onResumeConsumed }: Props) {
  const { data: environments } = useEnvironments()
  const row = activeRow(environments)
  const environment = environments?.active ?? undefined
  // The inputs from the MFA round trip are read once: App clears `resume` as soon as the page has taken it.
  const [restored] = useState(resume ?? null)
  const autoChecked = useRef(false)
  const initialPeriod = resume?.period ?? presetPeriod('last_quarter')
  const [step, setStep] = useState<Step>(resume?.jobId ? 5 : resume ? 3 : 1)
  const [preset, setPreset] = useState<PeriodPreset>(resume ? inferPreset(resume.period) : 'last_quarter')
  const [period, setPeriod] = useState<EvidencePeriod>(initialPeriod)
  const [acknowledged, setAcknowledged] = useState(resume?.gapsAcknowledged ?? false)
  const [jobId, setJobId] = useState<string | null>(resume?.jobId ?? null)
  const [buildError, setBuildError] = useState<string | null>(resume?.error ?? null)
  const [coverage, setCoverage] = useState<EvidenceCoverage | null>(null)
  const headingRef = useRef<HTMLHeadingElement>(null)
  const moved = useRef(false)

  useEffect(() => { if (resume) onResumeConsumed?.() }, [resume, onResumeConsumed])
  useEffect(() => {
    if (moved.current) headingRef.current?.focus()
    moved.current = true
  }, [step])

  const allowed = !row || can(row, 'build_evidence_package')
  const periodProblem = periodError(period)

  const check = useMutation({
    mutationFn: () => checkEvidencePackage(environment!, period, row?.id),
    onSuccess: cov => { setCoverage(cov); setAcknowledged(a => (cov.needs_acknowledgement ? a : false)) },
  })

  // A return from the MFA step-up without a finished build re-runs the coverage check for the restored period.
  useEffect(() => {
    if (restored && !restored.jobId && environment && step === 3 && !autoChecked.current) {
      autoChecked.current = true
      check.mutate()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [environment])

  const build = useMutation({
    mutationFn: () => prepareEvidencePackage(environment!, period, acknowledged, row?.id),
    onSuccess: resp => {
      setBuildError(null)
      if (isStepUpRequired(resp)) {
        // Hosted mode: nothing is built until the MFA approval returns. The period and the acknowledgement go with the browser.
        beginStepUp(resp.action_id, {
          kind: 'evidence_package', startedAt: Date.now(), environmentId: row?.id ?? '', period, gapsAcknowledged: acknowledged,
        })
        return
      }
      setJobId((resp as EvidenceJobStarted).job_id)
      setStep(5)
    },
    onError: (err: Error) => setBuildError(err.message),
  })

  const job = useQuery({
    queryKey: ['evidence_package', jobId],
    queryFn: () => fetchEvidencePackage(jobId!),
    enabled: !!jobId,
    refetchInterval: query => (query.state.data?.status === 'running' ? 1000 : false),
    refetchOnWindowFocus: false,
    retry: false,
  })
  const jobData = job.data
  useEffect(() => { if (jobData && jobData.status !== 'running' && step === 5) setStep(6) }, [jobData, step])

  const [secondsLeft, setSecondsLeft] = useState<number | null>(null)
  useEffect(() => {
    if (jobData?.status !== 'done' || jobData.seconds_left == null) { setSecondsLeft(null); return }
    const until = Date.now() + jobData.seconds_left * 1000
    const tick = () => setSecondsLeft(Math.max(0, Math.round((until - Date.now()) / 1000)))
    tick()
    const t = setInterval(tick, 1000)
    return () => clearInterval(t)
  }, [jobData?.status, jobData?.seconds_left, jobData?.job_id])

  const applyPreset = (next: PeriodPreset) => {
    setPreset(next)
    if (next !== 'custom') setPeriod(presetPeriod(next))
    setCoverage(null)
    setAcknowledged(false)
  }
  const editPeriod = (patch: Partial<EvidencePeriod>) => {
    setPreset('custom')
    setPeriod(p => ({ ...p, ...patch }))
    setCoverage(null)
    setAcknowledged(false)
  }
  const restart = () => {
    setJobId(null); setBuildError(null); setCoverage(null); setAcknowledged(false); setStep(1)
  }

  const canContinueFromCoverage = !!coverage && coverage.has_coverage && (!coverage.needs_acknowledgement || acknowledged)
  const ackLabel = useMemo(() => (coverage ? gapAcknowledgementLabel(coverage) : ''), [coverage])

  if (!environment) return <div className="text-sm text-text-faint">Connect an environment first.</div>
  if (!allowed && row) {
    return (
      <section className="card p-4 flex flex-col gap-2 max-w-3xl" aria-labelledby="ep-denied">
        <h2 id="ep-denied" className="text-sm font-semibold text-text">Evidence packages are not available to you on '{environment}'</h2>
        <p className="text-xs text-text-dim">{permissionReason(row, 'build_evidence_package') || 'You may not build evidence packages from this environment.'}</p>
      </section>
    )
  }

  const heading = (text: string) => (
    <h2 ref={headingRef} tabIndex={-1} className="text-sm font-semibold text-text outline-none focus-visible:ring-2 focus-visible:ring-accent rounded">
      Step {step} of {STEPS.length}: {text}
    </h2>
  )

  return (
    <div className="flex flex-col gap-4 max-w-3xl">
      <ol className="flex flex-wrap gap-x-4 gap-y-1 text-xs" aria-label="Steps">
        {STEPS.map((name, i) => (
          <li key={name} aria-current={step === i + 1 ? 'step' : undefined} className={step === i + 1 ? 'text-text font-semibold' : step > i + 1 ? 'text-text-dim' : 'text-text-faint'}>
            {i + 1}. {name}{step > i + 1 ? ' (done)' : ''}
          </li>
        ))}
      </ol>

      <div className="card p-3 text-xs text-text-dim flex items-start gap-2" role="note">
        <Info size={14} className="shrink-0 mt-0.5" aria-hidden="true" />
        <span>
          A package holds people's names, email addresses, IP addresses and what they did, for the period you choose. It is not encrypted and
          not signed. Send it only to the people who need it, and build it well before the audit date.
        </span>
      </div>

      {step === 1 && (
        <section className="card p-4 flex flex-col gap-3" aria-labelledby="ep-s1">
          <div id="ep-s1">{heading('Framework')}</div>
          <fieldset className="flex flex-col gap-2">
            <legend className="sr-only">Framework</legend>
            <label className="flex items-start gap-2 text-sm text-text">
              <input type="radio" name="framework" checked readOnly className="mt-1" />
              <span>SOC 2 <StatusBadge label="Proposed mapping" variant="neutral" />
                <span className="block text-xs text-text-faint">Reports are grouped under SOC 2 criteria. The grouping is suggested by this project and has not been reviewed by an auditor.</span>
              </span>
            </label>
            {['ISO 27001', 'SOX'].map(name => (
              <label key={name} className="flex items-start gap-2 text-sm text-text-faint">
                <input type="radio" name="framework" disabled className="mt-1" aria-describedby={`ep-na-${name.replace(/\s/g, '')}`} />
                <span>{name} <span id={`ep-na-${name.replace(/\s/g, '')}`}>Not available yet</span></span>
              </label>
            ))}
          </fieldset>
          <div className="flex justify-end"><button type="button" className="btn-primary" onClick={() => setStep(2)}>Continue</button></div>
        </section>
      )}

      {step === 2 && (
        <section className="card p-4 flex flex-col gap-3" aria-labelledby="ep-s2">
          <div id="ep-s2">{heading('Period')}</div>
          <fieldset className="flex flex-wrap gap-4 text-sm text-text">
            <legend className="section-label mb-1">Period</legend>
            {([['last_quarter', 'Last quarter'], ['last_12_months', 'Last 12 months'], ['custom', 'Custom dates']] as const).map(([value, label]) => (
              <label key={value} className="flex items-center gap-1.5">
                <input type="radio" name="preset" checked={preset === value} onChange={() => applyPreset(value)} /> {label}
              </label>
            ))}
          </fieldset>
          <div className="flex flex-wrap items-end gap-3">
            <div className="field">
              <label htmlFor="ep-start" className="section-label block mb-1">Start (UTC date)</label>
              <input id="ep-start" type="date" className="text-input" value={period.start} max={period.end || utcToday()} onChange={e => editPeriod({ start: e.target.value })}
                aria-invalid={periodProblem ? true : undefined} />
            </div>
            <div className="field">
              <label htmlFor="ep-end" className="section-label block mb-1">End (UTC date, included)</label>
              <input id="ep-end" type="date" className="text-input" value={period.end} min={period.start} max={utcToday()} onChange={e => editPeriod({ end: e.target.value })}
                aria-invalid={periodProblem ? true : undefined} />
            </div>
          </div>
          <p className="text-xs text-text-faint">Dates are UTC calendar days, both included. {!periodProblem && `${dayCount(period).toLocaleString()} days.`}</p>
          {periodProblem && <div className="text-xs text-loss" role="alert">{periodProblem}</div>}
          <div className="flex justify-between">
            <button type="button" className="btn-secondary" onClick={() => setStep(1)}>Back</button>
            <button type="button" className="btn-primary" disabled={!!periodProblem} onClick={() => { setStep(3); check.mutate() }}>Check coverage</button>
          </div>
        </section>
      )}

      {step === 3 && (
        <section className="card p-4 flex flex-col gap-3" aria-labelledby="ep-s3">
          <div id="ep-s3">{heading('Coverage check')}</div>
          <p className="text-xs text-text-faint">Period {period.start} to {period.end} (UTC).</p>
          {buildError && <div className="text-xs text-loss" role="alert">The package was not built: {buildError} Your choices are restored below.</div>}
          <div role="status" aria-live="polite">
            {check.isPending && <p className="text-sm text-text-dim">Checking the archive…</p>}
            {coverage && (
              <p className="text-sm text-text flex items-start gap-2">
                {coverage.has_coverage && !coverage.needs_acknowledgement
                  ? <CheckCircle2 size={14} className="shrink-0 mt-0.5 text-win" aria-hidden="true" />
                  : <AlertTriangle size={14} className="shrink-0 mt-0.5 text-warn" aria-hidden="true" />}
                <span>{coverageHeadline(coverage)}</span>
              </p>
            )}
          </div>
          {check.isError && <ErrorNotice title="Could not check the period" error={check.error} onRetry={() => check.mutate()} retrying={check.isPending} />}
          {coverage && (
            <>
              <dl className="grid grid-cols-[minmax(0,14rem)_1fr] gap-x-3 gap-y-1 text-xs">
                {coverageLines(coverage).map(l => (
                  <div key={l.key} className="contents"><dt className="text-text-faint">{l.label}</dt><dd className="text-text">{l.text}</dd></div>
                ))}
                <div className="contents"><dt className="text-text-faint">Archive starts</dt><dd className="text-text">{coverage.archive_start_date ?? 'unknown'}</dd></div>
                <div className="contents"><dt className="text-text-faint">Data as of (last successful sync)</dt><dd className="text-text">{coverage.data_as_of ?? 'no successful sync recorded'}</dd></div>
                <div className="contents"><dt className="text-text-faint">Events in the period</dt><dd className="text-text">{coverage.events_in_period.toLocaleString()}</dd></div>
              </dl>
              {coverage.limits.length > 0 && (
                <details className="text-xs text-text-dim">
                  <summary className="cursor-pointer">How this was worked out, and its limits</summary>
                  <ul className="list-disc pl-4 mt-1 flex flex-col gap-1">{coverage.limits.map(l => <li key={l}>{l}</li>)}</ul>
                </details>
              )}
              {coverage.needs_acknowledgement && (
                <label className="flex items-start gap-2 text-sm text-text card p-2.5">
                  <input type="checkbox" className="mt-1" checked={acknowledged} onChange={e => setAcknowledged(e.target.checked)} />
                  <span>{ackLabel}</span>
                </label>
              )}
            </>
          )}
          <div className="flex justify-between">
            <button type="button" className="btn-secondary" onClick={() => setStep(2)}>Back</button>
            <button type="button" className="btn-primary" disabled={!canContinueFromCoverage} onClick={() => setStep(4)}>Continue</button>
          </div>
        </section>
      )}

      {step === 4 && coverage && (
        <section className="card p-4 flex flex-col gap-3" aria-labelledby="ep-s4">
          <div id="ep-s4">{heading('Control matrix')}</div>
          <p className="text-xs text-text-faint">What the package will hold, per SOC 2 criterion. A report that maps to two criteria appears under both. Every mapping is proposed, not reviewed by an auditor.</p>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <caption className="sr-only">Criteria, their reports, rows in the period and mapping status</caption>
              <thead><tr className="text-left text-text-faint border-b border-border">
                <th scope="col" className="py-1 pr-2 font-medium">Criterion</th><th scope="col" className="py-1 pr-2 font-medium">Reports</th>
                <th scope="col" className="py-1 pr-2 font-medium text-right">Rows</th><th scope="col" className="py-1 font-medium">Mapping</th>
              </tr></thead>
              <tbody>
                {coverage.controls.map(c => (
                  <tr key={c.control_id} className="border-b border-border-sub align-top">
                    <th scope="row" className="py-1.5 pr-2 text-left font-medium text-text">SOC 2 {c.control_id}</th>
                    <td className="py-1.5 pr-2 text-text-dim">{c.reports.join(', ')}</td>
                    <td className="py-1.5 pr-2 text-right text-text">{c.rows.toLocaleString()}{c.rows === 0 ? ' (none in the period)' : ''}</td>
                    <td className="py-1.5 text-text-dim">{c.mapping_status === 'proposed' ? 'Proposed' : 'Auditor-reviewed'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="flex justify-between">
            <button type="button" className="btn-secondary" onClick={() => setStep(3)}>Back</button>
            <button type="button" className="btn-primary" onClick={() => setStep(5)}>Continue</button>
          </div>
        </section>
      )}

      {step === 5 && (
        <section className="card p-4 flex flex-col gap-3" aria-labelledby="ep-s5">
          <div id="ep-s5">{heading('Build')}</div>
          {!jobId && (
            <>
              <p className="text-sm text-text-dim">
                Build a package for {period.start} to {period.end} (UTC) from the archive of '{environment}'.
                {acknowledged && ' The gap days you confirmed will be listed as gaps in it.'}
                {' '}On a hosted server you will be asked for MFA first; your choices are kept.
              </p>
              {buildError && <div className="text-xs text-loss" role="alert">{buildError}</div>}
              <div className="flex justify-between">
                <button type="button" className="btn-secondary" onClick={() => setStep(coverage ? 4 : 3)} disabled={build.isPending}>Back</button>
                <button type="button" className="btn-primary" disabled={build.isPending} onClick={() => build.mutate()}>
                  {build.isPending ? 'Starting…' : 'Build the package'}
                </button>
              </div>
            </>
          )}
          {jobId && (
            <div role="status" aria-live="polite" className="flex flex-col gap-2">
              {job.isError && <ErrorNotice title="Could not read the build's progress" error={job.error} onRetry={() => job.refetch()} retrying={job.isFetching} />}
              <p className="text-sm text-text">{jobData?.stage ?? 'Starting'} ({Math.round((jobData?.progress ?? 0) * 100)}%)</p>
              <progress className="w-full" max={100} value={Math.round((jobData?.progress ?? 0) * 100)} aria-label="Build progress" />
              <p className="text-xs text-text-faint">Building can take a few minutes for a large archive. You can leave this page open; the package is kept on the server for 15 minutes after it is finished.</p>
            </div>
          )}
        </section>
      )}

      {step === 6 && (
        <section className="card p-4 flex flex-col gap-3" aria-labelledby="ep-s6">
          <div id="ep-s6">{heading('Result')}</div>
          {jobData?.status === 'done' && jobData.result && (
            <>
              <p className="text-sm text-text flex items-start gap-2" role="status">
                <CheckCircle2 size={14} className="shrink-0 mt-0.5 text-win" aria-hidden="true" />
                <span>The package is ready: {jobData.result.events.toLocaleString()} events, {jobData.result.report_rows.toLocaleString()} report rows, {(jobData.result.bytes / 1048576).toFixed(1)} MB.</span>
              </p>
              <div className="flex flex-col gap-1">
                <a className="btn-primary self-start inline-flex items-center gap-1.5" href={evidencePackageDownloadUrl(jobData.job_id)} download={jobData.result.filename}
                  aria-disabled={secondsLeft === 0 ? true : undefined}>
                  <Download size={14} aria-hidden="true" /> Download the package
                </a>
                <p className="text-xs text-text-dim" role="status">
                  {secondsLeft === 0
                    ? 'The download window has ended and the package was deleted from the server. Build it again.'
                    : `Available for download for 15 minutes after it was built: ${secondsLeft != null ? minutesLeftText(secondsLeft) : ''}.`}
                </p>
              </div>
              <dl className="grid grid-cols-[minmax(0,10rem)_1fr] gap-x-3 gap-y-1 text-xs">
                <dt className="text-text-faint">Package sha256</dt><dd><code className="break-all text-text">{jobData.result.sha256}</code></dd>
                <dt className="text-text-faint">Chain head</dt><dd><code className="break-all text-text">{jobData.result.chain_head ?? 'none'}</code></dd>
                <dt className="text-text-faint">Built at (UTC)</dt><dd className="text-text">{jobData.result.built_at}</dd>
                <dt className="text-text-faint">Coverage</dt><dd className="text-text">{jobData.result.coverage_pct}% of the days; {jobData.result.gap_days} gap days, {jobData.result.zero_days} zero-event days, {jobData.result.pruned_days} pruned days</dd>
              </dl>
              <p className="text-xs text-text-dim">
                Compare these two values with the server's build log (Audit Log, the <code>evidence_package.build_finished</code> entry). The auditor's check prints
                the same two values; the build log is the independent record of who built the package.
              </p>
              <details className="text-xs text-text-dim">
                <summary className="cursor-pointer">How the package is checked</summary>
                <ol className="list-decimal pl-4 mt-1 flex flex-col gap-1">
                  <li>Get <code>verify_evidence_package.py</code> from the release (the authoritative sha256 is in the signed release and its notes and on the signing-key page; the copy inside the package is a convenience).</li>
                  <li>Run <code>python3 -I verify_evidence_package.py package.zip</code>. It reads the zip without unpacking it and ends with <code>RESULT: PASS</code> or <code>RESULT: FAIL</code>.</li>
                  <li>It detects accidental or partial change and checks the events against the archive's hash chain as it stood at build time. The hashes are unkeyed and the package is not signed.</li>
                </ol>
                <p className="mt-1">
                  <a className="text-accent-text underline underline-offset-2" href={REPO_EVIDENCE_FORMAT_URL} target="_blank" rel="noreferrer">Package format and checking steps</a>
                  {' · '}
                  <a className="text-accent-text underline underline-offset-2" href={REPO_EVIDENCE_GUIDE_URL} target="_blank" rel="noreferrer">Administrator's guide</a>
                </p>
              </details>
            </>
          )}
          {jobData?.status === 'error' && (
            <div role="alert" className="text-sm text-loss flex items-start gap-2">
              <AlertTriangle size={14} className="shrink-0 mt-0.5" aria-hidden="true" />
              <span>The package was not built: {jobData.error}</span>
            </div>
          )}
          {jobData?.status === 'expired' && (
            <p role="status" className="text-sm text-text-dim">The download window for this package has ended and it was deleted from the server. Build it again.</p>
          )}
          <div className="flex justify-between">
            <button type="button" className="btn-secondary" onClick={restart}>{jobData?.status === 'done' ? 'Build another' : 'Start again'}</button>
          </div>
        </section>
      )}
    </div>
  )
}
