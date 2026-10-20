import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, CheckCircle2, Download, RefreshCw, ShieldCheck } from 'lucide-react'
import { checkUpgradeNow } from '../api/client'
import { useUpgradeStatus } from '../api/hooks'
import { toast } from '../hooks/useToast'
import type { UpgradeStatus } from '../types'
import { formatDateTime } from '../utils/format'
import {
  activeReleaseKey, describeCheckFailure, formatBytes, frequencyLabel, updateState,
} from '../utils/upgrade'
import { UpdateCheckForm } from './UpdateCheckForm'

type Tone = 'ok' | 'err' | 'warn' | 'acc' | 'neu'
const TONE: Record<Tone, string> = {
  ok: 'bg-win/10 text-win border-win/40',
  err: 'bg-loss/10 text-loss border-loss/40',
  warn: 'bg-warn/10 text-warn border-warn/40',
  acc: 'bg-accent-dim text-accent-text border-accent/50',
  neu: 'bg-bg-hover text-text-dim border-border',
}

export function Badge({ tone, children }: { tone: Tone; children: React.ReactNode }) {
  return (
    <span className={`inline-flex items-center gap-1 text-[11px] font-medium px-1.5 py-0.5 rounded border whitespace-nowrap align-middle ${TONE[tone]}`}>
      {children}
    </span>
  )
}

export function KeyId({ id, struck }: { id: string; struck?: boolean }) {
  return <code className={`font-mono text-xs ${struck ? 'line-through' : ''}`}>{id}</code>
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <>
      <span className="text-[11px] font-semibold uppercase tracking-[0.08em] text-muted">{label}</span>
      <span className="text-text-dim">{children}</span>
    </>
  )
}

const KV = 'grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-xs items-baseline'
const CARD_TITLE = 'm-0 mb-2.5 text-sm font-semibold flex items-center gap-2 flex-wrap text-text'

/** How far the server's clock is from this browser's (seconds), for the "your browser agrees" note. */
function clockSkewSeconds(status: UpgradeStatus): number {
  return Math.round(Math.abs(new Date(status.server.time).getTime() - Date.now()) / 1000)
}

function StatusCard({ status, onCheckNow, checking }: { status: UpgradeStatus; onCheckNow: () => void; checking: boolean }) {
  const state = updateState(status)
  const { latest, last_check: last, check } = status
  const skew = clockSkewSeconds(status)
  const canCheck = check.enabled
  return (
    <section className="card p-4" aria-labelledby="t-status">
      <div className="flex justify-between gap-4 flex-wrap items-start">
        <div className="min-w-0 flex-1">
          <h2 className={CARD_TITLE} id="t-status">
            Installed version
            {state === 'up_to_date' && <Badge tone="ok"><CheckCircle2 size={12} aria-hidden="true" />Up to date</Badge>}
            {state === 'update_available' && <Badge tone="acc"><Download size={12} aria-hidden="true" />Update available</Badge>}
            {state === 'failed' && <Badge tone="warn"><AlertTriangle size={12} aria-hidden="true" />Last check failed</Badge>}
            {(state === 'not_enabled') && <Badge tone="neu">Update check not enabled</Badge>}
            {state === 'off' && <Badge tone="neu">Update check off</Badge>}
            {state === 'waiting' && <Badge tone="neu">Waiting for the first check</Badge>}
          </h2>
          <div className={KV}>
            <Row label="Installed">
              <strong className="text-text text-sm">{status.installed_version}</strong>
              {status.installed_at && <> · installed {formatDateTime(status.installed_at)}</>}
            </Row>
            <Row label="Latest stable">
              {latest
                ? <>{latest.version}{latest.published_at && <> (released {formatDateTime(latest.published_at)})</>}{!status.update_available && ' · no newer release'}</>
                : state === 'not_enabled' || !last.at ? 'Unknown — this server has never checked.' : 'No stable release is published.'}
            </Row>
            {last.at && (
              <Row label="Last check">
                {formatDateTime(last.at)} · result: {last.status === 'ok' ? (status.update_available ? 'newer release found' : 'up to date') : describeCheckFailure(last.code)}
                {last.by && <> · by {last.by.replace(/^admin:/, '')} (Check now)</>}
                {last.next_at && check.frequency === 'daily' && <> · next automatic check {formatDateTime(last.next_at)}</>}
              </Row>
            )}
            {!check.prompt_needed && <Row label="Server clock">
              {formatDateTime(status.server.time)}{status.server.zone && <> ({status.server.zone})</>} ·{' '}
              {skew <= 5 ? `your browser agrees within ${Math.max(skew, 1)} s` : <span className="text-warn">your browser differs by {skew} s</span>}
            </Row>}
          </div>
        </div>
        {check.prompt_needed ? null : <div className="flex gap-2 flex-wrap items-center shrink-0">
          <button type="button" className="btn-secondary !text-text-dim" onClick={onCheckNow} disabled={!canCheck || checking}
            title={canCheck ? undefined : 'Turn the update check on first'}>
            <RefreshCw size={14} aria-hidden="true" className={checking ? 'animate-spin' : ''} />Check now
          </button>
        </div>}
      </div>
      {!check.prompt_needed && (
        <p className="text-xs text-muted mt-3 mb-0">Check now asks the release server for the latest stable release. It is limited to once a minute and never installs anything.</p>
      )}
      {last.consecutive_failures > 0 && (
        <p className="text-xs text-warn mt-2 mb-0" role="alert">
          The last {last.consecutive_failures} check{last.consecutive_failures === 1 ? '' : 's'} failed
          {last.failing_since && <> (since {formatDateTime(last.failing_since)})</>}: {describeCheckFailure(last.code)}.
          It will try again by itself; details are in the Audit Log.
        </p>
      )}
    </section>
  )
}

function AvailableCard({ status }: { status: UpgradeStatus }) {
  const latest = status.latest!
  const key = activeReleaseKey(status)
  return (
    <>
      <section className="card p-4 border-accent/50" aria-labelledby="t-avail">
        <div className="flex justify-between gap-4 flex-wrap items-start">
          <div className="min-w-0 flex-1">
            <h2 className={CARD_TITLE} id="t-avail">
              {latest.version} is available
              {latest.signed_artifact
                ? <Badge tone="ok"><ShieldCheck size={12} aria-hidden="true" />Signed download attached</Badge>
                : <Badge tone="warn"><AlertTriangle size={12} aria-hidden="true" />No signed download</Badge>}
              {latest.signed_artifact && key && (
                <span className="text-xs text-muted font-normal">will be verified against key <KeyId id={key.key_id} /> (primary, active)</span>
              )}
            </h2>
            <div className={KV}>
              <Row label="Installed">{status.installed_version}{status.installed_at && <> · installed {formatDateTime(status.installed_at)}</>}</Row>
              <Row label="Available">
                <strong className="text-text text-sm">{latest.version}</strong>
                {latest.published_at && <> · released {formatDateTime(latest.published_at)}</>}
                {latest.signed_artifact && <> · <code className="font-mono text-xs">ocw-{latest.version}.tar.gz</code>{latest.size ? ` ${formatBytes(latest.size)}` : ''}</>}
                {latest.release_url && <> · <a href={latest.release_url} target="_blank" rel="noreferrer noopener" className="text-accent-text underline">release notes</a></>}
              </Row>
              <Row label="Downloaded">
                Not yet. The signed release is downloaded and verified on this server when you install it; the check itself never downloads anything.
              </Row>
              {status.last_check.at && (
                <Row label="Last check">{formatDateTime(status.last_check.at)}{status.last_check.by && <> · by {status.last_check.by.replace(/^admin:/, '')} (Check now)</>}</Row>
              )}
            </div>
          </div>
          <div className="flex gap-2 flex-wrap items-center shrink-0">
            <button type="button" className="btn-primary" disabled title="Upgrading from this page arrives in a later version">
              <Download size={14} aria-hidden="true" />Upgrade now
            </button>
            <button type="button" className="btn-secondary !text-text-dim" disabled title="Scheduling arrives in a later version">Schedule…</button>
          </div>
        </div>
        {latest.signed_artifact ? (
          <>
            <p className="text-xs text-muted mt-3 mb-1">
              Upgrading and scheduling from this page arrive in a later version. For now install from a shell on the server, as the account that owns the installation:
            </p>
            <code className="block p-2 rounded bg-bg-elevated text-text break-all select-all font-mono text-xs">server/deploy.sh --release {latest.version}</code>
            <p className="text-xs text-muted mt-2 mb-0">
              The download is checked against this install's pinned signing key and refused if it is unsigned or altered. Take a backup first (README, "Upgrading").
            </p>
          </>
        ) : (
          <p className="flex items-start gap-1.5 text-warn text-xs mt-3 mb-0" role="alert">
            <AlertTriangle size={14} className="shrink-0 mt-0.5" aria-hidden="true" />
            This release has no signed download attached, so it cannot be installed with the verified upgrade. Wait for the maintainers to
            publish a signed one; do not install an unsigned copy on a production server.
          </p>
        )}
      </section>
      {(latest.notes || latest.notes_title) && (
        <section className="card p-4" aria-labelledby="t-new">
          <h2 className={CARD_TITLE} id="t-new">What's new</h2>
          <div className="border-l-2 border-border pl-3">
            {latest.notes_title && <h3 className="m-0 mb-0.5 text-xs font-semibold text-text">{latest.notes_title}</h3>}
            {latest.notes && <p className="m-0 text-xs text-text-dim whitespace-pre-line">{latest.notes}</p>}
          </div>
          <p className="text-xs text-muted mt-2.5 mb-0">
            Excerpt of the release's published notes (not signed). The signed manifest inside the release is what is checked when you install.
          </p>
        </section>
      )}
    </>
  )
}

function CheckSettingsCard({ status }: { status: UpgradeStatus }) {
  const [editing, setEditing] = useState(false)
  const { check } = status
  return (
    <section className="card p-4" aria-labelledby="t-check">
      <h2 className={CARD_TITLE} id="t-check">Update check</h2>
      {editing && !check.env_locked ? (
        <UpdateCheckForm status={status} secondaryLabel="Cancel" onSecondary={() => setEditing(false)} onSaved={() => setEditing(false)} />
      ) : (
        <>
          <div className={KV}>
            <Row label="Schedule">{frequencyLabel(status)}</Row>
            <Row label="Sends">
              {check.frequency === 'off'
                ? 'Nothing: the check is off.'
                : <>One HTTPS request a day to <code className="font-mono text-xs">{checkHost(check.url)}</code> and nothing about your tenant, users or data.</>}
            </Row>
            <Row label="Version in request">{check.share_version ? 'Shared (on)' : 'Not shared (off)'}</Row>
            <Row label="Release channel">Stable{check.mirror && ' (via a configured mirror)'}</Row>
          </div>
          {check.env_locked ? (
            <p className="text-xs text-muted mt-3 mb-0" role="status">
              Set by this server's configuration (OPA_UPDATE_CHECK = {check.enabled ? 'on' : 'off'}). Change it there; this screen cannot override it.
            </p>
          ) : (
            <div className="flex flex-wrap items-center gap-2 mt-3">
              <button type="button" className="btn-secondary !text-text-dim" onClick={() => setEditing(true)}>Change…</button>
              <span className="text-xs text-muted">Changes need a step-up MFA approval, like other settings (local installs apply at once).</span>
            </div>
          )}
          {check.env_invalid_value && (
            <p className="text-xs text-warn mt-2 mb-0" role="alert">OPA_UPDATE_CHECK has the value "{check.env_invalid_value}", which is ignored. Use "on" or "off".</p>
          )}
        </>
      )}
    </section>
  )
}

function checkHost(url: string | undefined): string {
  try { return url ? new URL(url).host : 'the release server' } catch { return 'the release server' }
}

function FirstRunCard({ status, onNotNow }: { status: UpgradeStatus; onNotNow: () => void }) {
  return (
    <section className="card p-4 border-accent/50" aria-labelledby="t-enable">
      <h2 className={CARD_TITLE} id="t-enable">Enable the update check?</h2>
      <p className="text-xs text-text-dim mb-3 max-w-[80ch]">
        OPA Compliance Wizard does not contact anything until you choose. This is a one-time decision; you can change it here later.
      </p>
      <div className="grid gap-5 md:grid-cols-2">
        <div>
          <div className="text-[11px] font-semibold uppercase tracking-[0.08em] text-muted mb-1.5">What the check sends</div>
          <ul className="m-0 pl-[18px] list-disc flex flex-col gap-1.5 text-xs text-text-dim">
            <li>One HTTPS <code className="font-mono">GET</code> to <code className="font-mono break-all">{status.check.url ?? 'the release API'}</code>, once a day (or only when an admin clicks Check now).</li>
            <li>Request headers: <code className="font-mono">User-Agent: opa-compliance-wizard-update-check</code> and the <code className="font-mono">ETag</code> of the previous answer. That is all.</li>
            <li>GitHub sees this server's public IP address, as with any HTTPS request.</li>
          </ul>
        </div>
        <div>
          <div className="text-[11px] font-semibold uppercase tracking-[0.08em] text-muted mb-1.5">What it never sends</div>
          <ul className="m-0 pl-[18px] list-disc flex flex-col gap-1.5 text-xs text-text-dim">
            <li>Your tenant, environment names, users, groups, secrets, archive data or audit log.</li>
            <li>The installed version (unless you turn on the optional toggle below).</li>
            <li>Nothing is downloaded or installed by the check. An upgrade is always a separate, deliberate step.</li>
          </ul>
        </div>
      </div>
      <div className="mt-4">
        <UpdateCheckForm status={status} secondaryLabel="Not now" onSecondary={onNotNow} />
      </div>
      <p className="text-xs text-muted mt-3 mb-0">
        Fleet-managed servers can force this off with <code className="font-mono">OPA_UPDATE_CHECK=off</code> in <code className="font-mono">/etc/opa-compliance-wizard.env</code>;
        proxies use <code className="font-mono">https_proxy</code>; a corporate mirror uses <code className="font-mono">OPA_RELEASE_API_URL</code> (signatures are still verified against
        the pinned keys, so a mirror can delay a release but not change one).
      </p>
    </section>
  )
}

export function KeysSummaryCard({ status, onOpenKeys }: { status: UpgradeStatus; onOpenKeys: () => void }) {
  const keys = status.signing_keys
  const primary = keys.keys.filter(k => k.role === 'release')
  const standby = keys.keys.filter(k => k.role === 'standby')
  return (
    <section className="card p-4" aria-labelledby="t-keys">
      <h2 className={CARD_TITLE} id="t-keys">Release signing keys</h2>
      {keys.error ? (
        <p className="flex items-start gap-1.5 text-loss text-xs m-0" role="alert">
          <AlertTriangle size={14} className="shrink-0 mt-0.5" aria-hidden="true" />
          The signing-key list on this server is damaged: {keys.error}
        </p>
      ) : !keys.pinned ? (
        <p className="text-xs text-text-dim m-0">
          No release signing key is pinned on this server yet, so signed upgrades (<code className="font-mono">deploy.sh --release</code>) are not available until the
          project publishes its key. Everything else works as before; existing installs are unaffected.
        </p>
      ) : (
        <div className={KV}>
          <Row label="Primary">
            {primary.map(k => (
              <span key={k.key_id} className="mr-3">
                <KeyId id={k.key_id} struck={k.status === 'revoked'} /> · <Badge tone={k.status === 'active' ? 'ok' : k.status === 'revoked' ? 'err' : 'neu'}>{k.status === 'active' ? 'Active' : k.status === 'revoked' ? 'Revoked' : 'Retired'}</Badge>
                {k.status === 'active' && <> since {k.since} · signs releases</>}
              </span>
            ))}
          </Row>
          <Row label="Standby">
            {standby.map(k => (
              <span key={k.key_id} className="mr-3">
                <KeyId id={k.key_id} struck={k.status === 'revoked'} /> · <Badge tone="neu">{k.status === 'active' ? 'Standby' : k.status === 'revoked' ? 'Revoked' : 'Retired'}</Badge>
                {k.status === 'active' && <> pinned since {k.since}, kept offline · can only sign a revocation of the primary</>}
              </span>
            ))}
          </Row>
        </div>
      )}
      <p className="text-xs text-muted mt-2.5 mb-0">
        Revocations are fetched with the update check or applied from a file.{' '}
        <button type="button" className="text-accent-text underline bg-transparent border-0 p-0 cursor-pointer" onClick={onOpenKeys}>Details and history</button>
      </p>
    </section>
  )
}

/** The admin-only Updates page (5.46.0): notify-only. It shows whether a newer release exists and how to install it
 * from the server's shell; it never installs anything. The daily check is OFF until an admin chooses. */
export function UpdatesPage({ onOpenKeys }: { onOpenKeys: () => void }) {
  const { data: status, isLoading, isError, error } = useUpgradeStatus(true)
  const queryClient = useQueryClient()
  const [notNow, setNotNow] = useState(false)
  const checkNow = useMutation({
    mutationFn: checkUpgradeNow,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['upgrade_status'] })
      queryClient.invalidateQueries({ queryKey: ['audit_log'] })
    },
    onError: (err: Error) => toast({ title: 'Could not check now', description: err.message, variant: 'error' }),
  })

  if (isLoading) return <p className="text-xs text-muted">Loading…</p>
  if (isError || !status) return <p role="alert" className="text-xs text-loss">Could not load the update status: {(error as Error | null)?.message}</p>

  const state = updateState(status)
  return (
    <div className="flex flex-col gap-5">
      <StatusCard status={status} onCheckNow={() => checkNow.mutate()} checking={checkNow.isPending} />
      {state === 'update_available' && status.latest && <AvailableCard status={status} />}
      {status.check.prompt_needed && !notNow && <FirstRunCard status={status} onNotNow={() => setNotNow(true)} />}
      {status.check.prompt_needed && notNow && (
        <section className="card p-4 flex items-center justify-between gap-3 flex-wrap">
          <p className="text-xs text-text-dim m-0">The update check stays off until you choose. Nothing is sent.</p>
          <button type="button" className="btn-secondary !text-text-dim" onClick={() => setNotNow(false)}>Enable the update check…</button>
        </section>
      )}
      {!status.check.prompt_needed && <CheckSettingsCard status={status} />}
      {!status.check.prompt_needed && <KeysSummaryCard status={status} onOpenKeys={onOpenKeys} />}
    </div>
  )
}
