import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle } from 'lucide-react'
import { checkUpgradeNow, fetchAuditLog } from '../api/client'
import { useUpgradeStatus } from '../api/hooks'
import { toast } from '../hooks/useToast'
import type { AuditLogEntry, UpgradeKey, UpgradeStatus } from '../types'
import { formatDateTime } from '../utils/format'
import { roleLabel } from '../utils/upgrade'
import { Badge, KeyId } from './UpdatesPage'

const CARD_TITLE = 'm-0 mb-2.5 text-sm font-semibold flex items-center gap-2 flex-wrap text-text'
const TH = 'text-left text-[11px] font-semibold uppercase tracking-[0.08em] text-muted px-2 py-1.5 border-b border-border'
const TD = 'px-2 py-[7px] border-b border-border-sub align-top text-text-dim'

function can(key: UpgradeKey): [string, string] {
  if (key.status === 'revoked') return ['—', 'Anything. Signatures by this key are refused forever on this install.']
  if (key.status === 'retired') return ['—', 'Sign new releases.']
  return key.role === 'release'
    ? ['Sign releases; ship a successor primary in a release', 'Change the standby; undo a revocation']
    : ['Sign a revocation that revokes a primary and installs a new one', 'Sign a release']
}

function since(key: UpgradeKey): string {
  return key.status === 'revoked' && key.revoked_at ? `${key.since} → ${formatDateTime(key.revoked_at)}` : key.since
}

export function describeKeyEvent(e: AuditLogEntry): string {
  const d = e.details as Record<string, unknown>
  const list = (v: unknown) => (Array.isArray(v) ? v.join(', ') : '')
  if (e.action === 'upgrade.key_revoked') return `${list(d.revoked)} revoked${d.reason ? ` (${String(d.reason)})` : ''}; signed by ${String(d.signed_by ?? '—')}`
  if (e.action === 'upgrade.key_added') return `${list(d.added)} added, via revocation signed by ${String(d.signed_by ?? '—')}`
  if (e.action === 'upgrade.key_list_installed') return `Key list from release ${String(d.version ?? '—')}, signed by ${String(d.signed_by ?? '—')}`
  if (e.action === 'upgrade.key_revocation_rejected') return `A published revocation was rejected: ${String(d.reason ?? '—')}`
  return ''
}

function actorLabel(e: AuditLogEntry): string {
  return e.actor_email ?? (e.action.startsWith('upgrade.key_') ? 'update check (server)' : 'server')
}

function RevocationCard({ status }: { status: UpgradeStatus }) {
  const rev = status.revocation!
  const queryClient = useQueryClient()
  const checkNow = useMutation({
    mutationFn: checkUpgradeNow,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['upgrade_status'] }),
    onError: (err: Error) => toast({ title: 'Could not check now', description: err.message, variant: 'error' }),
  })
  const newKeys = status.signing_keys.keys.filter(k => rev.added.includes(k.key_id))
  return (
    <section className="card p-4 border-loss/50" aria-labelledby="t-rev">
      <h2 className={CARD_TITLE} id="t-rev">
        <AlertTriangle size={14} className="text-loss" aria-hidden="true" />
        Revocation applied <Badge tone="err">{rev.revoked.length === 1 ? 'A signing key was revoked' : 'Signing keys were revoked'}</Badge>
      </h2>
      <div className="grid gap-5 md:grid-cols-2">
        <div className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-xs items-baseline">
          <Label>Received</Label>
          <span className="text-text-dim">{formatDateTime(rev.applied_at)} · revocation serial {rev.serial} · from {rev.source === 'static_url' ? 'the owner-controlled static URL' : rev.source === 'file' ? 'a file applied by an operator' : 'the release channel'}</span>
          <Label>Signed by</Label>
          <span className="text-text-dim">standby key {rev.signed_by ? <KeyId id={rev.signed_by} /> : '—'} · signature verified against the pinned standby</span>
          <Label>Revokes</Label>
          <span className="text-text-dim">{rev.revoked.map(id => <span key={id} className="mr-2"><KeyId id={id} /></span>)} · reason: <em>{rev.reason}</em>
            {rev.advisory_url && <> · advisory <a href={rev.advisory_url} target="_blank" rel="noreferrer noopener" className="text-accent-text underline break-all">{rev.advisory_url}</a></>}</span>
          {newKeys.length > 0 && (<><Label>Installs</Label><span className="text-text-dim">{newKeys.map(k => <span key={k.key_id} className="mr-2">new {roleLabel(k).toLowerCase()} <KeyId id={k.key_id} /></span>)}</span></>)}
          <Label>Audit</Label>
          <span className="text-text-dim"><code className="font-mono text-xs">upgrade.key_revoked</code>{rev.added.length > 0 && <>, <code className="font-mono text-xs">upgrade.key_added</code></>} · actor: update check (server)</span>
        </div>
        <div>
          <div className="text-[11px] font-semibold uppercase tracking-[0.08em] text-muted mb-1.5">What this means for you</div>
          <ol className="m-0 pl-[22px] list-decimal flex flex-col gap-[7px] text-xs text-text-dim">
            <li>Nothing already installed changes. This version keeps running.</li>
            <li>A release signed by a revoked key after the revocation is refused by <code className="font-mono">deploy.sh --release</code>; releases it signed before the revocation stay valid.</li>
            <li>Confirm the revocation matches the published advisory before trusting anything new: open the advisory, and on the server run <code className="font-mono">python -m server.updater keys list</code> and compare the key ids shown here.</li>
            <li>Click Check now to look for the next release, which is signed by the new primary. Air-gapped installs apply the revocation from a file: <code className="font-mono">python -m server.updater keys apply-revocation revocation.json</code>.</li>
            <li>If this revocation looks wrong to you, do not install anything and contact the maintainers (SECURITY.md). A revocation cannot be undone by any key.</li>
          </ol>
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-2 mt-3">
        <button type="button" className="btn-primary" onClick={() => checkNow.mutate()} disabled={checkNow.isPending || !status.check.enabled}>Check now</button>
        {rev.advisory_url && <a href={rev.advisory_url} target="_blank" rel="noreferrer noopener" className="btn-secondary !text-text-dim no-underline">Open the advisory</a>}
        <span className="text-xs text-muted">The red banner stays for admins for 30 days after a revocation is applied.</span>
      </div>
    </section>
  )
}

function Label({ children }: { children: React.ReactNode }) {
  return <span className="text-[11px] font-semibold uppercase tracking-[0.08em] text-muted">{children}</span>
}

/** Updates > Release signing keys: the pinned keys, what each can and cannot do, and the key history from the audit log. */
export function UpdateKeysPage({ onBack }: { onBack: () => void }) {
  const { data: status, isLoading } = useUpgradeStatus(true)
  const { data: audit } = useQuery({ queryKey: ['audit_log', 'update-keys'], queryFn: () => fetchAuditLog(200, 0), staleTime: 30_000 })
  if (isLoading || !status) return <p className="text-xs text-muted">Loading…</p>
  const events = (audit?.entries ?? []).filter(e => e.action.startsWith('upgrade.key_')).slice(0, 15)
  const order = (k: UpgradeKey) => (k.role === 'release' && k.status === 'active' ? 0 : k.role === 'standby' && k.status === 'active' ? 1 : 2)
  const keys = [...status.signing_keys.keys].sort((a, b) => order(a) - order(b))
  return (
    <div className="flex flex-col gap-5">
      <button type="button" onClick={onBack} className="self-start text-xs text-accent-text underline bg-transparent border-0 p-0 cursor-pointer">← Back to Updates</button>
      {status.revocation && <RevocationCard status={status} />}
      <section className="card p-4" aria-labelledby="t-keys">
        <h2 className={CARD_TITLE} id="t-keys">Pinned keys</h2>
        {keys.length === 0 ? (
          <p className="text-xs text-text-dim m-0">No release signing key is pinned on this server yet. Signed upgrades are unavailable until the project publishes its key; nothing else is affected.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-xs">
              <thead><tr>
                <th scope="col" className={TH}>Role</th><th scope="col" className={TH}>Key id</th><th scope="col" className={TH}>Status</th>
                <th scope="col" className={TH}>Since</th><th scope="col" className={TH}>Can</th><th scope="col" className={TH}>Cannot</th>
              </tr></thead>
              <tbody>
                {keys.map(k => {
                  const [canText, cannotText] = can(k)
                  return (
                    <tr key={k.key_id}>
                      <td className={TD}>{roleLabel(k)}{k.status === 'revoked' && k.role === 'release' ? ' (old)' : ''}</td>
                      <td className={TD}><KeyId id={k.key_id} struck={k.status === 'revoked'} /></td>
                      <td className={TD}>
                        <Badge tone={k.status === 'active' ? (k.role === 'standby' ? 'neu' : 'ok') : k.status === 'revoked' ? 'err' : 'neu'}>
                          {k.status === 'revoked' ? 'Revoked' : k.status === 'retired' ? 'Retired' : k.role === 'standby' ? 'Standby · offline' : 'Active'}
                        </Badge>
                      </td>
                      <td className={TD}>{since(k)}</td><td className={TD}>{canText}</td><td className={TD}>{cannotText}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
        <p className="text-xs text-muted mt-2.5 mb-0">
          Stored in the install's <code className="font-mono">server/release_keys.json</code>, plus <code className="font-mono">release_keys.local.json</code> for what this install has learned (revocations and the highest revocation serial,
          currently {status.signing_keys.serial ?? 0}). A release can add or retire primary keys but can never change the standby or bring a revoked key back.
        </p>
      </section>
      <section className="card p-4" aria-labelledby="t-kh">
        <h2 className={CARD_TITLE} id="t-kh">Key history (audit log)</h2>
        {events.length === 0 ? (
          <p className="text-xs text-muted m-0">No key changes have been recorded on this install.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-xs">
              <thead><tr><th scope="col" className={TH}>When</th><th scope="col" className={TH}>Event</th><th scope="col" className={TH}>Detail</th><th scope="col" className={TH}>Actor</th></tr></thead>
              <tbody>
                {events.map((e, i) => (
                  <tr key={`${e.timestamp}-${e.action}-${i}`}>
                    <td className={TD}>{formatDateTime(e.timestamp)}</td>
                    <td className={TD}><code className="font-mono text-xs">{e.action}</code></td>
                    <td className={TD}>{describeKeyEvent(e)}</td>
                    <td className={TD}>{actorLabel(e)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  )
}
