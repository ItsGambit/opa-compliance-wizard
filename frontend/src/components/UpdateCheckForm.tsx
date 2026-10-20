import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ShieldCheck } from 'lucide-react'
import { isStepUpRequired, saveUpgradeSettings } from '../api/client'
import { useWhoami } from '../api/hooks'
import { toast } from '../hooks/useToast'
import type { UpdateFrequency, UpgradeStatus } from '../types'
import { beginStepUp } from '../utils/stepUp'

const OPTIONS: { value: UpdateFrequency; title: string; text: string }[] = [
  { value: 'daily', title: 'Daily', text: ' (recommended) — about once a day, plus whenever an admin clicks Check now. A new release shows as a one-line banner to admins.' },
  { value: 'manual', title: 'Manual only', text: ' — only when an admin clicks Check now.' },
  { value: 'off', title: 'Off', text: ' — never contact the release server. You can still install from a signed file you carry in (README, "Upgrading": deploy.sh --from-dir).' },
]

interface Props {
  status: UpgradeStatus
  /** "Save with MFA" in hosted mode, "Save" in local mode -- decided here; this is for the secondary button. */
  secondaryLabel: string
  onSecondary: () => void
  onSaved?: () => void
}

/** The update-check choice: frequency (Daily / Manual / Off) and the optional "share my version" switch.
 * Hosted mode saves through the same step-up MFA round trip as other settings (the page leaves for a fresh
 * challenge and comes back to this screen); local mode has no identity provider and applies at once. */
export function UpdateCheckForm({ status, secondaryLabel, onSecondary, onSaved }: Props) {
  const { data: whoami } = useWhoami()
  const isLocal = !!whoami?.is_local
  const queryClient = useQueryClient()
  const [frequency, setFrequency] = useState<UpdateFrequency>(status.check.frequency ?? 'daily')
  const [share, setShare] = useState(status.check.share_version)
  const [second, setSecond] = useState(!!status.check.second_approval)
  const [channel, setChannel] = useState<'stable' | 'prerelease'>(status.check.channel ?? 'stable')
  const channelKnown = status.check.channel !== undefined
  const channelLocked = status.check.channel_source === 'env'
  const locked = status.check.env_locked

  const save = useMutation({
    mutationFn: () => saveUpgradeSettings({
      frequency, share_version: share,
      // only what changed, so an older server never sees a field it does not know
      ...(second !== !!status.check.second_approval ? { second_approval: second } : {}),
      ...(channelKnown && !channelLocked && channel !== status.check.channel ? { channel } : {}),
    }),
    onSuccess: resp => {
      if (isStepUpRequired(resp)) {
        // Hosted mode: approve with MFA first; the page leaves here and returns to Updates.
        beginStepUp(resp.action_id, {
          kind: 'environment_change', action: resp.action, label: 'Update check settings', startedAt: Date.now(), reopen: 'updates',
        })
        return
      }
      queryClient.invalidateQueries({ queryKey: ['upgrade_status'] })
      queryClient.invalidateQueries({ queryKey: ['audit_log'] })
      toast({ title: frequency === 'off' ? 'Update check is off' : 'Update check saved', variant: 'success',
        description: frequency === 'off' ? 'Nothing will be sent.' : frequency === 'daily' ? 'Checking now; the result appears here shortly.' : undefined })
      onSaved?.()
    },
    onError: (err: Error) => toast({ title: 'Could not change the update check', description: err.message, variant: 'error' }),
  })

  return (
    <form onSubmit={e => { e.preventDefault(); save.mutate() }}>
      <fieldset className="border-0 p-0 m-0 flex flex-col gap-2" disabled={locked}>
        <legend className="text-[11px] font-semibold uppercase tracking-[0.08em] text-muted mb-1.5">How often</legend>
        {OPTIONS.map(o => (
          <label key={o.value} className="flex gap-2 items-start p-2.5 border border-border rounded-lg bg-bg-card cursor-pointer text-xs text-text-dim">
            <input type="radio" name="update-frequency" className="mt-0.5 accent-[var(--color-accent)]" checked={frequency === o.value}
              onChange={() => setFrequency(o.value)} />
            <span><strong className="text-text">{o.title}</strong>{o.text}</span>
          </label>
        ))}
      </fieldset>
      <label className="flex gap-2.5 items-start mt-3 text-xs text-text-dim cursor-pointer">
        <input type="checkbox" className="mt-0.5 w-[15px] h-[15px] accent-[var(--color-accent)]" checked={share} disabled={locked}
          onChange={e => setShare(e.target.checked)} />
        <span>Include the installed version in the request (helps the maintainers see which versions are in use; off by default).</span>
      </label>
      {channelKnown && (
        <fieldset className="border-0 p-0 m-0 mt-3 flex flex-col gap-2" disabled={locked || channelLocked}>
          <legend className="text-[11px] font-semibold uppercase tracking-[0.08em] text-muted mb-1.5">Release channel</legend>
          {([['stable', 'Stable', ' (recommended) — only releases the maintainers marked as stable.'],
            ['prerelease', 'Pre-release', ' — also offers release candidates. For a test install, not for production.']] as const).map(([value, title, text]) => (
            <label key={value} className="flex gap-2 items-start p-2.5 border border-border rounded-lg bg-bg-card cursor-pointer text-xs text-text-dim">
              <input type="radio" name="update-channel" className="mt-0.5 accent-[var(--color-accent)]" checked={channel === value} onChange={() => setChannel(value)} />
              <span><strong className="text-text">{title}</strong>{text}</span>
            </label>
          ))}
          {channelLocked && <p className="text-xs text-muted m-0" role="status">The channel is set by this server's environment and cannot be changed here. Change it there (and restart).</p>}
        </fieldset>
      )}
      {!isLocal && status.upgrade && (
        <label className="flex gap-2.5 items-start mt-3 text-xs text-text-dim cursor-pointer">
          <input type="checkbox" className="mt-0.5 w-[15px] h-[15px] accent-[var(--color-accent)]" checked={second} disabled={locked}
            onChange={e => setSecond(e.target.checked)} />
          <span>Require a second admin to approve every upgrade (two-person rule; off by default). The first admin's approval is held for 24 hours.</span>
        </label>
      )}
      <div className="flex flex-wrap items-center gap-2 mt-4">
        <button type="submit" className="btn-primary" disabled={save.isPending || locked}>
          <ShieldCheck size={14} aria-hidden="true" />
          {isLocal ? 'Save' : 'Save with MFA'}
        </button>
        <button type="button" className="btn-secondary !text-text-dim" disabled={save.isPending} onClick={onSecondary}>{secondaryLabel}</button>
        <span className="text-xs text-muted">
          {isLocal
            ? 'This install has no identity provider, so the change applies at once. The choice is written to the audit log.'
            : 'Saving leaves this page for a fresh Okta MFA challenge, like other settings. The choice is written to the audit log.'}
        </span>
      </div>
    </form>
  )
}
