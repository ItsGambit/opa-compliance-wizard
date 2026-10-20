import * as Dialog from '@radix-ui/react-dialog'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, CheckCircle2, Download, ShieldAlert } from 'lucide-react'
import { saveUpgradeSettings } from '../api/client'
import { useUpgradeStatus } from '../api/hooks'
import { toast } from '../hooks/useToast'
import { formatDateTime } from '../utils/format'
import { describeCheckFailure } from '../utils/upgrade'
import { DialogCloseButton } from './DialogCloseButton'

interface Props {
  open: boolean
  onOpenChange: (open: boolean) => void
}

/** The admin-only Updates screen (5.46.0): notify-only. It shows whether a
 * newer release exists and how to install it from the server's shell; it
 * never installs anything. The daily check is OFF until an admin turns it
 * on (one request a day to GitHub; nothing about the tenant, users or data
 * is sent). */
export function UpdatesDialog({ open, onOpenChange }: Props) {
  const { data: status, isLoading, isError, error } = useUpgradeStatus(open)
  const queryClient = useQueryClient()
  const save = useMutation({
    mutationFn: (settings: { enabled?: boolean; share_version?: boolean }) => saveUpgradeSettings(settings),
    onSuccess: (_resp, vars) => {
      queryClient.invalidateQueries({ queryKey: ['upgrade_status'] })
      queryClient.invalidateQueries({ queryKey: ['audit_log'] })
      if (vars.enabled === true) toast({ title: 'Update check turned on', description: 'Checking now; the result appears here shortly.', variant: 'success' })
      if (vars.enabled === false) toast({ title: 'Update check is off', description: 'Nothing will be sent.', variant: 'success' })
    },
    onError: (err: Error) => toast({ title: 'Could not change the update check', description: err.message, variant: 'error' }),
  })

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/60 z-40" />
        <Dialog.Content aria-describedby={undefined} className="card fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-50 w-[calc(100vw-2rem)] sm:w-[32rem] max-h-[85vh] overflow-y-auto p-5">
          <div className="flex items-center justify-between mb-3">
            <Dialog.Title className="text-sm font-semibold text-text">Updates</Dialog.Title>
            <DialogCloseButton />
          </div>

          {isLoading && <p className="text-xs text-text-faint">Loading…</p>}
          {isError && <p role="alert" className="text-xs text-loss">Could not load the update status: {(error as Error).message}</p>}

          {status && (
            <div className="flex flex-col gap-4 text-xs text-text-dim leading-relaxed">
              <p>Installed version: <span className="font-medium text-text">{status.installed_version}</span></p>

              {status.check.prompt_needed && (
                <div className="card p-3 bg-bg-hover" role="group" aria-label="Turn on the daily update check?">
                  <p className="font-medium text-text mb-1">Turn on the daily update check?</p>
                  <p>
                    It is off, and nothing leaves this server until you turn it on. When on, the server asks GitHub once a day
                    for the latest release number. GitHub sees this server's IP address; <strong>nothing about your tenant, users or
                    data is sent</strong>. It only tells you a newer version exists; it never installs anything.
                  </p>
                  <div className="flex gap-2 mt-3">
                    <button type="button" className="btn-primary" disabled={save.isPending} onClick={() => save.mutate({ enabled: true })}>Turn on</button>
                    <button type="button" className="btn-secondary" disabled={save.isPending} onClick={() => save.mutate({ enabled: false })}>Keep it off</button>
                  </div>
                </div>
              )}

              {status.check.env_locked && (
                <p className="card p-3 bg-bg-hover" role="status">
                  The update check is set by this server's configuration (OPA_UPDATE_CHECK = {status.check.enabled ? 'on' : 'off'}).
                  Change it there; this screen cannot override it.
                </p>
              )}
              {status.check.env_invalid_value && (
                <p className="text-warn" role="alert">
                  OPA_UPDATE_CHECK has the value "{status.check.env_invalid_value}", which is ignored. Use "on" or "off".
                </p>
              )}

              {!status.check.prompt_needed && !status.check.enabled && !status.check.env_locked && (
                <div className="flex items-center justify-between gap-3">
                  <p>The daily update check is <strong>off</strong>. Nothing is sent.</p>
                  <button type="button" className="btn-secondary" disabled={save.isPending} onClick={() => save.mutate({ enabled: true })}>Turn on</button>
                </div>
              )}

              {status.check.enabled && (
                <>
                  {status.update_available && status.latest ? (
                    <div className="card p-3 border-accent" role="status">
                      <p className="flex items-center gap-1.5 font-medium text-text">
                        <Download size={14} aria-hidden="true" /> Version {status.latest.version} is available
                      </p>
                      <p className="mt-1 text-text-faint">
                        Published {formatDateTime(status.latest.published_at)}.{' '}
                        {status.latest.release_url && (
                          <a href={status.latest.release_url} target="_blank" rel="noreferrer noopener" className="underline">Read the release notes</a>
                        )}
                      </p>
                      {status.latest.signed_artifact ? (
                        <>
                          <p className="mt-2">To install it, run this on the server, as the account that owns the installation:</p>
                          <code className="block mt-1 p-2 rounded bg-bg-hover text-text break-all select-all">server/deploy.sh --release {status.latest.version}</code>
                          <p className="mt-2 text-text-faint">
                            The download is checked against this install's pinned signing key and refused if it is unsigned or altered.
                            Back up first (README, "Upgrading"). This screen does not install anything.
                          </p>
                        </>
                      ) : (
                        <p className="mt-2 flex items-start gap-1.5 text-warn" role="alert">
                          <AlertTriangle size={14} className="shrink-0 mt-0.5" aria-hidden="true" />
                          This release has no signed download attached, so it cannot be installed with the verified upgrade.
                          Wait for the maintainers to publish a signed one; do not install an unsigned copy on a production server.
                        </p>
                      )}
                    </div>
                  ) : (
                    <p className="flex items-center gap-1.5">
                      <CheckCircle2 size={14} className="text-accent" aria-hidden="true" />
                      {status.last_check.at
                        ? (status.latest ? `You are on the latest release (${status.latest.version}).` : 'No newer release was found.')
                        : 'Waiting for the first check…'}
                    </p>
                  )}

                  <div>
                    <p>
                      Last check: {status.last_check.at ? formatDateTime(status.last_check.at) : 'not yet'}
                      {status.last_check.next_at && status.last_check.status === 'ok' && <> · next {formatDateTime(status.last_check.next_at)}</>}
                    </p>
                    {status.last_check.consecutive_failures > 0 && (
                      <p className="text-warn mt-1" role="alert">
                        The last {status.last_check.consecutive_failures} check{status.last_check.consecutive_failures === 1 ? '' : 's'} failed
                        {status.last_check.failing_since && <> (since {formatDateTime(status.last_check.failing_since)})</>}:{' '}
                        {describeCheckFailure(status.last_check.code)}. It will try again by itself; details are in the Audit Log.
                      </p>
                    )}
                  </div>

                  {!status.check.env_locked && (
                    <label className="flex items-start gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        className="mt-0.5"
                        checked={status.check.share_version}
                        disabled={save.isPending}
                        onChange={e => save.mutate({ share_version: e.target.checked })}
                      />
                      <span>Share this server's version with GitHub in the check (off by default; helps the maintainers see which versions are in use).</span>
                    </label>
                  )}
                  {!status.check.env_locked && (
                    <div>
                      <button type="button" className="btn-secondary" disabled={save.isPending} onClick={() => save.mutate({ enabled: false })}>Turn the check off</button>
                    </div>
                  )}
                </>
              )}

              <div className="border-t border-border-sub pt-3">
                {status.signing_keys.error ? (
                  <p className="flex items-start gap-1.5 text-loss" role="alert">
                    <ShieldAlert size={14} className="shrink-0 mt-0.5" aria-hidden="true" />
                    The signing-key list on this server is damaged: {status.signing_keys.error}
                  </p>
                ) : status.signing_keys.pinned ? (
                  <p>Signed upgrades: this server has the project's release signing key pinned (last revocation serial {status.signing_keys.serial}).</p>
                ) : (
                  <p>
                    No release signing key is pinned on this server yet, so signed upgrades (<code>deploy.sh --release</code>) are not
                    available until the project publishes its key. Everything else works as before; existing installs are unaffected.
                  </p>
                )}
              </div>
            </div>
          )}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}
