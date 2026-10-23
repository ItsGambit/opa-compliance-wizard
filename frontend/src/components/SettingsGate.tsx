import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Info, Loader2, Lock, LockOpen } from 'lucide-react'
import { lockSettings, startSettingsUnlock, isStepUpRequired } from '../api/client'
import { useSettingsStatus } from '../api/hooks'
import { toast } from '../hooks/useToast'
import { beginStepUp, type SettingsUnlockReopen } from '../utils/stepUp'
import { createRegistry, SettingsDraftContext } from './settingsDraft'
import { ErrorNotice } from './ErrorNotice'

/** Shown when the server did not send its own wording (it does: GET /api/settings/status `local_notice`). */
const LOCAL_NOTICE_FALLBACK =
  'No MFA in local mode. This computer runs the wizard without a login gate or identity provider, so Settings and Updates open ' +
  'without a second factor. Anyone who can use this computer as you can change these settings. Each opening is recorded in the Audit Log.'

/** Under this many seconds left the pill turns amber. */
const EXPIRING_SOON_SECONDS = 60

/** Seconds left in the unlock, counted down in the browser from what the server last said (its own clock decides; the
 * browser only measures the time since the answer arrived, never compares its clock with the server's). */
function useSecondsLeft(secondsLeft: number | undefined, answeredAt: number): number {
  const [, tick] = useState(0)
  useEffect(() => {
    if (!secondsLeft) return
    const id = setInterval(() => tick(n => n + 1), 1000)
    return () => clearInterval(id)
  }, [secondsLeft, answeredAt])
  if (!secondsLeft) return 0
  return Math.max(0, Math.ceil(secondsLeft - (Date.now() - answeredAt) / 1000))
}

function timeLeftLabel(seconds: number): string {
  return seconds >= EXPIRING_SOON_SECONDS ? `${Math.floor(seconds / 60)} min left` : `Expires in ${seconds} s`
}

interface Props {
  /** Which part of the app this gate protects: recorded in local mode, and where the unlock returns to. */
  area: 'settings' | 'updates'
  /** The screen to open again after the unlock (and to put the user's unsaved input back into). */
  reopen: SettingsUnlockReopen
  /** What the prompt names, e.g. "Access control". */
  what: string
  /** "Not now": the screen closes. */
  onNotNow: () => void
  children: ReactNode
}

/** 5.53.0: Settings and Updates ask for a fresh MFA before they show anything, then stay open for a short window.
 *
 * - Locked: a card with "Continue with Okta" and "Not now". Nothing behind it is mounted, so nothing is fetched.
 * - Unlocking: the button is disabled while the server stores the request; then the whole page goes to Okta and back
 *   (the same round trip as every other approval -- a redirect, not a popup).
 * - Unlocked: a pill "Unlocked · N min left" with "Lock now"; amber "Expires in N s" in the last minute. Nothing moves.
 * - Locked again while the screen is open: the content STAYS mounted so nothing typed is lost. A save asks for its own MFA
 *   anyway (and reopens the window), so it still works; to keep browsing, unlock again.
 * - Local mode (no login gate): no prompt, a persistent notice, and the server records each opening.
 *
 * The browser never decides anything: every protected request is checked by the server. This only explains it. */
export function SettingsGate({ area, reopen, what, onNotNow, children }: Props) {
  const drafts = useMemo(createRegistry, [])
  const queryClient = useQueryClient()
  const { data: status, isLoading, isError, error, refetch, isFetching, dataUpdatedAt } = useSettingsStatus(area)
  const seconds = useSecondsLeft(status?.mode === 'hosted' && status.unlocked ? status.seconds_left : undefined, dataUpdatedAt)
  const live = status?.mode === 'hosted' && status.unlocked && seconds > 0
  const [wasUnlocked, setWasUnlocked] = useState(false)
  useEffect(() => { if (live) setWasUnlocked(true) }, [live])

  // The countdown reached zero here: ask the server (another tab, or a save, may have extended the window).
  const ranOut = status?.mode === 'hosted' && status.unlocked && seconds === 0
  useEffect(() => { if (ranOut) void refetch() }, [ranOut, refetch])

  const unlock = useMutation({
    mutationFn: () => startSettingsUnlock(),
    onSuccess: resp => {
      if (isStepUpRequired(resp)) {
        beginStepUp(resp.action_id, { kind: 'settings_unlock', startedAt: Date.now(), reopen, ...drafts.collect() })
        return
      }
      void queryClient.invalidateQueries({ queryKey: ['settings_status'] })
    },
    onError: (err: Error) => toast({ title: 'Could not start the unlock', description: err.message, variant: 'error' }),
  })

  const lock = useMutation({
    mutationFn: () => lockSettings(),
    onSuccess: () => {
      setWasUnlocked(false)
      void queryClient.invalidateQueries({ queryKey: ['settings_status'] })
    },
    onError: (err: Error) => toast({ title: 'Could not lock Settings', description: err.message, variant: 'error' }),
  })

  if (isLoading) return <div className="text-xs text-text-faint py-4">Loading…</div>
  if (isError || !status) {
    return <ErrorNotice title="Could not check whether Settings is unlocked" error={error} onRetry={() => { void refetch() }} retrying={isFetching} />
  }

  if (status.mode === 'local') {
    return (
      <>
        <div role="note" className="w-full border rounded px-3 py-2 mb-3 flex items-start gap-2 text-xs bg-accent-dim text-text border-accent/40">
          <Info size={14} className="shrink-0 mt-0.5" aria-hidden="true" />
          <span>{status.local_notice ?? LOCAL_NOTICE_FALLBACK}</span>
        </div>
        {children}
      </>
    )
  }

  if (!live && !wasUnlocked) {
    return (
      <div className="card p-4 flex flex-col gap-3" role="region" aria-label={`Unlock ${what}`}>
        <div className="flex items-start gap-2">
          <Lock size={16} className="shrink-0 mt-0.5 text-text-dim" aria-hidden="true" />
          <div className="flex flex-col gap-1">
            <div className="text-sm font-semibold text-text">Unlock {what} with MFA</div>
            <p className="text-xs text-text-dim leading-relaxed">
              You will be sent to Okta and back. The unlock lasts 10 minutes, and every save still asks again.
            </p>
          </div>
        </div>
        <div className="flex justify-end gap-2">
          <button type="button" className="btn-secondary" onClick={onNotNow} disabled={unlock.isPending}>Not now</button>
          <button type="button" className="btn-primary" onClick={() => unlock.mutate()} disabled={unlock.isPending}>
            {unlock.isPending && <Loader2 size={13} className="animate-spin" aria-hidden="true" />}
            {unlock.isPending ? 'Preparing…' : 'Continue with Okta'}
          </button>
        </div>
      </div>
    )
  }

  const expiringSoon = live && seconds <= EXPIRING_SOON_SECONDS
  return (
    <SettingsDraftContext.Provider value={drafts.registry}>
      {live ? (
        <div className="flex items-center justify-end gap-2 mb-3 text-xs">
          <span
            className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border font-medium ${
              expiringSoon ? 'bg-warn/10 text-warn border-warn/40' : 'bg-accent-dim text-text border-accent/40'
            }`}
          >
            <LockOpen size={12} aria-hidden="true" />
            {expiringSoon ? timeLeftLabel(seconds) : `Unlocked · ${timeLeftLabel(seconds)}`}
          </span>
          <button
            type="button"
            className="underline bg-transparent border-0 p-0 cursor-pointer text-text-dim hover:text-text"
            onClick={() => lock.mutate()}
            disabled={lock.isPending}
          >
            Lock now
          </button>
          {/* Screen readers hear about the last minute once, not a countdown. */}
          <span role="status" className="sr-only">{expiringSoon ? 'Settings unlock expires in under a minute.' : ''}</span>
        </div>
      ) : (
        <div role="alert" className="w-full border rounded px-3 py-2 mb-3 flex items-start gap-2 text-xs bg-warn/10 text-text border-warn/40">
          <Lock size={14} className="shrink-0 mt-0.5 text-warn" aria-hidden="true" />
          <span className="flex-1">
            Settings locked again. What you typed is kept. Verify with Okta to carry on (this screen reopens with your input);
            a save asks for its own MFA anyway.
          </span>
          <button type="button" className="btn-secondary !py-0.5 !px-2 shrink-0" onClick={() => unlock.mutate()} disabled={unlock.isPending}>
            {unlock.isPending ? 'Preparing…' : 'Verify with Okta'}
          </button>
        </div>
      )}
      {children}
    </SettingsDraftContext.Provider>
  )
}
