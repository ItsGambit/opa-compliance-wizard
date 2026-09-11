import { ShieldCheck, ShieldOff } from 'lucide-react'
import { useSetPreserveLogsLocally } from '../hooks/useSetPreserveLogsLocally'

interface Props {
  enabled: boolean
  /** When given, renders as a clickable toggle (environment manager row)
   * instead of a plain read-only badge (Secrets Access Dashboard toolbar). */
  envName?: string
}

/** Clear on/off indicator for an environment's "preserve System Log
 * locally" setting — Okta's own System Log is capped at 90 days, so this
 * is the only way audit history for the Secrets Access Dashboard survives
 * longer than that. Deliberately never color-alone: an icon (ShieldCheck
 * vs ShieldOff) plus a text label, same "don't rely on color alone"
 * convention as ServiceAccountGroupStatus. */
export function LogRetentionIndicator({ enabled, envName }: Props) {
  const toggleMutation = useSetPreserveLogsLocally()

  const label = enabled ? 'Preserving logs locally' : 'Local log preservation off'
  const title = enabled
    ? 'System Log events for this environment are being cached to disk (secrets_log_cache.json) so history survives past Okta\'s 90-day retention.'
    : 'Only Okta\'s live 90-day System Log window is available — history older than that is unrecoverable.'
  const classes = `inline-flex items-center gap-1 text-xs shrink-0 ${enabled ? 'text-win' : 'text-text-faint'}`

  if (!envName) {
    return (
      <span className={classes} title={title}>
        {enabled ? <ShieldCheck size={12} /> : <ShieldOff size={12} />} {label}
      </span>
    )
  }

  return (
    <button
      type="button"
      className={`btn-secondary !py-0.5 !px-2 text-xs ${enabled ? '!text-win' : ''}`}
      disabled={toggleMutation.isPending}
      title={`${title} Click to turn ${enabled ? 'off' : 'on'}.`}
      onClick={() => toggleMutation.mutate({ name: envName, enabled: !enabled })}
    >
      {enabled ? <ShieldCheck size={12} /> : <ShieldOff size={12} />} {label}
    </button>
  )
}
