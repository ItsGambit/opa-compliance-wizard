import { AlertTriangle } from 'lucide-react'

/** UI-04 (external review, 2026-10-05): a failed load must never look like
 * an empty result -- a compliance report that says "No events found" when
 * the query actually failed points an auditor the wrong way. Shared error
 * card with an optional Retry. */
export function ErrorNotice({ title, error, onRetry, retrying }: {
  title: string
  error: unknown
  onRetry?: () => void
  retrying?: boolean
}) {
  const message = error instanceof Error ? error.message : error ? String(error) : 'Unknown error'
  return (
    <div className="card p-3 text-sm text-loss flex items-start gap-2" role="alert">
      <AlertTriangle size={14} className="shrink-0 mt-0.5" aria-hidden="true" />
      <div className="flex-1 min-w-0">
        <div className="font-medium">{title}</div>
        <div className="text-xs text-text-dim mt-0.5 break-words">{message}</div>
      </div>
      {onRetry && (
        <button type="button" className="btn-secondary text-xs shrink-0" onClick={onRetry} disabled={retrying}>
          {retrying ? 'Retrying…' : 'Retry'}
        </button>
      )}
    </div>
  )
}
