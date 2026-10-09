import { Lock } from 'lucide-react'
import type { FolderAccessEntry } from '../types'

interface Props {
  entries: FolderAccessEntry[] | undefined
  /** True until the folder has a real OPA ID (not yet created, or the
   * tree was edited since the last Load/Preview/Execute). */
  disabled: boolean
  onClick: () => void
}

export function FolderAccessBadge({ entries, disabled, onClick }: Props) {
  if (disabled) {
    return <span className="text-[0.6875rem] text-text-faint">—</span>
  }

  const groupNames = [...new Set((entries ?? []).flatMap(e => e.groups.map(g => g.name)))]
  const label =
    entries && entries.length > 0
      ? `${entries.length} polic${entries.length === 1 ? 'y' : 'ies'}${groupNames.length ? ` · ${groupNames.slice(0, 2).join(', ')}${groupNames.length > 2 ? '…' : ''}` : ''}`
      : 'No policy'

  return (
    <button
      type="button"
      onClick={onClick}
      className="flex items-center gap-1 text-[0.6875rem] text-text-faint hover:text-text-dim transition-colors whitespace-nowrap"
      title="Assign access"
    >
      <Lock size={11} aria-hidden="true" />
      {label}
    </button>
  )
}
