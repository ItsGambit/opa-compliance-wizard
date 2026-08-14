interface Props {
  label: string
  variant: 'neutral' | 'exists' | 'new' | 'created' | 'error'
}

const VARIANT_CLASSES: Record<Props['variant'], string> = {
  neutral: 'bg-bg-hover text-text-faint border-border',
  exists: 'bg-accent-dim text-accent border-accent/40',
  new: 'bg-bg-hover text-text-dim border-border',
  created: 'bg-win/10 text-win border-win/40',
  error: 'bg-loss/10 text-loss border-loss/40',
}

export function StatusBadge({ label, variant }: Props) {
  return (
    <span className={`text-[0.6875rem] font-medium px-1.5 py-0.5 rounded border ${VARIANT_CLASSES[variant]} whitespace-nowrap`}>
      {label}
    </span>
  )
}
