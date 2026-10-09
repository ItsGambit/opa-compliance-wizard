import { useId, type ReactNode } from 'react'

interface Props {
  label: ReactNode
  /** Render the control with the id the label points at. */
  children: (id: string) => ReactNode
  hint?: ReactNode
  className?: string
}

/** UI-19 (external review, 2026-10-05): a visible label that is actually
 * associated with its control (<label htmlFor> + useId), so a screen reader
 * announces "Key Secret, edit text" rather than "edit text" -- the shared
 * replacement for the <span className="section-label"> + input pairs. */
export function Field({ label, children, hint, className = 'flex flex-col gap-1' }: Props) {
  const id = useId()
  return (
    <div className={className}>
      <label htmlFor={id} className="section-label block">{label}</label>
      {children(id)}
      {hint}
    </div>
  )
}
