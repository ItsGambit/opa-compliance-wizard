import type { ReactNode } from 'react'
import { sectionDomId, sectionHeaderId } from './useSectionState'

interface Props {
  id: string
  title: string
  count: number
  open: boolean
  onToggle: () => void
  children: ReactNode
}

/** One resource-type section: a small header (name, muted count, chevron)
 * that expands and collapses the rows below it. */
export function TypeSection({ id, title, count, open, onToggle, children }: Props) {
  const bodyId = `${sectionDomId(id)}-body`
  return (
    <section id={sectionDomId(id)} className="xp-section" aria-labelledby={sectionHeaderId(id)}>
      <h3 className="xp-section-h">
        <button
          type="button"
          id={sectionHeaderId(id)}
          className="xp-section-btn"
          aria-expanded={open}
          aria-controls={bodyId}
          onClick={onToggle}
        >
          <span className="xp-section-name">{title}</span>
          <span className="xp-section-count">{count}</span>
          <span className="xp-chev" aria-hidden="true" />
        </button>
      </h3>
      {open && <div id={bodyId}>{children}</div>}
    </section>
  )
}
