import type { ReactNode } from 'react'

/** The auto-fit grid of an expanded row (columns of >= 300 px). */
export function DetailGrid({ children }: { children: ReactNode }) {
  return <div className="xp-detail-grid">{children}</div>
}

/** One titled block of an expanded row. `full` spans the whole grid. */
export function DetailSection({ title, children, full }: { title: ReactNode; children: ReactNode; full?: boolean }) {
  return (
    <div className={`xp-dsec${full ? ' is-full' : ''}`}>
      <h4>{title}</h4>
      {children}
    </div>
  )
}

/** Small bordered chip, the one tag style of the Explorer views. */
export function Chip({ children }: { children: ReactNode }) {
  return <span className="xp-tag">{children}</span>
}

export function ChipList({ children, empty = 'None' }: { children: ReactNode[]; empty?: string }) {
  return children.length > 0 ? <div>{children}</div> : <p className="xp-mute">{empty}</p>
}
