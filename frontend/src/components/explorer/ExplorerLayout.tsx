import { useCallback, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { ExplorerContext } from './explorerContext'
import { layoutForWidth, type ExplorerLayoutMode } from './layout'

interface Props {
  /** The selector / identity / counts / filters / export column. */
  rail: ReactNode
  children: ReactNode
  /** Accessible name of the rail landmark. */
  railLabel?: string
  /** Content width (px) from which the rail sits beside the main pane (default 1100). The Users view uses 900, as in the approved design. */
  wideMin?: number
  /** Rail width in CSS (default 264px; the Users view uses 300px). */
  railWidth?: string
}

/** Two-pane Access Explorer frame: a sticky left rail plus a wide main pane
 * when the CONTENT area is >= 1100 px, stacked below that. The width is
 * measured on an outer wrapper with a ResizeObserver (the grid itself never
 * observes its own size), so it follows the real page content width. */
export function ExplorerLayout({ rail, children, railLabel = 'Selection and filters', wideMin, railWidth }: Props) {
  const wrapRef = useRef<HTMLDivElement>(null)
  const [mode, setMode] = useState<ExplorerLayoutMode>('narrow')
  const [openRowId, setOpenRowId] = useState<string | null>(null)

  useLayoutEffect(() => {
    const el = wrapRef.current
    if (!el) return
    setMode(layoutForWidth(el.getBoundingClientRect().width, wideMin))
    if (typeof ResizeObserver === 'undefined') return
    const observer = new ResizeObserver(entries => {
      const entry = entries[entries.length - 1]
      if (entry) setMode(layoutForWidth(entry.contentRect.width, wideMin))
    })
    observer.observe(el)
    return () => observer.disconnect()
  }, [wideMin])

  const setOpen = useCallback((id: string | null) => setOpenRowId(id), [])
  const value = useMemo(() => ({ mode, wide: mode === 'wide', openRowId, setOpenRowId: setOpen }), [mode, openRowId, setOpen])

  return (
    <ExplorerContext.Provider value={value}>
      <div ref={wrapRef} className="xp-wrap" data-layout={mode} style={railWidth ? ({ '--xp-rail-w': railWidth } as React.CSSProperties) : undefined}>
        <div className="xp-page">
          <aside className="xp-rail" aria-label={railLabel}>{rail}</aside>
          <div className="xp-main">{children}</div>
        </div>
      </div>
    </ExplorerContext.Provider>
  )
}
