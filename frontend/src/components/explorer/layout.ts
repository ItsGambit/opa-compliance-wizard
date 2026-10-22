/** Content-area widths (px) at which the Access Explorer changes shape. */
export const WIDE_MIN_WIDTH = 1100
export const COMPACT_MAX_WIDTH = 560

export type ExplorerLayoutMode = 'wide' | 'narrow' | 'compact'

/** The layout for the real width of the content container (NOT the window:
 * the SideNav takes width away). An unmeasurable width (0, e.g. before the
 * first layout or under jsdom) reads as the middle, stacked layout. */
export function layoutForWidth(width: number, wideMin: number = WIDE_MIN_WIDTH): ExplorerLayoutMode {
  if (!width || !Number.isFinite(width)) return 'narrow'
  if (width >= wideMin) return 'wide'
  if (width < COMPACT_MAX_WIDTH) return 'compact'
  return 'narrow'
}

/** Zebra stripe for the Nth VISIBLE row of a section. Computed in code from
 * the rendered (already filtered) list, never from CSS :nth-child, which
 * would also count rows a filter hides. The stripe's colours are theme
 * dependent and live in index.css (.xp-row[data-stripe]). */
export function stripeFor(visibleIndex: number): 'dark' | 'light' {
  return visibleIndex % 2 === 0 ? 'dark' : 'light'
}
