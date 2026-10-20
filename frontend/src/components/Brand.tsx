import type { ReactNode } from 'react'
import { BRAND_NAME } from '../utils/brand'

/** Logo B, the ledger shield: a shield holding two ledger lines and a tick. Colours come from the
 * theme tokens (--color-brand-shield / --color-brand-tick), so it reads on dark and light. */
export function BrandMark({ size = 20, title }: { size?: number; title?: string }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      role={title ? 'img' : undefined}
      aria-label={title}
      aria-hidden={title ? undefined : true}
      className="shrink-0"
    >
      <path d="M16 2.5 27 6.5V15c0 7.2-4.6 12-11 14.5C9.6 27 5 22.2 5 15V6.5Z" fill="none" stroke="var(--color-brand-shield)" strokeWidth="2.4" strokeLinejoin="round" />
      <path d="M11 11h10M11 15.5h10" stroke="var(--color-brand-shield)" strokeWidth="2.4" strokeLinecap="round" />
      <path d="m11.5 20.5 3 3 6-6.5" fill="none" stroke="var(--color-brand-tick)" strokeWidth="2.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

interface BrandProps {
  /** The mark (an SVG element); defaults to Logo B. Swap it here to rebrand every surface. */
  mark?: ReactNode
  wordmark?: string
  /** Omit in the sidebar (wordmark only); shown on About and similar surfaces. */
  tagline?: string
  /** 'row' = the sidebar's one-line brand; 'lockup' = large mark with the wordmark and tagline beside it. */
  variant?: 'row' | 'lockup'
}

/** The brand row / lockup. One component so the mark, wordmark and tagline can each be replaced in one place. */
export function Brand({ mark, wordmark = BRAND_NAME, tagline, variant = 'row' }: BrandProps) {
  if (variant === 'lockup') {
    return (
      <div className="flex items-center gap-4">
        {mark ?? <BrandMark size={56} title={`${BRAND_NAME} mark`} />}
        <div>
          <div className="text-2xl font-semibold tracking-tight leading-tight text-text">{wordmark}</div>
          {tagline && <div className="text-sm text-text-dim mt-1">{tagline}</div>}
        </div>
      </div>
    )
  }
  return (
    <span className="flex items-center gap-2 min-w-0">
      {mark ?? <BrandMark size={20} title={`${BRAND_NAME} mark`} />}
      <span className="text-sm font-semibold text-text leading-snug">{wordmark}</span>
    </span>
  )
}
