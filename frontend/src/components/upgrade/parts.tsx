import type { ReactNode } from 'react'

export type Tone = 'ok' | 'err' | 'warn' | 'acc' | 'neu'
const TONE: Record<Tone, string> = {
  ok: 'bg-win/10 text-win border-win/40',
  err: 'bg-loss/10 text-loss border-loss/40',
  warn: 'bg-warn/10 text-warn border-warn/40',
  acc: 'bg-accent-dim text-accent-text border-accent/50',
  neu: 'bg-bg-hover text-text-dim border-border',
}

export function Badge({ tone, children }: { tone: Tone; children: ReactNode }) {
  return (
    <span className={`inline-flex items-center gap-1 text-[11px] font-medium px-1.5 py-0.5 rounded border whitespace-nowrap align-middle ${TONE[tone]}`}>
      {children}
    </span>
  )
}

export function KeyId({ id, struck }: { id: string; struck?: boolean }) {
  return <code className={`font-mono text-xs ${struck ? 'line-through' : ''}`}>{id}</code>
}

export function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <>
      <span className="text-[11px] font-semibold uppercase tracking-[0.08em] text-muted">{label}</span>
      <span className="text-text-dim">{children}</span>
    </>
  )
}

export const KV = 'grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-xs items-baseline'
export const CARD_TITLE = 'm-0 mb-2.5 text-sm font-semibold flex items-center gap-2 flex-wrap text-text'
export const SEC_LABEL = 'text-[11px] font-semibold uppercase tracking-[0.08em] text-muted'

/** The small accent ring used for "now / working" (mockups: .spin). */
export function Spinner({ size = 14 }: { size?: number }) {
  return (
    <span aria-hidden="true" className="inline-block rounded-full border-2 border-accent border-t-transparent animate-spin shrink-0" style={{ width: size, height: size }} />
  )
}

export function CommandBlock({ children, label }: { children: string; label: string }) {
  return (
    <code aria-label={label} className="block p-2 rounded bg-bg-elevated text-text break-all select-all font-mono text-xs">{children}</code>
  )
}

/** A release's change summary ("5.48.0 — title\nparagraph…") with the version in bold, as the mockups show it. */
export function Excerpt({ text }: { text: string }) {
  const lines = text.split('\n')
  const m = /^(\d+\.\d+\.\d+)( — )(.*)$/.exec(lines[0] ?? '')
  const rest = lines.slice(1).join('\n').trim()
  return (
    <p className="m-0 text-xs text-text-dim whitespace-pre-line max-w-[80ch]">
      {m ? <><strong className="text-text">{m[1]}</strong>{m[2]}{m[3]}{rest ? '\n' + rest : ''}</> : text}
    </p>
  )
}
