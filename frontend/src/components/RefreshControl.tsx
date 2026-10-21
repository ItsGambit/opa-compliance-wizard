import { useCallback, useEffect, useId, useRef, useState } from 'react'
import { ChevronDown, Loader2, RefreshCw } from 'lucide-react'
import type { RefreshPartName } from '../types'

export interface RefreshMenuExtra {
  key: string
  label: string
  hint?: string
  onSelect: () => void
  disabled?: boolean
}

interface Props {
  /** A refresh is running (this one or another tab's): the main button reads "Refreshing…" and does nothing. */
  running: boolean
  /** Why the viewer may not refresh ('' when they may). The reason is read out and shown, not hidden in a tooltip (WCAG 2.1.1, 1.3.1). */
  disabledReason: string
  onRefresh: (parts?: RefreshPartName[]) => void
  /** Menu entries below the divider (Verify the chain, Build sign-in figures...). They are not refreshes and stay usable while one runs. */
  extras?: RefreshMenuExtra[]
}

const REFRESH_ITEMS: { key: string; label: string; hint: string; parts?: RefreshPartName[] }[] = [
  { key: 'all', label: 'Refresh everything', hint: 'OPA · Okta · System Log' },
  { key: 'opa', label: 'OPA scan only', hint: 'roster, policies, resources', parts: ['opa'] },
  { key: 'okta', label: 'Okta scan only', hint: 'admin roles, lifecycle, counts', parts: ['okta'] },
  { key: 'log', label: 'System Log only', hint: 'archive sync', parts: ['log'] },
]

/** The Overview's split button (5.51.0): the whole refresh is the primary action; single parts and the two non-refresh actions are in the
 * menu. A real menu button: the caret announces it opens a menu, opening focuses the first item, the arrow keys, Home and End move,
 * Escape closes and returns focus to the caret, Tab and a click outside close. */
export function RefreshControl({ running, disabledReason, onRefresh, extras = [] }: Props) {
  const [open, setOpen] = useState(false)
  const caretRef = useRef<HTMLButtonElement>(null)
  const menuRef = useRef<HTMLDivElement>(null)
  const wrapRef = useRef<HTMLDivElement>(null)
  const menuId = useId()
  const reasonId = useId()
  const blocked = !!disabledReason

  const items = () => Array.from(menuRef.current?.querySelectorAll<HTMLButtonElement>('[role="menuitem"]') ?? [])

  const close = useCallback((returnFocus: boolean) => {
    setOpen(false)
    if (returnFocus) caretRef.current?.focus()
  }, [])

  useEffect(() => {
    if (!open) return
    const first = items().find(i => i.getAttribute('aria-disabled') !== 'true') ?? items()[0]
    first?.focus()
    const onDown = (e: MouseEvent) => { if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) setOpen(false) }
    document.addEventListener('mousedown', onDown)
    return () => document.removeEventListener('mousedown', onDown)
  }, [open])

  const onMenuKey = (e: React.KeyboardEvent) => {
    const list = items()
    const at = list.indexOf(document.activeElement as HTMLButtonElement)
    const go = (i: number) => { e.preventDefault(); list[(i + list.length) % list.length]?.focus() }
    if (e.key === 'ArrowDown') go(at + 1)
    else if (e.key === 'ArrowUp') go(at <= 0 ? list.length - 1 : at - 1)
    else if (e.key === 'Home') go(0)
    else if (e.key === 'End') go(list.length - 1)
    else if (e.key === 'Escape') { e.preventDefault(); close(true) }
    else if (e.key === 'Tab') setOpen(false)
  }

  const refreshBlocked = blocked || running
  const pick = (disabled: boolean, run: () => void) => () => { if (disabled) return; setOpen(false); run() }

  return (
    <div className="flex flex-col gap-1">
      <div className="relative inline-flex" ref={wrapRef}>
        <button
          type="button"
          className="btn-primary rounded-r-none"
          aria-disabled={refreshBlocked}
          aria-describedby={blocked ? reasonId : undefined}
          onClick={() => { if (!refreshBlocked) onRefresh() }}
        >
          {running ? <Loader2 size={13} aria-hidden="true" className="animate-spin" /> : <RefreshCw size={13} aria-hidden="true" />}
          {running ? 'Refreshing…' : 'Refresh'}
        </button>
        <button
          type="button"
          ref={caretRef}
          className="btn-primary rounded-l-none border-l border-white/25 min-w-8 justify-center px-2"
          aria-label="More refresh options"
          aria-haspopup="menu"
          aria-expanded={open}
          aria-controls={open ? menuId : undefined}
          onClick={() => setOpen(o => !o)}
          onKeyDown={e => { if (e.key === 'ArrowDown' && !open) { e.preventDefault(); setOpen(true) } }}
        >
          <ChevronDown size={14} aria-hidden="true" />
        </button>
        {open && (
          <div id={menuId} ref={menuRef} role="menu" aria-label="Refresh options" onKeyDown={onMenuKey}
            className="absolute left-0 top-full mt-1 z-20 min-w-[16.5rem] bg-bg-elevated border border-border rounded-lg shadow-[var(--shadow-xl)] p-1.5 flex flex-col gap-0.5">
            {REFRESH_ITEMS.map(item => (
              <button key={item.key} type="button" role="menuitem" tabIndex={-1} aria-disabled={refreshBlocked}
                onClick={pick(refreshBlocked, () => onRefresh(item.parts))}
                className="text-left text-[0.8125rem] px-2.5 py-1.5 rounded-md flex justify-between gap-3 text-text-dim hover:bg-bg-hover aria-disabled:opacity-55 aria-disabled:cursor-not-allowed">
                <span>{item.label}</span><small className="text-muted text-[0.6875rem]">{item.hint}</small>
              </button>
            ))}
            {extras.length > 0 && <hr className="border-0 border-t border-border-sub my-1" />}
            {extras.map(x => (
              <button key={x.key} type="button" role="menuitem" tabIndex={-1} aria-disabled={!!x.disabled}
                onClick={pick(!!x.disabled, x.onSelect)}
                className="text-left text-[0.8125rem] px-2.5 py-1.5 rounded-md flex justify-between gap-3 text-text-dim hover:bg-bg-hover aria-disabled:opacity-55 aria-disabled:cursor-not-allowed">
                <span>{x.label}</span>{x.hint && <small className="text-muted text-[0.6875rem]">{x.hint}</small>}
              </button>
            ))}
          </div>
        )}
      </div>
      {blocked && <span id={reasonId} className="text-xs text-muted max-w-[60ch]">{disabledReason}</span>}
    </div>
  )
}
