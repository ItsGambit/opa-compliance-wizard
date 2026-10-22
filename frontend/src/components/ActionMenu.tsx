import { useCallback, useEffect, useId, useRef, useState } from 'react'
import { ChevronDown } from 'lucide-react'

export interface ActionMenuItem {
  key: string
  label: string
  /** "menuitemradio" for a choice among several (paper size); the checked one says so to a screen reader. */
  kind?: 'item' | 'radio'
  checked?: boolean
  disabled?: boolean
  /** Draws a divider before this item. */
  separated?: boolean
  onSelect: () => void
}

interface Props {
  label: string
  items: ActionMenuItem[]
  /** Accessible name of the menu itself. */
  menuLabel?: string
}

/** A menu button (the Overview's "Export…"): a real menu for a keyboard and a screen reader. Opening focuses the first item; Up, Down,
 * Home and End move; Escape closes and returns focus to the button; Tab and a click outside close; choosing returns focus to the button. */
export function ActionMenu({ label, items, menuLabel }: Props) {
  const [open, setOpen] = useState(false)
  const buttonRef = useRef<HTMLButtonElement>(null)
  const menuRef = useRef<HTMLDivElement>(null)
  const wrapRef = useRef<HTMLDivElement>(null)
  const menuId = useId()
  const list = () => Array.from(menuRef.current?.querySelectorAll<HTMLButtonElement>('[role^="menuitem"]') ?? [])
  const close = useCallback((returnFocus: boolean) => { setOpen(false); if (returnFocus) buttonRef.current?.focus() }, [])

  useEffect(() => {
    if (!open) return
    const first = list().find(i => i.getAttribute('aria-disabled') !== 'true') ?? list()[0]
    first?.focus()
    const onDown = (e: MouseEvent) => { if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) setOpen(false) }
    document.addEventListener('mousedown', onDown)
    return () => document.removeEventListener('mousedown', onDown)
  }, [open])

  const onKey = (e: React.KeyboardEvent) => {
    const els = list()
    const at = els.indexOf(document.activeElement as HTMLButtonElement)
    const go = (i: number) => { e.preventDefault(); els[(i + els.length) % els.length]?.focus() }
    if (e.key === 'ArrowDown') go(at + 1)
    else if (e.key === 'ArrowUp') go(at <= 0 ? els.length - 1 : at - 1)
    else if (e.key === 'Home') go(0)
    else if (e.key === 'End') go(els.length - 1)
    else if (e.key === 'Escape') { e.preventDefault(); close(true) }
    else if (e.key === 'Tab') setOpen(false)
  }

  return (
    <div className="relative inline-flex" ref={wrapRef}>
      <button ref={buttonRef} type="button" className="btn-secondary" aria-haspopup="menu" aria-expanded={open} aria-controls={open ? menuId : undefined}
        onClick={() => setOpen(o => !o)} onKeyDown={e => { if (e.key === 'ArrowDown' && !open) { e.preventDefault(); setOpen(true) } }}>
        {label}<ChevronDown size={13} aria-hidden="true" />
      </button>
      {open && (
        <div id={menuId} ref={menuRef} role="menu" aria-label={menuLabel ?? label} onKeyDown={onKey}
          className="absolute right-0 top-full mt-1 z-20 min-w-[13rem] bg-bg-elevated border border-border rounded-lg shadow-[var(--shadow-xl)] p-1.5 flex flex-col gap-0.5">
          {items.map(item => (
            <div key={item.key} className="contents">
              {item.separated && <hr className="border-0 border-t border-border-sub my-1" />}
              <button type="button" tabIndex={-1} role={item.kind === 'radio' ? 'menuitemradio' : 'menuitem'} aria-checked={item.kind === 'radio' ? !!item.checked : undefined}
                aria-disabled={!!item.disabled}
                onClick={() => { if (item.disabled) return; setOpen(false); item.onSelect(); buttonRef.current?.focus() }}
                className="text-left text-[0.8125rem] px-2.5 py-1.5 rounded-md text-text-dim hover:bg-bg-hover aria-disabled:opacity-55 aria-disabled:cursor-not-allowed flex items-center justify-between gap-3">
                <span>{item.label}</span>{item.kind === 'radio' && item.checked && <span aria-hidden="true">✓</span>}
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
