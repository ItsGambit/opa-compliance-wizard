import { useCallback, useEffect, useState } from 'react'

export function sectionDomId(id: string): string {
  return `xp-sec-${id}`
}
export function sectionHeaderId(id: string): string {
  return `xp-sec-btn-${id}`
}

/** Open/closed state of a view's sections.
 *
 * - Until the user changes anything, only the first section is open.
 * - `resetKey` (the view's selection) puts that default back when it changes.
 * - `autoOpenKey`: while non-empty (a search or filter is active) and every
 *   time it changes, all sections that have rows open, so matches are seen.
 * - `jumpTo(id)` opens a section, scrolls to it and moves focus to its
 *   header (the count list in the rail uses it). */
export function useSectionState(sectionIds: string[], options: { resetKey?: string; autoOpenKey?: string } = {}) {
  const { resetKey = '', autoOpenKey = '' } = options
  const [open, setOpen] = useState<Set<string> | null>(null)
  const [pendingJump, setPendingJump] = useState<{ id: string; n: number } | null>(null)
  const idsSignature = sectionIds.join('\u0000')

  useEffect(() => { setOpen(null) }, [resetKey])
  useEffect(() => {
    if (autoOpenKey) setOpen(new Set(idsSignature ? idsSignature.split('\u0000') : []))
  }, [autoOpenKey, idsSignature])

  const isOpen = useCallback(
    (id: string) => (open ? open.has(id) : sectionIds[0] === id),
    // sectionIds is represented by idsSignature
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [open, idsSignature]
  )
  const current = useCallback(
    () => (open ? new Set(open) : new Set(sectionIds.slice(0, 1))),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [open, idsSignature]
  )
  const toggle = useCallback((id: string) => {
    const next = current()
    if (next.has(id)) next.delete(id)
    else next.add(id)
    setOpen(next)
  }, [current])
  const expandAll = useCallback(() => setOpen(new Set(idsSignature ? idsSignature.split('\u0000') : [])), [idsSignature])
  const collapseAll = useCallback(() => setOpen(new Set()), [])
  const jumpTo = useCallback((id: string) => {
    const next = current()
    next.add(id)
    setOpen(next)
    setPendingJump(prev => ({ id, n: (prev?.n ?? 0) + 1 }))
  }, [current])

  // Runs after the section has rendered open: scroll to it and focus its header.
  useEffect(() => {
    if (!pendingJump) return
    const section = document.getElementById(sectionDomId(pendingJump.id))
    section?.scrollIntoView?.({ behavior: 'smooth', block: 'start' })
    document.getElementById(sectionHeaderId(pendingJump.id))?.focus({ preventScroll: true })
  }, [pendingJump])

  return { isOpen, toggle, expandAll, collapseAll, jumpTo }
}

export type SectionState = ReturnType<typeof useSectionState>
