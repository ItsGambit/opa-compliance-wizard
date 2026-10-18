import { useCallback, useState } from 'react'

/** Search text plus the set of ticked Filter entries, shared by every
 * Explorer view. `autoOpenKey` is what useSectionState watches: non-empty
 * while anything is searched or filtered, so matching sections open. */
export function useFilterState() {
  const [query, setQuery] = useState('')
  const [active, setActive] = useState<Set<string>>(() => new Set())
  const toggle = useCallback((id: string) => {
    setActive(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])
  const clear = useCallback(() => { setActive(new Set()); setQuery('') }, [])
  const filtering = query.trim() !== '' || active.size > 0
  const autoOpenKey = filtering ? `${query.trim()}|${[...active].sort().join(',')}` : ''
  return { query, setQuery, active, toggle, clear, filtering, autoOpenKey }
}
