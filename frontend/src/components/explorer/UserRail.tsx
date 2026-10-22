import { useMemo, useRef, useState } from 'react'
import { Search } from 'lucide-react'
import type { AccessModel } from '../../types'
import { useFuzzyFilter } from '../../utils/fuzzySearch'

const MAX_ROWS = 50
const KEYS = ['label', 'email', 'name', 'first', 'last']

interface Row { id: string; label: string; email: string; name: string; first: string; last: string; service: boolean; groupsError: boolean; flag: string }

interface Props {
  users: AccessModel['users']
  /** Okta lifecycle flag per user id (cross-check C1), shown as a suffix. */
  flags?: Record<string, 'inactive' | 'absent' | 'unknown' | null | undefined>
  selectedId?: string
  onSelect: (id: string) => void
}

function flagText(flag: string | null | undefined): string {
  return flag === 'inactive' ? 'Okta: inactive' : flag === 'absent' ? 'Okta: not found' : ''
}

/** The Users view's left rail (5.51.0, the approved mockup): a search box over a list of people, in place of a dropdown. A listbox with
 * one tab stop: Up, Down, Home and End move between people, Enter or Space picks one, and the search box above filters by name, login,
 * e-mail or first and last name. A person whose groups could not be read carries a warning (as text, not only a symbol). */
export function UserRail({ users, flags, selectedId, onSelect }: Props) {
  const [query, setQuery] = useState('')
  const listRef = useRef<HTMLUListElement>(null)
  const rows = useMemo<Row[]>(() => users.map(u => ({
    id: u.id, label: u.details?.full_name || u.name, email: u.details?.email ?? '', name: u.name, first: u.details?.first_name ?? '', last: u.details?.last_name ?? '',
    service: u.user_type === 'service', groupsError: !!u.groups_error, flag: flagText(flags?.[u.id]),
  })), [users, flags])
  const matches = useFuzzyFilter(rows, query, KEYS).map(m => m.item)
  const shown = query.trim() ? matches : rows
  const visible = shown.slice(0, MAX_ROWS)
  const focusableId = visible.some(r => r.id === selectedId) ? selectedId : visible[0]?.id

  const options = () => Array.from(listRef.current?.querySelectorAll<HTMLElement>('[role="option"]') ?? [])
  const onKey = (e: React.KeyboardEvent) => {
    const list = options()
    const at = list.indexOf(document.activeElement as HTMLElement)
    const go = (i: number) => { e.preventDefault(); list[Math.max(0, Math.min(list.length - 1, i))]?.focus() }
    if (e.key === 'ArrowDown') go(at + 1)
    else if (e.key === 'ArrowUp') go(at - 1)
    else if (e.key === 'Home') go(0)
    else if (e.key === 'End') go(list.length - 1)
    else if ((e.key === 'Enter' || e.key === ' ') && at >= 0) { e.preventDefault(); list[at].click() }
  }

  return (
    <div className="flex flex-col gap-1.5">
      <span className="section-label">Users</span>
      <label className="flex items-center gap-2 border border-border rounded-lg px-2.5 py-1.5 text-xs text-muted bg-bg-elevated">
        <Search size={13} aria-hidden="true" />
        <input type="search" aria-label="Search users" className="bg-transparent outline-none flex-1 min-w-0 text-text placeholder:text-muted" placeholder={`Search ${users.length.toLocaleString()} user${users.length === 1 ? '' : 's'}`}
          value={query} onChange={e => setQuery(e.target.value)} />
      </label>
      <ul ref={listRef} role="listbox" aria-label="Users" onKeyDown={onKey} className="list-none p-0 m-0 flex flex-col gap-0.5 max-h-72 overflow-y-auto">
        {visible.map(r => (
          <li key={r.id} role="option" aria-selected={r.id === selectedId} tabIndex={r.id === focusableId ? 0 : -1} onClick={() => onSelect(r.id)}
            className={`flex justify-between gap-2 px-2 py-1.5 rounded-md text-[0.8125rem] cursor-pointer ${r.id === selectedId ? 'bg-accent-dim text-accent-text' : 'text-text-dim hover:bg-bg-hover'}`}>
            <span className="min-w-0">
              <span className={r.service ? 'text-warn' : ''}>{r.label}</span>
              <small className="block text-[0.6875rem] text-muted break-words">{r.service ? 'service user · API key' : r.email}{r.flag ? ` · ${r.flag}` : ''}</small>
            </span>
            {r.groupsError && <small className="text-warn shrink-0" title="Groups could not be read for this person"><span aria-hidden="true">⚠</span><span className="sr-only">Groups could not be read</span></small>}
          </li>
        ))}
      </ul>
      {shown.length > visible.length && <small className="text-[0.6875rem] text-muted px-2">… {(shown.length - visible.length).toLocaleString()} more: search to narrow the list</small>}
      {shown.length === 0 && <small className="text-xs text-text-dim px-2" role="status">No user matches “{query}”.</small>}
    </div>
  )
}
