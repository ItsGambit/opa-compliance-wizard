/** Covers useFuzzyFilter's real behavioral contract (not the lint
 * suppression itself, which is a style choice documented in the hook's
 * own comment): a new `items` reference must always produce fresh
 * results, and the empty-query "show everything unfiltered" case must
 * match every existing picker's prior behavior exactly. Used by six
 * components (Select.tsx, ComplianceReportDetail.tsx, ResourcesTab.tsx,
 * ReportRowsTable.tsx, AuditLogPage.tsx, UsersTab.tsx) -- a regression
 * here has a six-way blast radius. */
import { render, renderHook, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { HighlightedText, useFuzzyFilter } from './fuzzySearch'

interface Item {
  name: string
  email: string
}

const ITEMS: Item[] = [
  { name: 'Alice Johnson', email: 'alice@example.com' },
  { name: 'Bob Smith', email: 'bob@example.com' },
  { name: 'Carol Davies', email: 'carol@example.com' },
]

describe('useFuzzyFilter', () => {
  it('returns every item unfiltered with empty matches when query is blank', () => {
    const { result } = renderHook(() => useFuzzyFilter(ITEMS, '', ['name', 'email']))
    expect(result.current).toHaveLength(3)
    expect(result.current.every(r => r.matches.length === 0)).toBe(true)
    expect(result.current.map(r => r.item)).toEqual(ITEMS)
  })

  it('a query that fuzzy-matches returns a non-empty result with populated matches', () => {
    const { result } = renderHook(() => useFuzzyFilter(ITEMS, 'alice', ['name', 'email']))
    expect(result.current.length).toBeGreaterThan(0)
    expect(result.current[0].item.name).toBe('Alice Johnson')
    expect(result.current[0].matches.length).toBeGreaterThan(0)
  })

  it('matches on a field other than the primary display label (e.g. email)', () => {
    const { result } = renderHook(() => useFuzzyFilter(ITEMS, 'bob@example.com', ['name', 'email']))
    expect(result.current.length).toBeGreaterThan(0)
    expect(result.current[0].item.name).toBe('Bob Smith')
  })

  it('a new items reference always produces fresh results -- no stale cache from an old Fuse index', () => {
    const { result, rerender } = renderHook(
      ({ items }: { items: Item[] }) => useFuzzyFilter(items, 'dana', ['name', 'email']),
      { initialProps: { items: ITEMS } }
    )
    expect(result.current).toHaveLength(0) // "dana" matches nothing in the original list

    const withDana = [...ITEMS, { name: 'Dana Lee', email: 'dana@example.com' }]
    rerender({ items: withDana })
    expect(result.current.length).toBeGreaterThan(0)
    expect(result.current[0].item.name).toBe('Dana Lee')
  })

  it('a new inline array literal for keys (same contents, new reference) does not break matching', () => {
    // Behavioral smoke test for the documented useMemo deps tradeoff --
    // asserts results stay correct across renders even when `keys` is a
    // fresh literal each time, NOT that the Fuse index wasn't rebuilt
    // (an implementation detail this test deliberately doesn't assert on).
    const { result, rerender } = renderHook(
      ({ keys }: { keys: string[] }) => useFuzzyFilter(ITEMS, 'carol', keys),
      { initialProps: { keys: ['name', 'email'] } }
    )
    expect(result.current[0]?.item.name).toBe('Carol Davies')

    rerender({ keys: ['name', 'email'] }) // new array, same contents
    expect(result.current[0]?.item.name).toBe('Carol Davies')
  })
})

describe('HighlightedText', () => {
  it('renders plain text unchanged when indices is undefined', () => {
    render(<HighlightedText text="hello world" />)
    expect(screen.getByText('hello world')).toBeTruthy()
    expect(document.querySelector('mark')).toBeNull()
  })

  it('renders plain text unchanged when indices is an empty array', () => {
    render(<HighlightedText text="hello world" indices={[]} />)
    expect(document.querySelector('mark')).toBeNull()
  })

  it('wraps a single matched range in <mark>', () => {
    render(<HighlightedText text="hello world" indices={[[0, 4]]} />)
    const mark = document.querySelector('mark')
    expect(mark?.textContent).toBe('hello')
  })

  it('handles multiple non-overlapping ranges in order', () => {
    render(<HighlightedText text="hello world" indices={[[6, 10], [0, 4]]} />)
    const marks = document.querySelectorAll('mark')
    expect(marks).toHaveLength(2)
    // Sorted by start index regardless of input order -- "hello" then "world".
    expect(marks[0].textContent).toBe('hello')
    expect(marks[1].textContent).toBe('world')
  })
})
