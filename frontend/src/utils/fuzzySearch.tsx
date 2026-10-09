import Fuse from 'fuse.js'
import { useMemo, type JSX } from 'react'

export interface FuzzyMatch {
  item: unknown
  matches: { key: string; indices: [number, number][] }[]
}

/** Every existing filter/picker in this app (Select dropdowns, the
 * Compliance Report table's per-column filters) used to be plain
 * case-insensitive substring matching -- no typo tolerance, and no way to
 * show WHY a result matched. This hook is the one shared fuzzy-matching
 * implementation for the whole app (Select.tsx, ComplianceReportDetail.tsx,
 * ResourcesTab.tsx all use it) so every picker upgrades consistently
 * instead of each growing its own slightly-different matcher.
 *
 * Returns EVERY item unfiltered (as { item, matches: [] }) when `query` is
 * blank -- matches the "no filter = show all" behavior every existing
 * picker already had, so this is a drop-in upgrade, not a behavior change
 * for the empty-query case. `keys` are dot-paths into each item (Fuse's own
 * key syntax, e.g. "details.email") -- pass every field a user might
 * reasonably type into, not just the primary display label, so e.g.
 * searching a user by email still works. */
export function useFuzzyFilter<T>(items: T[], query: string, keys: string[]): { item: T; matches: FuzzyMatch['matches'] }[] {
  // FE-12: the index is rebuilt when the key LIST changes (by value, so a
  // new array literal with the same keys each render costs nothing).
  const keysSignature = keys.join('\u0000')
  const fuse = useMemo(
    () =>
      new Fuse(items, {
        keys,
        includeMatches: true,
        threshold: 0.4, // Fuse's own tuned default range for "typo tolerant but not noisy" -- 0 is exact-only, 1 matches almost anything
        ignoreLocation: true, // a match anywhere in the string counts, not just near Fuse's default 0-index window (a UUID/hostname match happens anywhere)
      }),
    // keysSignature stands in for `keys` (same contents => same index).
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [items, keysSignature]
  )

  return useMemo(() => {
    const trimmed = query.trim()
    if (!trimmed) return items.map(item => ({ item, matches: [] }))
    return fuse.search(trimmed).map(result => ({
      item: result.item,
      matches: (result.matches ?? []).map(m => ({ key: String(m.key), indices: m.indices as [number, number][] })),
    }))
  }, [fuse, items, query])
}

/** Renders `text` with the character ranges in `indices` (Fuse's own
 * 0-indexed, inclusive-inclusive [start, end] pairs) wrapped for visual
 * highlighting -- the "hint" showing why a fuzzy result matched. Renders
 * plain text unchanged when there's nothing to highlight (e.g. the
 * no-query "show everything" case, or a field with no match on this
 * particular row). */
export function HighlightedText({ text, indices }: { text: string; indices?: [number, number][] }) {
  if (!indices || indices.length === 0) return <>{text}</>
  const sorted = [...indices].sort((a, b) => a[0] - b[0])
  const parts: JSX.Element[] = []
  let cursor = 0
  sorted.forEach(([rawStart, rawEnd], i) => {
    // FE-12: never trust the ranges to be in bounds or disjoint -- an
    // overlapping range used to print characters twice and move the
    // cursor backwards. Clamp to the text and to what is already printed;
    // the rendered text is always exactly `text`.
    const start = Math.max(rawStart, cursor, 0)
    const end = Math.min(rawEnd, text.length - 1)
    if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) return
    if (start > cursor) parts.push(<span key={`plain-${i}`}>{text.slice(cursor, start)}</span>)
    parts.push(
      <mark key={`hit-${i}`} className="bg-accent-dim text-text rounded-[2px] px-0">
        {text.slice(start, end + 1)}
      </mark>
    )
    cursor = end + 1
  })
  if (cursor < text.length) parts.push(<span key="plain-end">{text.slice(cursor)}</span>)
  return <>{parts}</>
}
