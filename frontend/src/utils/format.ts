export function labelize(key: string): string {
  return key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

/** Renders a value for on-screen display — empty/null/undefined become an
 * em dash so a field reads as "known to be empty" rather than looking
 * broken. Use `cellValue` instead for exports, where a plain empty string
 * is more useful for downstream processing. */
export function displayValue(value: unknown): string {
  if (value === null || value === undefined || value === '') return '—'
  if (Array.isArray(value) && value.length === 0) return '—'
  return cellValue(value)
}

/** Renders a value as plain text with no placeholder for empty — the
 * export-friendly counterpart to displayValue. */
export function cellValue(value: unknown): string {
  if (value === null || value === undefined) return ''
  if (typeof value === 'boolean') return value ? 'Yes' : 'No'
  if (Array.isArray(value)) return value.map(v => cellValue(v)).join(', ')
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}
