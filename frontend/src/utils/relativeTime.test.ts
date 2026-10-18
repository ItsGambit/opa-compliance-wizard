import { describe, expect, it } from 'vitest'
import { relativeTime } from './relativeTime'

const now = Date.parse('2026-10-18T12:00:00Z')

describe('relativeTime', () => {
  it('formats minutes, hours, days and months', () => {
    expect(relativeTime('2026-10-18T11:59:30Z', now)).toBe('just now')
    expect(relativeTime('2026-10-18T11:45:00Z', now)).toBe('15 minutes ago')
    expect(relativeTime('2026-10-18T11:00:00Z', now)).toBe('1 hour ago')
    expect(relativeTime('2026-10-15T12:00:00Z', now)).toBe('3 days ago')
    expect(relativeTime('2026-08-01T12:00:00Z', now)).toBe('2 months ago')
  })
  it('returns null for blank or unparsable input and clamps the future', () => {
    expect(relativeTime(null, now)).toBeNull()
    expect(relativeTime('nonsense', now)).toBeNull()
    expect(relativeTime('2027-01-01T00:00:00Z', now)).toBe('just now')
  })
})
