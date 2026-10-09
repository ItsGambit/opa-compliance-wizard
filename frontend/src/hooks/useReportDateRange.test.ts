/** UI-18: shared report date range. */
import { act, renderHook } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { useReportDateRange, utcDaysAgo, utcToday } from './useReportDateRange'

afterEach(() => { vi.useRealTimers() })

describe('useReportDateRange', () => {
  it('defaults to the last 90 UTC days', () => {
    const { result } = renderHook(() => useReportDateRange())
    expect(result.current.from).toBe(utcDaysAgo(90))
    expect(result.current.to).toBe(utcToday())
    expect(result.current.range).toEqual({ from: utcDaysAgo(90), to: utcToday() })
  })

  it('rejects From after To and runs no query', () => {
    const { result } = renderHook(() => useReportDateRange())
    act(() => { result.current.setFrom('2030-01-02'); result.current.setTo('2030-01-01') })
    expect(result.current.error).toMatch(/after/)
    expect(result.current.range).toBeUndefined()
  })

  it('an untouched To follows the date (no stale "today" after midnight UTC)', () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-10-09T23:59:00Z'))
    const { result, rerender } = renderHook(() => useReportDateRange())
    expect(result.current.to).toBe('2026-10-09')
    vi.setSystemTime(new Date('2026-10-10T00:01:00Z'))
    rerender()
    expect(result.current.to).toBe('2026-10-10')
  })

  it('a To the user picked stays put', () => {
    const { result } = renderHook(() => useReportDateRange())
    act(() => { result.current.setTo('2026-01-01') })
    expect(result.current.to).toBe('2026-01-01')
  })

  it('utcToday uses the UTC calendar day', () => {
    expect(utcToday(Date.parse('2026-10-09T23:30:00-07:00'))).toBe('2026-10-10')
  })
})
