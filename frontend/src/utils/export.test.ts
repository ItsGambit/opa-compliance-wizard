/** FE-09: CSV / Markdown export correctness. */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { csvEscape, downloadTextFile, markdownCell, toCsv, toMarkdown } from './export'

afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks() })

describe('csvEscape', () => {
  it('quotes a bare CR, LF, comma or quote', () => {
    expect(csvEscape('a\rb')).toBe('"a\rb"')
    expect(csvEscape('a\nb')).toBe('"a\nb"')
    expect(csvEscape('a,b')).toBe('"a,b"')
    expect(csvEscape('x"y')).toBe('"x""y"')
    expect(csvEscape('plain')).toBe('plain')
  })
  it('still neutralises formulas', () => {
    expect(csvEscape('=1+1')).toBe("'=1+1")
    expect(csvEscape('@SUM(A1)')).toBe("'@SUM(A1)")
  })
  it('keeps non-ASCII text as is', () => {
    expect(csvEscape('Zoë — ok')).toBe('Zoë — ok')
  })
})

describe('toMarkdown', () => {
  it('keeps one table row per record: newlines, pipes and backslashes escaped', () => {
    expect(markdownCell('a\nb')).toBe('a<br>b')
    expect(markdownCell('a\r\nb')).toBe('a<br>b')
    expect(markdownCell('a|b')).toBe('a\\|b')
    expect(markdownCell('ends\\')).toBe('ends\\\\')
    const md = toMarkdown([{ title: 'T', rows: [{ 'Col|1': 'x\ny', B: 'z\\' }] }])
    const lines = md.split('\n')
    expect(lines).toHaveLength(5)
    expect(lines[2]).toBe('| Col\\|1 | B |')
    expect(lines[4]).toBe('| x<br>y | z\\\\ |')
  })
})

describe('toCsv', () => {
  it('writes each record on one physical line unless quoted', () => {
    const csv = toCsv([{ title: 'T', rows: [{ A: 'one\rtwo', B: 'ok' }] }])
    expect(csv).toBe('T\nA,B\n"one\rtwo",ok')
  })
})

describe('downloadTextFile', () => {
  it('revokes the object URL after the click, not during it', () => {
    vi.useFakeTimers()
    const create = vi.fn(() => 'blob:x')
    const revoke = vi.fn()
    Object.assign(URL, { createObjectURL: create, revokeObjectURL: revoke })
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    downloadTextFile('a.csv', 'x', 'text/csv')
    expect(click).toHaveBeenCalled()
    expect(revoke).not.toHaveBeenCalled()
    vi.runAllTimers()
    expect(revoke).toHaveBeenCalledWith('blob:x')
  })
})
