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
  // TEST-11: every formula sigil, and nothing else, gets the apostrophe.
  it.each([
    ['=cmd', "'=cmd"], ['+1', "'+1"], ['-2', "'-2"], ['@x', "'@x"], ['\tx', "'\tx"],
    ['a=b', 'a=b'], [' =x', ' =x'], ['', ''], ["'already", "'already"],
  ])('neutralises a leading formula sigil: %j', (input, expected) => {
    expect(csvEscape(input)).toBe(expected)
  })
  it('a leading CR is neutralised and quoted', () => {
    expect(csvEscape('\r=x')).toBe('"\'\r=x"')
  })
  it('output never starts with a formula sigil (seeded fuzz)', () => {
    let seed = 20261009
    const rand = () => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed / 2147483648 }
    const alphabet = '=+-@\t\r\n",ab1 \'|'
    for (let i = 0; i < 500; i++) {
      let v = ''
      for (let n = Math.floor(rand() * 8); n > 0; n--) v += alphabet[Math.floor(rand() * alphabet.length)]
      const out = csvEscape(v)
      const body = out.startsWith('"') ? out.slice(1) : out
      expect(/^[=+\-@\t\r]/.test(body)).toBe(false)
    }
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
