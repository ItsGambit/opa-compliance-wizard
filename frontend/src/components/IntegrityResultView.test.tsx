/** FE-15: plain-language integrity results. */
import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { IntegrityResultView } from './IntegrityResultView'

describe('IntegrityResultView', () => {
  it('says when there is nothing to check', () => {
    render(<IntegrityResultView state={{ phase: 'done', deep: false, result: { valid: true, manifest_count: 0, broken_at: null, reason: null } }} />)
    expect(screen.getByText(/nothing has been archived yet/)).toBeTruthy()
  })
  it('names where a broken chain breaks', () => {
    render(<IntegrityResultView state={{ phase: 'done', deep: true, result: { valid: false, manifest_count: 5, broken_at: 3, reason: 'entry_hash mismatch' } }} />)
    expect(screen.getByText(/Broken at record 3: entry_hash mismatch/)).toBeTruthy()
  })
  it('never claims sealed events were verified when none were sealed', () => {
    render(<IntegrityResultView state={{ phase: 'done', deep: true, result: { valid: true, manifest_count: 2, broken_at: null, reason: null, deep_applicable: false, verified_rows: 0 } }} />)
    expect(screen.getByText(/No record carries a content seal yet/)).toBeTruthy()
    expect(screen.queryByText(/Re-read/)).toBeNull()
  })
})
