/** UI-13 follow-up: an older audit page must line up with what is shown. */
import { describe, expect, it, vi } from 'vitest'
import type { AuditLogEntry } from '../types'
import { AUDIT_PAGE_SIZE, AuditLogShiftedError, entryFingerprint, fetchAuditPage, nextAuditPageParam } from './auditPaging'

const e = (n: number) => ({ timestamp: 't', action: 'a', details: { n } } as unknown as AuditLogEntry)

describe('audit paging', () => {
  it('first page is a plain fetch', async () => {
    const f = vi.fn().mockResolvedValue({ entries: [e(1)] })
    await fetchAuditPage({ offset: 0, anchor: null }, f)
    expect(f).toHaveBeenCalledWith(AUDIT_PAGE_SIZE, 0)
  })
  it('an older page overlaps by one and drops the overlap when it matches', async () => {
    const f = vi.fn().mockResolvedValue({ entries: [e(49), e(50)] })
    const page = await fetchAuditPage({ offset: 50, anchor: entryFingerprint(e(49)) }, f)
    expect(f).toHaveBeenCalledWith(AUDIT_PAGE_SIZE + 1, 49)
    expect(page.entries).toEqual([e(50)])
  })
  it('a shifted log is refused', async () => {
    const f = vi.fn().mockResolvedValue({ entries: [e(48), e(49)] })
    await expect(fetchAuditPage({ offset: 50, anchor: entryFingerprint(e(49)) }, f)).rejects.toBeInstanceOf(AuditLogShiftedError)
  })
  it('the next param carries the last entry as anchor; a short page ends paging', () => {
    const full = { entries: Array.from({ length: AUDIT_PAGE_SIZE }, (_, i) => e(i)) }
    expect(nextAuditPageParam(full, [full])).toEqual({ offset: AUDIT_PAGE_SIZE, anchor: entryFingerprint(e(AUDIT_PAGE_SIZE - 1)) })
    expect(nextAuditPageParam({ entries: [e(1)] }, [full, { entries: [e(1)] }])).toBeUndefined()
  })
})
