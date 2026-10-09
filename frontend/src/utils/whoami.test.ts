/** UI-06 (external review, 2026-10-05): canAdminFrom follows the server. */
import { describe, expect, it } from 'vitest'
import { canAdminFrom } from './whoami'

describe('canAdminFrom', () => {
  it('uses the server-reported can_admin when present', () => {
    expect(canAdminFrom({ is_local: true, is_admin: false, can_admin: true })).toBe(true)
    expect(canAdminFrom({ is_local: false, is_admin: false, can_admin: false })).toBe(false)
    expect(canAdminFrom({ is_local: true, is_admin: false, can_admin: false })).toBe(false)
  })

  it('falls back to is_admin || is_local for a pre-5.40.3 server', () => {
    expect(canAdminFrom({ is_local: true, is_admin: false })).toBe(true)
    expect(canAdminFrom({ is_local: false, is_admin: true })).toBe(true)
    expect(canAdminFrom({ is_local: false, is_admin: false })).toBe(false)
  })

  it('is false before whoami has loaded', () => {
    expect(canAdminFrom(undefined)).toBe(false)
    expect(canAdminFrom(null)).toBe(false)
  })
})
