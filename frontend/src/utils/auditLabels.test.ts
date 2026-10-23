import { describe, expect, it } from 'vitest'
import { auditActionLabel } from './auditLabels'

describe('auditActionLabel (5.53.0)', () => {
  it('labels the three Settings unlock events and leaves every other action alone', () => {
    expect(auditActionLabel('settings.unlocked')).toBe('Settings and Updates opened with MFA')
    expect(auditActionLabel('settings.locked')).toBe('Settings and Updates locked again')
    expect(auditActionLabel('settings.access_without_mfa_local')).toBe('Opened without MFA (local mode)')
    expect(auditActionLabel('environment.upsert')).toBeNull()
  })
})
