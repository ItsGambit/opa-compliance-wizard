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

describe('evidence package entries (5.53.0)', () => {
  it('has a plain label for each of the four build-log actions', () => {
    for (const a of ['evidence_package.build', 'evidence_package.build_finished', 'evidence_package.build_failed', 'evidence_package.downloaded']) {
      expect(auditActionLabel(a)).toMatch(/^Evidence package/)
    }
  })
})
