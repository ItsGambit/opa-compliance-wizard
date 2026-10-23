/// <reference types="node" />
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { auditActionLabel } from './auditLabels'
import { UPGRADE_AUDIT_ACTIONS, upgradeActionLabel, upgradeTone } from './auditUpgrade'

/** The server's own source, read as text: the list of actions below is derived from it, not copied. */
const SERVER = resolve(__dirname, '../../../server')

function pythonSources(dir: string): string[] {
  return readdirSync(dir).flatMap((name: string) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return name === '__pycache__' ? [] : pythonSources(path)
    return name.endsWith('.py') ? [readFileSync(path, 'utf8')] : []
  })
}
const SERVER_SOURCES = pythonSources(SERVER)

/** Quoted `upgrade.*` names in the server code that are not audit actions: the approval gate's action types, and file names. */
const NOT_AUDIT_ACTIONS = new Set(['upgrade.request', 'upgrade.preview', 'upgrade.json', 'upgrade.service', 'upgrade.path'])

function actionsTheServerWrites(): string[] {
  const found = new Set<string>()
  for (const source of SERVER_SOURCES) {
    for (const m of source.matchAll(/["'](upgrade\.[a-z_]+)["']/g)) found.add(m[1])
  }
  return [...found].filter(a => !NOT_AUDIT_ACTIONS.has(a)).sort()
}

describe('Audit Log upgrade actions (5.53.0)', () => {
  const written = actionsTheServerWrites()

  it('finds the server actions (guards the scan itself)', () => {
    expect(written.length).toBeGreaterThan(25)
    expect(written).toContain('upgrade.check')
    expect(written).toContain('upgrade.completed')
  })

  it('knows every upgrade.* action the server code can write', () => {
    expect(written.filter(a => !UPGRADE_AUDIT_ACTIONS.includes(a))).toEqual([])
  })

  it.each(written)('%s is styled as an upgrade event with words in its label', action => {
    const label = upgradeActionLabel(action)
    expect(label).toBeTruthy()
    expect(label).not.toBe('upgrade event')               // a real sentence, not the fallback
    expect(auditActionLabel(action)).toBe(label)
    const tone = upgradeTone(action)
    if (tone === 'failure') expect(label).toMatch(/failed|missed|rejected|refused|rolled back/)   // the words carry the meaning, not only the colour
  })

  it('treats upgrade.check like the other upgrade events, and a failed check as a failure in words too', () => {
    expect(upgradeTone('upgrade.check', { outcome: 'up_to_date' })).toBe('normal')
    expect(upgradeTone('upgrade.completed')).toBe('normal')
    expect(upgradeTone('upgrade.check', { outcome: 'failed' })).toBe('failure')
    expect(upgradeActionLabel('upgrade.check', { outcome: 'failed' })).toBe('update check failed')
  })

  it('marks failures and refusals', () => {
    for (const a of ['upgrade.failed', 'upgrade.verify_failed', 'upgrade.missed', 'upgrade.key_revocation_rejected', 'upgrade.local_failed', 'upgrade.request_rejected', 'upgrade.rolled_back']) {
      expect(upgradeTone(a)).toBe('failure')
    }
  })

  it('gives a future upgrade.* action a neutral label rather than none, and other actions nothing', () => {
    expect(upgradeActionLabel('upgrade.something_new')).toBe('upgrade event')
    expect(upgradeActionLabel('environment.upsert')).toBeNull()
  })
})
