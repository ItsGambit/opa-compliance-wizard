import { createContext, useContext, useEffect, useRef } from 'react'
import type { PendingStepUp } from '../utils/stepUp'

type Unlock = Extract<PendingStepUp, { kind: 'settings_unlock' }>
/** The unsaved input a screen can hand to the Settings unlock so it survives the round trip (never secrets). */
export type SettingsDraft = Partial<Pick<Unlock, 'environmentDraft' | 'syncDraft' | 'permissionsDraft' | 'bannerDraft' | 'accessControlDraft'>>
type Getter = () => SettingsDraft | null

interface Registry {
  register: (key: string, getter: Getter) => () => void
}

export const SettingsDraftContext = createContext<Registry | null>(null)

/** Inside a SettingsGate: tell it how to read this screen's unsaved input. The getter is called only when the user unlocks,
 * so it may read the latest state; return null when there is nothing to keep. */
export function useRegisterSettingsDraft(key: string, getter: Getter, active = true): void {
  const registry = useContext(SettingsDraftContext)
  const latest = useRef(getter)
  latest.current = getter
  useEffect(() => {
    if (!registry || !active) return
    return registry.register(key, () => latest.current())
  }, [registry, key, active])
}

export function createRegistry(): { registry: Registry; collect: () => SettingsDraft } {
  const getters = new Map<string, Getter>()
  return {
    registry: { register: (key, getter) => { getters.set(key, getter); return () => { getters.delete(key) } } },
    collect: () => Object.assign({}, ...Array.from(getters.values(), g => g() ?? {})),
  }
}
