import { useId } from 'react'
import type { PermissionSetting, PermissionValue, SharedCapability, SharedCapabilityKey } from '../types'
import { resolvePreview, valueLabel } from '../utils/sharedPermissions'

interface Props {
  capabilities: SharedCapability[]
  /** The edited setting per capability ("inherit" = no stored value). */
  settings: Partial<Record<SharedCapabilityKey, PermissionSetting>>
  onChange: (key: SharedCapabilityKey, value: PermissionSetting) => void
  /** What "inherit" resolves to, per capability, and its name ("global
   * default", "built-in default"). */
  inherited: (key: SharedCapabilityKey) => { value: PermissionValue; from: string }
  /** The value in effect right now and where it comes from (shown beside
   * each setting so an admin sees the result, not only the setting). */
  current: (key: SharedCapabilityKey) => { value: PermissionValue; from: string }
  disabled?: boolean
}

/** 5.42.0: one labelled native <select> per shared-environment capability --
 * keyboard and screen-reader friendly, themed by the shared text-input
 * utility. Used for the global defaults and for per-environment overrides. */
export function PermissionSettingsList({ capabilities, settings, onChange, inherited, current, disabled }: Props) {
  const base = useId()
  return (
    <ul className="flex flex-col gap-2">
      {capabilities.map(cap => {
        const id = `${base}-${cap.key}`
        const setting = settings[cap.key] ?? 'inherit'
        const inh = inherited(cap.key)
        const now = current(cap.key)
        const preview = resolvePreview(setting, inh.value)
        return (
          <li key={cap.key} className="card p-2.5 flex flex-col gap-1">
            <div className="flex flex-wrap items-center gap-2">
              <label htmlFor={id} className="text-xs font-medium text-text flex-1 min-w-[10rem]">{cap.label}</label>
              <select
                id={id}
                aria-describedby={`${id}-desc ${id}-effect`}
                className="text-input !py-1 text-xs"
                value={setting}
                disabled={disabled}
                onChange={e => onChange(cap.key, e.target.value as PermissionSetting)}
              >
                <option value="inherit">Inherit — {inh.from} ({valueLabel(inh.value).toLowerCase()})</option>
                <option value="allow">Allow</option>
                <option value="deny">Don't allow</option>
              </select>
            </div>
            <p id={`${id}-desc`} className="text-[0.6875rem] text-text-dim">{cap.description}</p>
            <p id={`${id}-effect`} className="text-[0.6875rem] text-text-dim">
              Now: <span className={now.value === 'allow' ? 'text-win' : 'text-loss'}>{valueLabel(now.value)}</span> (from {now.from})
              {preview !== now.value ? (
                <> · after saving: <span className={preview === 'allow' ? 'text-win' : 'text-loss'}>{valueLabel(preview)}</span></>
              ) : null}
            </p>
          </li>
        )
      })}
    </ul>
  )
}
