import type { SelectOption } from '../components/Select'

/** A native stand-in for components/Select in tests (Radix Select's popper
 * needs layout APIs jsdom lacks). Same props, same accessible name. */
export function MockSelect({ value, onValueChange, options, placeholder, ariaLabel, id }: {
  value?: string; onValueChange: (v: string) => void; options: SelectOption[]; placeholder: string; ariaLabel?: string; id?: string
}) {
  return (
    <select id={id} aria-label={ariaLabel} value={value ?? ''} onChange={e => onValueChange(e.target.value)}>
      <option value="">{placeholder}</option>
      {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
    </select>
  )
}
