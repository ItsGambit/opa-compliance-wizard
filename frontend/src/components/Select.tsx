import * as RadixSelect from '@radix-ui/react-select'
import { Check, ChevronDown } from 'lucide-react'

export interface SelectOption {
  value: string
  label: string
  // Optional extra class(es) for this option's label text -- e.g. calling
  // out a service account among human users. Every existing caller leaves
  // this unset and is unaffected.
  labelClassName?: string
}

interface SelectProps {
  value?: string
  onValueChange: (value: string) => void
  options: SelectOption[]
  placeholder: string
  disabled?: boolean
  loading?: boolean
}

export function Select({ value, onValueChange, options, placeholder, disabled, loading }: SelectProps) {
  return (
    <RadixSelect.Root value={value} onValueChange={onValueChange} disabled={disabled || loading}>
      <RadixSelect.Trigger
        className="text-input inline-flex items-center justify-between gap-2 min-w-56 disabled:opacity-40 disabled:cursor-default"
      >
        <RadixSelect.Value placeholder={loading ? 'Loading…' : placeholder} />
        <RadixSelect.Icon>
          <ChevronDown size={14} className="text-text-faint" />
        </RadixSelect.Icon>
      </RadixSelect.Trigger>
      <RadixSelect.Portal>
        <RadixSelect.Content className="dropdown z-50" position="popper" sideOffset={4}>
          <RadixSelect.Viewport className="p-1 max-h-72">
            {options.length === 0 && (
              <div className="px-3 py-2 text-xs text-text-faint">No options</div>
            )}
            {options.map(opt => (
              <RadixSelect.Item
                key={opt.value}
                value={opt.value}
                className="text-sm text-text-dim rounded-md px-2 py-1.5 pl-7 relative cursor-pointer outline-none
                  data-[highlighted]:bg-bg-hover data-[highlighted]:text-text"
              >
                <RadixSelect.ItemIndicator className="absolute left-2 top-1/2 -translate-y-1/2">
                  <Check size={13} className="text-accent" />
                </RadixSelect.ItemIndicator>
                <RadixSelect.ItemText>
                  <span className={opt.labelClassName}>{opt.label}</span>
                </RadixSelect.ItemText>
              </RadixSelect.Item>
            ))}
          </RadixSelect.Viewport>
        </RadixSelect.Content>
      </RadixSelect.Portal>
    </RadixSelect.Root>
  )
}
