import * as RadixSelect from '@radix-ui/react-select'
import { Check, ChevronDown, Search } from 'lucide-react'
import { useState } from 'react'
import { HighlightedText, useFuzzyFilter } from '../utils/fuzzySearch'

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

// Every dropdown in the app (Resource Groups, Projects, Groups, Policies,
// Users, the Resources kind-picker, ProjectSelect, ResourceGroupSelect,
// GroupPicker -- one shared component, so this upgrades all of them at
// once) gets a fuzzy, typo-tolerant search box once the option count makes
// scanning by eye impractical. A short list (e.g. the 3 CONTROL tabs) has
// no real need for a search box, so it's only shown once there's enough
// to search through.
const SEARCH_THRESHOLD = 8

export function Select({ value, onValueChange, options, placeholder, disabled, loading }: SelectProps) {
  const [query, setQuery] = useState('')
  const filtered = useFuzzyFilter(options, query, ['label', 'value'])

  return (
    <RadixSelect.Root
      value={value}
      onValueChange={onValueChange}
      disabled={disabled || loading}
      onOpenChange={open => {
        if (!open) setQuery('')
      }}
    >
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
          {options.length >= SEARCH_THRESHOLD && (
            <div className="flex items-center gap-1.5 px-2 py-1.5 border-b border-border">
              <Search size={12} className="text-text-faint shrink-0" />
              <input
                type="text"
                autoFocus
                placeholder="Search…"
                value={query}
                onChange={e => setQuery(e.target.value)}
                // Radix Select intercepts typing for its own type-ahead --
                // stop it from reaching Radix so this search box actually
                // receives every keystroke instead of Radix eating them.
                onKeyDown={e => e.stopPropagation()}
                className="flex-1 bg-transparent text-xs text-text outline-none placeholder:text-text-faint"
              />
            </div>
          )}
          <RadixSelect.Viewport className="p-1 max-h-72">
            {filtered.length === 0 && (
              <div className="px-3 py-2 text-xs text-text-faint">No options</div>
            )}
            {filtered.map(({ item: opt, matches }) => {
              const labelMatch = matches.find(m => m.key === 'label')
              return (
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
                    <span className={opt.labelClassName}>
                      <HighlightedText text={opt.label} indices={labelMatch?.indices} />
                    </span>
                  </RadixSelect.ItemText>
                </RadixSelect.Item>
              )
            })}
          </RadixSelect.Viewport>
        </RadixSelect.Content>
      </RadixSelect.Portal>
    </RadixSelect.Root>
  )
}
