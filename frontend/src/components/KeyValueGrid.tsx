import { displayValue, labelize } from '../utils/format'

interface Props {
  /** Rendered in insertion order — pass a pre-sorted/pre-filtered record. */
  data: Record<string, unknown>
}

/** Renders every key in `data` as a label/value pair. Used where the goal
 * is showing *everything* available about an object (e.g. a Project) —
 * new fields the API starts returning show up automatically. */
export function KeyValueGrid({ data }: Props) {
  const entries = Object.entries(data)
  return (
    <dl className="grid grid-cols-2 gap-x-4 gap-y-2">
      {entries.map(([key, value]) => (
        <div key={key} className="flex flex-col gap-0.5">
          <dt className="section-label">{labelize(key)}</dt>
          <dd className="text-sm text-text-dim break-words">{displayValue(value)}</dd>
        </div>
      ))}
    </dl>
  )
}
