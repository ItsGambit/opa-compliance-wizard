import type { useReportDateRange } from '../hooks/useReportDateRange'

/** From/To pickers shared by the report detail and resource history views
 * (they were copy-pasted). Labelled as UTC days because that is how the
 * server filters (UI-18); the table beside them shows times in the
 * viewer's own zone, which the Timestamp column says. */
export function DateRangeFields({ range, idPrefix }: { range: ReturnType<typeof useReportDateRange>; idPrefix: string }) {
  return (
    <div className="card p-3 flex flex-col gap-2">
      <div className="flex flex-wrap items-end gap-3">
        <div className="field">
          <label htmlFor={`${idPrefix}-from`} className="section-label block mb-1">From (UTC day)</label>
          <input
            id={`${idPrefix}-from`}
            type="date"
            className="text-input"
            value={range.from}
            max={range.to}
            aria-invalid={range.error ? true : undefined}
            onChange={e => range.setFrom(e.target.value)}
          />
        </div>
        <div className="field">
          <label htmlFor={`${idPrefix}-to`} className="section-label block mb-1">To (UTC day, inclusive)</label>
          <input
            id={`${idPrefix}-to`}
            type="date"
            className="text-input"
            value={range.to}
            min={range.from}
            aria-invalid={range.error ? true : undefined}
            onChange={e => range.setTo(e.target.value)}
          />
        </div>
      </div>
      {range.error && <div className="text-xs text-loss" role="alert">{range.error}</div>}
    </div>
  )
}
