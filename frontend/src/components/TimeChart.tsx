import { useId, useMemo, useState, type KeyboardEvent } from 'react'

// A small single-axis chart (5.50.0): lines or bars over a list of x labels, drawn in SVG with the product's chart
// tokens. Accessible: the figure has a text name, the same numbers are in a visually hidden table, and the hover
// readout also opens from the keyboard (Left / Right on the focused chart). No chart library.

export interface ChartSeries {
  name: string
  /** CSS colour, normally a var(--color-s1..3). */
  color: string
  values: (number | null)[]
  /** Draw this series dashed (a second series that must be told apart without colour). */
  dashed?: boolean
}

interface Props {
  title: string
  labels: string[]
  series: ChartSeries[]
  kind: 'line' | 'bar'
  stacked?: boolean
  /** How a y value reads in ticks and in the readout (counts by default). */
  format?: (v: number) => string
  /** Fixed top of the axis (e.g. 1 for a share); otherwise a rounded maximum of the data. */
  yMax?: number
  /** x label text: the short axis form, and the longer readout form. */
  axisLabel?: (label: string) => string
  readoutLabel?: (label: string) => string
  height?: number
  /** Drawing width in SVG units (text keeps its size, so a wide chart gets a larger value). */
  width?: number
}

const DEFAULT_W = 440
const PAD = { l: 40, r: 10, t: 8, b: 22 }

function niceMax(v: number): number {
  if (v <= 0) return 1
  const p = Math.pow(10, Math.floor(Math.log10(v)))
  const n = v / p
  return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * p
}

const defaultFormat = (v: number) => v.toLocaleString()

export function TimeChart({ title, labels, series, kind, stacked, format = defaultFormat, yMax, axisLabel = l => l, readoutLabel = l => l, height = 170, width = DEFAULT_W }: Props) {
  const W = width
  const id = useId()
  const [active, setActive] = useState<number | null>(null)
  const H = height
  const n = labels.length
  const plotW = W - PAD.l - PAD.r
  const plotH = H - PAD.t - PAD.b
  const max = useMemo(() => {
    if (yMax != null) return yMax
    let m = 0
    for (let i = 0; i < n; i++) {
      const vals = series.map(s => s.values[i] ?? 0)
      m = Math.max(m, stacked ? vals.reduce((a, b) => a + b, 0) : Math.max(...vals, 0))
    }
    return niceMax(m)
  }, [series, n, stacked, yMax])
  const x = (i: number) => PAD.l + (n <= 1 ? plotW / 2 : (i * plotW) / (n - 1))
  const slot = n > 0 ? plotW / n : plotW
  const barX = (i: number) => PAD.l + i * slot + slot / 2
  const px = (i: number) => (kind === 'bar' ? barX(i) : x(i))
  const y = (v: number) => PAD.t + plotH - (v / max) * plotH
  const ticks = [0, 0.25, 0.5, 0.75, 1].map(f => f * max)
  const xTickIdx = n <= 5 ? labels.map((_, i) => i) : [0, 1, 2, 3, 4].map(k => Math.round((k * (n - 1)) / 4))

  const onKey = (e: KeyboardEvent<SVGSVGElement>) => {
    if (n === 0) return
    if (e.key === 'ArrowLeft') { e.preventDefault(); setActive(a => (a == null ? n - 1 : Math.max(0, a - 1))) }
    else if (e.key === 'ArrowRight') { e.preventDefault(); setActive(a => (a == null ? 0 : Math.min(n - 1, a + 1))) }
    else if (e.key === 'Escape') setActive(null)
  }
  const onMove = (clientX: number, rect: DOMRect) => {
    const rel = ((clientX - rect.left) / rect.width) * W
    const i = kind === 'bar' ? Math.floor((rel - PAD.l) / slot) : Math.round(((rel - PAD.l) / plotW) * (n - 1))
    setActive(i >= 0 && i < n ? i : null)
  }

  const summary = `${title}. ${series.map(s => `${s.name}: ${s.values.map(v => (v == null ? 'no data' : format(v))).slice(-1)[0] ?? 'no data'} latest`).join('; ')}.`
  const tip = active != null ? series.map(s => `${s.name}: ${s.values[active] == null ? 'no data' : format(s.values[active] as number)}`) : []
  const tipW = 160
  const tipX = active != null ? Math.min(Math.max(px(active) - tipW / 2, PAD.l), W - PAD.r - tipW) : 0

  return (
    <figure className="m-0">
      <svg
        viewBox={`0 0 ${W} ${H}`} className="block w-full h-auto" role="img" aria-label={summary} aria-describedby={`${id}-t`} tabIndex={0}
        onKeyDown={onKey} onBlur={() => setActive(null)}
        onMouseMove={e => onMove(e.clientX, e.currentTarget.getBoundingClientRect())} onMouseLeave={() => setActive(null)}
      >
        {ticks.map(t => (
          <g key={t}>
            <line x1={PAD.l} x2={W - PAD.r} y1={y(t)} y2={y(t)} stroke="var(--color-grid)" strokeWidth={1} />
            <text x={PAD.l - 6} y={y(t) + 4} textAnchor="end" fontSize={11} fill="var(--color-axis)">{format(t)}</text>
          </g>
        ))}
        <line x1={PAD.l} x2={W - PAD.r} y1={y(0)} y2={y(0)} stroke="var(--color-axis)" strokeWidth={1} />
        {xTickIdx.map(i => (
          <text key={i} x={px(i)} y={H - 6} textAnchor={i === 0 && n > 1 ? 'start' : i === n - 1 && n > 1 ? 'end' : 'middle'} fontSize={11} fill="var(--color-axis)">{axisLabel(labels[i])}</text>
        ))}
        {kind === 'line' && series.map(s => {
          const pts = s.values.map((v, i) => (v == null ? null : [x(i), y(v)] as const))
          const segments: string[] = []
          let cur = ''
          pts.forEach(p => { if (p) cur += `${cur ? 'L' : 'M'}${p[0].toFixed(1)},${p[1].toFixed(1)}`; else if (cur) { segments.push(cur); cur = '' } })
          if (cur) segments.push(cur)
          return (
            <g key={s.name}>
              {segments.map((d, k) => <path key={k} d={d} fill="none" stroke={s.color} strokeWidth={2} strokeDasharray={s.dashed ? '5 3' : undefined} strokeLinejoin="round" />)}
              {n <= 2 && pts.map((p, i) => p && <circle key={i} cx={p[0]} cy={p[1]} r={3} fill={s.color} />)}
              {active != null && pts[active] && <circle cx={pts[active]![0]} cy={pts[active]![1]} r={4} fill={s.color} stroke="var(--color-bg-card)" strokeWidth={1.5} />}
            </g>
          )
        })}
        {kind === 'bar' && labels.map((_, i) => {
          const bw = stacked ? Math.min(slot * 0.7, 22) : Math.min((slot * 0.8) / series.length, 14)
          let acc = 0
          return (
            <g key={i}>
              {series.map((s, k) => {
                const v = s.values[i] ?? 0
                const bx = stacked ? barX(i) - bw / 2 : barX(i) - (bw * series.length) / 2 + k * bw
                const top = stacked ? y(acc + v) : y(v)
                const h = stacked ? y(acc) - y(acc + v) : y(0) - y(v)
                acc += v
                return v > 0 ? <rect key={s.name} x={bx} y={top} width={Math.max(bw - 1, 1)} height={Math.max(h, 0)} fill={s.color} rx={1.5} /> : null
              })}
            </g>
          )
        })}
        {active != null && (
          <g pointerEvents="none">
            <line x1={px(active)} x2={px(active)} y1={PAD.t} y2={y(0)} stroke="var(--color-axis)" strokeDasharray="3 3" strokeWidth={1} />
            <rect x={tipX} y={PAD.t} width={tipW} height={18 + tip.length * 15} rx={6} fill="var(--color-bg-elevated)" stroke="var(--color-border)" />
            <text x={tipX + 8} y={PAD.t + 14} fontSize={11} fontWeight={600} fill="var(--color-text)">{readoutLabel(labels[active])}</text>
            {tip.map((t, i) => <text key={i} x={tipX + 8} y={PAD.t + 29 + i * 15} fontSize={11} fill="var(--color-text-dim)">{t}</text>)}
          </g>
        )}
      </svg>
      <figcaption id={`${id}-t`} className="sr-only">{summary} Use the left and right arrow keys to read each point.</figcaption>
      <table className="sr-only">
        <caption>{title}</caption>
        <thead><tr><th>Period</th>{series.map(s => <th key={s.name}>{s.name}</th>)}</tr></thead>
        <tbody>{labels.map((l, i) => <tr key={l}><td>{readoutLabel(l)}</td>{series.map(s => <td key={s.name}>{s.values[i] == null ? 'no data' : format(s.values[i] as number)}</td>)}</tr>)}</tbody>
      </table>
    </figure>
  )
}

export function Legend({ items }: { items: { name: string; color: string; dashed?: boolean }[] }) {
  return (
    <div className="flex gap-3 flex-wrap text-[0.6875rem] text-text-dim mb-1.5">
      {items.map(i => (
        <span key={i.name} className="inline-flex items-center gap-1.5">
          <i aria-hidden="true" className="inline-block w-4 h-[3px] rounded-sm" style={{ background: i.dashed ? `repeating-linear-gradient(90deg, ${i.color} 0 5px, transparent 5px 8px)` : i.color }} />
          {i.name}
        </span>
      ))}
    </div>
  )
}

/** A tiny trend line for a table cell: decorative (the numbers beside it carry the meaning). */
export function Sparkline({ values, color = 'var(--color-s1)' }: { values: number[]; color?: string }) {
  if (values.length < 2) return <span className="text-text-faint" aria-hidden="true">–</span>
  const w = 64
  const h = 18
  const min = Math.min(...values)
  const max = Math.max(...values)
  const span = max - min || 1
  const d = values.map((v, i) => `${i ? 'L' : 'M'}${((i * (w - 2)) / (values.length - 1) + 1).toFixed(1)},${(h - 2 - ((v - min) / span) * (h - 4) + 1).toFixed(1)}`).join('')
  return <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} aria-hidden="true"><path d={d} fill="none" stroke={color} strokeWidth={1.6} /></svg>
}
