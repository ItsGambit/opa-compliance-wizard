import type { ExecuteResponse, PreviewResponse } from '../types'

interface Props {
  preview: PreviewResponse | null
  execute: ExecuteResponse | null
}

export function ResultsPanel({ preview, execute }: Props) {
  const collisions = execute?.collisions ?? preview?.collisions ?? {}
  const collisionEntries = Object.entries(collisions)
  const invalidNames = preview?.invalid_names ?? []
  const caseVariants = preview?.case_variants ?? []

  if (collisionEntries.length === 0 && invalidNames.length === 0 && caseVariants.length === 0 && !execute) return null

  return (
    <div className="flex flex-col gap-2">
      {invalidNames.length > 0 && (
        <div className="card p-3 border-loss/40 text-xs text-loss">
          <div className="font-medium mb-1">Invalid folder name(s):</div>
          {invalidNames.map(n => (
            <div key={n.path}>"{n.name}" (from {n.path})</div>
          ))}
        </div>
      )}
      {collisionEntries.length > 0 && (
        <div className="card p-3 border-warn/40 text-xs text-warn">
          <div className="font-medium mb-1">Name collisions — OPA requires unique folder names per project:</div>
          {collisionEntries.map(([name, paths]) => (
            <div key={name}>"{name}" used at: {paths.join(', ')}</div>
          ))}
        </div>
      )}
      {caseVariants.length > 0 && (
        <div className="card p-3 border-warn/40 text-xs text-warn">
          <div className="font-medium mb-1">Names that differ only by letter case — OPA may treat them as the same name:</div>
          {caseVariants.map(paths => (
            <div key={paths.join('|')}>{paths.join(', ')}</div>
          ))}
        </div>
      )}
      {execute && (
        <div className="card p-3 text-xs text-text-dim">
          {execute.output_file
            ? <>Results written to <span className="text-accent">{execute.output_file}</span> ({execute.results.length} row(s))</>
            : <>The run finished ({execute.results.length} row(s)), but the results file could not be written — see the server log.</>}
        </div>
      )}
    </div>
  )
}
