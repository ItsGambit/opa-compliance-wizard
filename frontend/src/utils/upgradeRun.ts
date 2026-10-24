import type { UpgradeNoticeRun, UpgradeRun } from '../types'

/** 5.53.0: the run the Updates page shows, from two sources. The status (behind the Settings unlock) has everything; the admin
 * notice (always answered) has the progress only. While the status is locked, restarting or not loaded yet, the notice keeps the
 * step list moving; when both answer for the same run, the newer one wins field by field and the status keeps its extra detail. */
export function mergeRun(statusRun: UpgradeRun | null | undefined, noticeRun: UpgradeNoticeRun | null | undefined): UpgradeRun | null {
  const base = statusRun ?? null
  const note = noticeRun && noticeRun.correlation_id ? noticeRun : null
  if (!note) return base
  if (!base) return asRun(note)
  if (base.correlation_id !== note.correlation_id) {
    // two different runs: the one that started later is the current one
    return Date.parse(note.started_at ?? '') > Date.parse(base.started_at ?? '') ? asRun(note) : base
  }
  const noteNewer = Date.parse(note.updated_at ?? '') >= Date.parse(base.updated_at ?? '')
  if (!noteNewer) return base
  const have = new Set((base.steps_done ?? []).map(s => s.step))
  const extra = (note.steps_done ?? []).filter(s => !have.has(s.step))
  const health = (note.health?.length ?? 0) > (base.health?.length ?? 0)
    ? note.health!.map(h => ({ id: h.id, ok: h.ok, detail: base.health?.find(b => b.id === h.id)?.detail ?? '' }))
    : base.health
  return {
    ...base,
    step: note.step, result: note.result, reason_code: note.reason_code ?? base.reason_code, failed_step: note.failed_step ?? base.failed_step,
    updated_at: note.updated_at, seconds: note.seconds ?? base.seconds, rolled_back_to: note.rolled_back_to ?? base.rolled_back_to,
    step_started_at: note.step_started_at ?? base.step_started_at,
    steps_done: [...(base.steps_done ?? []), ...extra],
    health,
  }
}

function asRun(n: UpgradeNoticeRun): UpgradeRun {
  return {
    correlation_id: n.correlation_id, action: n.action, version_from: n.version_from, version_to: n.version_to, step: n.step, result: n.result,
    reason_code: n.reason_code, started_at: n.started_at, updated_at: n.updated_at, seconds: n.seconds, failed_step: n.failed_step,
    operator_reason: null, bundle: null, schema_before: null, schema_after: null,
    steps_done: n.steps_done ?? null, step_started_at: n.step_started_at, rolled_back_to: n.rolled_back_to,
    health: n.health ? n.health.map(h => ({ id: h.id, ok: h.ok, detail: '' })) : null,
    backup: n.backup && n.backup.size != null ? { name: '', size: n.backup.size, integrity: n.backup.integrity ?? '' } : null,
  }
}
