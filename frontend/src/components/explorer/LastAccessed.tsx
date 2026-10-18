import { useState } from 'react'
import type { ResourceAccessEvent, ResourceAccessInfo } from '../../types'
import type { AccessLookup, TrackGap, TrackTarget } from '../../utils/accessResources'
import { archiveNote, describeEventTypes, evidenceFooter, eventWord, usesChip, windowLabel } from '../../utils/accessEvidence'
import { formatDateTime } from '../../utils/format'
import { relativeTime } from '../../utils/relativeTime'

/** A request id you can copy. Shows the first 8 characters; the full id is
 * the button's title and what gets copied. Clipboard access can be blocked
 * (insecure context, permissions), so a failure is silent and shown as no
 * "Copied" confirmation rather than an error. */
export function CopyId({ id }: { id: string }) {
  const [done, setDone] = useState(false)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(id)
      setDone(true)
      window.setTimeout(() => setDone(false), 1200)
    } catch {
      /* clipboard unavailable: nothing to confirm */
    }
  }
  return (
    <button type="button" className="xp-copy" data-done={done} title={done ? 'Copied' : `Copy request id ${id}`} aria-label={`Copy request id ${id}`} onClick={() => { void copy() }}>
      <code>{id.length > 8 ? `${id.slice(0, 8)}…` : id}</code>
    </button>
  )
}

const MATCHED_BY: Record<string, string> = {
  name: 'matched by exact account name',
  server_account: 'matched by server and account name',
  server: 'server-level: some account on this server',
}

/** The latest events as a short table: time, action in plain words, outcome,
 * request id (copyable). */
function RecentActivity({ events, label }: { events: ResourceAccessEvent[]; label: string }) {
  return (
    <table className="xp-ev" aria-label={label}>
      <tbody>
        {events.map((e, i) => (
          <tr key={i}>
            <td>{formatDateTime(e.published)}</td>
            <td>
              {eventWord(e.event_type)}
              {e.matched_by && <span className="xp-mute" title={MATCHED_BY[e.matched_by]}> · {e.matched_by === 'server' ? 'server-level' : 'by name'}</span>}
              {e.source === 'live' && <span className="xp-mute" title="Found in the live System Log"> · live</span>}
            </td>
            <td className="xp-mute">{e.outcome ?? ''}</td>
            <td>{e.request_id ? <CopyId id={e.request_id} /> : null}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

/** Database / Active Directory selector rows: the events of every account of
 * that family the user accessed, grouped by account name (newest first). */
function AccountSelectorAccess({ events, now }: { events: ResourceAccessEvent[]; now: number }) {
  const groups = new Map<string, ResourceAccessEvent[]>()
  for (const e of events) {
    const name = e.account_name || 'Unnamed account'
    groups.set(name, [...(groups.get(name) ?? []), e])
  }
  return (
    <ul className="flex flex-col gap-1.5" aria-label="Accounts accessed">
      {[...groups.entries()].map(([name, evs]) => {
        const [latest, ...older] = evs
        const rel = relativeTime(latest.published, now)
        return (
          <li key={name}>
            <strong>{name}</strong>: last accessed <time dateTime={latest.published} title={formatDateTime(latest.published)}>{rel ?? formatDateTime(latest.published)}</time>
            {latest.event_type && <> · {eventWord(latest.event_type).toLowerCase()}</>}
            {latest.outcome && <> · {latest.outcome}</>}
            {latest.request_id && <> · request <CopyId id={latest.request_id} /></>}
            {older.length > 0 && (
              <details className="xp-more">
                <summary>{older.length} older</summary>
                <RecentActivity events={older} label={`Older activity for ${name}`} />
              </details>
            )}
          </li>
        )
      })}
    </ul>
  )
}

function Footer({ info, now }: { info: ResourceAccessInfo; now: number }) {
  const note = archiveNote(info)
  return (
    <>
      <p className="xp-evidence-foot">{evidenceFooter(info, now)}</p>
      {note && <p className="xp-evidence-foot">{note}</p>}
      {info.newer_than_sync && <p className="xp-evidence-foot xp-flag">Includes activity newer than the last sync, found in the live System Log.</p>}
      {info.live_error && <p className="xp-evidence-foot xp-flag">The newest events could not be checked: {info.live_error}. This is the archive only.</p>}
    </>
  )
}

function TargetAccess({ lookup, target, now }: { lookup: AccessLookup; target: TrackTarget; now: number }) {
  if (lookup.status === 'loading') return <span className="xp-mute">loading…</span>
  if (lookup.status === 'error') return <span className="text-warn">unavailable</span>
  const info = lookup.byId.get(target.id)
  // A ready lookup that has no entry for this resource: the server did not
  // report on it -- say so rather than spinning forever.
  if (!info) return <span className="xp-mute italic">Unknown: no result was returned for this resource</span>
  if (!info.supported) return <span className="xp-mute italic">Not tracked: the System Log does not record access for this resource type</span>
  const covered = describeEventTypes(info.event_types)
  if (info.events.length === 0 && info.ambiguous) {
    return (
      <div>
        <span className="text-warn">Unknown: cannot tell which account. Another account has the same name and was used in {windowLabel(info.window_days)}.</span>
        <Footer info={info} now={now} />
      </div>
    )
  }
  if (info.events.length === 0) {
    return (
      <div>
        {info.complete === false
          ? <span className="text-warn">Unknown: no use found in the events read, but the lookup is not complete (a page limit, a stretch the archive does not cover, or the live log could not be read), so this is not a full answer for {windowLabel(info.window_days)}.</span>
          : <span className="xp-mute">Never used in {windowLabel(info.window_days)}{covered ? ` (counts: ${covered})` : ''}</span>}
        {info.coverage_from && <Footer info={info} now={now} />}
      </div>
    )
  }
  if (target.kind === 'account_selector') {
    return (
      <div>
        <AccountSelectorAccess events={info.events} now={now} />
        {info.coverage_from && <Footer info={info} now={now} />}
      </div>
    )
  }
  const [latest] = info.events
  const rel = relativeTime(latest.published, now)
  const chip = usesChip(info.uses, info.window_days)
  return (
    <div>
      <div>
        last used <time dateTime={latest.published} title={formatDateTime(latest.published)}>{rel ?? formatDateTime(latest.published)}</time>
        {chip && <span className="xp-chip">{chip}</span>}
      </div>
      <RecentActivity events={info.events} label="Recent activity" />
      {info.uses !== undefined && info.uses > info.events.length && (
        <p className="xp-note">The newest {info.events.length} of {info.uses} uses are listed.</p>
      )}
      {info.coverage_from && <Footer info={info} now={now} />}
    </div>
  )
}

/** The "Last used" block of an expanded resource: per account, the latest use,
 * a short Recent activity list and an evidence footer (source, coverage,
 * last sync); a folder rolls up the secrets inside it. Every state of the
 * lookup (loading, failed with Retry, no result, not trackable, incomplete)
 * keeps its own plain message, and "Never used" always names its window. */
export function LastAccessed({ lookup, targets, folder, now }: { lookup: AccessLookup; targets: TrackTarget[]; folder?: boolean; now: number }) {
  const list = (
    <div className="flex flex-col gap-2.5">
      {targets.map(t => (
        <div key={t.id}>
          <div className="xp-mute">{t.label}</div>
          <TargetAccess lookup={lookup} target={t} now={now} />
        </div>
      ))}
    </div>
  )
  return (
    <div>
      {lookup.status === 'error' && (
        <div className="text-xs text-warn flex items-center gap-2 mb-2" role="status">
          Last-used lookup unavailable: {lookup.message}
          <button type="button" className="btn-secondary !py-0 !px-1.5 text-xs" onClick={lookup.onRetry} disabled={lookup.retrying}>
            {lookup.retrying ? 'Retrying…' : 'Retry'}
          </button>
        </div>
      )}
      {folder ? (
        <details className="xp-more !pt-0">
          <summary>{targets.length} secret{targets.length === 1 ? '' : 's'} in this folder</summary>
          {list}
        </details>
      ) : list}
    </div>
  )
}

/** The block for a resource with nothing to look up: says Unknown (why) or
 * Not tracked (why), never a bare dash. */
export function NoTracking({ gap }: { gap?: TrackGap }) {
  if (gap?.state === 'unknown') return <p className="text-warn">Unknown: {gap.reason}</p>
  return <p className="xp-mute">Not tracked: {gap?.reason ?? 'the System Log does not record access per resource of this kind.'}</p>
}
