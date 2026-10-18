import { useState } from 'react'
import type { ResourceAccessEvent } from '../../types'
import type { AccessLookup, TrackTarget } from '../../utils/accessResources'
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

function EventTable({ events }: { events: ResourceAccessEvent[] }) {
  return (
    <table className="xp-ev">
      <tbody>
        {events.map((e, i) => (
          <tr key={i}>
            <td>{formatDateTime(e.published)}</td>
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
            {latest.outcome && <> · {latest.outcome}</>}
            {latest.request_id && <> · request <CopyId id={latest.request_id} /></>}
            {older.length > 0 && (
              <details className="xp-more">
                <summary>{older.length} older</summary>
                <EventTable events={older} />
              </details>
            )}
          </li>
        )
      })}
    </ul>
  )
}

function TargetAccess({ lookup, target, now }: { lookup: AccessLookup; target: TrackTarget; now: number }) {
  if (lookup.status === 'loading') return <span className="xp-mute">loading…</span>
  if (lookup.status === 'error') return <span className="text-warn">unavailable</span>
  const info = lookup.byId.get(target.id)
  // A ready lookup that has no entry for this resource: the server did not
  // report on it -- say so rather than spinning forever.
  if (!info) return <span className="xp-mute italic">no result returned for this resource</span>
  if (!info.supported) return <span className="xp-mute italic">access tracking not available for this resource type</span>
  if (info.events.length === 0 && info.ambiguous) {
    return <span className="text-warn">cannot tell which account: another account has the same name and was used in the last 90 days</span>
  }
  if (info.events.length === 0) {
    return info.complete === false
      ? <span className="text-warn">no access found in the events read — the lookup hit its page limit, so this is not a complete 90-day answer</span>
      : <span className="xp-mute">not accessed (or not within the last 90 days)</span>
  }
  if (target.kind === 'account_selector') return <AccountSelectorAccess events={info.events} now={now} />
  const [latest, ...older] = info.events
  const rel = relativeTime(latest.published, now)
  return (
    <div>
      <div>
        last accessed <time dateTime={latest.published} title={formatDateTime(latest.published)}>{rel ?? formatDateTime(latest.published)}</time>
        {latest.outcome && <> · {latest.outcome}</>}
        {latest.request_id && <> · request <CopyId id={latest.request_id} /></>}
      </div>
      {older.length > 0 && (
        <details className="xp-more">
          <summary>{older.length} older</summary>
          <EventTable events={older} />
          <p className="xp-note">The newest {info.events.length} events are loaded.</p>
        </details>
      )}
    </div>
  )
}

/** The "Last accessed" block of an expanded resource (System Log, last 90
 * days): per account, one line with the latest access and a "+N older"
 * fold; a folder rolls up the secrets inside it. Every state of the lookup
 * (loading, failed with Retry, no result, not trackable, incomplete) keeps
 * its own plain message. */
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
          Last-accessed lookup unavailable: {lookup.message}
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
