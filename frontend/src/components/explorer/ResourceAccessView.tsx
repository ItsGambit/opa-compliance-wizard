import type { ReactNode } from 'react'
import type { NamedRef } from '../../types'
import { describePrivilegeRaw, trackTargets, type AccessLookup, type AccessResource } from '../../utils/accessResources'
import { labelize } from '../../utils/format'
import { Chip, DetailGrid, DetailSection } from './DetailBlocks'
import { LastAccessed } from './LastAccessed'

const KIND_WORD: Record<string, string> = {
  secret: 'Secret',
  secret_folder: 'Secret folder',
  individual_server: 'Server',
  individual_server_account: 'Server account',
  individual_managed_saas_app_account: 'Managed SaaS app account',
  individual_unmanaged_saas_app_account: 'Unmanaged SaaS app account',
  individual_okta_account: 'Okta account',
  individual_database_account: 'Database account',
  individual_active_directory_account: 'Active Directory account',
}

function kindWord(kind: string): string {
  if (kind.startsWith('relationship_assignment:')) return `${KIND_WORD[kind.slice('relationship_assignment:'.length)] ?? labelize(kind.slice('relationship_assignment:'.length))} (granted through a relationship)`
  return KIND_WORD[kind] ?? labelize(kind)
}

interface Props {
  resource: AccessResource
  /** Present only where "last accessed" applies (a human user's view). */
  lookup?: AccessLookup
  now: number
  /** An inline action per granting group (the Users view passes Remove). */
  renderGroupAction?: (group: NamedRef) => ReactNode
}

/** The expanded view of one resource: what it is, what the subject can do
 * with it, the conditions, how they get it (every policy rule and group
 * behind it) and, where it applies, when it was last accessed. */
export function ResourceAccessView({ resource, lookup, now, renderGroupAction }: Props) {
  const res = resource.resolution
  const targets = trackTargets(resource)
  const privileges = resource.lines.flatMap(l => l.rule.privileges.map(describePrivilegeRaw))
  const uniquePrivileges = [...new Set(privileges)]
  return (
    <DetailGrid>
      <DetailSection title="What it is">
        {res.kind === 'resolved' ? (
          <>
            <p>
              {kindWord(res.resource_kind)}
              {res.project_name
                ? ` in project ${res.project_name}`
                // relationship_assignment resolutions are team-wide grants with no
                // project by design -- "(project unknown)" would imply a data gap.
                : res.resource_kind.startsWith('relationship_assignment:') ? '' : ' (project unknown)'}
              .
            </p>
            {resource.selectors.length > 0 && (
              <p className="xp-mute">Matched by the rule selector: {resource.selectors.join('; ')}.</p>
            )}
            {res.relationship_name && res.assignment_name && (
              <p className="xp-mute">Granted through the relationship {res.relationship_name} → {res.assignment_name}.</p>
            )}
          </>
        ) : (
          <>
            <p>{res.description}</p>
            <p className="xp-mute">A selector (a pattern), not a list of resources, so the individual resources it matches are not named here.</p>
          </>
        )}
      </DetailSection>

      <DetailSection title="What they can do">
        {resource.actions.length > 0 ? (
          <ul>{resource.actions.map(a => <li key={a}>{a}</li>)}</ul>
        ) : (
          <p className="xp-mute">None listed.</p>
        )}
        {uniquePrivileges.length > 0 && (
          <div aria-label="Privileges as the policy states them">{uniquePrivileges.map(p => <Chip key={p}>{p}</Chip>)}</div>
        )}
      </DetailSection>

      <DetailSection title="Conditions">
        {resource.conditions.length > 0 ? (
          <ul>{resource.conditions.map(c => <li key={c}>{c}</li>)}</ul>
        ) : (
          <p>None. No MFA, approval or gateway is required.</p>
        )}
      </DetailSection>

      <DetailSection title="How they get it">
        {resource.lines.map((line, i) => (
          <div key={`${line.policy.id}-${i}`} className="xp-grant">
            <div>
              Rule “{line.rule.name}” · policy {line.policy.name}
              {line.groups.length > 0 && (
                <>
                  , through{' '}
                  {line.groups.map((g, gi) => (
                    <span key={g.id}>{gi > 0 && ', '}<strong>{g.name}</strong></span>
                  ))}
                </>
              )}
            </div>
            {renderGroupAction && line.groups.map(g => (
              <div key={g.id} className="xp-grant-sub">
                {g.name}: {renderGroupAction(g)}
              </div>
            ))}
            {line.othersCount > 0 && (
              <div className="xp-grant-sub">This rule also covers {line.othersCount} other resource{line.othersCount === 1 ? '' : 's'} not listed in this view.</div>
            )}
          </div>
        ))}
      </DetailSection>

      {lookup && (
        <DetailSection title={<>Last accessed <span className="normal-case tracking-normal font-normal">· System Log, 90 days</span></>} full>
          {targets.length > 0 ? (
            <LastAccessed lookup={lookup} targets={targets} folder={res.kind === 'resolved' && res.resource_kind === 'secret_folder'} now={now} />
          ) : (
            <p className="xp-mute">Not tracked: the System Log does not record access per resource of this kind (or the folder is empty).</p>
          )}
        </DetailSection>
      )}
    </DetailGrid>
  )
}
