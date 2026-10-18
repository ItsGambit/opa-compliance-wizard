import { useMemo, useState } from 'react'
import type { AccessModel } from '../types'
import { aggregateResources } from '../utils/accessResources'
import type { ExportSection } from '../utils/export'
import { projectFieldRows, visibleAccessSections } from '../utils/exportSections'
import { rulesGrantedForProject } from '../utils/policy'
import { ExplorerLayout } from './explorer/ExplorerLayout'
import { GrantsMain } from './explorer/GrantsMain'
import { CountList, FilterMenu, RailField } from './explorer/RailParts'
import { ResourceAccessView } from './explorer/ResourceAccessView'
import { TypeSection } from './explorer/TypeSection'
import { useGrantsExplorer } from './explorer/useGrantsExplorer'
import { ExportButtons } from './ExportButtons'
import { KeyValueGrid } from './KeyValueGrid'
import { Select } from './Select'

interface Props {
  model: AccessModel
}

export function ProjectsTab({ model }: Props) {
  const [rgId, setRgId] = useState<string | undefined>(undefined)
  const [projectId, setProjectId] = useState<string | undefined>(undefined)
  const [now] = useState(() => Date.now())
  const [settingsOpen, setSettingsOpen] = useState(false)

  const projectsInRg = useMemo(() => model.projects.filter(p => p.resource_group_id === rgId), [model.projects, rgId])
  const project = model.projects.find(p => p.id === projectId)
  const rg = model.resource_groups.find(r => r.id === rgId)

  const grants = useMemo(() => (projectId ? rulesGrantedForProject(model.policies, projectId) : []), [model.policies, projectId])
  // A rule can also name resources in other projects: this view lists only
  // this project's (and the rule's selectors); the row says how many it left out.
  const resources = useMemo(
    () => aggregateResources(grants, { includeResolution: res => res.project_id === projectId }),
    [grants, projectId]
  )
  const ex = useGrantsExplorer({ resources, resetKey: projectId ?? '' })

  const exportSectionsForProject: ExportSection[] = useMemo(() => {
    if (!project) return []
    return [
      { title: `Project: ${project.name}`, rows: projectFieldRows(project) },
      ...visibleAccessSections(ex.visible, now, 'Policies Granting Access'),
    ]
  }, [project, ex.visible, now])

  const handleRgChange = (id: string) => {
    setRgId(id)
    setProjectId(undefined)
  }

  const rail = (
    <>
      <RailField label="Resource group">
        <Select
          ariaLabel="Resource group"
          value={rgId}
          onValueChange={handleRgChange}
          placeholder="Select a resource group"
          options={model.resource_groups.map(r => ({ value: r.id, label: r.name, keywords: r.description ? [r.description] : undefined }))}
        />
      </RailField>
      <RailField label="Project">
        <Select
          ariaLabel="Project"
          value={projectId}
          onValueChange={setProjectId}
          disabled={!rgId}
          placeholder="Select a project"
          options={projectsInRg.map(p => ({ value: p.id, label: p.name }))}
        />
      </RailField>
      {project && (
        <>
          <div className="flex flex-col gap-1">
            <span className="xp-rail-title">{project.name}</span>
            {rg?.name && <span className="xp-rail-sub">{rg.name}</span>}
          </div>
          <CountList items={ex.countItems} onSelect={ex.jump} />
          <FilterMenu items={ex.filterItems} active={ex.active} onToggle={ex.toggleFilter} />
          <div className="xp-rail-actions">
            <ExportButtons sections={exportSectionsForProject} filenameBase={`opa-project-${project.name}`} />
          </div>
        </>
      )}
    </>
  )

  return (
    <ExplorerLayout rail={rail} railLabel="Resource group, project and filters">
      {!project ? (
        <p className="xp-note">Select a resource group, then a project, to see the access that policies give to its resources.</p>
      ) : (
        <GrantsMain
          ex={ex}
          now={now}
          searchLabel="Search this project's access"
          emptyMessage={`No policy resolves a specific resource in this project. (Resource-group-wide rules — server labels, Active Directory, database selectors — may still apply; check the Resource Groups tab for ${rg?.name ?? 'its resource group'}.)`}
          renderDetail={resource => <ResourceAccessView resource={resource} now={now} />}
          after={
            <TypeSection id="project-settings" title="Project settings" count={Object.keys(project).length} open={settingsOpen} onToggle={() => setSettingsOpen(o => !o)}>
              <KeyValueGrid data={project} />
            </TypeSection>
          }
        />
      )}
    </ExplorerLayout>
  )
}
