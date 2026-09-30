import { useVersion } from '../api/hooks'

// Points at this project's real GitHub location (OPA/Secrets-Wizard/ inside
// the ItsGambit/Okta repo, not a dedicated repo of its own) -- keep this in
// sync if the project ever moves to its own repo.
const REPO_README_URL = 'https://github.com/ItsGambit/Okta/blob/main/OPA/Secrets-Wizard/README.md'
const REPO_CHANGELOG_URL = `${REPO_README_URL}#changelog`

export function Footer() {
  const { data: version } = useVersion()

  return (
    <footer className="max-w-4xl mx-auto w-full mt-4 pt-3 border-t border-border text-xs text-text-faint flex items-center justify-center gap-3">
      <span>OPA Compliance Wizard{version && ` v${version.version}`}</span>
      <span aria-hidden="true">·</span>
      <a href={REPO_README_URL} target="_blank" rel="noreferrer" className="hover:text-text-dim underline">
        README
      </a>
      <span aria-hidden="true">·</span>
      <a href={REPO_CHANGELOG_URL} target="_blank" rel="noreferrer" className="hover:text-text-dim underline">
        Changelog
      </a>
    </footer>
  )
}
