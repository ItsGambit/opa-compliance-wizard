# OPA Compliance Wizard

**A compliance evidence helper for Okta Privileged Access (OPA) and core
Okta.** Okta's own System Log only keeps 90 days of history; most audits
(SOC 2, SOX, ISO 27001) ask for 12 months or more. This tool closes that
gap — it continuously archives System Log history past Okta's retention
window and turns it into 16 pre-built, framework-mapped reports, giving
PAM admins the underlying evidence their auditors ask for without
needing to know Okta's System Log event-type names or write a query. It
doesn't produce a finished SOC 2/SOX/ISO 27001 report on its own — it
gets you most of the way there, and that's the direction this project is
headed. It also includes the tool this project started as: building and
managing OPA vault secret folders, resource groups, projects, and access
policies.

Ships as both an interactive dashboard for everyday use and a CLI for
scripting — same underlying engine, no logic duplicated between them.

## Project status

**Community project, not an official Okta product.** No support
commitment, provided as-is under the MIT license — see
[No warranty](#no-warranty) below.

Every endpoint, auth flow, and field name documented here was
**live-verified against a real OPA/Okta tenant**, not just inferred from
published docs — see [docs/api-notes.md](docs/api-notes.md) for specifics,
several of which contradict Okta's own documentation. Security-sensitive
code paths (the hosted-deployment login/MFA gate, cross-tenant data
isolation, admin authorization) have gone through internal review and
multiple independent AI-assisted security passes, with findings verified
against the real code and fixed — see [CHANGELOG.md](CHANGELOG.md) for
specifics. **No independent third-party security audit has been
performed.** If you're evaluating this for a production tenant, treat it
accordingly: start with a disposable/preview org, review the code
yourself, and see [SECURITY.md](SECURITY.md) if you find something
worth reporting privately.

## Where to go next

| I want to... | Go here |
|---|---|
| Just run it on my own machine | Quickstart, below |
| Understand what each feature does | [docs/features.md](docs/features.md) |
| Host it for a team, with Okta login | [docs/hosting.md](docs/hosting.md) |
| Use the CLI instead of the dashboard | [docs/hosting.md](docs/hosting.md#running-it-as-a-cli-instead) |
| See a live-verified API quirk or gotcha | [docs/api-notes.md](docs/api-notes.md) |
| See what changed between versions | [CHANGELOG.md](CHANGELOG.md) |
| Contribute a fix or feature | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Report a security issue privately | [SECURITY.md](SECURITY.md) |

## What it does

1. **Generates audit-ready evidence reports** — MFA enforcement,
   provisioning, privileged access, policy changes, and more — from a
   local, indefinitely-retained archive of Okta System Log + OPA
   activity, mapped to the controls auditors ask about (SOC 2, SOX,
   ISO 27001). This is the data PAM admins need to hand their auditors;
   it isn't a finished SOC 2/SOX/ISO 27001 report in itself. **This is
   the primary use case.** See
   [Compliance Reports Dashboard](docs/features.md#compliance-reports-dashboard),
   plus two per-resource views built on the same archive: the
   [Secrets Access Dashboard](docs/features.md#secrets-access-dashboard)
   (every secret and folder in a project, with who created, changed,
   retrieved or deleted it) and the
   [Service Accounts Dashboard](docs/features.md#service-accounts-dashboard)
   (every SaaS app and Okta service account across the tenant, including
   ones since deleted, with reveals, checkouts and rotation history).
2. **Creates a tree of OPA vault secret folders** (any depth) — and, if
   needed, the resource group / project / access group they live under —
   from a CSV file or the dashboard's visual tree editor. See
   [Resource Groups, Projects, and Groups](docs/features.md#resource-groups-projects-and-groups)
   and [Building the folder tree](docs/features.md#building-the-folder-tree).

Data model: **Resource Group → Project → Folder** (folders can nest
under other folders). Resource groups require at least one **group** for
access delegation; groups are always created in **Okta** and synced into
OPA via **Group Push** — never via OPA's own local-group endpoint.

## Prerequisites

| Requirement | Minimum version | Why |
|---|---|---|
| Python | 3.9+ | `keyring` (encrypted credential storage) requires it; CI tests 3.9, 3.12 and 3.14 |
| Node.js | 20.19+ or 22.12+ | Vite 8 (the frontend build tool) requires it. Running the frontend *tests* (contributors only) needs 22.22.2+ or 24.15+ (jsdom) |
| npm | bundled with Node | frontend dependency install/build |
| pip | bundled with Python | installs `keyring` |

You don't need to check these yourself — `launch.py` (and every launcher
below) checks on every run and, if something is missing or too old,
offers to install/upgrade it for you via whatever package manager your
OS already has (`winget` on Windows, `brew` on macOS, `apt`/`dnf`/`pacman`
on Linux), asking for confirmation first. If none of those are available,
it prints the exact manual install command and exits cleanly instead of
failing partway through a build. If your package manager's Node.js is
still too old after installing, it says so and points you to nodejs.org.
Python packages go into a project virtual environment (`.venv`). The
frontend is rebuilt only when its sources changed; if a build fails and
there is no earlier build, the launcher stops instead of opening a page
that can't load. If a dashboard server from this folder is still running
on the port, it asks before stopping it (and never touches any other
process).

## Quickstart (desktop dashboard)

You can skip this: the launcher below offers to do it. By hand:

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt   # Windows: .venv\Scripts\pip
cd frontend && npm ci
```

(`npm ci`, not `npm install`: it installs exactly the versions in
`package-lock.json` and never rewrites it. The virtual environment keeps
the packages out of your system Python, which on current Debian/Ubuntu
and Homebrew refuses a plain `pip install`; `launch.py` uses `.venv`
automatically when it exists.)

Then run it — cross-platform, no credentials needed to launch:

| OS | How to run |
|---|---|
| Windows | Double-click `Start OPA Compliance Wizard.bat` |
| Mac / Linux | Run `./start-wizard.sh` |
| Any OS | `python launch.py` (or `python3 launch.py`) |

The dashboard's setup screen walks you through adding your first OPA
environment on first launch. See
[Environments](docs/features.md#environments-dev--uat--prod-etc) for
details, and [docs/features.md](docs/features.md) for everything else
the dashboard does.

Want to run it as a CLI instead, or host it for a team? See
[docs/hosting.md](docs/hosting.md).

## No warranty

This tool is provided **as-is, with no warranty of any kind** — see
[LICENSE](LICENSE) (MIT). It creates and deletes real objects in your
OPA/Okta tenant via real API calls; **you are responsible for
reviewing what it does before running it against a production
environment**, and assume all risk of using it. The same notice is
shown in the dashboard itself via the ⓘ icon next to the gear/settings
icon.

## Security: encrypted credential storage

**No secret is ever written to disk in plaintext.** The dashboard's
multi-environment store (`environments.json`, next to this README) holds
only non-secret metadata (base domain, team name, key ID, Okta URL).
The two actual secrets — the OPA service-user **key secret** and the
**Okta API token** — are stored exclusively in your OS's encrypted
credential store via the `keyring` package:

| OS | Backend |
|---|---|
| Windows | Credential Locker (Credential Manager) |
| macOS | Keychain |
| Linux | Secret Service (GNOME Keyring, KWallet, etc.) |

The CLI resolves credentials in this order: (1) OS environment variables,
(2) a local `.env` file (legacy, plaintext, fully opt-in — only used if
you create one yourself; nothing in this tool writes one anymore, and
it's already excluded via `.gitignore` if you do), (3) the dashboard's
encrypted environment store — whichever environment is active there.
This means the CLI automatically follows whatever environment you last
activated in the dashboard, with zero plaintext involved.

This only protects secrets at rest on disk. The OS keychain backends
above unlock with your OS login session — on an unlocked, logged-in
workstation, any process running as you (including this tool itself)
can read what's stored there, the same as any other app using your OS's
native credential store. Lock your workstation like you would for any
other credential-bearing session.

## License

[MIT](LICENSE) — see [No warranty](#no-warranty) above.
