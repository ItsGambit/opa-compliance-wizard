<p><img src="frontend/public/logo.svg" alt="OPA Compliance Wizard" height="40"></p>

# OPA Compliance Wizard

*Evidence for OPA audits.*

OPA Compliance Wizard produces audit evidence for Okta Privileged Access
(OPA) tenants. *An independent open-source tool. Not affiliated with or
endorsed by Okta, Inc. Okta and Okta Privileged Access are trademarks of
Okta, Inc.*

**A compliance evidence helper for Okta Privileged Access (OPA) and core
Okta.** Okta's own System Log only keeps 90 days of history; most audits
(SOC 2, SOX, ISO 27001) ask for 12 months or more. This tool closes that
gap — it continuously archives System Log history past Okta's retention
window and turns it into 16 pre-built, framework-mapped reports, giving
PAM admins the underlying evidence their auditors ask for without
needing to know Okta's System Log event-type names or write a query. It
doesn't produce a finished SOC 2/SOX/ISO 27001 report on its own — it
gets you most of the way there, and that's the direction this project is
headed. It also includes Folder Builder, for creating OPA vault folders,
resource groups, projects, and access policies from a CSV or a visual tree.

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
| Upgrade a server (signed releases, the update check) | [Upgrading](#upgrading) |
| Publish a release (maintainers) | [docs/releasing.md](docs/releasing.md) |
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

## Upgrading

**Nothing changes for you unless you choose it.** Upgrading to 5.46.0 changes no
behaviour of an existing install: the update check is **off**, `server/deploy.sh`
and `--ref` work as before (with a warning that they install unsigned source), and
no key has to be pinned. What 5.46.0 adds is a way to install **signed releases**
and to learn that one exists.

### Where your install stands

| State | What it means |
|---|---|
| *No release signing key pinned* (only a fork or self-built copy whose `server/release_keys.json` is empty; 5.46.0 ships with the project's keys) | `deploy.sh --release` refuses with "no release key pinned"; the Updates screen says so. Everything else works exactly as before. |
| *Key pinned* | `deploy.sh --release <version>` verifies every download against it. |
| *Key revoked* (see below) | Releases signed by the old key after the revocation are refused; you apply the published revocation, then install the new release. |

### The update check (off by default)

When you turn it on, the server makes **one HTTPS request a day to `api.github.com`**
and nothing else leaves the machine. GitHub sees the server's egress IP address and
a fixed User-Agent (`opa-compliance-wizard-update-check`); **nothing about your
tenant, users, data or host name is sent**, and the installed version is not sent
unless you tick "share my version". It only reports that a newer release exists; it
never downloads or installs anything. The only things stored are the latest version
seen, its publish date and link, whether a signed download is attached, and when
the check last ran (file `update_check.json` next to the app, owner-only).

- Turn it on or off: **Updates** (admins, sidebar) or `python -m server.updater enable-check` / `disable-check`.
- `OPA_UPDATE_CHECK=off` in the server's environment always wins and cannot be
  overridden from the screen; `OPA_UPDATE_CHECK=on` turns it on without an admin action.
- Behind a proxy: set `https_proxy` / `no_proxy` in the service's environment file.
  A mirror inside your network: `OPA_RELEASE_API_URL`, `OPA_REVOCATION_URL_BASE`
  (https; redirects only to the mirror). Without a mirror, redirects are followed
  only to GitHub's own hosts.
- A failed check (no network, rate limit, bad answer) is shown in plain words on the
  Updates screen and recorded in the **Audit Log**; an identical failure is not
  logged again, and the next success says how many failed and since when.

### Installing a signed release

On the server, as the account that owns the installation:

```bash
server/deploy.sh --release 5.47.0
```

It downloads `ocw-5.47.0.tar.gz` and its `.minisig` from the project's GitHub
release, checks them against the signing key pinned in `server/release_keys.json`
(the **installed** copy is the root of trust, never the file being checked) and
refuses, before changing anything, if the file is unsigned, altered, renamed,
signed by a standby or revoked key, built for a different version than it claims,
not newer than what is installed (no downgrades), or needs a newer starting
version. The release carries the built frontend, so **Node.js is not needed**
on the server. Then it installs exactly like the unsigned path: backup (if
`OPA_DEPLOY_BACKUP_DIR` is set), file sync, `pip install --require-hashes -r
requirements.lock`, restarts with health checks, nginx validation.

- **No internet on the server:** download the two files (and, if published,
  `revocation.json` + `revocation.json.sig`) elsewhere, carry them over, run
  `server/deploy.sh --release 5.47.0 --from-dir /path/to/dir`.
- **Re-run the same version** (for example after a failed run): add `--reinstall`.
- **Going back:** a signed `--release` never installs an older version. To return to
  an earlier version, restore your backup of the installation and archive, or
  `deploy.sh --ref <previous tag>` (unsigned; maintainers). There is no automatic
  code rollback in 5.46.0.
- **Take a backup first.** Set `OPA_DEPLOY_BACKUP_DIR` (see [docs/hosting.md](docs/hosting.md)).
- Every refusal is recorded in the Audit Log as `upgrade.verify_failed` with a reason code.

### From the command line

Everything on the Updates screen is also available from a shell. Run from the
install directory with the app's Python (`.venv/bin/python -m server.updater ...`).

| Command | What it does |
|---|---|
| `status [--json]` | The same data as `GET /api/upgrade/status`: installed version, check on/off and why, latest release, last check, signing-key state. |
| `check [--force] [--json]` | Run the check now. Respects off unless `--force` (which is recorded). Exit 1 when a newer release exists. |
| `enable-check` / `disable-check` | Same switch as the screen, same audit entry (actor recorded as `cli:<os user>`). |
| `verify <tar.gz> <.minisig>` | Verify a download (see below). |
| `keys list` / `keys apply-revocation <revocation.json>` | Show or update the pinned signing keys. |
| `audit [--since DATE] [--json]` | List the upgrade-related Audit Log entries (`upgrade.*`, `deploy.*`). |

Exit codes: `0` ok, `1` a newer release is available (`check`), `2` usage error, `3` failure
(the message says what to do).

### Verify a download by hand

With this project's own verifier (no extra software, works offline):

```bash
python -m server.updater.verify ocw-5.47.0.tar.gz ocw-5.47.0.tar.gz.minisig --installed-version none
```

It prints one `OK` line per fact (signature, version, hashes) or `ERROR:` and what to
do. With the reference tool [minisign](https://jedisct1.github.io/minisign/), using
the minisign public-key line the project publishes with each release (it is the key in
`server/release_keys.json` with role `release`; the file lists it as 32 raw bytes, minisign
wants `base64("Ed" || id || key)`, which `tools/release.py pubkey` prints):

```bash
minisign -Vm ocw-5.47.0.tar.gz -P <public key> -H
```

(`-H` requires the prehashed signature format the project uses.) `minisign` checks the
signature and the signed comment; the project's verifier additionally checks the
version, file name and the manifest of every file inside, and that the key is a current
release key. Prefer the project's verifier.

### If the signing key is compromised

The project holds two keys in different places: a **primary** that signs releases and a
**standby** (a different kind of key, in a different cloud) that can only sign a *revocation*. If the primary is ever lost or stolen the
maintainers publish a signed `revocation.json` that revokes it and installs a new release key (and,
if needed, a new standby), with a link to a security advisory. It is published in two places: as an
asset of the GitHub release tagged `revocation`, and (optional, `OPA_REVOCATION_URL`) at an
owner-controlled static URL, so one outage or one compromised account cannot hide it.

What you will see: a release signed by a key you do not know (*"signed by key ... which is not
pinned ... apply the published revocation"*), or by a key marked revoked (*"was revoked ... Do
not install it"*). Releases the old key signed **before** the revocation stay valid.

What to do:
1. **Online:** with the update check on, the server fetches and applies the revocation by itself
   (recorded in the Audit Log as `upgrade.key_revoked`); `deploy.sh --release` also
   applies a published revocation before it verifies. Nothing to do.
2. **Offline:** on a trusted computer download `revocation.json` from the project's `revocation`
   release; copy it to the server; run
   `.venv/bin/python -m server.updater keys apply-revocation revocation.json`
   (or `python -m server.updater.verify --apply-revocation revocation.json`, or put the file next to the
   release files for `--from-dir`). It checks the standby key's signature and that the revocation's serial
   is newer than anything applied before. Then install the new release as usual.
3. **If you suspect your copy of the keys itself:** compare the key ids with the project's security
   advisory over a second channel before applying anything. If both of the project's keys were lost, the
   advisory will tell you to re-pin a new key by hand (replace `server/release_keys.json` with the
   published list after checking its key ids through two independent channels).

Applying a revocation writes `release_keys.local.json` next to the app (kept across deploys, owner-only):
the install remembers every key, its status and the highest revocation serial, so no later release can
bring a revoked key back.

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
