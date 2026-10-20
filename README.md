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

**Nothing changes for you unless you choose it.** Upgrading to 5.47.0 changes no
behaviour of an existing install: the update check is **off**, `server/deploy.sh` and `--ref`
keep working in place (with a note that the install can move to the upgrade layout), and no
key has to be pinned. 5.46.0 added **signed releases** and the update check; 5.47.0 adds the
**upgrade layout** and the **updater**: one command stages a signed release, backs up the
archive, switches versions, health-checks the result and rolls back by itself if it is not healthy.

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

### The upgrade layout and the updater (5.47.0, recommended for production)

Run once, on the server, as root. Start with `--dry-run`: it prints exactly what it would do and
changes nothing.

```bash
sudo server/install.sh --dry-run
sudo server/install.sh
```

What it does, and why:

| | |
|---|---|
| `/opt/opa-compliance-wizard/` (owned by root) | `releases/<version>/` (each with its own Python environment), `current` and `previous` symlinks, and the small root-run **updater** (Python standard library only, `updater/`). The web application's account **cannot write its own code**. |
| `/var/lib/opa-compliance-wizard/` | The application's data (archive, audit log, access control, folder templates): the only place it writes (`OPA_DATA_DIR`). The root-owned `upgrade/` directory inside it holds the updater's state, backups and support bundles. |
| accounts | the application's account (unchanged) and `ocw-updater`, an unprivileged account that downloads, verifies and unpacks a release and builds its environment. Root re-verifies everything and never executes anything from a release. |
| `ocw-upgrade.path`, `ocw-upgrade.service`, `ocw-stage@.service` | the units that activate, roll back and resume after a crash. `/usr/local/bin/ocw-updater` is the command. |

An existing install is **migrated**: the data files are copied (the originals are renamed
`*.migrated-<time>`, never deleted), the units are rewritten (`WorkingDirectory`, `ExecStart`,
`ReadWritePaths`; the keyring and `/run/user` carve-outs stay exactly as they were), the services are
restarted and checked, and if they do not come up healthy everything is put back. The old directory is
left where it is. `--remove-legacy-sudoers` removes the old deploy sudoers file (after checking it only
grants what `deploy.sh` needed; it is moved aside, not deleted); nothing removes it unasked.
`--apply-nginx` also applies this release's nginx template, which adds the maintenance page shown to
other users while the version switches. Offline server: `--wheelhouse DIR` installs the Python packages
from a directory only.

**Upgrading:**

```bash
sudo ocw-updater stage 5.48.0              # downloads, verifies, unpacks, builds the environment (as ocw-updater)
sudo ocw-updater apply 5.48.0              # shows what changes, asks you to type the version, then runs the whole sequence
sudo server/deploy.sh --release 5.48.0     # the same two steps (this script is now a thin wrapper)
```

The sequence, with every step in the Audit Log (`upgrade.*`, one correlation id for the whole run) and
the server journal (JSON lines): request accepted and validated; staged release re-verified by root (signature, version, every
file against the signed manifest; the tree is made root-owned first, so nothing can change after the check); preflight (free disk
space on both volumes, no archive sync running, nginx template bakes); **backup** of the archive (SQLite's online backup, integrity-checked, root-only,
never pruned automatically) and the audit chain heads; **switch** (atomic symlink rename, while nginx shows the maintenance page);
restart; **eight health checks** (the unit is active with no restarts; `/api/version` answers the new version from a
*new* process; `/healthz` is not worse than before; the login gate answers 401; the archive's `quick_check`; the schema version; the audit
chain heads are unchanged; an authenticated read works). Any failure rolls back **once, automatically**.

#### Rollback is code only; restoring data is a separate, typed decision

* **Rollback** (automatic on a failed health check, or `sudo ocw-updater rollback` within 24 hours, typed `ROLLBACK`)
  switches the *code* back to the previous release and restarts. **Data is never touched.** A newer release may have
  migrated the archive schema forward; the old code runs on it when the migration is *rollback-safe* (each migration says so
  in `server/schema_migrations.json` and the release manifest; `ocw-updater apply` tells you before you approve).
* **Restore** (`sudo ocw-updater restore --confirm RESTORE`) replaces the archive with the copy taken before the last upgrade. It
  **loses every event archived since** and is never automatic. The database it replaces is moved aside (never deleted).
  Only do this if the maintainers tell you to, and after you have the support bundle.
* If the rollback itself fails the updater does not leave the service down silently: nginx shows a page that says an operator
  is needed, a `CRIT` line goes to the journal, `upgrade.failed` is written to the Audit Log, the state is `failed_needs_operator`,
  and the bundle is written. `ocw-updater status` tells you what to do; the previous code is still on disk.
* A version that failed is not tried again until `sudo ocw-updater clear-failure`; after two failures it stays off.

#### The support bundle ("send to the maintainers")

When an upgrade fails, the updater builds a redacted bundle (`ocw-support-<from>-to-<to>-<time>-<id>.tar.gz`, at most 5 MB) before anyone asks.
An **app administrator without shell access can download it**: `GET /api/upgrade/bundle?name=...` (admin-only; it is linked from the
failed upgrade's Audit Log entry, which records `bundle.name`, size and sha256; the Audit Log offers the download button). From a shell: `sudo ocw-updater bundle`
(`--include-hosts` keeps host and environment names). Email it yourself to the address in SECURITY.md; **nothing is ever sent automatically.**

* **In it:** `summary.json` (versions, reason code, failed step, timings, OS / Python / SQLite / systemd versions, free space, the
  manifest, the health results, `pip freeze`, schema before and after, the chain-head comparison, the run's history), the last 500 journal lines of each
  OPA unit and of the updater, `nginx -t`, `systemctl status`, the audit entries of this run only, and `redaction-report.txt` (how many
  things were redacted, never what).
* **Never in it:** the environment file, anything from the keyring, the session key, the archive or any row of it, environment (tenant)
  metadata, the nginx site file (it holds the proxy secret), request bodies, cookies.
* **Redacted before it is written:** the values of every secret in the server's environment file wherever they appear; variables named
  `*SECRET`, `*TOKEN`, `*PASSWORD`, `*KEY`; `Authorization`, `Cookie`, `Set-Cookie` headers; Okta tokens and JWTs; long token-like strings; e-mail addresses
  (`user-<hash>@redacted`), Okta subject ids (`sub-<hash>`), host names and IP addresses (`host-<hash>`), tenant and environment names (`env-<hash>`).
  The hashes use a random salt per bundle. Host and IP detection is pattern-based (known top-level domains): read the bundle once before you send it.

#### Air-gapped servers

Download `ocw-<version>.tar.gz` and `ocw-<version>.tar.gz.minisig` on a computer with internet access, carry them over, and run
`sudo ocw-updater stage ocw-<version>.tar.gz` then `sudo ocw-updater apply <version>`. A published key revocation
(`revocation.json`) is applied with `sudo ocw-updater trust apply revocation.json`. For packages without internet access, `install.sh --wheelhouse`
covers the first install; a vendored-wheel release bundle is planned.

#### The command

| Command | What it does |
|---|---|
| `ocw-updater status [--json]` | installed, staged, scheduled, updater health, keys, backups, last run (reads only; any user) |
| `stage <file or version>` | verify and stage (root) |
| `apply <version> [--at "YYYY-MM-DD HH:MM" [--tz Europe/London]]` | install now or schedule (typed confirmation); `cancel` removes a schedule |
| `rollback` / `restore --confirm RESTORE` | code-only rollback / archive restore, as above |
| `bundle [--correlation ID] [--include-hosts]`, `clear-failure` | support bundle; allow a failed version again |
| `trust list`, `trust apply <revocation.json>`, `trust add <key.json>` | the signing keys root trusts (the standby key can only change by a signed revocation; `add` takes only an active release key and a typed `TRUST`) |
| `nginx-sync` | apply the current release's nginx template (maintenance page) |
| `check`, `enable-check`, `disable-check`, `verify`, `audit`, `keys ...` | the 5.46.0 tools (run as the application's account automatically) |

Exit codes: `0` ok, `2` refused (signature, version, key, sync running, another upgrade in flight, bad usage), `3` failed and rolled back,
`4` failed and an operator is needed. `--json` where it makes sense. Every action writes the same audit events as the in-app flow (the actor is `cli:<os user>`).

#### Upgrading from the Updates page (5.48.0)

On an install that has run `server/install.sh`, administrators can upgrade without a shell: **Updates**, then **Upgrade now** or **Schedule…**.

1. The page reads the new release's signature file and manifest (a few KB), checks the signature's trusted comment against the pinned keys and runs a
   **preflight** (free disk space, Python and SQLite versions, no sync running, the updater present). **Re-check** repeats it.
2. A **confirmation screen** shows exactly what is approved: versions, artifact, sha256, signing key, what changes, schema migrations (and which of them a code
   rollback cannot undo), the backup, the rollback policy and the downtime. You tick the acknowledgement and **Approve with MFA**: a fresh Okta challenge that is
   bound to *this* version, hash and time. Nothing is installed before you return from it.
3. **Now** writes the request to the updater, which downloads, verifies, backs up, switches, restarts and health-checks (README above). The page shows the nine
   steps live and keeps waiting through the restart (other users see the maintenance page; your session survives); when the new version answers it reloads once.
   **Scheduled** upgrades are held by the application and handed to the updater at the chosen time; if the application is not running then, the upgrade is marked
   **missed** and is never run late. Cancelling or rescheduling needs MFA too.
4. The result is a card: success (with the eight health checks and a 24-hour rollback window), or failure (what happened, where you are now, and the redacted
   **support bundle to download**, also linked from the failed upgrade's Audit Log entry). Every step of the run is in the Audit Log under one correlation id.

Notes:

* **Two-person rule** (Update check, "Change…"; off by default): a second, different administrator must approve within 24 hours.
* **Rollback, restore, clear-failure and building a bundle on demand are command-line actions** (`sudo ocw-updater rollback | restore --confirm RESTORE | clear-failure | bundle`); the page shows
  the exact command. After a failure the same version is refused until `clear-failure`; if the rollback itself failed the page says an operator must act.
* **Local (laptop) mode** does not offer this flow (no identity provider to step up with); it shows the commands `python launch.py upgrade` and
  `python launch.py upgrade --restore-previous`.
* `server/deploy.sh --ref` (unsigned source) is deprecated for operators; use the Updates page or `ocw-updater`.
* The page needs the upgrade layout. Without it, the page says so and shows the manual `deploy.sh --release` command.

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
- **Going back:** a signed `--release` never installs an older version. On the upgrade
  layout use `sudo ocw-updater rollback` (code only, 24 hours); on an install that has not
  run `install.sh` there is no automatic rollback: restore your backup of the installation and
  archive, or `deploy.sh --ref <previous tag>` (unsigned; maintainers).
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
asset of a GitHub release (`revocation`, or `revocation-<serial>` for later ones), and (optional, `OPA_REVOCATION_URL`) at an
owner-controlled static URL, so one outage or one compromised account cannot hide it.

What you will see: a release signed by a key you do not know (*"signed by key ... which is not
pinned ... apply the published revocation"*), or by a key marked revoked (*"was revoked ... Do
not install it"*). A revoked key's releases are refused, except the ones the revocation names
by version and file digest as known good.

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
