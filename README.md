<p><img src="frontend/public/logo.svg" alt="OPA Compliance Wizard" height="40"></p>

# OPA Compliance Wizard

*Evidence for OPA audits.*

OPA Compliance Wizard produces audit evidence for Okta Privileged Access
(OPA) tenants. *An independent open-source tool. Not affiliated with or
endorsed by Okta, Inc. Okta and Okta Privileged Access are trademarks of
Okta, Inc.*

**A compliance evidence helper for Okta Privileged Access (OPA) and core
Okta.** Okta's own System Log only keeps 90 days of history; most audits
ask for 12 months or more. This tool closes that
gap — it continuously archives System Log history past Okta's retention
window and turns it into pre-built reports, mapped to SOC 2 criteria
(the mapping is labelled proposed; ISO 27001 and SOX are planned, not
mapped yet), giving PAM admins the underlying evidence their auditors ask
for without needing to know Okta's System Log event-type names or write
a query. It doesn't produce a finished SOC 2 (or SOX or ISO 27001)
report on its own — it gets you most of the way there, and that's the
direction this project is headed. It also includes Folder Builder, for creating OPA vault folders,
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
| Install it on a clean server with one command | [Installing on a server](#installing-on-a-server) |
| Host it for a team, with Okta login | [docs/hosting.md](docs/hosting.md) |
| Use the CLI instead of the dashboard | [docs/hosting.md](docs/hosting.md#running-it-as-a-cli-instead) |
| See a live-verified API quirk or gotcha | [docs/api-notes.md](docs/api-notes.md) |
| Upgrade a server (signed releases, the update check) | [Upgrading](#upgrading) |
| Publish a release (maintainers) | [docs/releasing.md](docs/releasing.md) |
| See what changed between versions | [CHANGELOG.md](CHANGELOG.md) |
| Contribute a fix or feature | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Report a security issue privately | [SECURITY.md](SECURITY.md) |

## What it does

1. **Generates evidence for your auditor** — reports on MFA enforcement,
   provisioning, privileged access, policy changes, and more — from a
   local, indefinitely-retained archive of Okta System Log + OPA
   activity, mapped to SOC 2 criteria (CC6, CC7 and CC8; the mapping is
   labelled proposed; ISO 27001 and SOX are planned, not mapped). This is
   the data PAM admins need to hand their auditors; it isn't a finished
   SOC 2 report in itself. **This is the primary use case.** See
   [Compliance Reports Dashboard](docs/features.md#compliance-reports-dashboard),
   plus two per-resource views built on the same archive: the
   [Secrets Access Dashboard](docs/features.md#secrets-access-dashboard)
   (every secret and folder in a project, with who created, changed,
   retrieved or deleted it) and the
   [Service Accounts Dashboard](docs/features.md#service-accounts-dashboard)
   (every SaaS app and Okta service account across the tenant, including
   ones since deleted, with reveals, checkouts and rotation history).
   Since 5.50.0, two views that join Okta and OPA: the
   [Okta Admins report](docs/features.md#okta-admins-report-and-cross-checks)
   and the lifecycle cross-check.
   Around the reports sit four more pages: the
   [Overview](docs/features.md#overview) (counts of who holds Okta admin
   and OPA privileged access, who holds both, and how complete the
   evidence behind them is, with one **Refresh** for everything), the
   [Access Explorer](docs/features.md#access-explorer) ("who has access
   to what", opening from a stored OPA scan with an "as of" time), the
   [Okta Admins](docs/features.md#okta-admins-report-and-cross-checks)
   report, and, for administrators, the
   [Audit Log](docs/features.md#audit-log-page) and the
   [Updates page](docs/features.md#updates-page) (the update check and
   upgrades, see [Upgrading](#upgrading)).
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

## Installing on a server

One command installs a signed release on a clean **Debian 12 or newer, or Ubuntu 22.04 or newer** server (the LTS releases are the ones
meant; x86-64 or ARM, with systemd, run as root): it checks the system, downloads the release and its signature, **verifies the signature against the
project's release key before anything is installed**, applies any published key revocation, and runs the installer from the
verified release. That installer creates the application account, the settings file with generated secrets, the services and the
nginx site with a certificate, starts the backend and checks it. It installs `nginx`, the keyring packages and `python3-venv` from
your distribution when they are missing, and leaves the login gate waiting for your Okta settings.

```bash
curl -fsSLO https://github.com/ItsGambit/opa-compliance-wizard/releases/latest/download/get-ocw.sh && sudo bash get-ocw.sh
```

The file is downloaded first and then run (not piped into a shell): a script that is cut short halfway does nothing, you can read it
before it runs, and it asks its questions through your terminal. Variants:

```bash
sudo bash get-ocw.sh --dry-run                     # the whole plan after a real download and verification; nothing is changed
sudo bash get-ocw.sh --version 5.52.0              # a specific release (the default is the latest stable one)
sudo bash get-ocw.sh --from-dir /media/usb/ocw     # no internet: ocw-X.Y.Z.tar.gz and its .minisig (and revocation.json) brought over
sudo bash get-ocw.sh --uninstall --keep-data       # remove the software; every data file stays
```

It asks for the server's public name (or IP address) and for the TLS certificate (your own, or a temporary self-signed one that makes
browsers warn until you install a trusted one), shows the plan, and asks once. For scripts, `--yes` needs the choices spelled out:
`--server-name HOST` and `--cert FILE --key FILE`, `--self-signed` or `--no-nginx`. Nothing ever takes a secret on the command line:
the three secrets the application needs are generated inside the installer and written to `/etc/opa-compliance-wizard.env` (mode
0600); they are never printed and never logged. The log of every run is `/var/log/ocw-install/<time>.log` (mode 0600).

**What you trust.** The first file (`get-ocw.sh`, a few hundred lines of shell plus the verifier) is fetched over TLS from the
project's GitHub release; everything after it is checked against the signing key held in a cloud HSM, which no GitHub credential can
use. To remove the dependency on GitHub's account for that first file, verify `get-ocw.sh` with `minisign` before running it:

```bash
curl -fsSLO https://github.com/ItsGambit/opa-compliance-wizard/releases/latest/download/get-ocw.sh
curl -fsSLO https://github.com/ItsGambit/opa-compliance-wizard/releases/latest/download/get-ocw.sh.minisig
minisign -Vm get-ocw.sh -P RWQZ6MDGT7XfiNw30FMcGZ/sL1IZFaHr+f7So4QAvmFg77qt3/Fcr2Ka -H    # key id 88DFB54FC6C0E819
less get-ocw.sh                                                                          # read it
sudo bash get-ocw.sh
```

That key line is published in the same repository as the script, so it only helps if you get it from somewhere GitHub's account does
not control: the command trusts GitHub for the first file. To check it independently, compare the key id with the one published on
a page the project controls outside GitHub, <https://apps.ruchir.pw/keys/opa-compliance-wizard> (plain text: `/keys/opa-compliance-wizard.txt`).
If they differ, stop and report it privately (see [SECURITY.md](SECURITY.md)). Python packages are installed with `pip --require-hashes` from the hash-pinned list inside the signed release;
system packages come signed from your distribution. **No independent third-party audit of this installer or the project has been
performed.**

**What it does not do (5.52.0).**

- **Run end to end on a real Debian 13 x86-64 server only.** Ubuntu and ARM (aarch64) are covered by automated tests with stubbed system
  commands, not yet by a real-machine install.

- Red Hat family systems (RHEL, Rocky, Alma, Fedora, Amazon Linux) are recognised and refused, with the reason and nothing changed:
  follow [docs/hosting.md](docs/hosting.md) by hand. Debian 11 and older, Ubuntu 20.04 and older, Alpine, servers without systemd as
  PID 1 (most containers, WSL1) and macOS are refused too, each with its own reason. A Docker image is on the backlog.
- It does not set up Okta. The four Okta settings (commented in the settings file) and the client secret and admin-check token (in the
  application's keyring, with the backend running) are still entered by you; the last lines of the run print the exact steps. The login gate is installed
  but **neither enabled nor started** until you have done that (an enabled gate without its settings would crash-loop at every boot); the last lines of the run give the command.
- `get-ocw.sh --from-dir DIR` accepts the offline bundle (`ocw-X.Y.Z-offline.tar.gz`) as well as the loose release file and its signature; its packages are used unless you pass `--wheelhouse DIR`.
- `--uninstall` keeps the data (the archive, audit log, settings file, session key, TLS files, the application account and the packages).
  Removing them is a manual step, listed in [docs/hosting.md](docs/hosting.md#uninstalling).

Behind a proxy, or with a mirror, pass the settings through `sudo`, which resets the environment:
`sudo https_proxy=https://proxy.example.com:3128 OCW_RELEASE_BASE_URL=https://mirror.example.com/releases/download OCW_REVOCATION_URL=https://example.com/revocation.json bash get-ocw.sh --version 5.52.0`.
A mirror must name the version (it cannot choose what gets installed) and also answers for the key-revocation files, so when you use one
set `OCW_REVOCATION_URL` to a page you control: a mirror that hides a revocation would otherwise go unnoticed.

A server that already runs the upgrade layout is left alone (the command prints its status and exits; upgrade from the Updates page or
`sudo ocw-updater apply <version>`; `sudo bash get-ocw.sh --refresh-updater` refreshes the updater, the units and the command from a
release). A server that runs from a home directory is migrated with the migration's own checks and rollback, after two confirmations.
An interrupted fresh install is resumed by running the same command again; it never overwrites a data or settings file. Exit status:
`0` done, `2` refused and nothing was changed, `3` failed and everything was put back, `4` failed and you have to act (the message says what).

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

## Data this tool stores locally (5.51.0)

The Overview, the Access Explorer, the Okta Admins report and the cross-checks read your OPA team and your Okta org with the
environment's existing credentials (read-only: nothing is written to either, apart from the Folder Builder's own actions) and store the
result locally, in this app's archive. One **Refresh** (on the Overview, or **Sync now** in the footer) reads the OPA scan, the Okta scan and
the System Log in one job; the daily schedule runs the same job.

| What is stored | Why | How it is removed |
|---|---|---|
| The OPA scan: resource groups, projects, groups and their roles, users (name, e-mail, type, group memberships), security policies with the resources they resolve to, servers, accounts (SaaS, Okta Universal Directory, Active Directory, database), connections, gateways, enrolled clients, Okta-managed devices (display name, platform, manufacturer, model, OS version, serial number, registration date, management state, secure-hardware and disk-encryption flags, authenticator enrolment names and status, and the Okta user ids bound to the device) | the Access Explorer, the Overview and the cross-checks open from the stored scan instead of reading OPA every time, also after a restart | replaced by every successful scan; deleted with the environment |
| Daily OPA access state: one sealed record per user, group and policy (names, e-mails, roles, which resources a policy resolves to, by id), plus counts | evidence of who could reach what on a date | kept until the environment's archive is purged; never pruned |
| Okta admins: user id, status, login, e-mail, first and last name, role assignments (role, status, dates, group or app targets, time-bound grants), custom roles and their permission names, resource sets | the Okta Admins report, as of any snapshot date | with the environment's archive (delete the environment with "also delete its archive", or purge an orphaned archive) |
| The Okta status of each OPA user and Okta service account | the lifecycle cross-check | same |
| Daily counts (OPA objects, Okta users, groups, apps, policies by type, admin role holders) | the Overview's inventory over time | same; counts only, no names |
| Per person and week: counts of sign-ins and of multi-factor events by factor class | the Overview's sign-in and MFA figures | follows the event retention setting (weeks that ended before the cutoff are deleted at each sync; the all-people totals hold no names and stay), or with the archive |

Never stored: secret values, service-user key secrets, the OPA service key, the Okta token, Okta `credentials` objects, any Okta profile
attribute beyond login, e-mail and name. (The stored scan does include device names and serial numbers, and people's names and e-mails: they
are in the table above.) A scan that contains a credential-shaped value is refused and not stored. The sealed records (the access state, the
Okta admins and the lifecycle status hold names) are part of the same hash chain as the archived log and are never pruned by
retention: they are kept until the environment's archive is purged. A deep integrity check verifies them.

**Keep the data folder on an encrypted disk.** The app does not encrypt the archive (`audit_store.db`, `audit_log.jsonl` and the environment
store): use FileVault, BitLocker or LUKS for the disk the data directory is on. The app sets owner-only permissions on the archive on macOS and
Linux. On Windows the file inherits its folder's permissions, and the app warns (in the log and in About) if the folder is one other users of the
computer can read, such as `C:\Users\Public`, `C:\ProgramData`, the root of a drive or a network share; move it with `OPA_DATA_DIR`.

**Which Okta role the token needs.** The Okta Admins report calls Okta's role-assignment APIs, which Okta
only answers for a token whose admin can view roles and admin assignments: **Super Administrator**, or a
custom admin role with the permission `okta.iam.read` (view roles, resources and admin assignments) plus
permission to read users. Organization Administrator and Read-only Administrator tokens are refused (Okta
error E0000006). When Okta refuses, the report says: "Your Okta token cannot read admin role assignments;
this report needs a token whose admin can view roles and admin assignments (for example a custom admin role
with that permission, or Super Administrator)." and every other screen keeps working. The cross-check needs a
token whose admin can read users; the System Log archive needs log read access, as before. The app does not
test the token's permissions up front: each screen says what it could not read.

## Upgrading

**After upgrading to 5.53.0, opening Settings or Updates asks for MFA** on a hosted server: the first time you open Access control,
Shared permissions, Orphaned archives, the environment details or the Updates page, the wizard sends you through your Okta
step-up sign-in and back, then keeps Settings open for 10 minutes (a countdown shows how long is left). Saving the announcement
banner asks for MFA as well. A computer running without a login gate (local mode) is not asked, and says so on screen. The
upgrade itself needs nothing from you and changes no nginx or service file; an additional login gate's site generated before
5.42.0 must be regenerated first (see [docs/hosting.md](docs/hosting.md), "Opening Settings and Updates needs a fresh MFA too").

**Nothing else changes for you unless you choose it.** Upgrading changes no other
behaviour of an existing install by itself: the update check is **off**, `server/deploy.sh` and `--ref`
keep working in place (with a note that the install can move to the upgrade layout), and no
key has to be pinned. One thing you will notice after a *minor* upgrade (for example 5.52 to 5.53):
the stored OPA scan is tied to the release's minor number, so the first refresh reads OPA again
instead of reusing the scan stored by the earlier release. A patch upgrade keeps it. 5.46.0 added **signed releases** and the update check; 5.47.0 adds the
**upgrade layout** and the **updater**: one command stages a signed release, backs up the
archive, switches versions, health-checks the result and rolls back by itself if it is not healthy.

### Where your install stands

| State | What it means |
|---|---|
| *No release signing key pinned* (only a fork or self-built copy whose `server/release_keys.json` is empty; 5.46.0 ships with the project's keys) | `deploy.sh --release` refuses with "no release key pinned"; the Updates screen says so. Everything else works exactly as before. |
| *Key pinned* | `deploy.sh --release <version>` verifies every download against it. |
| *Key revoked* (see below) | Releases signed by the old key after the revocation are refused; you apply the published revocation, then install the new release. |
| *Installed with `get-ocw.sh`* (5.52.0, see [Installing on a server](#installing-on-a-server)) | The release was verified against the pinned key before it was unpacked; `ocw-updater status` shows the key that signed it. The updater layout is in place from the first minute. |

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

The units, the `ocw-updater` command and `server/install.sh` are replaced only by `install.sh`, never by the updater. `install.sh`
records in the updater's config (`install_sh_version`) the version of the release it was last run from, and every release says in its
manifest the newest version that changed those files (`install_sh_min_version`). The updater refuses an upgrade with
`needs_install_sh` only while the recorded version is missing or older, and the message names the fix: unpack the release file for the
new version (the one you downloaded, not the staging copy) and run

```bash
sudo server/install.sh --refresh-updater   # from the unpacked new release; refreshes units, command and updater, records the version, touches no data
sudo bash get-ocw.sh --refresh-updater     # 5.52.0 and newer: the same, downloading and verifying the release for you
```

then apply again. 5.48.0 changes only the `ocw-updater` command, so an install on the 5.47.0 layout can apply it directly (the 5.47.0
updater only looks at a flag that is set when a unit file changed); it gets the new command and the record when you run the
command above, which the next release will ask for (reason `needs_install_sh`) until you have.

**Migrating a server that has additional login gates** (`setup-second-gate.sh`): neither `install.sh` nor the updater changes a gate's
nginx site, and a site generated before 5.47.0 does not answer 403 on `/api/upgrade`. The dry run and the end of the real run list each
gate and whether its site denies it. Regenerate them (from the live main site; each keeps its port, listen address and host; `nginx -t`
first, the old site put back if it fails, the old copy kept in the install backup directory):

```bash
sudo server/install.sh --apply-nginx --regenerate-second-sites
```

The updater's preflight only reads those sites: it warns, and writes an Audit Log entry, while one lacks the deny.

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
  **loses every event archived since** and is never automatic. A request from the Updates page names the exact copy that page showed and is refused if it would restore another one or an upgrade is running. The database it replaces is moved aside (never deleted).
  Only do this if the maintainers tell you to, and after you have the support bundle.
* If the rollback itself fails the updater does not leave the service down silently: nginx shows a page that says an operator
  is needed, a `CRIT` line goes to the journal, `upgrade.failed` is written to the Audit Log, the state is `failed_needs_operator`,
  and the bundle is written. `ocw-updater status` tells you what to do; the previous code is still on disk. In that state only
  `sudo ocw-updater clear-failure` on the server ends it: the Updates page does not offer to.
* A version that failed is not tried again until `sudo ocw-updater clear-failure`; after two failures it stays off.

#### The support bundle ("send to the maintainers")

When an upgrade fails, the updater builds a redacted bundle (`ocw-support-<from>-to-<to>-<time>-<id>.tar.gz`, at most 5 MB) before anyone asks.
An **app administrator without shell access can download it**: `GET /api/upgrade/bundle?name=...` (admin-only; it is linked from the
failed upgrade's Audit Log entry, which records `bundle.name`, size and sha256; the Audit Log offers the download button). From a shell: `sudo ocw-updater bundle`
(`--include-hosts` keeps host and environment names). Attach it to a private report as SECURITY.md describes (GitHub Security Advisories); **nothing is ever sent automatically.**

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
covers the first install; for releases use the **offline bundle** described under "Upgrading without internet access" below (the bundle is
accepted by `server/deploy.sh --release X --from-dir` on the in-place layout; the updater layout stages the release inside it and cannot yet
install its packages from the bundle: see that section).

#### The command

| Command | What it does |
|---|---|
| `ocw-updater status [--json]` | installed, staged, scheduled, updater health, keys, backups, last run (reads only; any user) |
| `stage <file or version>` | verify and stage (root) |
| `apply <version> [--at "YYYY-MM-DD HH:MM" [--tz Europe/London]]` | install now or schedule (typed confirmation); `cancel` removes a schedule |
| `rollback` / `restore --confirm RESTORE` | code-only rollback / archive restore, as above |
| `bundle [--correlation ID] [--include-hosts]`, `clear-failure` | support bundle; allow a failed version again |
| `prune-backups --keep N` or `--name FILE ...` with `--confirm PRUNE` | delete old pre-upgrade archive copies (never the newest, never the last upgrade's); command line only, the Updates page cannot do this |
| `trust list`, `trust apply <revocation.json>`, `trust add <key.json>` | the signing keys root trusts (the standby key can only change by a signed revocation; `add` takes only an active release key and a typed `TRUST`) |
| `nginx-sync` | apply the current release's nginx template (maintenance page) |
| `check`, `enable-check`, `disable-check`, `verify`, `audit`, `keys ...` | the 5.46.0 tools (run as the application's account automatically) |

Exit codes: `0` ok, `2` refused (signature, version, key, sync running, another upgrade in flight, bad usage), `3` failed and rolled back,
`4` failed and an operator is needed. `--json` where it makes sense. Every action writes the same audit events as the in-app flow (the actor is `cli:<os user>`).

#### Upgrading from the Updates page (5.48.0)

On an install that has run `server/install.sh`, administrators can upgrade without a shell: **Updates**, then **Upgrade now** or **Schedule…**.

1. The page reads the new release's signature file and manifest (a few KB), checks the signature's trusted comment against the pinned keys and runs a
   **preflight** (free disk space, Python and SQLite versions, no sync running, the updater present). **Re-check** repeats it.
2. A **confirmation screen** shows exactly what is approved: versions, artifact, sha256, signing key, what changes, schema migrations (what each does, and which of them a code
   rollback cannot undo), the backup and where it goes, the rollback policy and the downtime. You tick the acknowledgement and **Approve with MFA**: a fresh Okta challenge that is
   bound to *this* version, hash and time. Nothing is installed before you return from it.
3. **Now** writes the request to the updater, which downloads, verifies, backs up, switches, restarts and health-checks (README above). Right after the approval the page shows
   **Starting** (with Follow progress), then the nine steps live, and keeps waiting through the restart (other users see the maintenance page; your session survives); when the new
   version answers it reloads once. **Scheduled** upgrades are held by the application and handed to the updater at the chosen time; if the application is not running then, the
   upgrade is marked **missed** and is never run late. Cancelling or rescheduling needs MFA too.
4. The result is a page: success (who approved it, how it ran, the eight health checks and a 24-hour rollback window), or failure (what happened and when, where you are now, and the redacted
   **support bundle to download**, also linked from the failed upgrade's Audit Log entry). "View the N audit entries" opens the Audit Log filtered to that upgrade; every step of the run is there under one correlation id.

Notes:

* **One banner at a time** tells every signed-in user what is going on: an upgrade running or failed, then a key revocation (admins), then a scheduled window, then "an update is available" (admins).
* **Two-person rule** (Update check, "Change…"; off by default): a second, different administrator must approve within 24 hours.
* **Rollback, restore, clear failure and rebuilding the support bundle with host names are buttons** on the page (typed word where something is lost: `ROLLBACK`, `RESTORE`; then the MFA approval), and each is also a
  command: `sudo ocw-updater rollback | restore --confirm RESTORE | clear-failure | bundle [--include-hosts]`. Restore is tied to the backup file the page shows. The updater re-checks every request and
  refuses what the command line would refuse. After a failure the same version is refused until the failure is cleared; while an operator must act (the rollback itself failed) the page shows the command
  instead of a button. If the server's updater is older than this release the buttons stay off and the page shows `sudo server/install.sh --refresh-updater`.
* **Deleting pre-upgrade backups is command-line only**: `sudo ocw-updater prune-backups --keep N --confirm PRUNE` (never the newest copy, never the last upgrade's). The page lists the copies (version, date, size, integrity) but
  has no delete button: they are the only copies of the archive the web application cannot touch, so removing them needs a shell on the server.
* **Local (laptop) mode** does not offer this flow (no identity provider to step up with); it shows the commands `python launch.py upgrade` and
  `python launch.py upgrade --restore-previous`.
* `server/deploy.sh --ref` (unsigned source) is deprecated for operators; use the Updates page or `ocw-updater`.
* The page needs the upgrade layout. Without it, the page says so and shows the manual `deploy.sh --release` command.

### Upgrading a local (laptop or desktop) install

Local mode (`python launch.py`, Windows, macOS or Linux) has no sign-in, so there is **no MFA** for upgrading and none is faked: the guided
upgrade asks you to **type the version** instead, and everything else is the same as on a server: signed, verified, logged. Run it from the
install folder, with no dashboard running (it offers to stop this folder's dashboard):

```bash
python launch.py upgrade --check                # is there a newer signed release? sends one HTTPS request to the release host, nothing about your data
python launch.py upgrade                        # download, verify, prepare, ask you to type the version, swap folders
python launch.py upgrade --to 5.49.0            # a specific version (must be newer than the installed one)
python launch.py upgrade --from-file ocw-5.49.0-offline.tar.gz          # files you brought (see "without internet access")
python launch.py upgrade --from-file ocw-5.49.0.tar.gz ocw-5.49.0.tar.gz.minisig
python launch.py upgrade --restore-previous     # bring the previous version back (typed RESTORE)
python launch.py upgrade --discard-previous     # delete the kept previous version (typed DELETE)
python launch.py upgrade --status
```

What it does, in order (it stops, having changed nothing you own, at any step before the last):

1. Downloads `ocw-<version>.tar.gz` and its `.minisig` (or takes the files you name) and applies any published signing-key revocation.
2. **Verifies the signature, the signed manifest and the version against the keys pinned in your install, before unpacking anything.** An unsigned, altered,
   renamed, wrongly signed, downgrading or mislabelled file is refused. Archives that contain links, absolute or `..` paths, Windows device names or
   files the manifest does not list are refused.
3. Unpacks into a sibling folder, `<your folder>-<version>`, and builds its Python environment from the hash-pinned `requirements.lock`
   (a `.venv` is created when your current folder has one or this Python lacks the packages).
4. Shows what changes (database migrations and whether they are rollback-safe) and asks you to type the version.
5. Copies your data into the new folder, swaps the folder names (`<your folder>` becomes `<your folder>-previous`; the new one takes its name), then
   starts the new code once with its own Python, which also migrates the **copy** of the database. If that fails, the previous folder is put back automatically.

Your data lives in the install folder and is **copied, never moved**: `audit_store.db` (copied with SQLite's online backup, integrity-checked),
`environments.json`, `audit_log.jsonl`, `banner_config.json`, `access_control.json`, `secrets_log_cache.json`, `update_check.json`,
`release_keys.local.json`, `.env`, your saved folder templates (`*.csv` the release does not ship) and `folders_result_*.csv`, with their file permissions.
Credentials stored in your operating system's keychain are not touched. The previous folder keeps its own copies until you delete it
(`--discard-previous`), including the plain-text files above; files that are not on this list are left in the previous folder and listed.
If you keep the data elsewhere (`OPA_DATA_DIR`), it is not touched at all.

**Restoring.** `--restore-previous` swaps the folders back (the one it replaces is kept as `<your folder>-replaced-<version>`). By default it is
**code only**: your current data stays, and the restore is refused if the newer database can no longer be read by the older code (a migration that is
not rollback-safe). `--restore-data` then brings back the previous folder's own, older data instead; everything recorded since the upgrade stays in the
replaced folder. If a swap is ever interrupted (power cut), run `python <your folder>-previous/launch.py upgrade --restore-previous`: it puts the old folder back.

Exit codes: `0` ok or up to date, `1` (`--check`) a newer release exists, `2` refused (signature, version, key, not confirmed, usage), `3` failed and
nothing changed or everything was put back, `4` failed and you have to act (the message says how). For scripts, `--confirm 5.49.0` (or `RESTORE`,
`DELETE`) replaces the typed confirmation.

**Windows.** Needs no admin rights and no symbolic links. Windows will not rename a folder while a program has a file in it open: close the dashboard
(and its window), File Explorer windows on the folder and editors, and run the upgrade with the system Python (`py -3 launch.py upgrade`);
the launcher does the renames from the outer process when it has relaunched itself in `.venv`. Keep the install path short (about 200 characters at most).
Run the upgrade from the install folder, not from `<folder>-previous`.

**Release channel.** The default is `stable`. To also see releases the maintainers mark as prereleases (more testing wanted; still signed and checked against the
same pinned keys): `python -m server.updater set-channel prerelease` (back with `set-channel stable`; `OPA_UPDATE_CHANNEL` fixes it from the environment), or
`python launch.py upgrade --check --channel prerelease` for one run. On the prerelease channel the newest release of either kind is offered. A prerelease is never
downgraded when you switch back; you simply wait for the next stable release. The installed version is added to the check's User-Agent only if you
opt in: `python -m server.updater share-version on` (off by default).

### Upgrading without internet access (the offline bundle)

On a computer that has internet access, download from the release page either the three files (`ocw-<version>.tar.gz`, `.minisig`, `manifest.json`) or the
**offline bundle** `ocw-<version>-offline.tar.gz` (with its `.sha256`): the same signed release plus the hash-pinned Python packages for Windows, macOS and
Linux (x86-64 and ARM) on Python 3.9 to 3.14 (Linux needs glibc 2.28 or newer; Alpine is not covered; macOS means Apple silicon: the pinned
`cryptography` publishes no wheel for Intel Macs, so they are not in the bundle). Carry it over on removable media; check the copy
with `sha256sum -c ocw-<version>-offline.tar.gz.sha256` if you like (the signature inside is what the install trusts).

* **Local install:** `python launch.py upgrade --from-file ocw-<version>-offline.tar.gz`. Nothing is fetched from the internet; packages are installed with
  `pip install --no-index --require-hashes`. If a signing-key revocation was published, apply it first
  with `python -m server.updater keys apply-revocation revocation.json` (for `--from-file` with the two separate files, a `revocation.json` next to them is applied automatically).
* **Server, in-place layout:** put the bundle in a directory and run `server/deploy.sh --release <version> --from-dir <dir>` (the directory holds only the bundle).
* **Server, upgrade layout (`install.sh`):** `sudo ocw-updater stage ocw-<version>.tar.gz` stages the signed release from the three files; installing its
  packages without internet from the bundle is not supported by the updater yet, so `server/deploy.sh --from-dir` refuses a bundle there with a clear message.

The bundle itself carries no signature of its own, and needs none: the release inside it is verified like any other, and `pip` refuses any package whose
sha256 is not recorded in that release's signed `requirements.lock`. A wrong, damaged or substituted package can make the install fail; it cannot be installed.

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
  `server/deploy.sh --release 5.47.0 --from-dir /path/to/dir`. From 5.49.0 the directory may hold the offline bundle
  `ocw-5.47.0-offline.tar.gz` instead (see "Upgrading without internet access").
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

The release key's minisign line (key id `88DFB54FC6C0E819`) is `RWQZ6MDGT7XfiNw30FMcGZ/sL1IZFaHr+f7So4QAvmFg77qt3/Fcr2Ka`; the same check
works for `get-ocw.sh` and `get-ocw.sh.minisig`. (`-H` requires the prehashed signature format the project uses.) `minisign` checks the
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
shown in the dashboard itself under **About** (the ⓘ item at the bottom
of the sidebar).

## Security: encrypted credential storage

**The credentials for your OPA team and Okta org are never written to
disk in plaintext.** The dashboard's multi-environment store (the
`app_environments` table of `audit_store.db` in the data directory: the
folder `OPA_DATA_DIR` names, `/var/lib/opa-compliance-wizard` on the
upgrade layout, otherwise the project folder; `environments.json` is only
the legacy file older versions imported once) holds only non-secret
metadata (base domain, team name, key ID, Okta URL). The two
per-environment secrets — the OPA service-user **key secret** and the
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

A server installed with `server/install.sh` (hosted mode) stores a few
more things, none of them in the repository:

* `/etc/opa-compliance-wizard.env` (mode 0600, owned by the application
  account) holds three generated secrets (`NGINX_PROXY_SECRET`,
  `KEYRING_UNLOCK_PASSWORD`, `INTERNAL_API_SHARED_SECRET`) in plaintext,
  with the other settings. The installer never prints them.
* `/etc/opa-secrets-wizard-session.key` (32 random bytes, root-owned,
  readable by the application group) signs the login gate's sessions.
* The nginx site file carries the proxy secret and is group-readable
  (mode 0640), not world-readable.
* The keyring on that server (the application account's login keyring,
  under the data directory) also holds the Okta client secret and the
  admin-check token the login gate needs, besides each environment's
  OPA key secret and Okta API token.

Keep the host's disk encrypted and its backups private (see
[docs/hosting.md](docs/hosting.md#backups-and-restore)).

This only protects secrets at rest on disk. The OS keychain backends
above unlock with your OS login session — on an unlocked, logged-in
workstation, any process running as you (including this tool itself)
can read what's stored there, the same as any other app using your OS's
native credential store. Lock your workstation like you would for any
other credential-bearing session.

## License

[MIT](LICENSE) — see [No warranty](#no-warranty) above.
