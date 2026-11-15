# Upgrading

Every release is signed. An upgrade checks the signature against keys your install already trusts, **before** it unpacks
anything, and refuses a file that is unsigned, altered, older than what you run, or built for another version. Your data is
backed up first, and a server rolls back by itself if the new version does not come up healthy.

Find your case:

| You run it... | Go to |
|---|---|
| On a server, installed with `get-ocw.sh` (the [server guide](install-server.md)) | [Upgrade a server](#upgrade-a-server) |
| On your own computer, from a downloaded release | [Upgrade a computer install](#upgrade-a-computer-install) |
| On a server set up by hand before the one-line installer existed | [Older servers](#older-servers-that-still-run-from-a-home-directory) |
| With no internet access | [Without internet access](#without-internet-access-offline) |

Nothing here changes by itself: the update check is **off** until you turn it on, and nothing is installed until you approve it.

## Upgrade a server

Do these in order.

### 1. If your server is older than 5.53.0, run one command first

Servers older than 5.53.0 must refresh their updater before they can take 5.53.0 or any newer release. The old updater refuses
the upgrade until you do, and nothing is changed until then. The refresh touches no data.

```bash
sudo bash get-ocw.sh --refresh-updater --version 5.53.0
```

(You can download `get-ocw.sh` as in the [server guide](install-server.md#step-2-run-the-installer).) If you installed from a checkout
instead, unpack the release and run `sudo bash server/install.sh --refresh-updater` from it. The Updates page names this command
too when it is needed. A server installed with 5.53.0 or newer does not need this step.

### 2. Upgrade

**From the browser (administrators).** Open **Updates**, then **Upgrade now** (or **Schedule...** for a later time).

1. The page reads the new release's signature and runs a **preflight** check (free disk space, Python and SQLite versions, no
   sync running, no evidence package waiting, the updater present). **Re-check** repeats it.
2. A **confirmation screen** lists exactly what you approve: versions, file, checksum, signing key, what changes, database
   changes (and which of them a rollback cannot undo), where the backup goes, and the downtime. Tick the box and choose
   **Approve with MFA**. A fresh Okta check is tied to this version and time.
3. The page then shows the steps live and waits through the restart. Other users see a maintenance page. When the new version
   answers, the page reloads once.
4. The result page says it worked (with the health checks and a 24-hour rollback window) or failed (what happened, where you are
   now, and a redacted support bundle to download).

A scheduled upgrade is held by the application and handed to the updater at the chosen time. If the application is not running
then, it is marked **missed** and never runs late.

**From a shell on the server.**

```bash
sudo ocw-updater stage 5.53.0     # downloads, verifies, unpacks, builds the Python environment
sudo ocw-updater apply 5.53.0     # shows what changes, asks you to type the version, then runs the whole sequence
```

(`sudo ocw-updater apply <version> --at "YYYY-MM-DD HH:MM" --tz Europe/London` schedules it.) `ocw-updater status` shows what is
installed, staged and scheduled.

What happens, with every step in the Audit Log:

1. Request accepted and checked. The staged release is **re-verified by root** (signature, version, every file against the signed
   manifest).
2. Preflight: free space on both volumes, no archive sync running, the nginx template valid.
3. **Backup** of the archive (SQLite's online backup, integrity-checked, readable by root only, never deleted automatically).
4. **Switch** to the new version (an atomic link change, while nginx shows a maintenance page), and restart.
5. **Eight health checks:** the service is active with no restarts; `/api/version` answers the new version from a new process;
   `/healthz` is not worse than before; the login gate answers 401; the archive's quick check; the schema version; the audit chain
   heads are unchanged; an authenticated read works.
6. If any check fails, it rolls back **once, automatically**.

Exit codes of `ocw-updater`: `0` ok, `2` refused (signature, version, key, a sync running, another upgrade in flight, bad usage),
`3` failed and rolled back, `4` failed and an operator is needed.

### After upgrading to 5.53.0 or newer

On a server with the login gate, opening **Access control, Shared permissions, Orphaned archives, the environment details or Updates**
asks for MFA. You sign in through Okta again, and Settings stay open for 10 minutes (a countdown shows how long). Saving the
announcement banner asks for MFA as well. A computer without a login gate is not asked. An *additional* login gate's nginx site made
before 5.42.0 must be regenerated first ([the reference](hosting.md#serving-a-second-okta-org-optional-5380)).

After a *minor* upgrade (for example 5.52 to 5.53) the first refresh reads OPA again, because the stored OPA scan is tied to the
release's minor number. A patch upgrade keeps it.

### Roll back, or restore data

#### Rollback is code only; restoring data is a separate, typed decision

- **Rollback** (automatic after a failed health check, or `sudo ocw-updater rollback` within 24 hours, then type `ROLLBACK`) switches
  the *code* back to the previous release and restarts. **Data is never touched.** A newer release may have changed the archive's
  schema; the old code can run on it only when the change was *rollback-safe*. `ocw-updater apply` tells you before you approve.
- **Restore** (`sudo ocw-updater restore --confirm RESTORE`) replaces the archive with the copy taken before the last upgrade. It
  **loses every event archived since**, and is never automatic. The Updates page offers it too, naming the exact copy; the database
  it replaces is moved aside, never deleted. Do this only if the maintainers tell you to, and after you have the support bundle.
- If the rollback itself fails, nginx shows a page saying an operator is needed, a `CRIT` line goes to the journal, `upgrade.failed` is
  written to the Audit Log, the state is `failed_needs_operator`, and a bundle is written. `ocw-updater status` says what to do. Only
  `sudo ocw-updater clear-failure` on the server ends that state; the Updates page does not offer it.
- A version that failed is not tried again until `sudo ocw-updater clear-failure`; after two failures it stays off.
- Deleting old pre-upgrade backups is command-line only: `sudo ocw-updater prune-backups --keep N --confirm PRUNE` (never the newest
  copy, never the last upgrade's). They are the only copies of the archive that the web application cannot touch.

### The support bundle

When an upgrade fails, the updater builds a redacted bundle (`ocw-support-<from>-to-<to>-<time>-<id>.tar.gz`, at most 5 MB) before
anyone asks. An administrator can download it from the failed upgrade's Audit Log entry, or from a shell: `sudo ocw-updater bundle`
(`--include-hosts` keeps host and environment names). Attach it to a **private** report as [SECURITY.md](../SECURITY.md) describes.
**Nothing is ever sent automatically.**

- **In it:** versions, the reason and failed step, timings, OS/Python/SQLite/systemd versions, free space, the manifest, the health
  results, `pip freeze`, schema before and after, the last 500 journal lines of each OPA unit and of the updater, `nginx -t`,
  `systemctl status`, this run's audit entries, and `redaction-report.txt` (how many things were redacted, never what).
- **Never in it:** the settings file, anything from the keyring, the session key, the archive or any row of it, environment (tenant)
  details, the nginx site file (it holds the proxy secret), request bodies, cookies.
- **Redacted before it is written:** the values of every secret in the settings file wherever they appear; variables named
  `*SECRET`, `*TOKEN`, `*PASSWORD`, `*KEY`; `Authorization`, `Cookie` and `Set-Cookie` headers; Okta tokens and JWTs; long token-like
  strings; e-mail addresses, Okta subject ids, host names and IP addresses, tenant and environment names (replaced by salted hashes).
  Host and IP detection is pattern-based: read the bundle once before you send it.

### The `ocw-updater` command

| Command | What it does |
|---|---|
| `status [--json]` | Installed, staged, scheduled, updater health, keys, backups, last run. Reads only; any user. |
| `stage <file or version>` | Verify and stage a release (root). |
| `apply <version> [--at "YYYY-MM-DD HH:MM" [--tz ZONE]]`, `cancel` | Install now or schedule it (typed confirmation); `cancel` removes a schedule. |
| `rollback`, `restore --confirm RESTORE` | Code-only rollback; archive restore (above). |
| `bundle [--correlation ID] [--include-hosts]`, `clear-failure` | Support bundle; allow a failed version again. |
| `prune-backups --keep N` or `--name FILE ...` with `--confirm PRUNE` | Delete old pre-upgrade archive copies. |
| `trust list`, `trust seed`, `trust apply <revocation.json>`, `trust add <key.json>` | The signing keys root trusts. |
| `nginx-sync` | Apply the current release's nginx template (the maintenance page). |
| `check`, `enable-check`, `disable-check`, `verify`, `audit`, `keys ...` | The update check and key tools (run as the application's account automatically). |

### The units behind it

The installer adds `ocw-stage@.service` (downloads and unpacks as an unprivileged account; optional proxy settings in
`/etc/ocw-updater.env`), `ocw-upgrade.path` and `ocw-upgrade.service` (root: activate, roll back, resume after a crash).

## Upgrade a computer install

An install made by [Install on your computer](install-computer.md) has no sign-in, so there is **no MFA** for upgrading. The guided
upgrade asks you to **type the version** instead; everything else is the same as on a server: signed, verified, logged. Run it from the
install folder, with the dashboard closed (it offers to stop this folder's dashboard).

```bash
python3 launch.py upgrade --check      # is there a newer signed release? (one HTTPS request; nothing about your data is sent)
python3 launch.py upgrade              # download, verify, prepare, ask you to type the version, swap folders
```

Windows: use `py -3 launch.py upgrade`.

Other forms:

```bash
python3 launch.py upgrade --to 5.53.0                        # a specific version (must be newer than the installed one)
python3 launch.py upgrade --from-file ocw-5.53.0.tar.gz ocw-5.53.0.tar.gz.minisig    # files you brought (see offline, below)
python3 launch.py upgrade --restore-previous                 # bring the previous version back (type RESTORE)
python3 launch.py upgrade --discard-previous                 # delete the kept previous version (type DELETE)
python3 launch.py upgrade --status
```

What it does, in order. It stops, having changed nothing you own, at any step before the last:

1. Downloads `ocw-<version>.tar.gz` and its `.minisig` (or takes the files you name) and applies any published signing-key revocation.
2. **Verifies the signature, the signed manifest and the version against the keys pinned in your install, before unpacking anything.**
   An unsigned, altered, renamed, wrongly signed, downgrading or mislabelled file is refused, and so is an archive with links,
   absolute or `..` paths, Windows device names or files the manifest does not list.
3. Unpacks into a sibling folder, `<your folder>-<version>`, and builds its Python environment from the hash-pinned `requirements.lock`.
4. Shows what changes (database changes, and whether a rollback can undo them) and asks you to type the version.
5. Copies your data into the new folder, swaps the folder names (`<your folder>` becomes `<your folder>-previous`), then starts the new
   code once, which also migrates the **copy** of the database. If that fails, the previous folder is put back automatically.

Your data is **copied, never moved**: `audit_store.db` (copied with SQLite's online backup, integrity-checked), `environments.json`,
`audit_log.jsonl`, `banner_config.json`, `access_control.json`, `secrets_log_cache.json`, `update_check.json`,
`release_keys.local.json`, `.env`, your saved folder templates and `folders_result_*.csv`, with their permissions. Credentials in your
operating system's keychain are not touched. The previous folder keeps its own copies until you delete it (`--discard-previous`),
including the plain-text files above. If you keep the data elsewhere (`OPA_DATA_DIR`), it is not touched at all.

**Restoring.** `--restore-previous` swaps the folders back (the one it replaces is kept as `<your folder>-replaced-<version>`). By
default it is **code only**: your current data stays, and the restore is refused if the newer database can no longer be read by the
older code. `--restore-data` brings back the previous folder's own, older data instead; everything recorded since the upgrade stays in
the replaced folder. If a swap is interrupted (power cut), run `python3 <your folder>-previous/launch.py upgrade --restore-previous`.

Exit codes: `0` ok or up to date, `1` (`--check`) a newer release exists, `2` refused, `3` failed and nothing changed or everything was
put back, `4` failed and you have to act (the message says how). For scripts, `--confirm 5.53.0` (or `RESTORE`, `DELETE`) replaces the
typed confirmation.

**Windows.** Needs no admin rights and no symbolic links. Windows will not rename a folder while a program has a file in it open: close the
dashboard (and its window), File Explorer windows on the folder and editors, and run the upgrade with the system Python
(`py -3 launch.py upgrade`). Keep the install path short (about 200 characters at most). Run the upgrade from the install folder, not
from `<folder>-previous`.

## The update check (off by default)

When you turn it on, the server makes **one HTTPS request a day to `api.github.com`** and nothing else leaves the machine. GitHub sees
the server's address and a fixed User-Agent (`opa-compliance-wizard-update-check`); **nothing about your tenant, users, data or host name
is sent**, and the installed version is not sent unless you tick "share my version". It only reports that a newer release exists; it
never downloads or installs anything. What is stored: the latest version seen, its publish date and link, whether a signed download is
attached, and when the check last ran (`update_check.json`, owner-only).

- Turn it on or off: **Updates** (administrators, sidebar) or `python -m server.updater enable-check` / `disable-check`
  (on a server: `sudo ocw-updater enable-check`).
- `OPA_UPDATE_CHECK=off` in the server's environment always wins and cannot be overridden from the screen; `OPA_UPDATE_CHECK=on` turns
  it on without an admin action.
- Behind a proxy, set `https_proxy` / `no_proxy` in the service's environment file. For a mirror inside your network use
  `OPA_RELEASE_API_URL` and `OPA_REVOCATION_URL_BASE` (https; redirects only to the mirror). Without a mirror, redirects are followed only
  to GitHub's own hosts.
- A failed check (no network, rate limit, bad answer) is shown in plain words on the Updates screen and recorded in the Audit Log.
  An identical failure is not logged again, and the next success says how many failed and since when.
- **Two-person rule** (Update check, "Change..."; off by default): a second, different administrator must approve within 24 hours.
- **One banner at a time** tells every signed-in user what is going on: an upgrade running or failed, then a key revocation
  (administrators), then a scheduled window, then "an update is available" (administrators).

**Release channel.** The default is `stable`. To also see releases the maintainers mark as prereleases (more testing wanted; still signed
and checked against the same keys): `python -m server.updater set-channel prerelease` (back with `set-channel stable`;
`OPA_UPDATE_CHANNEL` fixes it from the environment), or `python3 launch.py upgrade --check --channel prerelease` for one run. A
prerelease is never downgraded when you switch back; you wait for the next stable release. The installed version is added to the check's
User-Agent only if you opt in: `python -m server.updater share-version on`.

## Without internet access (offline)

On a computer with internet access, download from the release page the three files (`ocw-<version>.tar.gz`,
`ocw-<version>.tar.gz.minisig`, `manifest.json`), or, **when the release has one**, the offline bundle
`ocw-<version>-offline.tar.gz` with its `.sha256`. The bundle is the same signed release plus the hash-pinned Python packages for
Windows, macOS (Apple silicon) and Linux (x86-64 and ARM) on Python 3.9 to 3.14 (Linux needs glibc 2.28 or newer; Alpine and Intel Macs
are not covered). The maintainers attach a bundle only to releases they built one for, so look at the release's **Assets** first.
Carry the files over on removable media. The bundle carries no signature of its own and needs none: the release inside it is verified
like any other, and `pip` refuses any package whose sha256 is not in that release's signed `requirements.lock`.

- **Computer install:** `python3 launch.py upgrade --from-file ocw-<version>-offline.tar.gz`. Nothing is fetched; packages are
  installed with `pip install --no-index --require-hashes`. For the two loose files, a `revocation.json` next to them is applied
  automatically. If a key revocation was published, you can also apply it first:
  `python -m server.updater keys apply-revocation revocation.json`.
- **First install of a server:** `sudo bash get-ocw.sh --from-dir DIR` where `DIR` holds the three files or the offline bundle
  (add `--wheelhouse DIR` for packages from a directory instead).
- **Server upgrade:** `sudo ocw-updater stage ocw-<version>.tar.gz` then `sudo ocw-updater apply <version>` stage and apply the
  release from the file. The updater builds the release's Python environment while staging and **cannot yet install packages from an
  offline bundle**, so the server needs a route to a Python package index (a mirror or proxy is fine; proxy settings go in
  `/etc/ocw-updater.env`). A published key revocation is applied with `sudo ocw-updater trust apply revocation.json`.

## Older servers that still run from a home directory

A server set up by hand (the [manual install](install-server-manual.md)) before the upgrade layout existed runs its code from a home
directory and is upgraded with `server/deploy.sh`. You can **migrate** it once to the layout above (code owned by root, data in
`/var/lib/opa-compliance-wizard`, the root-run updater, rollback and the Updates page). Run as root, starting with the dry run, which
prints exactly what it would do and changes nothing:

```bash
sudo server/install.sh --dry-run
sudo server/install.sh
```

The migration copies the data files (the originals are renamed `*.migrated-<time>`, never deleted), rewrites the units, restarts the
services and checks them, and puts everything back if they do not come up healthy. The old directory is left where it is.
`--remove-legacy-sudoers` removes the old deploy sudoers file (after checking it grants only what `deploy.sh` needed; it is moved aside,
not deleted). `--apply-nginx` also applies this release's nginx template. `--wheelhouse DIR` installs packages from a directory
only. `get-ocw.sh` does the same migration when it finds such a server, after two confirmations.

A server with **additional login gates** (`setup-second-gate.sh`): neither `install.sh` nor the updater changes a gate's nginx site. The
dry run and the end of the real run list each gate and whether its site is current. Regenerate old ones from the live main site
(`nginx -t` runs first and the old site is put back if it fails):

```bash
sudo server/install.sh --apply-nginx --regenerate-second-sites
```

Until you migrate, upgrade in place with `server/deploy.sh --release <version>`. It downloads `ocw-<version>.tar.gz` and its `.minisig`
from the project's GitHub release, checks them against the key pinned in `server/release_keys.json` (the **installed** copy is the root of
trust), and refuses before changing anything if the file is unsigned, altered, renamed, signed by a standby or revoked key, built for
another version, not newer than what is installed, or needs a newer starting version. The release carries the built frontend, so
**Node.js is not needed**. Then it backs up (if `OPA_DEPLOY_BACKUP_DIR` is set), syncs files, runs `pip install --require-hashes -r
requirements.lock`, restarts with health checks and validates nginx. `--from-dir DIR` installs from files you carried in (the three
files, or the offline bundle); `--reinstall` allows the same version again. There is no automatic rollback on this layout: restore
your backup of the installation and archive. Every refusal is recorded in the Audit Log as `upgrade.verify_failed` with a reason code.
`deploy.sh --ref` (unsigned source from the repository) is for maintainers and test servers only. The settings and warnings of
`deploy.sh` are in [Hosting reference](hosting.md#redeploying-with-deploysh-older-servers).

## Command-line tools of the update check

Everything on the Updates screen is also available from a shell. Run from the install directory with the app's Python
(`.venv/bin/python -m server.updater ...`; on a server `sudo ocw-updater ...` does it for you):

| Command | What it does |
|---|---|
| `status [--json]` | The same data as `GET /api/upgrade/status`: installed version, check on/off and why, latest release, last check, signing-key state. |
| `check [--force] [--json]` | Run the check now. Respects "off" unless `--force` (which is recorded). Exit 1 when a newer release exists. |
| `enable-check` / `disable-check` | The same switch as the screen, with the same audit entry (actor `cli:<os user>`). |
| `verify <tar.gz> <.minisig>` | Verify a download ([Verifying releases](verifying-releases.md)). |
| `keys list` / `keys apply-revocation <revocation.json>` | Show or update the pinned signing keys. |
| `audit [--since DATE] [--json]` | List the upgrade-related Audit Log entries (`upgrade.*`, `deploy.*`). |

Exit codes: `0` ok, `1` a newer release is available (`check`), `2` usage error, `3` failure (the message says what to do).
