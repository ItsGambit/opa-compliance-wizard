<p><img src="frontend/public/logo.svg" alt="OPA Compliance Wizard" height="40"></p>

# OPA Compliance Wizard

*Evidence for OPA audits.*

*An independent open-source tool. Not affiliated with or endorsed by Okta, Inc. Okta and Okta Privileged Access are trademarks of
Okta, Inc.*

Okta keeps its System Log for only 90 days, and most audits ask for 12 months or more. OPA Compliance Wizard closes that gap for
Okta Privileged Access (OPA) and core Okta. It keeps an archive of System Log history and OPA activity for as long as you choose,
turns it into ready-made reports (grouped under SOC 2 criteria; the grouping is labelled *proposed*, ISO 27001 and SOX are
planned, not mapped), and can build one zip of evidence for your auditor. It gives you the underlying evidence; it does not produce a
finished SOC 2, SOX or ISO 27001 report on its own.

It also includes **Folder Builder**, which creates OPA vault folders, resource groups, projects and access policies from a CSV file
or a visual tree. A command-line tool for the same folder creation is described in [the CLI guide](docs/hosting.md#running-it-as-a-cli-instead).

## Choose how to run it

|  | On your computer | On a server |
|---|---|---|
| **Who it is for** | One person who wants to try it, build reports, or prepare evidence for an audit | A team that shares the archive, signs in with Okta, and wants it to fill up every day without anyone present |
| **What you need** | Windows, macOS or Linux; Python 3.9 or newer; a browser; an OPA service-user API key | A Debian 12+ or Ubuntu 22.04+ server with root access and a web address; an Okta org where you can create an app |
| **Daily sync runs** | Only while the tool is open | Always |
| **Sign-in** | None (it listens on your computer only) | Okta, with MFA for changes |
| **Time** | About 10 minutes | About 30 minutes |
| **Start here** | [Install on your computer](docs/install-computer.md) | [Install on a server](docs/install-server.md) |

## Project status

**Community project, not an official Okta product.** No support commitment, provided as-is under the MIT license (see
[No warranty](#no-warranty)).

Every endpoint, sign-in flow and field name documented here was **live-verified against a real OPA/Okta tenant**, not just inferred from
published docs: see [docs/api-notes.md](docs/api-notes.md), several entries of which contradict Okta's own documentation.
Security-sensitive code (the hosted login and MFA gate, cross-tenant data isolation, admin authorization) has had internal review and
several independent AI-assisted security passes, with findings checked against the real code and fixed (see
[CHANGELOG.md](CHANGELOG.md)). **No independent third-party security audit has been performed.** If you evaluate this for a
production tenant, start with a disposable or preview org, read the code yourself, and report anything worrying privately
([SECURITY.md](SECURITY.md)).

## Where to go next

| I want to... | Go here |
|---|---|
| Try it on my own computer | [Install on your computer](docs/install-computer.md) |
| Run it for a team, with Okta login | [Install on a server](docs/install-server.md) |
| Install on another Linux, or see every step | [Install on a server by hand](docs/install-server-manual.md) |
| Upgrade, roll back, or install without internet | [Upgrading](docs/upgrading.md) |
| Check a download, or handle a signing-key problem | [Verifying releases](docs/verifying-releases.md) |
| Learn what each page does | [Features](docs/features.md) |
| Build an evidence package for an auditor, or check one | [Evidence packages](docs/evidence-package.md), [format and checking](docs/evidence-package-format.md) |
| Operate a server: settings, backups, sign-in rules, second Okta org | [Hosting reference](docs/hosting.md) |
| Use the command line instead of the dashboard | [CLI guide](docs/hosting.md#running-it-as-a-cli-instead) |
| Look up an Okta/OPA API quirk | [API notes](docs/api-notes.md) |
| See what changed between versions | [CHANGELOG.md](CHANGELOG.md) |
| Publish a release (maintainers) | [docs/releasing.md](docs/releasing.md) |
| Contribute a fix or feature | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Report a security issue privately | [SECURITY.md](SECURITY.md) |

## Upgrading and verifying

The full guides are [Upgrading](docs/upgrading.md) and [Verifying releases](docs/verifying-releases.md). Every release is signed, and
every upgrade checks the signature before it installs anything. The sections below are short pointers, kept because the application and
older messages refer to them by name.

### Upgrading

On a server: **Updates** in the app, or `sudo ocw-updater stage <version>` then `sudo ocw-updater apply <version>`. On your computer:
`python3 launch.py upgrade`. Servers older than 5.53.0 need one refresh command first; see
[Upgrading](docs/upgrading.md#1-if-your-server-is-older-than-5530-run-one-command-first).

### Rollback is code only; restoring data is a separate, typed decision

A rollback puts the previous *code* back and never touches your data; a restore replaces the archive with the pre-upgrade copy and
loses everything archived since. Details: [Rollback and restore](docs/upgrading.md#rollback-is-code-only-restoring-data-is-a-separate-typed-decision).

### The support bundle

A redacted bundle is built when an upgrade fails; nothing is sent automatically. See [the support bundle](docs/upgrading.md#the-support-bundle).

### Air-gapped servers

See [Without internet access](docs/upgrading.md#without-internet-access-offline).

### Verify a download by hand

See [Verifying releases](docs/verifying-releases.md#check-a-release-tarball-by-hand).

### If the signing key is compromised

See [Verifying releases](docs/verifying-releases.md#if-the-signing-key-is-compromised).

## No warranty

This tool is provided **as-is, with no warranty of any kind** (see [LICENSE](LICENSE), MIT). It creates and deletes real objects in
your OPA/Okta tenant through real API calls. **You are responsible for reviewing what it does before you run it against a production
environment**, and you assume all risk of using it. The same notice is shown in the dashboard under **About** (the ⓘ item at the bottom
of the sidebar).

## Security: where credentials are stored

**The credentials for your OPA team and Okta org are never written to disk in plaintext.** Each environment's metadata (domain, team
name, key ID, Okta URL) is stored in the archive database; its two secrets, the OPA service-user **key secret** and the **Okta API
token**, are stored only in your operating system's encrypted credential store through the `keyring` package:

| OS | Backend |
|---|---|
| Windows | Credential Locker (Credential Manager) |
| macOS | Keychain |
| Linux | Secret Service (GNOME Keyring, KWallet, etc.) |

The CLI looks for credentials in this order: (1) OS environment variables, (2) a local `.env` file (legacy, plaintext, used only if you
create one yourself; nothing in this tool writes one), (3) the dashboard's encrypted environment store, whichever environment is active
there. So the CLI follows whatever you last activated in the dashboard, with no plaintext involved.

A server stores a few more things: the settings file `/etc/opa-compliance-wizard.env` (mode 0600; three generated secrets, never
printed), the login gate's session key, and the nginx site (which carries the proxy secret, mode 0640). The server's keyring also holds the
Okta client secret and the admin-check token. Keep the host's disk encrypted and its backups private
([Backups and restore](docs/hosting.md#backups-and-restore)).

This protects secrets **at rest** only. On an unlocked, logged-in workstation, any process running as you (including this tool) can read
what your OS keychain holds, as with any other app that uses it. The archive itself (names, e-mail addresses, activity) is **not**
encrypted by the tool: keep the data folder on an encrypted disk ([what is stored](docs/features.md#data-this-tool-stores-locally)).

## License

[MIT](LICENSE). See [No warranty](#no-warranty).
