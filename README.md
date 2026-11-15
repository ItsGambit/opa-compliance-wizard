<p><img src="frontend/public/logo.svg" alt="" height="40"></p>

# OPA Compliance Wizard

*Evidence for OPA audits.*

**OPA Compliance Wizard keeps a long-term archive of your Okta and Okta Privileged Access (OPA) activity and turns it into reports
and an evidence package for your auditor.**

Okta keeps its System Log for only 90 days, and most audits ask for 12 months or more. This tool reads the log (and what OPA holds)
on a schedule, keeps it for as long as you choose, and gives you ready-made reports grouped under SOC 2 criteria. The grouping is
labelled *proposed*; ISO 27001 and SOX are planned, not mapped. It supplies the underlying evidence; it does not produce a finished
SOC 2, SOX or ISO 27001 report. Reports and the archive only **read** from your tenant; the separate **Folder Builder** feature is the
part that creates OPA vault folders, resource groups, projects and access policies (from a CSV file or a visual tree), and a
[command-line tool](docs/hosting.md#running-it-as-a-cli-instead) does the same folder creation.

*An independent open-source tool. Not affiliated with or endorsed by Okta, Inc. Okta and Okta Privileged Access are trademarks of
Okta, Inc.*

## Choose how to run it

**Get these before you start** (ask your administrators; [who to ask and a message to copy](docs/what-you-need.md)): your OPA base
domain and team name, an OPA service-user key ID and secret, your Okta URL, and an Okta API token.

On a computer, download the **release file** (`ocw-X.Y.Z.tar.gz`, under **Assets** on the
[latest release](https://github.com/ItsGambit/opa-compliance-wizard/releases/latest)), not the green **Code** button: the release
already contains the finished web pages. On a server you do not download anything yourself; the installer does.

|  | On your computer | On a server |
|---|---|---|
| **Who it is for** | One person who wants to try it, build reports, or prepare evidence for an audit | A team that shares the archive, signs in with Okta, and wants it to fill up every day without anyone present |
| **What you need** | Windows, macOS or Linux; Python 3.9 or newer; a browser; the five values above | A Debian 12+ or Ubuntu 22.04+ server with root access and a web address (DNS name); an Okta org (Identity Engine) where you can create an app and a group; the same five values |
| **Daily sync runs** | Only while the tool is open and the computer is awake | Always |
| **Sign-in** | None (it listens on your computer only) | Okta; changes and upgrades ask for a second factor |
| **Time** | About 10 minutes of your work, plus the first sync | About 30 minutes, plus the first sync |
| **Start here** | [Install on your computer](docs/install-computer.md) | [Install on a server](docs/install-server.md) |

New to the words used here (environment, archive, service user)? See the [glossary](docs/glossary.md).

## Where to go next

| I want to... | Go here |
|---|---|
| Try it on my own computer | [Install on your computer](docs/install-computer.md) |
| Run it for a team, with Okta login | [Install on a server](docs/install-server.md) |
| Know what to ask the OPA and Okta administrators for | [What to get before you start](docs/what-you-need.md) |
| Install on another Linux, or see every step | [Install on a server by hand](docs/install-server-manual.md) |
| Upgrade, roll back, or install without internet | [Upgrading](docs/upgrading.md) |
| Read the support-bundle rules for a failed upgrade | [The support bundle](docs/upgrading.md#the-support-bundle) |
| Check a download, or handle a signing-key problem | [Verifying releases](docs/verifying-releases.md) |
| Learn what each page does | [Features](docs/features.md) |
| Build an evidence package for an auditor, or check one | [Evidence packages](docs/evidence-package.md), [format and checking](docs/evidence-package-format.md) |
| Operate a server: settings, backups, sign-in rules, second Okta org | [Hosting reference](docs/hosting.md) |
| Use the command line instead of the dashboard | [CLI guide](docs/hosting.md#running-it-as-a-cli-instead) |
| Look up an Okta/OPA API quirk | [API notes](docs/api-notes.md) |
| See what changed between versions | [CHANGELOG.md](CHANGELOG.md) |
| Publish a release (maintainers) | [Releasing](docs/releasing.md) |
| Contribute a fix or feature | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Report a security issue privately | [SECURITY.md](SECURITY.md) |

## Project status

**Community project, not an official Okta product.** No support commitment, provided as-is under the MIT license (see
[No warranty](#no-warranty)).

Every endpoint, sign-in flow and field name documented here was live-verified against a real OPA/Okta tenant, not just inferred from
Okta's published docs ([API notes](docs/api-notes.md); several entries contradict Okta's own documentation). The security-sensitive code
has had internal review and several AI-assisted security passes, with findings checked and fixed (see [CHANGELOG.md](CHANGELOG.md)).
**No independent third-party security audit has been performed.** If you evaluate this for a production tenant, start with a disposable
or preview org, read the code yourself, and report anything worrying privately ([SECURITY.md](SECURITY.md)).

## No warranty

This tool is provided **as-is, with no warranty of any kind** (see [LICENSE](LICENSE), MIT). It creates and deletes real objects in
your OPA/Okta tenant through real API calls when you use Folder Builder. **You are responsible for reviewing what it does before you
run it against a production environment**, and you assume all risk of using it. The same notice is shown in the dashboard under
**About** (the circled "i" at the bottom of the sidebar).

## Security: where credentials are stored

Your OPA key secret and Okta API token are never written to disk in plaintext. They are kept in your operating system's encrypted
credential store (Windows Credential Locker, macOS Keychain, or the Linux Secret Service). **On a server the installer sets up the
application's own keyring**; you do not need a desktop. A server also keeps a settings file (mode 0600) with three generated
secrets: the installer never shows them on screen, but they are in that file, so protect and back it up like a password, a session key and an nginx site that carries a proxy secret: see the
[Hosting reference](docs/hosting.md#backups-and-restore) for what to back up and protect.

This protects secrets **at rest** only. On an unlocked, logged-in computer, any process running as you can read what your keychain
holds, as with any app that uses it. The archive itself (names, e-mail addresses, activity) is **not** encrypted by the tool: keep the
data folder on an encrypted disk ([what is stored](docs/features.md#data-this-tool-stores-locally)). The command-line tool reads
credentials from OS environment variables first, then an optional plaintext `.env` you create yourself, then the dashboard's
encrypted store.

## License

[MIT](LICENSE). See [No warranty](#no-warranty).

## Anchors used by the app

These short sections exist because the application and older messages link to them. The full text is in [Upgrading](docs/upgrading.md) and
[Verifying releases](docs/verifying-releases.md).

### Upgrading

On a server: **Updates** in the app, or `sudo ocw-updater stage <version>` then `sudo ocw-updater apply <version>`. On your computer:
`python3 launch.py upgrade` (Windows: `py -3 launch.py upgrade`). See [Upgrading](docs/upgrading.md), including the one refresh command that servers older than 5.53.0
need first.

### Rollback is code only; restoring data is a separate, typed decision

A rollback puts the previous *code* back and never touches your data; a restore replaces the archive with the pre-upgrade copy and loses
everything archived since. Details: [Rollback and restore](docs/upgrading.md#rollback-is-code-only-restoring-data-is-a-separate-typed-decision).

### If the signing key is compromised

See [Verifying releases](docs/verifying-releases.md#if-the-signing-key-is-compromised).
