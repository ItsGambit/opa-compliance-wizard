# Install on your computer

This page runs OPA Compliance Wizard on your own Windows, Mac or Linux computer. It is the quickest way to try the tool, build
reports, and prepare evidence for one person. You do not need an Okta app, a server, or a web address.

One limit to know first: the daily sync that keeps your archive current only runs **while the tool is open and your computer is
awake**. Closing the window, or the computer sleeping, pauses it. For an archive that keeps filling when nobody is at a desk, or for a
team, use [Install on a server](install-server.md).

Time: about 10 minutes, plus the first sync. Unfamiliar words (environment, archive, service user, Sync now) are explained in the
[glossary](glossary.md).

On this page, Mac and Linux use `python3`; on Windows use `py -3` in the place of `python3`.

## Before you start

You need all of these.

- **A computer:** Windows 10 or newer, macOS, or Linux.
- **Python 3.9 or newer.** Check with `python3 --version` (Windows: `py -3 --version`). If it is missing, get it from
  <https://www.python.org/downloads/>; on Windows tick **Add python.exe to PATH**. It must include SQLite 3.35 or newer; the
  python.org, Homebrew, Debian 12 and Ubuntu 22.04 builds do. You only need to check this if the tool later says SQLite is too old
  (`python3 -c "import sqlite3; print(sqlite3.sqlite_version)"` shows it).
- **A browser** and an internet connection (to download the tool, its Python packages, and to reach OPA and Okta).
- **An OPA service user with an API key** (you make it in step 3). Creating one needs an OPA administrator. If that is not you, ask
  them for the key ID and key secret now, and for the **base domain** and **team name** of your OPA team.
- **An Okta API token and your Okta URL** (step 3). The Okta System Log archive, which is the main reason to run this tool,
  cannot start without them. Creating a token needs an Okta administrator.
- **Node.js: not needed.** The release you download in step 1 already contains the finished web pages.

## Step 1. Download the tool

1. Open <https://github.com/ItsGambit/opa-compliance-wizard/releases/latest>.
2. Under **Assets**, download the file named **`ocw-X.Y.Z.tar.gz`** (X.Y.Z is the version, for example `ocw-5.53.0.tar.gz`; yours
   may be newer). **Do not use the green "Code" button or the "Source code" files:** they have no finished web pages and would need
   Node.js to build them.
3. Unpack it **into a new, empty folder**. The files go straight into the folder you name, so make one first. In the commands, use
   your file's real name.

Mac or Linux (Terminal):

```bash
mkdir -p ~/opa-wizard && tar -xzf ~/Downloads/ocw-X.Y.Z.tar.gz -C ~/opa-wizard && cd ~/opa-wizard
```

Windows (PowerShell):

```powershell
cd $HOME\Downloads; mkdir $HOME\opa-wizard; tar -xzf .\ocw-X.Y.Z.tar.gz -C $HOME\opa-wizard; cd $HOME\opa-wizard
```

You should now see `launch.py`, `README.md` and a `frontend` folder in that folder.

Nothing checks this first download for you (later upgrades are checked automatically). To check it yourself, see
[Verifying releases](verifying-releases.md); it takes one command.

## Step 2. Start it

Mac or Linux, in that folder:

```bash
python3 launch.py
```

Windows: double-click **`Start OPA Compliance Wizard.bat`** in the folder. Windows may show a "Windows protected your PC" notice for
a downloaded file: choose **More info**, then **Run anyway**. Or run `py -3 launch.py` in PowerShell.

The first start asks a few questions. Type the answer in the box below and press Enter.

- **`Install/upgrade Node.js now? [y/N]`** Answer `n`. You may see this question twice, and a warning "the dashboard likely won't
  start correctly without it". Both are wrong for a release download; the warning does not apply.
- **`Create it and run 'pip install -r requirements.txt' there now? [y/N]`** Answer `y`. It creates a `.venv` folder inside the tool's
  folder and installs the Python packages there. It takes about a minute.

Lines about Node.js, pip and the frontend build scroll by; they are fine. What you should see at the end:

```text
Frontend build is up to date.
Starting OPA Compliance Wizard server...
...
Press Ctrl+C to stop.
```

and your browser opens at <http://127.0.0.1:8766/>. If it does not open, type that address into the browser yourself. Leave the
terminal window open: closing it stops the tool. Press `Ctrl+C` in it to stop the tool on purpose.

The next time, the same command starts it at once, with no questions.

## Step 3. Connect OPA and Okta

The browser shows a page titled **Connect to Okta Privileged Access** with a form. Fill it in from the lists below, then click
**Save & Connect**. The tool tests the connection straight away. When it works, the dashboard opens.

**The form:**

- **Label:** any name for this connection, such as `prod`. You can add more later (dev, uat).
- **Base Domain:** the address you use to sign in to Okta Privileged Access, without `https://` (for example
  `yourorg.pam.okta.com`).
- **Team Name:** the name of your OPA team (for example `yourteam-pam`). It is the `{team}` part of OPA's API addresses. If you
  cannot find it, ask the OPA administrator.
- **Key ID** and **Key Secret:** the API key of an OPA **service user** (below).
- **Okta URL:** your Okta org's address, in the form `https://yourorg.okta.com`. Use the normal address, not the one with `-admin`
  in it, and no path after it.
- **Okta API Token:** an Okta API token (below).

The form's heading calls the two Okta fields "optional, only needed to create new groups". That label is out of date: **both are
required for the Okta System Log archive and for every Okta report.** Without them the tool reads only the OPA side, and a sync stops
with "No Okta URL/API token configured for this environment".

**The OPA service user.** A service user is an account for programs. An OPA administrator creates it: in the Okta Privileged Access
dashboard open **Directory → Users**, choose the **Service Users** tab, create the service user, and click **Create API Key**. Copy the
key ID and the secret at once: the secret cannot be shown again. What the tool can see is limited by what that service user may do in
OPA. Reports and the folder tools were built and tested with a service user that is in a group holding the `pam_admin` role. A narrower
role may work, but the project has not documented which; each screen tells you what it could not read.

**The Okta API token.** An Okta administrator creates it: in the Okta Admin Console go to **Security → API → Tokens → Create token**,
and copy it at once (it is shown once). A token has the permissions of the admin who made it, so it must be an admin who can read the
System Log, users and groups. The Okta Admins report also needs permission to view roles and admin assignments (a Super
Administrator, or a custom role with `okta.iam.read`; see [which Okta role the token needs](features.md#which-okta-role-the-token-needs)).
Okta stops honouring a token that has not been used for 30 days.

Your key secret and token are stored in your computer's own encrypted credential store (Windows Credential Locker, macOS Keychain, or the
Secret Service on Linux), not in a file.

## Step 4. Fill the archive

Okta keeps only 90 days of its System Log. The tool keeps what it reads, so the sooner you start, the more history you hold.

1. Open **Environments** (bottom of the sidebar), find your environment, and open its **sync settings**.
2. Turn on the schedule. The first time, it asks how to start. Choose **Backfill the last 90 days**: it pulls everything Okta still has.
   (The other choices are to import a System Log CSV you exported from Okta, or to start fresh with no history.)
3. Press **Sync now** in the page footer.

**How long it takes** depends on how busy your org is. You can keep using the tool; the footer shows **Syncing…**. A very busy org can
take well over an hour for the log part.

**What finished looks like:** the footer changes to **Last refresh `<date and time>`** followed by how many parts completed (for
example "3 of 3"). If a part did not complete, hover over the line to see which.

**What working looks like:** open **Compliance Reports**. Report cards (MFA Enforcement, Provisioning, and so on) show events. Click a
card to see a table with **User**, **Action**, **Timestamp** and **Affected Resource** columns and a date-range filter. A card that
shows nothing for a period may simply have had no such events; see "If it fails" if every report is empty. A tour of every page is in
[Features](features.md).

## Where things are stored

Everything the tool keeps (the archive, the audit log, settings) lives in the folder you unpacked into. Back that folder up, and
keep it on an encrypted disk (FileVault, BitLocker or LUKS): the archive holds people's names and e-mail addresses and is not
encrypted by the tool. To keep the data somewhere else, set the `OPA_DATA_DIR` environment variable before you start.

## If it fails

- **`No Python 3.9 or newer was found`** (the `.bat` window), or **`Python ... is below the minimum this dashboard needs`**: install
  Python (see "Before you start"), open a **new** terminal window, and start again.
- **`its bundled SQLite ... is below the 3.35.0`**: your Python's SQLite is too old (typical for the system Python of an old Linux).
  Install a newer Python from python.org or your package manager.
- **`Could not bind 127.0.0.1:8766`** or a message that port 8766 is in use: the tool, or something else, is already running. Close it,
  or start with another port: `python3 launch.py --port 8800`.
- **It says a dashboard from this folder is "still running" and asks to stop it:** that is a leftover from an earlier session.
  Answer `y`. Answer `n` only if you started a second copy on purpose.
- **`Could not create the virtual environment`** (Debian, Ubuntu): run `sudo apt-get install python3-venv`, then start again.
- **`ERROR: npm is not available and there is no frontend build`**: you unpacked a "Source code" download. Download
  `ocw-X.Y.Z.tar.gz` from the release's **Assets** (step 1) instead.
- **Saving the connection fails with a keyring error (Linux):** the tool needs a running keyring service such as GNOME Keyring or
  KWallet. A normal desktop has one; a bare server does not (use [Install on a server](install-server.md)).
- **"Could not connect" after Save & Connect:** re-check the base domain (no `https://`), the team name and the key. OPA's message is
  shown under the form.
- **"No Okta URL/API token configured for this environment":** open **Environments**, edit the environment, and fill the Okta URL and
  the Okta API token (step 3).
- **Every report is empty after the first sync:** check the footer says **Last refresh** and not "did not complete"; check the
  report's date range; check the Okta token still works (a token unused for 30 days stops working, and a deactivated admin's token
  dies); then press **Sync now** again.

## Next

- Learn what each page does: [Features](features.md).
- Build a package for your auditor: [Evidence packages](evidence-package.md).
- Update to a newer release: `python3 launch.py upgrade --check`, then see [Upgrading](upgrading.md#upgrade-a-computer-install). An
  upgrade keeps your data.
- Uninstall: close the tool and delete the folder. Delete the saved credentials from your keychain too if you want them gone.
- Prefer a command-line tool without the dashboard: [the CLI guide](hosting.md#running-it-as-a-cli-instead) (it is in the server
  reference page, but it works on any computer).
