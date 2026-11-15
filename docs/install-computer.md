# Install on your computer

This page runs OPA Compliance Wizard on your own Windows, Mac or Linux computer. It is the quickest way to try the tool, build
reports, and prepare evidence for one person. You do not need an Okta app, a server, or a web address.

A first report needs only **reading**: the sync and the reports read from OPA and Okta, and the one feature that creates or deletes
things (Folder Builder) is not involved.

One limit to know first: the daily sync only runs **while the tool is open and your computer is awake**. If it was closed or asleep,
it does not stop working: the next time it is open after the daily run time, it syncs within about five minutes and fetches
everything Okta published since the last sync, so nothing is lost as long as you open it within Okta's 90 days. For an archive that
fills without anyone at a desk, or for a team, use [Install on a server](install-server.md).

Time: about 10 minutes of your own work, plus the first sync, plus however long the administrators take to hand you the values below. Unfamiliar words (environment, archive, service user, Sync now) are explained in the
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
- **Five values from administrators:** OPA base domain, OPA team name, an OPA service-user key ID and key secret, your Okta URL, and an
  Okta API token. Ask for them now: [What to get before you start](what-you-need.md) says who to ask and has a message you can
  copy. The Okta System Log archive, the main reason to run this tool, cannot start without the Okta ones.
- **Node.js: not needed.** The release you download in step 1 already contains the finished web pages.

## Step 1. Download the tool

1. Open <https://github.com/ItsGambit/opa-compliance-wizard/releases/latest>.
2. Under **Assets**, download the file named **`ocw-X.Y.Z.tar.gz`** (X.Y.Z is the version, for example `ocw-5.53.0.tar.gz`; yours
   may be newer). **Do not use the green "Code" button or the "Source code" files:** they have no finished web pages and would need
   Node.js to build them.
3. Unpack it **into a new, empty folder**. The files go straight into the folder you name, so make one first. In the commands, use
   your file's real name: if you downloaded `ocw-5.53.0.tar.gz`, that is what replaces `ocw-X.Y.Z.tar.gz`.

Mac or Linux (Terminal):

```bash
mkdir -p ~/opa-wizard && tar -xzf ~/Downloads/ocw-X.Y.Z.tar.gz -C ~/opa-wizard && cd ~/opa-wizard
```

Windows (PowerShell; `tar` is built in from Windows 10 version 1803):

```powershell
cd $HOME\Downloads; mkdir $HOME\opa-wizard; tar -xzf (Get-ChildItem ocw-*.tar.gz).Name -C $HOME\opa-wizard; cd $HOME\opa-wizard
```

You should now see `launch.py`, `README.md` and a `frontend` folder in that folder.

Nothing checks this first download for you (later upgrades are checked automatically). It is fine to skip that for a trial; to
check it, see [Verifying releases](verifying-releases.md) (one command).

## Step 2. Start it

Mac or Linux, in that folder:

```bash
python3 launch.py
```

Windows: double-click **`Start OPA Compliance Wizard.bat`** in the folder. Windows may show a "Windows protected your PC" notice for
a downloaded file: choose **More info**, then **Run anyway**. A black console window opens and **stays open while the tool runs**;
close it only to stop the tool. Or run `py -3 launch.py` in PowerShell.

The first start asks a few questions. Type the answer in the box below and press Enter.

- **`Install/upgrade Node.js now? [y/N]`** Answer `n`. You may see this question twice, and a warning "the dashboard likely won't
  start correctly without it". Both are wrong for a release download; the warning does not apply.
- **`Create it and run 'pip install -r requirements.txt' there now? [y/N]`** Answer `y`. It creates a `.venv` folder inside the tool's
  folder and installs the Python packages there. It takes about a minute and needs internet (behind a proxy, set `https_proxy` first; without internet see
  [Without internet access](upgrading.md#without-internet-access-offline), which covers upgrades).

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

**The form's heading says the two Okta fields are "optional, only needed to create new groups". That label is out of date: both are
required for the Okta System Log archive and every Okta report.** Without them the tool reads only OPA, and a sync stops with "No Okta
URL/API token configured for this environment".

The browser shows a page titled **Connect to Okta Privileged Access**. Fill it in from the values in
[What to get before you start](what-you-need.md), then click **Save & Connect**. The tool tests the connection straight away. When it
works, the dashboard opens.

- **Label:** any name for this connection, such as `prod`. You can add more later (dev, uat).
- **Base Domain:** the host you sign in to OPA at, without `https://`. If you sign in at `https://yourorg.pam.okta.com/...`, it is
  `yourorg.pam.okta.com`.
- **Team Name:** your OPA team, for example `yourteam-pam`. If nobody can tell you, ask the OPA administrator.
- **Key ID** and **Key Secret:** the API key of the OPA service user.
- **Okta URL:** `https://yourorg.okta.com` (not the `-admin` address, no path).
- **Okta API Token:** the Okta token.

Your key secret and token are stored in your computer's own encrypted credential store (Windows Credential Locker, macOS Keychain, or the
Secret Service on Linux), not in a file.

## Step 4. Fill the archive

Okta keeps only 90 days of its System Log. The tool keeps what it reads, so the sooner you start, the more history you hold.

1. In the sidebar, click **Environments** (bottom). On your environment's row click the calendar button (its tooltip says
   **Compliance sync settings**).
2. Tick **Enable daily refresh** and click **Save**.
3. The first time, a choice appears: pick **Backfill last 90 days (live)** (it pulls everything Okta still holds; the other choices
   are **Import from a CSV export** and **Start fresh**, which keeps no history) and click **Continue**. **Continue starts the backfill
   itself.**
4. When it finishes, click **Sync now** in the page footer once. It is a separate action: it also reads OPA and the Okta
   scan, and from now on does the same job as the daily run.

**How long it takes** depends on how busy your org is. You can keep using the tool; the footer shows **Syncing…**. A very busy org can
take well over an hour for the log part.

**What finished looks like:** the footer changes to **Last refresh `<date and time>`** followed by how many parts completed (for
example "3 of 3"). If a part did not complete, hover over the line to see which.

**What working looks like:** open **Compliance Reports**. Report cards (MFA Enforcement, Provisioning, and so on) show events. Click a
card to see a table with **User**, **Action**, **Timestamp** and **Affected Resource** columns and a date-range filter. A card that
shows nothing for a period may simply have had no such events; see "If it fails" if every report is empty. A tour of every page is in
[Features](features.md).

## Where things are stored

Everything the tool keeps (the archive `audit_store.db`, the audit log `audit_log.jsonl`, settings) lives in the folder you unpacked
into. **Deleting that folder deletes your archive.** Back it up, and keep it on an encrypted disk (FileVault, BitLocker or LUKS): the archive holds people's names and e-mail addresses and is not
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
- Uninstall: close the tool and delete the folder (back up `audit_store.db` first if you want the archive). Delete the saved credentials from your keychain too if you want them gone.
- Prefer a command-line tool without the dashboard: [the CLI guide](hosting.md#running-it-as-a-cli-instead) (it is in the server
  reference page, but it works on any computer).
