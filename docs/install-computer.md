# Install on your computer

This page runs OPA Compliance Wizard on your own Windows, Mac or Linux computer. It is the quickest way to try the tool, build
reports, and prepare evidence for one person. You do not need an Okta app, a server, or a web address.

One limit to know first: the daily sync that keeps your archive current only runs **while the tool is open on your computer**. For an
archive that keeps filling when nobody is at a desk, or for a team, use [Install on a server](install-server.md).

Time: about 10 minutes.

## Before you start

| Need | Details |
|---|---|
| A computer | Windows 10 or newer, macOS, or Linux. |
| Python 3.9 or newer | Check with `python3 --version` (Windows: `py -3 --version`). Get it from <https://www.python.org/downloads/> if missing; on Windows tick **Add python.exe to PATH**. The Python must include SQLite 3.35 or newer; the python.org, Homebrew, Debian 12 and Ubuntu 22.04 builds do. |
| A browser | Any current one. |
| Internet | To download the tool and its Python packages and to reach your Okta Privileged Access (OPA) team. |
| An OPA service user | The tool signs in to OPA as a **service user**. You need its API **key ID** and **key secret** (step 3). |
| Node.js | **Not needed.** The release you download in step 1 already contains the finished web pages. |

## Step 1. Download the tool

1. Open <https://github.com/ItsGambit/opa-compliance-wizard/releases/latest>.
2. Under **Assets**, download **`ocw-<version>.tar.gz`** (for example `ocw-5.53.0.tar.gz`). Do not take "Source code": that copy
   has no finished web pages and would need Node.js to build them.
3. Unpack it **into a new, empty folder**. The files go straight into the folder you name, so make one first.

Mac or Linux (Terminal):

```bash
mkdir -p ~/opa-wizard && tar -xzf ~/Downloads/ocw-5.53.0.tar.gz -C ~/opa-wizard && cd ~/opa-wizard
```

Windows (PowerShell, in the folder where you saved the download):

```powershell
mkdir $HOME\opa-wizard; tar -xzf .\ocw-5.53.0.tar.gz -C $HOME\opa-wizard; cd $HOME\opa-wizard
```

Use the version number of the file you downloaded. You should now see `launch.py`, `README.md` and a `frontend` folder in that
folder.

Want to check the download first? See [Verifying releases](verifying-releases.md). It is optional here, because the tool runs on your
own computer only.

## Step 2. Start it

Mac or Linux, in that folder:

```bash
python3 launch.py
```

Windows: double-click **`Start OPA Compliance Wizard.bat`** in the folder (or run `py -3 launch.py` in PowerShell).

The first start asks a few questions. Answer like this:

| It asks | Answer |
|---|---|
| `Install/upgrade Node.js now? [y/N]` | **n** and Enter. You do not need Node.js. It asks this twice on a first start. It then prints "Skipping Node.js -- the dashboard likely won't start correctly without it" and "Continuing with the existing frontend build". Ignore the warning: it does not apply to a release download. |
| `Create it and run 'pip install -r requirements.txt' there now? [y/N]` | **y** and Enter. This creates a `.venv` folder inside the tool's folder and installs its packages there. It takes about a minute. |

What you should see at the end:

```text
Frontend build is up to date.
Starting OPA Compliance Wizard server...
...
Press Ctrl+C to stop.
```

and your browser opens at <http://127.0.0.1:8766/>. If it does not open, type that address into the browser yourself.
Leave the terminal window open: closing it stops the tool. Press **Ctrl+C** in it to stop the tool on purpose.

The next time, the same command starts it at once, with no questions.

## Step 3. Connect your OPA team

The browser shows **Connect to Okta Privileged Access**. Fill in:

| Field | What to enter |
|---|---|
| Label | Any name for this connection, such as `prod`. You can add more later (dev, uat). |
| Base Domain | Your OPA domain, in the form `yourorg.pam.okta.com`. |
| Team Name | Your OPA team, in the form `yourteam-pam`. |
| Key ID, Key Secret | The API key of an OPA **service user**. |
| Okta URL, Okta API Token | Optional. Only needed to create Okta groups from the tool. Leave empty to start. |

To make the key: in the OPA dashboard open **Directory → Users**, choose the **Service Users** tab, create a service user, and click
**Create API Key**. Copy the key ID and the secret now: you cannot read the secret again after you close that window. What the
tool can read or create is limited by what that service user is allowed to do in OPA, so give it the access you want the reports to
cover. If you are not sure about the domain or team name, ask whoever administers OPA for your company.

Click **Save & Connect**. The tool tests the connection straight away. When it works, the dashboard opens.

Your key secret and token are stored in your computer's own encrypted credential store (Windows Credential Locker, macOS Keychain, or
the Secret Service on Linux), not in a file.

## Step 4. Fill the archive

1. Open **Environments** (bottom of the sidebar), find your environment, and open its sync settings.
2. Turn on the schedule. The first time, it asks how to start: **backfill the last 90 days**, import a System Log CSV you
   exported from Okta, or start fresh.
3. Press **Sync now** (in the page footer) once.

Okta keeps only 90 days of its System Log. The tool keeps what it reads, so start early. After that, the reports under
**Compliance Reports** fill with data. A tour of every page is in [Features](features.md).

## Where things are stored

Everything the tool keeps (the archive, the audit log, settings) lives in the folder you unpacked into. Back that folder up, and
keep it on an encrypted disk (FileVault, BitLocker or LUKS): the archive holds people's names and e-mail addresses and is not
encrypted by the tool. To keep the data somewhere else, set the `OPA_DATA_DIR` environment variable before you start.

## If it fails

| What you see | What to do |
|---|---|
| `No Python 3.9 or newer found` (or the `.bat` window says Python was not found) | Install Python (see the table at the top), open a **new** terminal, and start again. |
| `its bundled SQLite ... is below the 3.35.0` | Your Python's SQLite is too old (typical for the system Python of an old Linux). Install a newer Python from python.org or your package manager. |
| `Port 8766 is in use` or `Could not bind 127.0.0.1:8766` | The tool, or something else, is already running. Close it, or start with another port: `python3 launch.py --port 8800`. |
| It says a dashboard from this folder is "still running" and asks to stop it | Answer `y` if you did not just start it on purpose; it is a leftover from an earlier session. |
| `Could not create the virtual environment` (Debian, Ubuntu) | `sudo apt-get install python3-venv`, then start again. |
| `ERROR: npm is not available and there is no frontend build` | You unpacked the "Source code" download. Download `ocw-<version>.tar.gz` from the release's **Assets** (step 1) instead. |
| Saving the connection fails with a keyring error (Linux) | The tool needs a running keyring service such as GNOME Keyring or KWallet. On a desktop it is there already; on a bare server, use [Install on a server](install-server.md). |
| "Could not connect" after you press the button | Re-check the domain, team name and key. The message from OPA is shown under the form. |

## Next

- Learn what each page does: [Features](features.md).
- Build a package for your auditor: [Evidence packages](evidence-package.md).
- Update to a newer release: `python3 launch.py upgrade --check`, then see [Upgrading](upgrading.md#upgrade-a-computer-install).
- Uninstall: close the tool and delete the folder. Delete the saved credentials from your keychain too if you want them gone.
- Prefer a command-line tool without the dashboard: [the CLI](hosting.md#running-it-as-a-cli-instead).
