# Install on a server

This page gets OPA Compliance Wizard running on a Linux server that your team signs in to with Okta. The server keeps the
audit archive up to date every day, even when nobody has the page open.

If you only want to try it on your own computer, use [Install on your computer](install-computer.md) instead. It is simpler and
needs no Okta app.

Time: about 15 minutes for the install and about 15 minutes for the Okta setup.

## Before you start

You need all of these. Check them first; a missing one is the most common reason an install stops.

| Need | Details |
|---|---|
| A server | Debian 12 or newer, or Ubuntu 22.04 or newer (x86-64 or ARM), with systemd. A normal virtual machine is fine. A container, WSL1, Alpine, and Red Hat family systems (RHEL, Rocky, Alma, Fedora, Amazon Linux) are refused: for those, see [Manual install](install-server-manual.md). |
| Access | `root`, or a user that can run `sudo`. |
| Software already on the server | `curl` and `python3` (3.9 or newer, with SQLite 3.35 or newer). Debian 12 and Ubuntu 22.04 already meet this. A minimal image may lack `python3`: run `sudo apt-get install -y python3 curl` first. |
| Disk | 2 GB free. The archive grows with your Okta activity. |
| Internet from the server | HTTPS to `github.com` and to GitHub's download hosts (`objects.githubusercontent.com`, `release-assets.githubusercontent.com`), and to your distribution's package mirrors. No internet? See [Upgrading](upgrading.md#without-internet-access-offline). |
| A name for the server | A DNS name such as `opa.example.com` that points at the server, or its IP address. People open this address in a browser. Ports 80 and 443 must be reachable by them. |
| A certificate (optional) | A certificate and private key (PEM files) for that name. If you have none, the installer makes a temporary self-signed one, and browsers show a warning until you replace it. |
| Okta | An Okta org where you can create an app and a group (Super Administrator, or an admin role that can do both), and an Okta API token (step 1). |

## Step 1. Prepare Okta

Do this first, so you have the values ready when the installer finishes. You need your server's name from the table above.
Below, `opa.example.com` stands for it.

1. In the Okta Admin Console, go to **Applications → Create App Integration**. Choose **OIDC - OpenID Connect**, then
   **Web Application**.
2. Set these, leave everything else as it is, and save:
   - **Grant type:** Authorization Code only.
   - **Sign-in redirect URI:** `https://opa.example.com/authorization-code/callback`
   - **Sign-out redirect URI:** `https://opa.example.com/login`
   - **Assignments:** the people or groups who may use the tool.
3. Write down the **Client ID** and the **Client secret** shown on the app page.
4. Make sure the app's **Authentication policy** asks for a second factor (MFA). Changes to settings and upgrades ask people to
   confirm with MFA; if the policy does not require it, Okta can skip the question and the confirmation is weaker than it looks.
5. Create or pick an Okta group for the people who will administer this tool. Open it (**Directory → Groups**) and write
   down its **group ID**: it is in the web address, `.../groups/<id>/...`. It must be the ID, not the group name.
6. Create an Okta API token (**Security → API → Tokens → Create token**) with an admin account that can read users and groups.
   Write it down; Okta shows it once. The tool uses it only to check, at each sign-in, whether the person is in the admin group.
   A token takes on the permissions of the admin who made it. **Okta stops honouring a token that has not been used for 30 days,
   and one whose admin account is deactivated.** The tool uses it at every sign-in, so it stays alive in normal use, but create it
   with an account that will last.

By default the tool signs people in through your Okta org's authorization server named `default`
(`https://<your org>/oauth2/default`). If you use another server, or the org authorization server, see
[the settings reference](hosting.md#settings-file-reference) after the install (`OKTA_AUTH_SERVER`).

## Step 2. Run the installer

Log in to the server and run:

```bash
curl -fsSLO https://github.com/ItsGambit/opa-compliance-wizard/releases/latest/download/get-ocw.sh && sudo bash get-ocw.sh
```

This downloads a short script and then runs it. It does not pipe anything into a shell, so you can read `get-ocw.sh` first
(`less get-ocw.sh`). It downloads the newest release, **checks its signature before installing anything**, and shows you a
plan.

What you should see, in order:

1. Lines starting `ok` for the system check and the signature check (for example `ok  release 5.53.0: signature valid`).
2. A question: **Public name or IP address of this server**. Type the name from step 1 (`opa.example.com`).
3. A question: **TLS certificate for the web site**. Choose `1` if you have a certificate and key (it asks for the two file
   paths), or `2` (the default) for a temporary self-signed one.
4. The plan, a list of everything it will create, and `Proceed? [y/N]`. Type `y`.
5. A few minutes of package installation, then:

```text
the backend is active and answers /api/version as 5.53.0

Done. OPA Compliance Wizard 5.53.0 is installed and the backend is running.
```

Nothing opens in a browser yet. The installer prints a list of **"Not done yet"** steps: they are steps 3 to 6 below with the
values filled in for your server, so you can copy them from there.

To look at the plan without changing anything, run `sudo bash get-ocw.sh --dry-run`.

To run it without questions (for scripts): `sudo bash get-ocw.sh --yes --server-name opa.example.com --self-signed`. With your own
certificate, use `--cert FILE --key FILE` instead of `--self-signed`; `--no-nginx` skips the web server (see
[the reference](hosting.md) if another proxy or a tunnel sits in front).

## Step 3. Fill in the Okta settings

Open the settings file as root:

```bash
sudoedit /etc/opa-compliance-wizard.env
```

Remove the `#` at the start of these three lines and replace the example values with yours:

```text
OKTA_ORG_URL=https://your-org.okta.com
OKTA_OIDC_CLIENT_ID=<the Client ID from step 1>
OKTA_ADMIN_GROUP_ID=<the group ID from step 1>
```

`DASHBOARD_ORIGIN` is already set to `https://` plus the name you gave the installer. Do not put the client secret or the token in
this file. Leave the generated secrets in it alone.

## Step 4. Store the two Okta secrets

The client secret and the API token go into the application's own encrypted keyring, not into the settings file. The installer
printed the first command below at the end of its run. Run each one: it asks for the secret (the typing is hidden, and nothing is
saved in your shell history). No output after you press Enter means it worked.

The client secret from step 1:

```bash
sudo -u ocw env XDG_RUNTIME_DIR=/run/user/$(id -u ocw) DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u ocw)/bus /opt/opa-compliance-wizard/current/.venv/bin/python -c "import getpass, keyring; keyring.set_password('opa-compliance-wizard:default', 'okta_client_secret', getpass.getpass('client secret: '))"
```

The API token from step 1:

```bash
sudo -u ocw env XDG_RUNTIME_DIR=/run/user/$(id -u ocw) DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u ocw)/bus /opt/opa-compliance-wizard/current/.venv/bin/python -c "import getpass, keyring; keyring.set_password('opa-compliance-wizard:default', 'okta_admin_check_token', getpass.getpass('API token: '))"
```

Run them while the backend is running (it is, right now): the backend keeps the keyring unlocked, and these commands use it.

## Step 5. Start the login gate

```bash
sudo systemctl enable --now opa-auth-gate
```

The installer leaves the login gate off on purpose: without steps 3 and 4 it cannot start. Check it:

```bash
sudo systemctl status opa-auth-gate
```

You should see `active (running)`.

## Step 6. Sign in

Open `https://opa.example.com` in a browser. With a self-signed certificate the browser warns you; continue past the warning
(you can install a trusted certificate later). You are sent to Okta, sign in, and land in the dashboard.

- If you are in the admin group you see everything, including **Access control**, **Audit Log** and **Updates** in the sidebar.
- Everyone else can use the tool but cannot change shared settings.

The dashboard then asks you to add your first environment: your OPA team's connection details (domain, team name, service user key
ID and secret). Where to find them is in [Install on your computer, step 3](install-computer.md#step-3-connect-your-opa-team);
the form is the same. Then run **Sync now** once; after that the server syncs every day by itself.

You are done. Next:

- Restrict who may sign in and set the admin and user groups in the app's **Access control** page
  ([how it works](hosting.md#admin-access)).
- Plan your backups ([Backups and restore](hosting.md#backups-and-restore)). The archive is the only copy of events older than
  Okta's 90 days.
- Replace the temporary certificate with a trusted one when you can.
- To upgrade later, see [Upgrading](upgrading.md).

## If it fails

| What you see | What to do |
|---|---|
| `refused: python3 was not found` or `refused: this system is ...` | Nothing was changed. Install what it names (`sudo apt-get install -y python3`), or use a supported system, and run the same command again. |
| The installer stops with an error, or you lose your connection | Run the **same command again**. It resumes, and never overwrites your data or settings. The log of every run is in `/var/log/ocw-install/`. |
| `The backend did not come up healthy` | Run `journalctl -u opa-compliance-wizard -n 100 --no-pager` and read the last lines. Fix the cause and run the installer again. |
| The browser shows a plain `500 Internal Server Error` | The login gate is not running yet. Finish steps 3 to 5 and check `sudo systemctl status opa-auth-gate`. |
| `opa-auth-gate` keeps restarting | Run `journalctl -u opa-auth-gate -n 30 --no-pager`. A message `No okta_client_secret in keyring` means step 4 was not done (or was done for another `OKTA_ENV_NAME`); a message about a missing setting means step 3. |
| Okta shows `redirect_uri` error or `access_denied` after the sign-in page | The redirect URI in Okta must match `DASHBOARD_ORIGIN` exactly (`https://`, no trailing slash, `/authorization-code/callback`). If you use a custom authorization server, it needs an access policy and a rule that allow this app. |
| Sign-in worked for weeks and then stops | The Okta API token (step 1, item 6) expired or its admin was deactivated. Create a new one and repeat step 4 for `okta_admin_check_token`. |

## Other things you may need

- **Another way to install** (another Linux, or to see every step): [Manual install](install-server-manual.md).
- **Behind a proxy or a mirror:** pass the settings through `sudo`, which clears the environment:
  `sudo https_proxy=https://proxy.example.com:3128 bash get-ocw.sh`. With a mirror (`OCW_RELEASE_BASE_URL`) you must also say
  `--version X.Y.Z` and set `OCW_REVOCATION_URL` to a page you control. See [Verifying releases](verifying-releases.md).
- **Uninstall:** `sudo bash get-ocw.sh --uninstall --keep-data` removes the software and keeps every data file. See
  [Uninstalling](hosting.md#uninstalling).
- **Exit status** of the installer: `0` done, `2` refused and nothing changed, `3` failed and everything put back, `4` failed and you
  must act (the message says what).
- **What the installer trusts and how to check it:** [Verifying releases](verifying-releases.md).
- **What has been tested:** a full install on a real Debian 13 x86-64 server. Ubuntu and ARM are covered by automated tests with
  simulated system commands, not yet by a real-machine install.
