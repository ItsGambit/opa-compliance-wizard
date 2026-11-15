# Install on a server

This page gets OPA Compliance Wizard running on a Linux server that your team signs in to with Okta. The server keeps the audit
archive up to date every day, even when nobody has the page open.

If you only want to try it on your own computer, use [Install on your computer](install-computer.md) instead. It is simpler and needs
no Okta app. Unfamiliar words (environment, archive, service user, login gate, keyring) are explained in the [glossary](glossary.md).

Time: about 30 minutes in all (15 for Okta, 15 for the install). It does not include the first sync (step 6) or the time the
administrators need to hand you the OPA and Okta values.

## How it fits together

```text
browser  ->  nginx (HTTPS, port 443)  ->  login gate (checks you with Okta)  ->  backend (the app, 127.0.0.1:8766)
```

nginx is the only part the network can reach. It asks the **login gate** whether the visitor is signed in through Okta; only then does
the request reach the **backend**, which holds the archive and the credentials. Because of this order, the site shows an error page
until the login gate is running (step 5).

## Before you start

You need all of these. Check them first; a missing one is the most common reason an install stops.

- **A server:** Debian 12 or newer, or Ubuntu 22.04 or newer (x86-64 or ARM), with systemd. A normal virtual machine is fine.
  A container, WSL1, Alpine, and Red Hat family systems (RHEL, Rocky, Alma, Fedora, Amazon Linux) are refused: for those, see
  [Install on a server by hand](install-server-manual.md). It has been tested end to end on a real Debian 13 x86-64 server; Ubuntu
  and ARM are covered by automated tests with simulated system commands, not yet by a real-machine install.
- **Access:** `root`, or a user that can run `sudo`.
- **Software already on the server:** `curl` and `python3` (3.9 or newer, with SQLite 3.35 or newer). Debian 12 and Ubuntu 22.04
  already meet this. A minimal image may lack them: run `sudo apt-get install -y python3 curl` first.
- **Disk:** 2 GB free. The archive grows with your Okta activity.
- **Outbound HTTPS from the server** to: `github.com`, `objects.githubusercontent.com` and `release-assets.githubusercontent.com`
  (the release); `pypi.org` and `files.pythonhosted.org` (the Python packages, installed during the install); your distribution's
  package mirrors; and your Okta org's address (sign-in and the admin check). No internet? See
  [Upgrading](upgrading.md#without-internet-access-offline).
- **A name for the server, decided now,** for example `opa.example.com`, with a DNS record pointing at the server (the name may be
  internal-only). You need it in step 1, because Okta's redirect addresses must match it exactly. Check that your laptop resolves it:
  `nslookup opa.example.com`. Ports 80 and 443 must be reachable by the people who sign in
  ([DNS and TLS details](hosting.md#dns-and-tls-for-a-server)).
- **A TLS certificate (recommended):** two PEM files from a certificate authority your browsers trust: the certificate with its chain
  (certbot's `fullchain.pem`) and the private key. Without them the installer makes a temporary self-signed certificate: browsers warn
  until you [replace it](hosting.md#dns-and-tls-for-a-server). Fine for a trial, not for daily use. A bare IP address is accepted, but
  Okta and certificates work best with a DNS name, and IP-only has not been tested against a real Okta org.
- **Okta:** an Okta org on **Okta Identity Engine** where you can create an app and a group (Super Administrator, or an admin role
  that can do both). Orgs created since 2022 are Identity Engine; if you are unsure, ask your Okta administrator. The MFA confirmation
  uses Identity Engine's step-up: on an older Classic Engine org it may not prompt, so a change or upgrade may go through without a
  second-factor check (sign-in itself still works).
- **The OPA and Okta values** (base domain, team name, service-user key, Okta URL, API token): ask for them now. See
  [What to get before you start](what-you-need.md); you use the Okta token in step 1 and the rest in step 6.

## Step 1. Prepare Okta

Do this first, so you have the values ready when the installer finishes. Below, `opa.example.com` stands for your server's name.

1. **Create the admin group first.** In the Okta Admin Console create or pick a group for the people who will administer this tool
   (**Directory → Groups**). Open it and copy its **group ID** from the web address: it looks like `00g1a2b3c4d5e6f7g8h9`, and the
   address looks like `https://yourorg-admin.okta.com/admin/group/00g1a2b3c4d5e6f7g8h9`. It must be the ID, not the group name.
2. Go to **Applications → Applications → Create App Integration**. Choose **OIDC - OpenID Connect**, then **Web Application**.
3. Set these and save. The defaults are fine for everything not listed (leave Refresh Token and PKCE as they are; the tool needs
   neither, and works with either).
   - **Grant type:** tick only Authorization Code.
   - **Client authentication:** client secret (the default).
   - **Sign-in redirect URI:** `https://opa.example.com/authorization-code/callback`
   - **Sign-out redirect URI:** `https://opa.example.com/login`
   - **Assignments:** the people or groups who may sign in. **Include the admin group from item 1 and yourself**, or you will be
     refused at your first sign-in.

   Both redirect addresses must start with `https://` and match the server's name **exactly** (no trailing slash). No extra scopes
   are needed: the tool asks for `openid profile email`, and it does not need a groups claim, because it checks group membership with the
   API token in item 6.
4. Write down the **Client ID** and the **Client secret** shown on the app page.
5. **Require a second factor.** Open the app's **Sign On** tab, find its **Authentication policy**, and check that a rule requires two
   factors. If none does, add one (**Security → Authentication Policies**), or Okta will not ask: the tool then lets a change or
   upgrade go through with no real second check.
6. Create an Okta API token (**Security → API → Tokens → Create token**; the token's name does not matter), with a dedicated admin account
   that can read users and groups ([what to ask for](what-you-need.md)). Write it down; Okta shows it once. The tool uses it only to
   check, at each sign-in, whether the person is in the admin group. **Okta stops honouring a token that has not been used for 30
   days, and one whose admin account is deactivated.** The tool uses it at every sign-in, so it stays alive in normal use.
7. **Check the authorization server.** The tool signs people in through your org's authorization server named `default`
   (`https://<your org>/oauth2/default`). That server belongs to Okta's API Access Management feature. Open **Security → API →
   Authorization Servers**: if you see a server named `default`, you are fine (if you made your own policies there, one policy and
   rule must allow this app). If you do not, either enable API Access Management, or tell the tool to use the org's own server by adding
   `OKTA_AUTH_SERVER=org` to the settings file in step 3. If you are unsure, use `default` when it exists and `org` when it does not.

## Step 2. Run the installer

Log in to the server and run:

```bash
curl -fsSLO https://github.com/ItsGambit/opa-compliance-wizard/releases/latest/download/get-ocw.sh && sudo bash get-ocw.sh
```

This downloads a short script and then runs it. It does not pipe anything into a shell, so you can read `get-ocw.sh` first
(`less get-ocw.sh`). It downloads the newest release, **checks its signature before installing anything**, and shows you a plan.

What you should see, in order (your version number will differ):

1. Lines starting `ok` for the system check and the signature check, for example `ok  release X.Y.Z: signature valid (key ...); sha256
   ...; N files match the signed manifest`.
2. A question: **Public name or IP address of this server**. Type the name from "Before you start" (`opa.example.com`).
3. A question: **TLS certificate for the web site**. Choose `1` if you have a certificate and key (it asks for the two file paths),
   `2` (the default) for a temporary self-signed one, or `3` if another proxy or a tunnel ends TLS in front of this server (then no
   nginx is set up here).
4. The plan, a list of everything it will create, and `Proceed? [y/N]`. Type `y`. If nginx already serves other sites on this server,
   they are left alone and this one is added with its own name; if something else already listens on port 443, choose `3`.
5. A few minutes of package installation, then:

```text
the backend is active and answers /api/version as X.Y.Z

Done. OPA Compliance Wizard X.Y.Z is installed and the backend is running.
```

Nothing opens in a browser yet. The installer then prints this (shortened) list; item 1 is step 1 above, and items 2 to 5 are steps 3
to 6 below with your server's values filled in:

```text
Not done yet (nothing works in a browser until this is):
1. Register the Okta OIDC web app ...
2. As root: sudoedit /etc/opa-compliance-wizard.env and fill OKTA_ORG_URL, OKTA_OIDC_CLIENT_ID, OKTA_ADMIN_GROUP_ID
3. Put the client secret and the read-only admin-check token in the application's keyring ...
4. sudo systemctl enable --now opa-auth-gate && sudo systemctl status opa-auth-gate
5. Open https://<your server>, sign in, add your first environment ...
```

## Step 3. Fill in the Okta settings

Open the settings file as root. `sudoedit` opens your default editor (set `EDITOR=nano` first if you prefer it):

```bash
sudoedit /etc/opa-compliance-wizard.env
```

The file already holds generated secrets (`NGINX_PROXY_SECRET`, `KEYRING_UNLOCK_PASSWORD`, `INTERNAL_API_SHARED_SECRET`), the origin and
the Okta lines as comments ([a sample](hosting.md#a-sample-settings-file)). Leave the secrets alone. Remove the `#` at the start of
these three lines and replace the example values with yours (no quotes, no spaces around `=`):

```text
OKTA_ORG_URL=https://your-org.okta.com
OKTA_OIDC_CLIENT_ID=<the Client ID from step 1>
OKTA_ADMIN_GROUP_ID=<the group ID from step 1>
```

Use your normal Okta address (not the one with `-admin` in it). `DASHBOARD_ORIGIN` is already set to `https://` plus the name you gave the
installer. Do not put the client secret or the token in this file: a file is easy to copy by accident; the keyring (step 4) is not.
If step 1 item 7 told you to, add `OKTA_AUTH_SERVER=org`.

Leave `OKTA_ENV_NAME` as it is (default `default`): step 4 stores the secrets under that name. Nothing needs restarting yet, because the
login gate is not running. After a later edit, see [which edit needs which restart](hosting.md#which-edit-needs-which-restart).

## Step 4. Store the two Okta secrets

The client secret and the API token go into the application's own encrypted keyring, not into the settings file. Each command asks
for the secret (the typing is hidden, and nothing is saved in your shell history). No output after you press Enter means it worked.

Why a keyring: the secrets are then encrypted at rest and never sit in a plain file. The server has no desktop, so the installer set up
a keyring for the `ocw` account and turned on *linger* (so it keeps running with nobody logged in). Both commands start with `sudo -u ocw env
XDG_RUNTIME_DIR=... DBUS_SESSION_BUS_ADDRESS=...`; that is not a secret, it points the command at the `ocw` keyring session that the running
backend keeps unlocked. Run them while the backend is running (it is, right now). Each is one long line: copy it whole.

The client secret from step 1:

```bash
sudo -u ocw env XDG_RUNTIME_DIR=/run/user/$(id -u ocw) DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u ocw)/bus /opt/opa-compliance-wizard/current/.venv/bin/python -c "import getpass, keyring; keyring.set_password('opa-compliance-wizard:default', 'okta_client_secret', getpass.getpass('client secret: '))"
```

The API token from step 1:

```bash
sudo -u ocw env XDG_RUNTIME_DIR=/run/user/$(id -u ocw) DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u ocw)/bus /opt/opa-compliance-wizard/current/.venv/bin/python -c "import getpass, keyring; keyring.set_password('opa-compliance-wizard:default', 'okta_admin_check_token', getpass.getpass('API token: '))"
```

To check that both are stored without printing them:

```bash
sudo -u ocw env XDG_RUNTIME_DIR=/run/user/$(id -u ocw) DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u ocw)/bus /opt/opa-compliance-wizard/current/.venv/bin/python -c "import keyring; [print(n, 'stored' if keyring.get_password('opa-compliance-wizard:default', n) else 'MISSING') for n in ('okta_client_secret', 'okta_admin_check_token')]"
```

You should see `okta_client_secret stored` and `okta_admin_check_token stored`. If you restart the server later and `/run/user/<id>`
is missing, start the backend (`sudo systemctl start opa-compliance-wizard`) and run the command again.

## Step 5. Start the login gate

```bash
sudo systemctl enable --now opa-auth-gate
```

The installer leaves the login gate off on purpose: without steps 3 and 4 it cannot start. Check it:

```bash
sudo systemctl status opa-auth-gate
```

You should see `active (running)`. Press `q` to leave the status view. Before you open the browser, check that the site now redirects
to Okta:

```bash
curl -sk -o /dev/null -w '%{http_code} %{redirect_url}\n' https://opa.example.com/login
```

You should see `302` and an address starting with your Okta org (`https://your-org.okta.com/oauth2/default/v1/authorize?...`; `-k` skips
the certificate check, for a self-signed certificate). A `502` or `504` means the
backend or the gate is down (`systemctl status opa-compliance-wizard opa-auth-gate`); a `500` means the gate is not running yet.

## Step 6. Sign in

First check that your laptop can find the server: `nslookup opa.example.com` (or open the address). Then open
`https://opa.example.com` in a browser. With a self-signed certificate the browser warns about the dashboard's address (only about
that); continue past the warning. You are sent to Okta; sign in. What can happen:

- **Okta says you are not assigned to the app:** add yourself, or a group you are in, under the app's **Assignments** (step 1).
- **Okta asks for a second factor:** that is your authentication policy working. Complete it.
- **You land in the dashboard and see everything,** including **Access control**, **Audit Log** and **Updates** in the sidebar: you
  are in the admin group.
- **You land in the dashboard but those admin items are missing:** you signed in, but you are not in the admin group. Check the group ID
  in step 3 and your membership in Okta, then sign out and in again.
- **Okta shows an error page** (`redirect_uri`, `access_denied`): see "If it fails" below.

Everyone assigned to the app in Okta can sign in and use the tool with their own, private environments; only the admin group gets the
admin pages. To limit sign-in to particular Okta groups, use **Access control**
([who can sign in, who is admin](hosting.md#who-can-sign-in-who-is-admin)).

The dashboard then asks you to add your first environment: your OPA team's connection details and your Okta URL and API token (the values
from [What to get before you start](what-you-need.md)). It is the same form as on a computer install; use
[Install on your computer, step 3](install-computer.md#step-3-connect-opa-and-okta) and [step 4](install-computer.md#step-4-fill-the-archive)
for the fields and the first sync, and **ignore everything about Python, `launch.py` and the desktop keychain**: this server already runs the
app. After the first sync the server syncs every day by itself.

You are done. Next:

- Plan your backups ([Backups and restore](hosting.md#backups-and-restore)). The archive is the only copy of events older than Okta's
  90 days.
- Replace the temporary certificate with a trusted one when you can.
- To upgrade later, see [Upgrading](upgrading.md).

## If it fails

- **`refused: python3 was not found` or `refused: this system is ...`:** nothing was changed. Install what it names
  (`sudo apt-get install -y python3`), or use a supported system, and run the same command again.
- **The installer stops with an error, or you lose your connection:** run the **same command again**. It resumes, and never overwrites
  your data or settings. The log of every run is in `/var/log/ocw-install/`.
- **A pip error such as `No matching distribution` or a timeout during the install:** the server cannot reach `pypi.org` and
  `files.pythonhosted.org`. Open them, set `https_proxy` (see below), or install from a directory with `--wheelhouse DIR`.
- **`The backend did not come up healthy`:** run `journalctl -u opa-compliance-wizard -n 100 --no-pager` and read the last lines. Fix
  the cause and run the installer again.
- **The browser shows a plain `500 Internal Server Error`** (see "How it fits together"): the login gate is not running yet.
  Finish steps 3 to 5 (back to [step 3](#step-3-fill-in-the-okta-settings)) and check `sudo systemctl status opa-auth-gate`.
- **`opa-auth-gate` keeps restarting:** run `journalctl -u opa-auth-gate -n 30 --no-pager`. `No okta_client_secret in keyring` means
  [step 4](#step-4-store-the-two-okta-secrets) was not done (or was done for another `OKTA_ENV_NAME`); a message about a missing setting
  means [step 3](#step-3-fill-in-the-okta-settings).
- **The keyring command fails with a D-Bus error, or `/run/user/<id>` is missing:** the backend is not running or the `ocw` account has no
  session. Run `sudo systemctl start opa-compliance-wizard`, wait ten seconds, and run the command again.
- **Okta shows a `redirect_uri` error or `access_denied` after the sign-in page:** the redirect address in Okta must match
  `DASHBOARD_ORIGIN` exactly (`https://`, no trailing slash, `/authorization-code/callback`). `access_denied` with "policy evaluation
  failed" means the `default` authorization server has no policy that allows this app: see step 1 item 7.
- **Sign-in worked for weeks and then stops:** the Okta API token (step 1, item 6) expired or its admin was deactivated. Create a new
  one and repeat [step 4](#step-4-store-the-two-okta-secrets) for `okta_admin_check_token`, then
  `sudo systemctl restart opa-auth-gate`.

## Other things you may need

- **Look at the plan first, or run without questions:** `sudo bash get-ocw.sh --dry-run` shows the plan and changes nothing. For
  scripts: `sudo bash get-ocw.sh --yes --server-name opa.example.com --self-signed`; with your own certificate use `--cert FILE --key
  FILE` instead of `--self-signed`; `--no-nginx` skips the web server (see the
  [Hosting reference](hosting.md#hosting-on-a-server-optional) if another proxy or a tunnel sits in front).
- **Another way to install** (another Linux, or to see every step): [Install on a server by hand](install-server-manual.md).
- **Behind a proxy or a mirror:** see [Installer options](hosting.md#installer-options-proxy-and-mirror).
- **Uninstall:** `sudo bash get-ocw.sh --uninstall --keep-data` removes the software and keeps every data file. See
  [Uninstalling](hosting.md#uninstalling).
- **Exit status** of the installer: `0` done, `2` refused and nothing changed, `3` failed and everything put back, `4` failed and you
  must act (the message says what).
- **What the installer trusts and how to check it:** [Verifying releases](verifying-releases.md).
