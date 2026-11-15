# Install on a server by hand

Use this page only if the [one-line installer](install-server.md) cannot be used on your server (another Linux distribution, for
example), or if you want to see exactly what that installer does. It is for system administrators. The result is an install that runs
from the application account's home directory; afterwards you can move it to the managed upgrade layout with
`sudo server/install.sh` (see [Upgrading](upgrading.md#older-servers-that-still-run-from-a-home-directory)).

The commands are for Debian and Ubuntu; adapt the package names for your distribution. The Okta setup is the same as in the
[server guide, step 1](install-server.md#step-1-prepare-okta), and every setting is explained in the
[settings reference](hosting.md#settings-file-reference).

## What the one-line installer does for you

So you know what you are replacing. After you confirm a plan, it installs `nginx`, `gnome-keyring`, `dbus-user-session`,
`python3-venv` and `openssl`; creates the application account `ocw` (a regular account with home `/var/lib/opa-compliance-wizard/home`,
shell `nologin`, lingering on); writes `/etc/opa-compliance-wizard.env` (mode 0600) with three generated secrets; writes the two
application units with the account's real numeric id in `/run/user/<uid>`; writes the login gate's session key; makes the nginx site
from the release's template with your server name, the proxy secret and a certificate; and starts the backend and checks it, also
through nginx. The login gate is installed but neither enabled nor started.

## 1. What the server needs

The hosted services cannot start without these, and an improvised fix on the login path tends to be an insecure one, so do all of them
before you start the services.

- **Packages:** `sudo apt-get install nginx python3-venv gnome-keyring dbus-user-session rsync git curl`, and, only if you build the
  web pages yourself, a Node.js the build accepts (`^20.19.0 || >=22.12.0`; a distribution's own `nodejs` is often older: use nodejs.org
  or NodeSource). Using a signed release (below) needs no Node.js.
- **The code**, as the application user (no sudo). Either unpack a signed release (`ocw-<version>.tar.gz`; check it first, see
  [Verifying releases](verifying-releases.md)), or clone `https://github.com/ItsGambit/opa-compliance-wizard.git` and build the
  frontend in it with `cd frontend && npm ci --ignore-scripts && npx vite build`. Then, in the folder:
  `python3 -m venv .venv && .venv/bin/pip install --require-hashes -r requirements.lock`. Every package must match a recorded
  checksum.
- **Lingering.** The application user's systemd user manager must keep running without a login session, because the keyring daemon
  lives in `/run/user/<uid>`: `sudo loginctl enable-linger <app-user>`. The unit templates carry `__APP_UID__` (and `__APP_USER_HOME__`)
  where that directory is named. When you install a unit by hand, replace them in both units.
- **The settings file** holds secrets (`KEYRING_UNLOCK_PASSWORD`, `NGINX_PROXY_SECRET`, `INTERNAL_API_SHARED_SECRET`). Create it
  owner-only before writing anything into it: `sudo install -m 600 -o <app-user> -g <app-user's group> /dev/null
  /etc/opa-compliance-wizard.env`, then edit it as the application user. `KEYRING_UNLOCK_PASSWORD` is the password
  `server/start-headless.sh` uses to unlock (or, the first time, create) the application user's login keyring; the backend
  refuses to start without it. Set `DEPLOYMENT_MODE=hosted`; the other settings are in the
  [settings reference](hosting.md#settings-file-reference).
- **A TLS certificate** for the nginx site. The template expects `/etc/nginx/ssl/opa-secrets-wizard.crt` and `.key`; any path works if
  the site names it. For a test on an IP address, make a self-signed one: `sudo install -d -m 700 /etc/nginx/ssl && sudo openssl req
  -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=<ip or host>" -addext "subjectAltName=IP:<ip>" -keyout
  /etc/nginx/ssl/opa-secrets-wizard.key -out /etc/nginx/ssl/opa-secrets-wizard.crt` (use `DNS:<host>` for a name).
- **The nginx site**, readable only by root and the application user's group (it will hold `NGINX_PROXY_SECRET`): `sudo install -m 0640
  -o root -g <app-user's group> server/nginx-opa-secrets-wizard.conf /etc/nginx/sites-available/opa-secrets-wizard`. Then `sudoedit`
  it to set your `server_name` (both blocks), the certificate paths and the proxy secret, and enable it: `sudo ln -s
  /etc/nginx/sites-available/opa-secrets-wizard /etc/nginx/sites-enabled/ && sudo nginx -t && sudo systemctl reload nginx`.
- **Executable scripts.** The shell scripts are executable in git; on a checkout where they are not (for example one edited from
  Windows), run `chmod +x server/*.sh start-wizard.sh`.

## 2. The two systemd units

Install and enable `opa-compliance-wizard.service` (the backend) and `opa-auth-gate.service` (the login gate). Both files use the
placeholders `__APP_USER__`, `__APP_DIR__`, `__DATA_DIR__` and `__APP_USER_HOME__` (the repository does not hardcode a user or path).
For the in-place layout set `__DATA_DIR__` to the same path as `__APP_DIR__`, and delete the `OPA_DATA_DIR` and `ProtectSystem` lines.
Run this from the application folder so `$(pwd)` is the real application directory:

```bash
sed -e "s|__APP_USER__|$(whoami)|g" \
    -e "s|__APP_DIR__|$(pwd)|g" \
    -e "s|__APP_USER_HOME__|$HOME|g" -e "s|__DATA_DIR__|$(pwd)|g" \
    server/opa-compliance-wizard.service | sudo tee /etc/systemd/system/opa-compliance-wizard.service
sed -e "s|__APP_USER__|$(whoami)|g" \
    -e "s|__APP_DIR__|$(pwd)|g" \
    -e "s|__APP_USER_HOME__|$HOME|g" -e "s|__DATA_DIR__|$(pwd)|g" \
    server/opa-auth-gate.service | sudo tee /etc/systemd/system/opa-auth-gate.service
sudo systemctl daemon-reload
```

`sudo tee` creates the files owned by root, which is what they must stay: systemd runs them as root, so a unit file the application user
can edit is a way to root at the next reload or boot. Check that the live unit's `EnvironmentFile=` path is the one your settings file
is at (`systemctl cat opa-compliance-wizard | grep EnvironmentFile`) before you copy a new unit over an old one: an older install may use a
different path, and overwriting the unit without merging the settings leaves the service with none of its secrets.

**Units are never re-copied by `deploy.sh`.** When a later release changes either `.service` file (its changelog entry says so), copy it
again by hand and run `systemctl daemon-reload` and `restart`. Check with `diff server/*.service /etc/systemd/system/`.

## 3. Okta settings, secrets and start

1. Do [step 1 of the server guide](install-server.md#step-1-prepare-okta) (the Okta app, the admin group, the API token).
2. Put the four Okta settings (`OKTA_ORG_URL`, `OKTA_OIDC_CLIENT_ID`, `DASHBOARD_ORIGIN`, `OKTA_ADMIN_GROUP_ID`) and
   `EXTRA_ALLOWED_ORIGINS` in the settings file (see the [reference](hosting.md#settings-file-reference)).
3. Start the backend: `sudo systemctl enable --now opa-compliance-wizard`.
4. Store the client secret and the admin-check token in the application user's keyring, **while the backend is running** (it keeps
   the keyring unlocked), as the application user:

   ```bash
   python3 -c "import getpass, keyring; keyring.set_password('opa-compliance-wizard:default', 'okta_client_secret', getpass.getpass('client secret: '))"
   python3 -c "import getpass, keyring; keyring.set_password('opa-compliance-wizard:default', 'okta_admin_check_token', getpass.getpass('API token: '))"
   ```

   (`default` is `OKTA_ENV_NAME`.) On a server made by the installer these commands need `XDG_RUNTIME_DIR` and
   `DBUS_SESSION_BUS_ADDRESS` set, as the installer's own command shows.
5. Start the login gate: `sudo systemctl enable --now opa-auth-gate`.
6. Open the dashboard address and sign in.

## Session-signing key

`auth_gate.py` signs its cookies with the key at `OPA_SESSION_KEY_PATH` (default `/etc/opa-secrets-wizard-session.key`). The gate
refuses to start if that file holds fewer than 32 bytes. Either let the gate create it (its directory must be writable by the
application user; it is created `0600`), or create it yourself:

```bash
sudo sh -c 'umask 027; head -c 32 /dev/urandom > /etc/opa-secrets-wizard-session.key'
sudo chown root:<app-user> /etc/opa-secrets-wizard-session.key
sudo chmod 0640 /etc/opa-secrets-wizard-session.key
```

**Emergency sign-out of everyone:** sessions are signed cookies with no server-side store, so replacing this key (same commands, then
`sudo systemctl restart opa-auth-gate`) ends every session at once, for example after offboarding an administrator (a session keeps the
admin flag it was issued with until it expires, 12 hours). Each additional gate has its own key (`/etc/opa-auth-gate-<name>/session.key`)
and unit (`opa-auth-gate-<name>`).

## Upgrading this install

Until you move it to the managed layout, upgrade with `server/deploy.sh --release <version>`
([Upgrading](upgrading.md#older-servers-that-still-run-from-a-home-directory)). No sudoers rule is needed for the current tools; an
old deploy rule can be removed with `sudo server/install.sh --remove-legacy-sudoers` after you migrate.
