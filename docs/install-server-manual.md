# Install on a server by hand

Use this page only if the [one-line installer](install-server.md) cannot be used on your server (another Linux distribution, for
example), or if you want to see exactly what that installer does. It is for system administrators. The result is an install that runs
from the application account's home directory; afterwards you can move it to the managed upgrade layout with
`sudo server/install.sh` (see [Upgrading](upgrading.md#older-servers-that-still-run-from-a-home-directory)).

The commands are for Debian and Ubuntu; adapt the package names for your distribution. The Okta setup is the same as in the
[server guide, step 1](install-server.md#step-1-prepare-okta), and every setting is explained in the
[settings reference](hosting.md#settings-file-reference).

## What the one-line installer does for you

So you know what you are replacing. After you confirm a plan, it installs whichever of `nginx`, `gnome-keyring`, `dbus-user-session`,
`python3-venv` and `openssl` are missing; creates the application account `ocw` (a regular account with home `/var/lib/opa-compliance-wizard/home`,
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
  frontend in it with `cd frontend && npm ci --ignore-scripts && npm run build`. Then, in the folder:
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
  /etc/nginx/sites-available/opa-secrets-wizard /etc/nginx/sites-enabled/ && sudo nginx -t && sudo systemctl enable --now nginx && sudo systemctl reload nginx`.
- **The login gate's session key** (32 random bytes; the gate refuses to start with less). The gate cannot create it in `/etc` by
  itself here, so make it: `sudo sh -c 'umask 027; head -c 32 /dev/urandom > /etc/opa-secrets-wizard-session.key' && sudo chown
  root:<app-user> /etc/opa-secrets-wizard-session.key && sudo chmod 0640 /etc/opa-secrets-wizard-session.key`. To end every session at
  once later, replace it ([Session key and emergency sign-out](hosting.md#session-key-and-emergency-sign-out)).
- **Executable scripts.** The shell scripts are executable in git; on a checkout where they are not (for example one edited from
  Windows), run `chmod +x server/*.sh start-wizard.sh`.

## 2. The two systemd units

Install and enable `opa-compliance-wizard.service` (the backend) and `opa-auth-gate.service` (the login gate). Both files use five
placeholders (the repository does not hardcode a user or path): `__APP_USER__` (the account), `__APP_UID__` (its numeric id, used for
`/run/user/<id>`, where the keyring daemon lives), `__APP_DIR__` (the application folder), `__DATA_DIR__` (where data is written) and
`__APP_USER_HOME__` (the account's home). For the in-place layout `__DATA_DIR__` is the same path as `__APP_DIR__`.
Run this as an administrator (a user with `sudo`), after you set the four variables to your values:

```bash
APP_USER=<app-user>                  # the account that runs the application
APP_DIR=/home/$APP_USER/opa-compliance-wizard   # the application folder
APP_HOME=/home/$APP_USER
for u in opa-compliance-wizard opa-auth-gate; do
  sed -e "s|__APP_USER__|$APP_USER|g" -e "s|__APP_UID__|$(id -u "$APP_USER")|g" \
      -e "s|__APP_DIR__|$APP_DIR|g" -e "s|__DATA_DIR__|$APP_DIR|g" -e "s|__APP_USER_HOME__|$APP_HOME|g" \
      "$APP_DIR/server/$u.service" | sudo tee /etc/systemd/system/$u.service >/dev/null
done
grep -l "__APP_" /etc/systemd/system/opa-compliance-wizard.service /etc/systemd/system/opa-auth-gate.service   # must print nothing
sudo systemctl daemon-reload
```

The `grep` must print nothing: a leftover `__APP_...__` placeholder means a unit that cannot work.

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
   the keyring unlocked). The two `env` settings point the command at that keyring session. Run each command as an administrator; it
   asks for the secret (hidden):

   ```bash
   APP_USER=<app-user>; APP_DIR=/home/$APP_USER/opa-compliance-wizard; U=$(id -u $APP_USER)
   for n in okta_client_secret okta_admin_check_token; do
     sudo -u $APP_USER env XDG_RUNTIME_DIR=/run/user/$U DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$U/bus \
       $APP_DIR/.venv/bin/python -c "import getpass, keyring; keyring.set_password('opa-compliance-wizard:default', '$n', getpass.getpass('$n: '))"
   done
   ```

   (`default` is `OKTA_ENV_NAME`.) Check that both are stored, without printing them:

   ```bash
   sudo -u $APP_USER env XDG_RUNTIME_DIR=/run/user/$U DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$U/bus \
     $APP_DIR/.venv/bin/python -c "import keyring; [print(n, 'stored' if keyring.get_password('opa-compliance-wizard:default', n) else 'MISSING') for n in ('okta_client_secret', 'okta_admin_check_token')]"
   ```
5. Start the login gate: `sudo systemctl enable --now opa-auth-gate`.
6. Open the dashboard address and sign in.

## 4. Upgrading this install

Until you move it to the managed layout, upgrade with `server/deploy.sh --release <version>`
([Upgrading](upgrading.md#older-servers-that-still-run-from-a-home-directory)). No sudoers rule is needed for the current tools; an
old deploy rule can be removed with `sudo server/install.sh --remove-legacy-sudoers` after you migrate.
