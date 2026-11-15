# Words used in these guides

- **Environment.** One saved connection in the tool: an OPA team plus, optionally, an Okta org, with the credentials for both. You can
  save several (dev, uat, prod) and switch between them. Everything the tool archives belongs to an environment.
- **OPA (Okta Privileged Access).** Okta's product for vaulting secrets and controlling privileged access. The tool reads from it and
  can create folders and policies in it.
- **OPA team.** The name of your OPA tenant, used in OPA's API addresses. The form calls it **Team Name**.
- **Base domain.** The host name of your OPA tenant, for example `yourorg.pam.okta.com`, without `https://`.
- **Service user.** An OPA account for programs. It has an API key (a **key ID** and a **key secret**) instead of a password. An OPA
  administrator creates it. The tool signs in to OPA as this user, so what the tool can see is limited by what the user may do.
- **Okta API token.** A secret that lets the tool call Okta's API with the permissions of the admin who created it. It stops working
  if it is not used for 30 days.
- **System Log.** Okta's record of what happened (sign-ins, changes, OPA activity). Okta keeps it for only 90 days.
- **Archive.** The tool's own long-term copy of the System Log and of what it reads from OPA, kept in a local database
  (`audit_store.db`). Reports and evidence packages are built from it.
- **Sync now / refresh.** Reads OPA, Okta and the System Log again and updates the archive. A daily schedule does the same.
- **Evidence package.** One zip of the archive for an audit period, with report files and a checking program for the auditor.
- **Login gate.** On a server, a small program (`opa-auth-gate`) that sits in front of the tool and signs people in through Okta. On
  your own computer there is none.
- **Keyring.** The operating system's encrypted store for secrets. The tool keeps the OPA key secret, the Okta token and (on a
  server) the login gate's Okta client secret there, not in files.
- **Settings file.** On a server, `/etc/opa-compliance-wizard.env`: plain-text settings and three generated secrets. Never put the
  Okta client secret or token in it.
- **Release.** A signed download of a version of the tool (`ocw-X.Y.Z.tar.gz`). **Upgrade** means installing a newer release over an
  older one.
