# Security Policy

## Reporting a vulnerability

**Please do not open a public GitHub issue for a security vulnerability.**

Report it privately via
[GitHub Security Advisories](https://github.com/ItsGambit/opa-compliance-wizard/security/advisories/new)
for this repository. This creates a private discussion visible only to
the maintainer until a fix is ready, and lets GitHub coordinate a
disclosure timeline with you if one is needed.

Include, if you can:
- What you found and why it's a security issue (not just "this seems
  wrong")
- Steps to reproduce it
- The version/commit you tested against
- Whether it requires a specific deployment mode to be exploitable (see
  [Deployment modes](#deployment-modes) below)

**Never put a secret, a token, a key, or a customer's data in a report.**
If a failed upgrade is part of what you are reporting, attach the
**support bundle** the updater builds (see below), not raw logs or files
from the server.

### The support bundle

When an upgrade fails, the updater builds a redacted bundle
(`ocw-support-<from>-to-<to>-<time>-<id>.tar.gz`, at most 5 MB) before anyone
asks. An administrator can download it from the Audit Log entry of the failed
upgrade, or from a shell with `sudo ocw-updater bundle`
(`--include-hosts` keeps host and environment names, which are otherwise
redacted). Attach it to the private advisory above. **Nothing is ever sent
automatically.** What it holds and what it never holds (the environment
file, the keyring, the session key, the archive, request bodies, cookies) is
listed in the README under "The support bundle". Read it before you attach it.

## Deployment modes

What a report is about depends on how the tool runs. Four situations exist,
and the first two are the application itself; the last two are code that
runs as `root`:

- **Local only.** `python launch.py` on one computer. The server binds
  `127.0.0.1`, there is no sign-in, and credentials live in the operating
  system's keyring.
- **Hosted.** The backend behind nginx and an Okta login gate
  (`server/auth_gate.py`) on a server, for a team. The gate, the proxy
  secret and the per-user environments are the security-sensitive parts.
- **The root-run updater (5.47.0 and later).** On the upgrade layout, a small
  updater written in the Python standard library runs as `root`, stages a
  signed release as an unprivileged account, switches versions, health-checks
  and rolls back. The web application cannot write its own code; it asks the
  updater through an inbox. Files under `server/updater/root/` and
  `server/nginx_bake.py` are root code.
- **The root installer (5.52.0).** `server/install.sh` and the one-line
  installer `get-ocw.sh` run as `root` on a fresh or an existing server: they
  create the application account, write the settings file with generated
  secrets, the login gate's session key and the nginx site, and install the
  release. `get-ocw.sh` verifies the release's signature before it unpacks
  anything (see "Release signing keys" below).

## What to expect

This is a community-maintained project with one informal maintainer, not
a company with a dedicated security team or an SLA. A genuine effort will
be made to acknowledge a report promptly and fix a confirmed issue — but
there's no guaranteed response time. If you don't hear back within a
reasonable window, a follow-up is completely fair.

## Current security review status

This project has gone through internal review and multiple
AI-assisted security review passes, with findings independently verified
against the real code before being fixed — see
[CHANGELOG.md](CHANGELOG.md) for the specific fixes shipped this way.
**No independent third-party security audit has been performed.** If
you're evaluating this for a production tenant, especially a hosted
multi-user deployment, factor that in — see the main
[README](README.md)'s "Project status" section for the full framing.

Two things deserve the most caution:

- **The installer** (`server/install.sh`, `server/get-ocw.sh.in`) has had no
  independent audit. It runs as root, so read its plan (`--dry-run`) before
  you accept it.
- **The updater's root files** (`server/updater/root/`) run as root. They are
  not reviewed like the rest of the application: a change to them is reviewed
  as code that runs as root (see [docs/releasing.md](docs/releasing.md)), and
  you should do the same before you trust a fork.

## Release signing keys

Every release is signed. The project holds two keys in different places: a
**release** key that signs releases, and a **standby** key (a different kind of
key, in a different cloud) that can only sign a *revocation*. Both are public
information and are pinned in `server/release_keys.json`, which ships inside
every release. The fingerprint below is the SHA-256 of the key as listed in
that file (the raw public key for the release key, the DER public key for the
standby), base64-decoded.

| Role | Algorithm | Key id | Fingerprint (SHA-256) | Since |
|---|---|---|---|---|
| Release | Ed25519 (minisign format) | `88DFB54FC6C0E819` | `19e8c0c64fb5df88b977a6c2e9c90fcf7840803b96fcf5b3ee8c20e5a483d4c9` | 5.46.0 |
| Standby (revocations only) | ECDSA P-256 (ES256) | `76A2D96A6B0FAAAD` | `76a2d96a6b0faaad21196a08e926817fe08070b7ba717fbcd99eaffa624aeccf` | 5.46.0 |

The release key's minisign public key line is
`RWQZ6MDGT7XfiNw30FMcGZ/sL1IZFaHr+f7So4QAvmFg77qt3/Fcr2Ka`. Each key id is derived
from the key itself: it is the first 8 bytes of the fingerprint (shown
byte-reversed for the release key, the way minisign shows ids).

**Check the key against a second source.** The values above are published in
this repository, so on their own they are only as trustworthy as the repository
and the account behind it. The same key ids are published on a page the project
controls outside GitHub: <https://apps.ruchir.pw/keys/opa-compliance-wizard>
(plain text: `/keys/opa-compliance-wizard.txt`). Before a first install, check
that the key id there matches the one here and in the installer's output. If
they differ, stop and report it privately.

### How to verify a release

Download the release file (`ocw-X.Y.Z.tar.gz`) and its signature
(`ocw-X.Y.Z.tar.gz.minisig`), then either:

```bash
# the project's own verifier (Python standard library, works offline)
python -m server.updater.verify ocw-X.Y.Z.tar.gz ocw-X.Y.Z.tar.gz.minisig --installed-version none

# or the reference tool, with the minisign line above (-H: prehashed signatures)
minisign -Vm ocw-X.Y.Z.tar.gz -P RWQZ6MDGT7XfiNw30FMcGZ/sL1IZFaHr+f7So4QAvmFg77qt3/Fcr2Ka -H
```

The project's verifier also checks the version, the file name, the manifest of
every file inside and that the key is a current release key; prefer it. The
same minisign check works for `get-ocw.sh` and `get-ocw.sh.minisig`. The
updater and `get-ocw.sh` run this verification for you before anything is
unpacked or installed. More detail: README, "Verify a download by hand".

### If a signing key is compromised

If the release key is lost or stolen, the maintainer signs a `revocation.json`
with the standby key that revokes it and installs a new release key, and
publishes a security advisory. It is published as an asset of a GitHub release
(`revocation`, or `revocation-<serial>` for later ones) and, optionally, at an
owner-controlled static URL (`OPA_REVOCATION_URL`), so one outage or one
compromised account cannot hide it. A server with the update check on applies
it by itself; otherwise apply it by hand (README, "If the signing key is
compromised"; maintainers: [docs/releasing.md](docs/releasing.md), "If the
release key is compromised"). If you think your own copy of the keys is wrong,
compare the key ids with the advisory over a second channel before applying
anything. A stolen standby key is as serious as a stolen release key and has no
automatic recovery: the advisory would tell you to re-pin a new key by hand.

### Documented residual: installed Python packages

The signed manifest covers every file of the release, but **not the Python
packages installed into the release's virtual environment.** They are
installed with `pip --require-hashes` from the signed lock file, the release
tree is owned by root and read-only to the application, and the root-run
updater never runs the application's Python. A re-check of the installed
packages against their pip `RECORD` hashes after installation is planned for
5.54.0.

## Evidence packages

Limits are described when the feature ships (5.53.0).

## Supported versions

This project ships one actively-maintained line — only the latest
released version receives fixes. There is no long-term-support branch.
Please update to the latest version before reporting an issue, in case
it's already fixed.
