# Verifying releases

You do not have to do anything on this page to install the tool: the installers and the upgrade commands check every signature
for you. This page is for people who want to check a download **by hand**, want to know exactly what they are trusting, or need to
handle a signing-key problem.

## What is signed, and what you trust

Every release has two files that matter: `ocw-<version>.tar.gz` (the code and the finished web pages) and
`ocw-<version>.tar.gz.minisig` (its signature). Inside the tarball a `manifest.json` lists the checksum of every file. Servers also
use `get-ocw.sh` (the one-line installer) and its own `get-ocw.sh.minisig`.

The signing key is held in a cloud key service, and no GitHub credential can use it. A second, different key held at another cloud
provider can only sign a *revocation*: a notice that the main key must no longer be trusted.

When you run the one-line installer, you trust two things:

1. **`get-ocw.sh` itself**, which you fetch over HTTPS from the project's GitHub release. Everything after it is checked against the
   signing key. To avoid depending on GitHub's account for this first file, verify it before you run it (next section).
2. **Your distribution's packages** (signed by your distribution) and the Python packages, which are installed with
   `pip --require-hashes` from the hash-pinned list inside the signed release.

No independent third-party audit of this installer or the project has been performed.

## Check `get-ocw.sh` before running it

You need [minisign](https://jedisct1.github.io/minisign/) (`sudo apt-get install minisign` on recent Debian and Ubuntu).

```bash
curl -fsSLO https://github.com/ItsGambit/opa-compliance-wizard/releases/latest/download/get-ocw.sh
curl -fsSLO https://github.com/ItsGambit/opa-compliance-wizard/releases/latest/download/get-ocw.sh.minisig
minisign -Vm get-ocw.sh -P RWQZ6MDGT7XfiNw30FMcGZ/sL1IZFaHr+f7So4QAvmFg77qt3/Fcr2Ka -H
less get-ocw.sh
sudo bash get-ocw.sh
```

The release key's id is `88DFB54FC6C0E819`, and the `-P` value above is its minisign public key. The `-H` flag is needed because the
project signs a prehashed form. `minisign` should print `Signature and comment signature verified`.

That key line is published in the same repository as the script, so by itself it only proves the file matches what GitHub holds.
To check it independently, compare the key id with the one published on a page the project controls outside GitHub:
<https://apps.ruchir.pw/keys/opa-compliance-wizard> (plain text: `/keys/opa-compliance-wizard.txt`). If they differ, **stop** and
report it privately ([SECURITY.md](../SECURITY.md)).

## Check a release tarball by hand

With this project's own verifier (no extra software, works offline; run it from an install folder, using that install's Python):

```bash
python -m server.updater.verify ocw-5.53.0.tar.gz ocw-5.53.0.tar.gz.minisig --installed-version none
```

It prints one `OK` line per fact (signature, version, hashes), or `ERROR:` and what to do. On a server with the upgrade layout,
`sudo ocw-updater stage <file>` does the same check and more.

With the reference tool minisign, using the same public key line as above:

```bash
minisign -Vm ocw-5.53.0.tar.gz -P RWQZ6MDGT7XfiNw30FMcGZ/sL1IZFaHr+f7So4QAvmFg77qt3/Fcr2Ka -H
```

minisign checks the signature and the signed comment. The project's verifier additionally checks the version, the file name, the
manifest of every file inside, and that the key is a current release key. Prefer the project's verifier.
(In the repository, the minisign form of any key in `server/release_keys.json` is printed by `tools/release.py pubkey`.)

An evidence package's checking program has its own checksum, published with each release. See
[Evidence packages](evidence-package.md#what-to-send).

## If the signing key is compromised

The project holds two keys in different places: a **primary** that signs releases and a **standby** that can only sign a *revocation*.
If the primary is ever lost or stolen, the maintainers publish a signed `revocation.json` that revokes it and installs a new release
key (and, if needed, a new standby), with a link to a security advisory. It is published in two places: as an asset of a GitHub
release (`revocation`, or `revocation-<serial>` for later ones) and, optionally, at a static address the owner controls
(`OPA_REVOCATION_URL`), so one outage or one compromised account cannot hide it.

What you would see: a release signed by a key you do not know (*"signed by key ... which is not pinned ... apply the published
revocation"*), or by a key marked revoked (*"was revoked ... Do not install it"*). A revoked key's releases are refused, except the
ones the revocation names by version and file checksum as known good.

What to do:

1. **Online:** with the update check on, the server fetches and applies the revocation by itself (recorded in the Audit Log as
   `upgrade.key_revoked`). `get-ocw.sh`, `deploy.sh --release` and the computer upgrade also apply a published revocation before they
   verify. You do nothing.
2. **Offline:** on a trusted computer download `revocation.json` from the project's `revocation` release, copy it over, and run
   `python -m server.updater keys apply-revocation revocation.json` (on a server: `sudo ocw-updater trust apply revocation.json`), or put
   the file next to the release files for `--from-file` / `--from-dir`. It checks the standby key's signature and that the revocation
   is newer than any applied before. Then install the new release as usual.
3. **If you suspect your copy of the keys itself:** compare the key ids with the project's security advisory over a second channel
   before applying anything. If both keys were lost, the advisory tells you to re-pin a new key by hand: replace
   `server/release_keys.json` with the published list after checking its key ids through two independent channels.

Applying a revocation writes `release_keys.local.json` next to the app (kept across upgrades, owner-only). The install remembers every
key, its status and the highest revocation serial, so no later release can bring a revoked key back.

For what "revocation" means to the maintainers, and how it is made, see [Releasing](releasing.md).
