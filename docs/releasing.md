# Releasing (maintainers)

How a release is built, signed and published, and how the signing keys are kept and replaced. Everything runs on the
maintainer's own computer with `tools/release.py` (and, only in an emergency, `tools/revoke.py`); nothing signs in CI, and no
signing key exists as a file anywhere. Operators' side of this is the README's ["Upgrading"](../README.md#upgrading).

## Why there is a signature

A server that installs "whatever is on the default branch" inherits every force-push, stolen account and broken merge. A signed
release is installed only when its signature verifies against a key the server already trusts (`server/release_keys.json`,
shipped with every release and pinned on first install). The signature covers the tarball and a *trusted comment*
`file=… version=… sha256=… timestamp=…`; inside the tarball a `manifest.json` lists the sha256 of every file, including the built
frontend.

## Two keys, two clouds

| Key | Role | Algorithm | Signs | Lives in |
|---|---|---|---|---|
| **release** | day-to-day | Ed25519, minisign format | releases only | **AWS KMS** (key spec `ECC_NIST_EDWARDS25519`) |
| **standby** | emergency | ES256 (ECDSA P-256, SHA-256) | a *revocation* only | **Azure Key Vault** (EC P-256), a different provider and account |

Azure Key Vault has no Ed25519, so the standby is P-256; it signs one small envelope, so nothing is lost. Install-side rules (all
in `server/updater/keys.py`, all tested): the verifier dispatches on each key's `alg`; a `standby` key never verifies a release and
a `release` key never verifies a revocation; a key whose `alg` does not fit its role is refused when the list is read; a release
that changes any standby entry is refused; a retired or revoked key can never become active again (the install remembers).
Neither key ever exists as a file in production: there is nothing to copy, lose or leak, and the maintainer's computer holds no
secret at all.

**Verification never depends on how a signature was produced.** A release signature is an ordinary minisign `ED` file (Ed25519
over the 64-byte BLAKE2b-512 digest of the tarball, plus a signed trusted comment); a revocation is the `ocw-revocation/1`
envelope below. `server/updater` checks both with `cryptography`; no cloud SDK or `minisign` is needed on any server.

### The revocation envelope (`revocation.json`)

```json
{"format": "ocw-revocation/1",
 "payload": "<base64url of the UTF-8 JSON below>",
 "signatures": [{"key_id": "<standby key id>", "alg": "es256", "sig": "<base64url R||S, 64 bytes>"}]}
```
Payload: `{"serial": 3, "issued_at": "2026-…Z", "revoke": ["<key id>" | {"key_id": "…", "last_good_version": "5.47.0"}],
"add_keys": [<key list entries>], "reason": "…", "advisory_url": "https://…"}`. The signed value is
`SHA-256("ocw-revocation/1\n" || payload bytes)`; Key Vault signs a digest, so the tool computes it locally and Azure's `R||S`
answer is converted to DER by the verifier. `serial` must exceed the highest one the install has applied (replay and rollback
protection). At least one valid signature from an active standby is required (the schema allows more later).

## Key custody (setup, once)

Generic steps; use your own names and never write account ids, vault names or key ARNs into the repository.

**Release key, AWS KMS**
1. Create a single-Region KMS key: key spec `ECC_NIST_EDWARDS25519`, usage `SIGN_VERIFY`, deletion window 30 days. The
   algorithm used is `ED25519_SHA_512` with `MessageType: RAW`, which is **pure Ed25519** over the bytes given (RFC 8032); never
   use the `…_PH_…` variant and never pre-hash with SHA-512.
2. Signer identity: an IAM Identity Center permission set carrying only the signer policy, MFA required at every sign-in,
   session 1–4 hours. `tools/release.py sign --aws-profile <profile>` starts `aws sso login` when there is no valid session, so
   nothing secret is stored on the computer. (A long-lived IAM user key is a conscious downgrade: if you must, bind
   `kms:Sign` to `aws:MultiFactorAuthPresent` in the key policy and use short MFA sessions.)
3. Key policy: keep the account-root statement; give a separate administrator identity the administration actions **without**
   `kms:Sign`; give the signer only `kms:Sign`, `kms:GetPublicKey`, `kms:DescribeKey` on this key, conditioned on
   `kms:SigningAlgorithm = ED25519_SHA_512` and `kms:MessageType = RAW`; add an explicit deny for the signer on everything else
   (so no IAM policy can add `PutKeyPolicy`, `DisableKey`, `ScheduleKeyDeletion`, `CreateGrant`…).
4. Alert on **every** `Sign`, and on `PutKeyPolicy`, `DisableKey`, `ScheduleKeyDeletion`, `CreateGrant`, `CancelKeyDeletion`.
   `Sign` appears in CloudTrail as a read-only management event, so an EventBridge rule needs state
   `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS` (CLI or CloudFormation, not the console). Send alerts somewhere a
   compromised computer cannot delete (a phone number or a second mailbox). **A release makes exactly four `Sign` calls** (5.52.0: the
   file digest, then signature + trusted comment, for the tarball and again for `get-ocw.sh`); `release.py` prints their request ids for the release log. Any other `Sign`
   is an incident: disable the key and start the revocation procedure.

**Standby key, Azure Key Vault**
1. A dedicated vault in a dedicated resource group, RBAC permission model, soft delete with the maximum retention and
   **purge protection on**. An `EC` / `P-256` key with operations limited to `sign` and `verify`, no rotation, not exportable.
2. One identity only (the owner's own account): the data-plane role *Key Vault Crypto User*, or a custom role with just
   `keys/read` and `keys/sign/action`. **No service principal, no managed identity, no automation identity.** Nobody holds the
   purge-operator role.
3. Conditional Access requiring MFA for the signing tenant (the data plane is not covered by Azure's built-in mandatory MFA).
   After each use run `az logout`; in an incident sign from a clean computer (a compromised computer's token cache is itself a
   credential).
4. Alerts: diagnostic settings to a Log Analytics workspace and a log-search alert on `KeySign`, `KeyBackup`, `KeyUpdate`,
   `KeyDelete`, `KeyPurge`, `KeyRestore`, `VaultDelete`, `VaultPatch`, plus an Activity Log alert on role assignment writes. The
   expected number of `KeySign` events is **zero** outside a revocation (or a drill).

**Pin the public keys** (public information; run once each):
```bash
python tools/release.py pubkey --aws-kms <key id, ARN or alias> --aws-profile <profile> --out release-key.json
python tools/release.py pubkey --azure https://<vault>/keys/<name>/<version> --out standby-key.json
```
Each prints the key-list entry (`key_id`, `alg`, `public_key`, `role`, `status`, `since`); put both into the `"keys"` of
`server/release_keys.json` and commit. A KMS key's id is derived from the key itself (first 8 bytes of SHA-256 of the raw public key,
shown the way minisign shows ids), so it is the same on every computer. The two key ids and fingerprints are recorded in `SECURITY.md`; update that table in the same commit whenever the key list changes.

**Standby drill** (before the first release, and whenever `tools/revoke.py` or the verifier changes): sign a test revocation
against a scratch install (a clone with a copy of the key list and a throwaway release), confirm that install now refuses a
release signed by the revoked test key and accepts one from the new key, then discard it.

## Releasing a version

Prerequisites on the releasing computer: Python 3.9+, git, Node.js 20.19+/22.12+ with npm, the AWS CLI v2, `pip install boto3`, and
(recommended) the official [`minisign`](https://jedisct1.github.io/minisign/) program for the interop check. Windows works
the same way from PowerShell.

```bash
# 1. Finish the change: bump the version in create_secret_folders.py (header "# Version" and SCRIPT_VERSION),
#    write the CHANGELOG entry, run the full test suite (pytest, and in frontend/: npx tsc -b, npm run lint, npm test).
git commit … && git tag v5.47.0              # releases are built from the TAG only
python tools/release.py build 5.47.0         # -> release-out/ocw-5.47.0.tar.gz + manifest.json
python tools/release.py sign release-out/ocw-5.47.0.tar.gz --signer kms --kms-key <key id or alias> \
       --aws-profile <profile> --require-minisign
```

`build` exports the tag (never your working tree), builds the frontend from it (`npm ci --ignore-scripts`, `vite build`), writes
`manifest.json` (version, commit, build time, `min_upgrade_from`, per-file sha256, changelog excerpt, downtime estimate) and a
reproducible `.tar.gz`. `sign` makes the four KMS calls (two for the tarball, two for `get-ocw.sh`), writes `ocw-5.47.0.tar.gz.minisig` and `get-ocw.sh.minisig` (trusted comment capped at 4000 bytes),
and then **verifies its own output** with the app's verifier against `server/release_keys.json` and, with `--require-minisign`, with
`minisign -V -H`; it deletes the signature and stops if either refuses. Check that the alert mailbox received exactly four Sign
notifications before you publish. Then:

1. On GitHub create the release for tag `v5.47.0` as a **draft**, attach exactly the five files `release.py sign` lists: `ocw-5.47.0.tar.gz`,
   `ocw-5.47.0.tar.gz.minisig`, `manifest.json`, `get-ocw.sh` and `get-ocw.sh.minisig` (5.52.0: the one-line installer, below), paste the
   CHANGELOG entry, then publish.
2. Enable **immutable releases** in the repository settings (once): a published release's assets and tag can no longer change.
   Create the release tagged `revocation` now (marked *pre-release* so it is never "latest"); **do not** make that one immutable:
   its `revocation.json` asset is replaced when a revocation is published.
3. Verify like a user would: download the five files from the published release and run
   `python tools/release.py verify ocw-5.47.0.tar.gz ocw-5.47.0.tar.gz.minisig --bootstrap get-ocw.sh --bootstrap-sig get-ocw.sh.minisig`, and
   `minisign -Vm get-ocw.sh -P <the release key's minisign line> -H` (see the README). The first re-renders `get-ocw.sh` from the
   tarball's own template, verifier and key list and compares it byte for byte, so a script that is not what the release produces is caught.
3a. **Publish the evidence package verifier's sha256** (5.53.0). `release.py build` writes it into `manifest.json` (field
   `verifier_sha256`, signed with the release) and into the manifest's changelog excerpt, and prints a ready-to-paste line. The
   GitHub release notes are written by hand, so paste that line into them, and put the same value on the project's signing-key page
   (the page the README and SECURITY.md name). Auditors compare a package's verifier with it.
4. Never reuse a version number. A bad release is superseded by the next patch (and its notes say so).
5. **`get-ocw.sh`, the one-line installer (5.52.0).** `release.py build` renders it next to the tarball, from the **tagged**
   `server/get-ocw.sh.in`, `server/updater/root/ocw_crypto.py`, `ocw_trust.py`, `ocw_bootstrap_verify.py` and `server/release_keys.json`
   (the verifier and the key list are embedded byte for byte; a test compares them with the sources), and lists its sha256 in the manifest
   as `bootstrap_sha256`. The render is deterministic, so anyone can rebuild it from the tag. `release.py sign` signs it with the release key
   (trusted comment `file=get-ocw.sh version=<v> sha256=<hex>`), checks first that it is exactly what the tarball renders, and verifies
   its own output. Users get it from `https://github.com/<repo>/releases/latest/download/get-ocw.sh`, which GitHub resolves to the newest
   release that is not a pre-release: never mark a release you do not want installed by default as the latest. A bootstrap kept from an
   older release refuses a release signed by a key it does not know and says to download the current `get-ocw.sh`.
   **Go-live items** (owner actions, not code): create the release tagged `revocation` (step 2: today it does not exist, and without it
   the installer's revocation check finds nothing to apply); publish the release key id `88DFB54FC6C0E819` and its minisign line on a page
   GitHub's account does not control (the README says to compare the key id with it); immutable releases on; hardware-key 2FA on the
   GitHub account.
6. **The offline bundle (5.49.0).** After signing, build the air-gapped bundle and attach it (and its `.sha256`) to the same release:
   ```bash
   python tools/release.py build-offline release-out/ocw-5.47.0.tar.gz        # -> release-out/ocw-5.47.0-offline.tar.gz (+ .sha256)
   # narrow it while testing:  --python 3.12 --platform linux-x86_64
   ```
   It checks the signature first (so sign before building it), then runs `pip download --no-deps --only-binary=:all: --require-hashes` once per Python
   (3.9 to 3.14) and platform (linux x86-64/aarch64, macOS arm64, Windows amd64; `macos-x86_64` is left out by default because the pinned `cryptography` has no wheel for it, and `--platform macos-x86_64` still tries) with the packages that `requirements.lock`'s environment markers
   select for that target, **requires every downloaded wheel to match a hash recorded in the signed lock** (anything else stops the build), and packs the
   release, its signature, `offline.json` and the wheels. This is the only step that needs the internet (PyPI); a platform with no wheel for a locked package
   fails the build and names the package. Needs `packaging` (`pip install packaging`) on the releasing computer. Test it: unpack on a machine
   without network and run `python launch.py upgrade --from-file …`. A new platform or Python version goes into `OFFLINE_PYTHONS` / `OFFLINE_PLATFORMS` in
   `tools/release.py`. Regenerating `requirements.lock` means building a new bundle; there is nothing to sign separately.
7. **When an existing install must re-run `install.sh` (5.52.0).** The manifest's `install_sh_min_version` is the newest of (a) the
   `OCW_INSTALL_SH_REQUIRED_SINCE="X.Y.Z"` line near the top of `server/install.sh` and (b) the last release in which a systemd unit
   (`server/ocw-*.service|path|timer`) or `server/ocw-updater.sh` changed. A change to `install.sh` alone (a fresh-install-only
   addition, say) does **not** raise it, so existing installs are not asked to run `--refresh-updater` for nothing. **Bump the marker to
   the release version when an existing install needs the new install.sh** (a new unit setting it writes, a changed layout, a fix to
   what it does on a re-run). `release.py build` stops if the marker is missing, malformed or newer than the release being built.
8. **Prereleases.** Mark a release as a *pre-release* on GitHub to offer it only to installs on the prerelease channel (they use `GET /releases`; stable installs
   keep using `/releases/latest`, which never returns a prerelease). It is built and signed exactly like any release; the tag is still `vX.Y.Z`.

**First release only: the KMS interop test.** The byte format of KMS's Ed25519 `Sign` answer is not documented beyond "the signature";
it is expected to be the raw 64-byte RFC 8032 signature. Before cutting 5.46.0 sign a throwaway file with the real key through this
tool and confirm both the app's verifier and the official `minisign -V -H` accept it (`--require-minisign` does exactly this on every
release). The unit tests prove the plumbing with a fake KMS client and, where `minisign` is installed, against the official binary;
they cannot prove what the real service returns.

`--min-upgrade-from` (default 5.41.0) refuses starting points the release was not tested from; `--downtime-seconds` sets the estimate.
The manifest lists the release's real migrations, each with `since` and `rollback_safe`, read from `server/schema_migrations.json` (see "What the updater needs from a release" below).

### Changing dependencies

`requirements.txt` is the source of truth; `requirements.lock` (hash-pinned, installed with `pip install --require-hashes -r
requirements.lock`) is generated from it:
`uv pip compile requirements.txt --universal --generate-hashes --python-version 3.9 --no-header --no-annotate -o requirements.lock`, then
restore the comment header, and check it installs on the oldest supported Python (`python3.9 -m venv v && v/bin/pip install
--require-hashes -r requirements.lock`). Without `uv`, use `pip-compile --generate-hashes` per platform and merge with environment
markers.

## What the updater needs from a release (5.47.0)

* **Declare every schema migration.** `server/schema_migrations.json` lists each migration in `audit_store.MIGRATIONS` with the
  release it came in (`since`) and `rollback_safe`: whether the *previous* release's code still works on a database at that
  schema (true for added tables, columns and indexes; false for anything older code reads that was dropped or renamed).
  `tools/release.py build` refuses a release that has an undeclared migration and writes the list, `expected_schema_version`,
  `migration_time_estimate_seconds` and `activator_version` into `manifest.json`; the updater shows the unsafe ones before an upgrade
  is approved. `tests/test_migration_rollback_safety.py` keeps the file in step with the code and opens a database migrated by the new
  code with the previous release's `audit_store.py` (`tests/fixtures/previous_release/`). **Refresh that fixture when you release**
  (copy `audit_store.py` from the tag you are replacing): it is what an automatic code rollback runs.
* **The updater updates itself.** After a successful upgrade root copies `server/updater/root/*.py` and `server/nginx_bake.py` from the
  *verified* release over its own files (after a self-test of the new copy), so an upgrade always runs the previous release's
  updater. Changing those files is changing code that runs as root: review them as such.
* **The nginx template** (`server/nginx-opa-secrets-wizard.conf`) is baked with the live server's values and applied by the updater
  (`nginx -t` first, restored on failure). Keep the template's layout (the directives `server/nginx_bake.py` carries over).
* **The real-systemd test:** before releasing a version that touches the updater, the units or `install.sh`, run
  `tests/integration/updater-vm.sh` on a throwaway Debian VM (synthetic data and test-only keys; see its header). It is not part of CI.

## Routine key rotation (release key)

Done with the key still healthy (a new KMS key, a key reaching old age). The new key is introduced by a release signed by the **current**
one:

```bash
python tools/release.py pubkey --aws-kms <new key> --aws-profile <profile> --out new-key.json
python tools/release.py rotate --add-key new-key.json         # adds the entry (status active)
# commit server/release_keys.json, build + sign the next release with the OLD key, publish;
# every install that takes that release now also trusts the new key.
# in a LATER release, signed by the NEW key, retire the old one:
python tools/release.py rotate --retire <old key id>           # status retired
```

A release may add release keys and retire keys; it may not add or change a standby, redefine an entry, or bring a retired or revoked
key back; installs refuse a release whose list breaks these rules. A retired key no longer signs releases, so keep the old key out
of use once the new one has shipped. Rotating the **standby** is done by a revocation (below), never by a release.

## If the release key is compromised (or lost)

1. Disable the old KMS key's use immediately (deny `kms:Sign`), and decide which already-published releases you are certain were
   signed before the key was exposed. Those can stay installable on servers that are behind: you pin each one by its version and the
   sha256 of its published tarball (`sha256sum ocw-X.Y.Z.tar.gz`). A time or a version number inside a signature proves nothing, because
   whoever holds the stolen key writes it; only the digest of the exact file does. Pin nothing if in doubt: a revoked key then verifies
   no release at all.
2. Create the replacements: a new KMS key (the new release key) and, if the standby was ever online with the release key or you want to
   rotate it anyway, a new Key Vault key (the new standby). Export their entries with `pubkey --out`.
3. On a **clean computer**, signed in to the standby's Azure account with MFA, run the interactive tool (it refuses to run without a
   terminal and asks you to type `REVOKE`):
   ```bash
   python tools/revoke.py --azure-key https://<vault>/keys/<name>/<version> \
       --revoke <release key id> --known-good <release key id>:5.47.0:<sha256 of ocw-5.47.0.tar.gz> --revoke <old standby id> \
       --add-key new-release-key.json --add-key new-standby-key.json \
       --reason "release key exposed" --advisory-url https://<advisory link> --out release-out
   az logout
   ```
   (Leave out the old standby and the new standby to keep the standby as it is.) The tool signs the digest through Key Vault, runs the
   app's verifier on the result against the pinned keys, and refuses to write a file that installs would refuse. It writes
   `revocation.json` and `release_keys.next.json`.
4. Publish `revocation.json` in **both** places and publish the security advisory:
   - a GitHub release named for the serial, `revocation-<serial>` (for example `revocation-1`, marked pre-release): installs look for
     `revocation-<their applied serial + 1>` as well as the fixed `revocation` tag, because once immutable releases are on, a published
     tag can never be changed, so a fixed `revocation` tag can carry one file for ever. Use the fixed tag only for the first revocation
     if you left it mutable (step 2 of "Releasing a version"), and a new `revocation-<serial>` tag for every later one;
   - the **owner-controlled static URL** that operators set as `OPA_REVOCATION_URL` (a file you can replace at any time). **Before
     go-live** the maintainer must own this URL, serve it over https from a host that is not the repository's, and tell operators to set
     `OPA_REVOCATION_URL` (in `<install dir>/.deploy.conf` or the environment of the update check, and in `/etc/ocw-updater.env` for the
     staging step). Without it a second revocation has no distribution channel that does not depend on GitHub.
5. Copy `release_keys.next.json` over `server/release_keys.json`, commit, and release the next version **signed by the new release
   key** (its key list must be that file).
6. After it, the revoked key verifies **nothing** on a server that has applied the revocation, except the releases the revocation pins in
   `known_good` (checked by version and file digest, never by a time). A revocation made with the older `key:last_good_version` form is
   still understood but no longer trusts any release: pin the ones you want with `--known-good`.

**A stolen standby key is as serious as a stolen release key**, because whoever holds it can sign a revocation that installs keys of
their choosing. By design a release cannot replace the standby, so there is no automatic recovery from it. If the standby was exposed, or both
keys are lost, publish a security advisory with the new key ids and tell operators to re-pin by hand (README, "If the signing key is
compromised", step 3). Keep the standby's identity locked down and alerted for exactly this reason.

## What each audience sees

Maintainers: the tools' errors name what to do. Operators: every refusal is an `upgrade.verify_failed` Audit Log entry with a reason code;
key-list changes are `upgrade.key_list_installed` / `upgrade.key_revoked` / `upgrade.key_added` / `upgrade.key_revocation_rejected`.
