#!/usr/bin/env python3
"""Maintainer tool: build, sign and verify a release; print and rotate public keys.

Runs on the MAINTAINER's computer (macOS, Linux or Windows with Python 3.9+, git
and Node 20.19+/22.12+). It is never run on a server and nothing in the app
calls it.

    release.py build <version> [--out DIR] [--repo DIR]
    release.py sign <ocw-version.tar.gz> --signer kms --kms-key K [--aws-profile P]
    release.py verify <ocw-version.tar.gz> <ocw-version.tar.gz.minisig> [...]
    release.py pubkey --aws-kms <key id|arn|alias> | --azure <key id URL> [--out entry.json]
    release.py rotate [--add-key entry.json] [--retire <key id>]

Where the keys live (decision, 5.46.0). No key is ever a file on this computer.
The release (primary) key is an AWS KMS Ed25519 key; `sign --signer kms` calls
KMS Sign with ED25519_SHA_512 and MessageType RAW (pure Ed25519) twice per
release: once over the file's BLAKE2b-512 digest, once over signature + trusted
comment. With `--aws-profile` the tool first makes sure there is a valid MFA-
backed IAM Identity Center session (it runs `aws sso login` if not), so nothing
secret is stored here. The standby key (Azure Key Vault, ES256) signs
revocations only and is used by tools/revoke.py, never from here.
boto3 is an optional dependency of THESE TOOLS ONLY, never of the app.

Every signature this tool produces is checked before it prints anything: by the
app's own verifier (server/updater/verify.py) against server/release_keys.json,
and, when the official `minisign` program is installed, by `minisign -V -H` too.
A failure deletes nothing but stops with an error and no upload list.
"""

import argparse
import base64
import datetime
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import signing_backends as sb  # noqa: E402
from signing_backends import AwsKmsBackend, AzureKeyVaultSigner, RawSignerBackend, ReleaseError  # noqa: E402,F401
from server.updater import keys as keylib  # noqa: E402
from server.updater import minisign  # noqa: E402
from server.updater import verify as verifylib  # noqa: E402

DEFAULT_MIN_UPGRADE_FROM = "5.41.0"  # first release with deploy.sh handoff protocol 2
DEFAULT_DOWNTIME_SECONDS = 60
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _run(cmd, cwd=None, capture=True, check=True):
    try:
        proc = subprocess.run(cmd, cwd=cwd, capture_output=capture, text=capture, check=False)
    except FileNotFoundError:
        raise ReleaseError(f"required program not found: {cmd[0]}")
    if check and proc.returncode != 0:
        detail = (proc.stderr or "").strip() if capture else ""
        raise ReleaseError(f"{' '.join(cmd[:3])} failed (exit {proc.returncode}){': ' + detail if detail else ''}")
    return proc


# --- build ----------------------------------------------------------------


def _git(repo, *args, binary=False):
    proc = subprocess.run(["git", "-C", str(repo), *args], capture_output=True)
    if proc.returncode != 0:
        raise ReleaseError(f"git {' '.join(args[:2])} failed: {proc.stderr.decode(errors='replace').strip()}")
    return proc.stdout if binary else proc.stdout.decode().strip()


def changelog_excerpt(text, version, limit=2000):
    """The version's heading line and summary paragraph (up to its first bullet)."""
    lines = text.splitlines()
    start = next((i for i, ln in enumerate(lines) if re.match(rf"^{re.escape(version)} — ", ln)), None)
    if start is None:
        raise ReleaseError(f"CHANGELOG.md has no entry starting '{version} — '. Write it before building.")
    out = [lines[start]]
    for ln in lines[start + 1:]:
        if re.match(r"^\d+\.\d+\.\d+ — ", ln) or ln.startswith("- "):
            break
        out.append(ln)
    return "\n".join(out).strip()[:limit]


def _collect_tag_files(repo, tag):
    """(path -> (mode, bytes)) of every regular file at the tag. Symlinks refused."""
    raw = _git(repo, "archive", "--format=tar", tag, binary=True)
    files = {}
    with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
        for m in tar:
            if m.isdir():
                continue
            if not m.isreg():
                raise ReleaseError(f"{m.name} is a link or special file; releases carry regular files only")
            files[m.name] = (0o755 if m.mode & 0o100 else 0o644, tar.extractfile(m).read())
    return files


def _build_frontend(files):
    """npm ci + vite build from the TAGGED sources, in a scratch directory."""
    with tempfile.TemporaryDirectory(prefix="ocw-frontend-") as tmp:
        for name, (_mode, data) in files.items():
            if name.startswith("frontend/"):
                dest = Path(tmp) / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(data)
        fe = Path(tmp) / "frontend"
        npm = shutil.which("npm") or "npm"
        npx = shutil.which("npx") or "npx"
        print("==> npm ci --ignore-scripts")
        _run([npm, "ci", "--ignore-scripts", "--silent"], cwd=fe, capture=False)
        print("==> vite build")
        _run([npx, "vite", "build", "--outDir", "dist"], cwd=fe, capture=False)
        return _read_dist(fe / "dist")


def _read_dist(dist):
    dist = Path(dist)
    if not (dist / "index.html").is_file():
        raise ReleaseError(f"{dist} has no index.html; the frontend build is missing")
    out = {}
    for p in sorted(dist.rglob("*")):
        if p.is_file():
            out["frontend/dist/" + p.relative_to(dist).as_posix()] = (0o644, p.read_bytes())
    return out


def _migrations_from(files):
    """([{version, since, rollback_safe}], highest migration) from the tagged audit_store.py and
    server/schema_migrations.json. A tree without audit_store.py (a test fixture) has none; a real one must declare every
    migration, so a release cannot ship a migration nobody judged for rollback safety."""
    store = files.get("audit_store.py")
    if store is None:
        return [], None
    text = store[1].decode("utf-8")
    block = re.search(r"^MIGRATIONS = \{(.*?)^\}", text, re.M | re.S)
    numbers = sorted(int(n) for n in re.findall(r"^\s*(\d+):\s*_migration_", block.group(1), re.M)) if block else []
    if not numbers:
        raise ReleaseError("cannot read MIGRATIONS from audit_store.py")
    decl = files.get("server/schema_migrations.json")
    if decl is None:
        raise ReleaseError("server/schema_migrations.json is missing (it declares each migration's rollback_safe flag)")
    declared = json.loads(decl[1].decode("utf-8")).get("migrations", {})
    missing = [n for n in numbers if str(n) not in declared]
    if missing:
        raise ReleaseError(f"server/schema_migrations.json does not declare migration(s) {missing}: decide rollback_safe for each")
    return ([{"version": n, "since": declared[str(n)]["since"], "rollback_safe": bool(declared[str(n)]["rollback_safe"])} for n in numbers],
            numbers[-1])


def _activator_version(files):
    m = files.get("server/updater/root/ocw_activate.py")
    found = re.search(rb'^ACTIVATOR_VERSION = "([^"]+)"', m[1], re.M) if m else None
    return found.group(1).decode() if found else None


def build_release(version, repo=REPO, out_dir=None, frontend_dist=None, min_upgrade_from=DEFAULT_MIN_UPGRADE_FROM,
                  downtime_seconds=DEFAULT_DOWNTIME_SECONDS, built_at=None):
    if not VERSION_RE.match(version):
        raise ReleaseError("version must look like 5.46.0")
    tag = f"v{version}"
    try:
        commit = _git(repo, "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}")
    except ReleaseError:
        raise ReleaseError(f"tag {tag} does not exist. Commit, then `git tag {tag}`; releases are built from the tag only.")
    files = _collect_tag_files(repo, tag)
    engine = files.get("create_secret_folders.py")
    m = re.search(rb'^SCRIPT_VERSION = "([^"]+)"', engine[1], re.M) if engine else None
    if not m or m.group(1).decode() != version:
        raise ReleaseError(f"{tag} has SCRIPT_VERSION {m.group(1).decode() if m else 'missing'}, not {version}")
    if "server/release_keys.json" not in files:
        raise ReleaseError(f"{tag} has no server/release_keys.json")
    keylib.parse_key_list_bytes(files["server/release_keys.json"][1])  # must be a valid list
    excerpt = changelog_excerpt(files["CHANGELOG.md"][1].decode("utf-8"), version)
    if any(n.startswith("frontend/dist/") for n in files):
        raise ReleaseError("frontend/dist is tracked in git; it must not be (it is built into the release)")
    dist = _read_dist(frontend_dist) if frontend_dist else _build_frontend(files)
    files.update(dist)
    lock = files.get("frontend/package-lock.json")
    migrations, expected_schema = _migrations_from(files)
    activator_version = _activator_version(files)
    manifest = {
        "schema": 1,
        "version": version,
        "commit": commit,
        "built_at": built_at or now_utc(),
        "min_upgrade_from": min_upgrade_from,
        "downtime_estimate_seconds": downtime_seconds,
        # Every schema migration this release's code knows (audit_store.MIGRATIONS), with the rollback_safe flag the
        # maintainers record in server/schema_migrations.json; the updater shows the ones above the installed schema.
        "migrations": migrations,
        "expected_schema_version": expected_schema,
        "migration_time_estimate_seconds": 30,
        # The updater compares the baked template with the live site itself, so this is always true: it only means
        # "check", and a release that does not change nginx leaves the site untouched.
        "nginx_template_changed": True,
        "requires_reboot": False,
        "activator_version": activator_version,
        "frontend_lock_sha256": hashlib.sha256(lock[1]).hexdigest() if lock else None,
        "changelog_excerpt": excerpt,
        "files": {name: hashlib.sha256(data).hexdigest() for name, (_m, data) in sorted(files.items())},
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    commit_time = int(_git(repo, "show", "-s", "--format=%ct", commit))
    out_dir = Path(out_dir or "release-out")
    out_dir.mkdir(parents=True, exist_ok=True)
    tar_path = out_dir / f"ocw-{version}.tar.gz"
    with open(tar_path, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as gz, \
            tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for name, (mode, data) in sorted({**files, "manifest.json": (0o644, manifest_bytes)}.items()):
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(data), mode, commit_time
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(data))
    (out_dir / "manifest.json").write_bytes(manifest_bytes)
    return tar_path, manifest


def cmd_build(a):
    tar_path, manifest = build_release(a.version, Path(a.repo), a.out, a.frontend_dist, a.min_upgrade_from, a.downtime_seconds)
    print(f"Built {tar_path} ({len(manifest['files'])} files, commit {manifest['commit'][:12]})")
    print(f"Next: release.py sign {tar_path} --key <primary.key>")


# --- sign / verify ---------------------------------------------------------------


def make_signer(a):
    if a.signer != "kms":
        raise ReleaseError("choose --signer kms (production keys live in AWS KMS; there is no local-key signer)")
    if not a.kms_key:
        raise ReleaseError("--signer kms needs --kms-key <key id, ARN or alias>")
    return AwsKmsBackend(a.kms_key, profile=a.aws_profile)


def interop_check(tar_path, sig_path, entry, mini, required):
    """Verify with the official minisign program when it is available."""
    mini = mini or os.environ.get("OPA_MINISIGN") or shutil.which("minisign")
    if not mini:
        if required:
            raise ReleaseError("--require-minisign: the official minisign program was not found on PATH")
        print("NOTE: the official minisign program is not installed, so the interop check was skipped. It is REQUIRED "
              "before the first release (docs/releasing.md).")
        return
    raw = base64.b64decode(entry["public_key"])
    stored = bytes.fromhex(entry["key_id"])[::-1]
    line = base64.b64encode(b"Ed" + stored + raw).decode()
    proc = subprocess.run([mini, "-V", "-H", "-q", "-m", str(tar_path), "-x", str(sig_path), "-P", line], capture_output=True, text=True)
    if proc.returncode != 0:
        raise ReleaseError("the official minisign program REJECTS this signature: " + (proc.stderr or proc.stdout).strip() +
                           "\nDo not upload it. (A KMS signature that fails here is not plain Ed25519.)")
    print("OK  the official minisign program verifies the signature too")


def sign_release_file(tar_path, signer, keys_path, mini=None, require_minisign=False):
    tar_path = Path(tar_path)
    _prehash, sha256, _ = minisign.hash_file(tar_path)
    with tarfile.open(tar_path, "r:gz") as tar:
        manifest = json.loads(tar.extractfile("manifest.json").read())
    version, built_at = manifest["version"], manifest.get("built_at")
    if tar_path.name != f"ocw-{version}.tar.gz":
        raise ReleaseError(f"file name must be ocw-{version}.tar.gz (it is {tar_path.name})")
    comment = f"file={tar_path.name} version={version} sha256={sha256}" + (f" timestamp={built_at}" if built_at else "")
    sig_path = Path(str(tar_path) + ".minisig")
    signer.sign_file(tar_path, comment, sig_path)
    eff = keylib.effective_from(keylib.load_key_list(keys_path))
    try:
        info = verifylib.verify_release(tar_path, sig_path, eff, None)
    except (verifylib.VerifyError, keylib.KeyListError) as exc:
        sig_path.unlink(missing_ok=True)
        raise ReleaseError(f"the signature was made but does NOT verify against {keys_path}: {exc}\n"
                           "Pin this key (role release) in server/release_keys.json, release it, and sign again. "
                           "The bad signature file was removed; do not upload anything.")
    entry = next(k for k in eff["keys"] if k["key_id"] == info.key_id)
    interop_check(tar_path, sig_path, entry, mini, require_minisign)
    return sig_path, info


def cmd_sign(a):
    tar_path = Path(a.tarball)
    signer = make_signer(a)
    keys_path = Path(a.keys or REPO / "server" / "release_keys.json")
    sig_path, info = sign_release_file(tar_path, signer, keys_path, a.minisign, a.require_minisign)
    print(f"Signed and self-verified with key {info.key_id}.")
    ids = [i for i in getattr(signer, "request_ids", []) if i]
    if ids:
        print("KMS Sign request ids (expect exactly two; keep them in the release log): " + ", ".join(ids))
    print("Upload these three files to the GitHub release for tag v" + info.version + ":")
    for p in (tar_path, sig_path, tar_path.parent / "manifest.json"):
        print(f"  {p}")


def cmd_verify(a):
    argv = [a.tarball, a.minisig]
    if a.keys:
        argv += ["--keys", a.keys]
    if a.installed_version:
        argv += ["--installed-version", a.installed_version]
    return verifylib.main(argv)


# --- public keys / rotation ------------------------------------------------------


def cmd_pubkey(a):
    """Print the pinned-format entry of a KMS / Key Vault key."""
    if bool(a.aws_kms) == bool(a.azure):
        raise ReleaseError("give exactly one of --aws-kms <key> or --azure <key identifier URL>")
    entry = (AwsKmsBackend(a.aws_kms, profile=a.aws_profile, since=a.since).entry if a.aws_kms
             else AzureKeyVaultSigner(a.azure, since=a.since).entry)
    print("Paste into the \"keys\" list of server/release_keys.json (public information):")
    print(json.dumps(entry, indent=2))
    print(f"\nKey id: {entry['key_id']}   role: {entry['role']}   alg: {entry['alg']}")
    if entry["alg"] == "ed25519-minisign":
        line = base64.b64encode(b"Ed" + bytes.fromhex(entry["key_id"])[::-1] + base64.b64decode(entry["public_key"])).decode()
        print(f"minisign public key (for `minisign -Vm FILE -P KEY -H`): {line}")
    if a.out:
        Path(a.out).write_text(json.dumps(entry, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote the entry to {a.out}")


def cmd_rotate(a):
    """Routine rotation: add a new release key and/or retire one in the key list
    the NEXT release carries. The current release key signs that release."""
    if not a.add_key and not a.retire:
        raise ReleaseError("give --add-key <entry.json> (from `pubkey --out`) and/or --retire <key id>")
    path = Path(a.keys)
    current = keylib.load_key_list(path)
    new = json.loads(json.dumps(current))
    if a.add_key:
        entry = json.loads(Path(a.add_key).read_text(encoding="utf-8"))
        new["keys"].append(entry)
    for key_id in a.retire or []:
        for k in new["keys"]:
            if k["key_id"] == key_id:
                k["status"] = "retired"
                break
        else:
            raise ReleaseError(f"{key_id} is not in {path}")
    new = keylib.validate_key_list(new)
    try:
        keylib.check_adoption(keylib.effective_from(current), new)
    except keylib.KeyListError as exc:
        raise ReleaseError(f"that change is not permitted for a release: {exc}")
    path.write_text(json.dumps(new, indent=2) + "\n", encoding="utf-8")
    print(f"Updated {path}. Review the diff, commit it, and build the next release;")
    print("sign that release with the CURRENT release key. Retire the old key only in a LATER release signed by the new one.")
    print("(Standby keys can only be changed by a revocation: tools/revoke.py.)")


def build_parser():
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--minisign", help="path to the official minisign program for the interop check (default: PATH)")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("build")
    s.add_argument("version")
    s.add_argument("--repo", default=str(REPO))
    s.add_argument("--out", default="release-out")
    s.add_argument("--frontend-dist", help="use an already built dist/ (testing); default builds from the tag")
    s.add_argument("--min-upgrade-from", default=DEFAULT_MIN_UPGRADE_FROM)
    s.add_argument("--downtime-seconds", type=int, default=DEFAULT_DOWNTIME_SECONDS)
    s.set_defaults(fn=cmd_build)
    s = sub.add_parser("sign")
    s.add_argument("tarball")
    s.add_argument("--signer", choices=("kms",), default="kms")
    s.add_argument("--kms-key", help="AWS KMS key id, ARN or alias")
    s.add_argument("--aws-profile", help="IAM Identity Center profile (MFA session; `aws sso login` is run if needed)")
    s.add_argument("--keys", help="key list to self-verify against (default server/release_keys.json)")
    s.add_argument("--require-minisign", action="store_true", help="fail if the official minisign program is not available")
    s.set_defaults(fn=cmd_sign)
    s = sub.add_parser("verify")
    s.add_argument("tarball")
    s.add_argument("minisig")
    s.add_argument("--keys")
    s.add_argument("--installed-version")
    s.set_defaults(fn=cmd_verify)
    s = sub.add_parser("pubkey")
    s.add_argument("--aws-kms", metavar="KEY", help="AWS KMS key id, ARN or alias (the release key)")
    s.add_argument("--azure", metavar="KEY_URL", help="Azure Key Vault key identifier URL (the standby)")
    s.add_argument("--aws-profile")
    s.add_argument("--since", help="release version the key is valid from (default: the current version)")
    s.add_argument("--out", help="also write the entry JSON to this file")
    s.set_defaults(fn=cmd_pubkey)
    s = sub.add_parser("rotate")
    s.add_argument("--add-key", help="entry JSON file of the new release key (from `pubkey --out`)")
    s.add_argument("--retire", action="append", help="key id to retire (use in a LATER release)")
    s.add_argument("--keys", default=str(REPO / "server" / "release_keys.json"))
    s.set_defaults(fn=cmd_rotate)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args) or 0
    except (ReleaseError, keylib.KeyListError, minisign.SignatureError, verifylib.VerifyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except (OSError, tarfile.TarError, KeyError, ValueError) as exc:
        print(f"ERROR: {getattr(exc, 'strerror', None) or exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
