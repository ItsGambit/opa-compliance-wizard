#!/usr/bin/env python3
"""Maintainer tool: build, sign and verify a release; print and rotate public keys.

Runs on the MAINTAINER's computer (macOS, Linux or Windows with Python 3.9+, git
and Node 20.19+/22.12+). It is never run on a server and nothing in the app
calls it.

    release.py build <version> [--out DIR] [--repo DIR]
    release.py sign <ocw-version.tar.gz> --signer kms --kms-key K [--aws-profile P]
    release.py build-offline <ocw-version.tar.gz> [--out DIR] [--python 3.12 ...] [--platform linux-x86_64 ...]
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
from server.updater import offline as offlinelib  # noqa: E402

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
    """([{version, since, rollback_safe, description?}], highest migration) from the tagged audit_store.py and
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
    out = []
    for n in numbers:
        entry = {"version": n, "since": declared[str(n)]["since"], "rollback_safe": bool(declared[str(n)]["rollback_safe"])}
        text = declared[str(n)].get("description")
        if isinstance(text, str) and text.strip():
            entry["description"] = text.strip()[:200]   # shown on the Updates page; optional
        out.append(entry)
    return out, numbers[-1]


NGINX_TEMPLATE = "server/nginx-opa-secrets-wizard.conf"


def _previous_tag(repo, version):
    """The newest release tag below `version`, or None."""
    try:
        tags = _git(repo, "tag", "--list", "v*").split()
    except ReleaseError:
        return None
    below = []
    for t in tags:
        v = t[1:]
        if VERSION_RE.match(v) and tuple(map(int, v.split("."))) < tuple(map(int, version.split("."))):
            below.append((tuple(map(int, v.split("."))), t))
    return max(below)[1] if below else None


def _nginx_template_changed(repo, files, version):
    """True when this release's nginx template differs from the previous tag's (or there is no previous tag to compare
    with): only then does the updater touch the server's nginx site."""
    mine = files.get(NGINX_TEMPLATE)
    prev = _previous_tag(repo, version)
    if mine is None or prev is None:
        return mine is not None
    try:
        old = subprocess.run(["git", "-C", str(repo), "show", f"{prev}:{NGINX_TEMPLATE}"], capture_output=True, check=True).stdout
    except (subprocess.CalledProcessError, OSError):
        return True
    return old != mine[1]


INSTALL_SH_FILES = ("server/ocw-stage@.service", "server/ocw-upgrade.service", "server/ocw-upgrade.path", "server/ocw-upgrade-due.service",
                    "server/ocw-upgrade-due.timer", "server/ocw-updater.sh", "server/install.sh")


def _requires_install_sh(repo, files, version):
    """True when a unit, the wrapper or install.sh differs from the previous tag's: the updater cannot replace those itself
    (only the root-owned Python files self-update), so the operator must re-run server/install.sh from the new release."""
    prev = _previous_tag(repo, version)
    if prev is None:
        return any(n in files for n in INSTALL_SH_FILES)
    for name in INSTALL_SH_FILES:
        mine = files.get(name)
        try:
            old = subprocess.run(["git", "-C", str(repo), "show", f"{prev}:{name}"], capture_output=True, check=True).stdout
        except (subprocess.CalledProcessError, OSError):
            old = None
        if (mine[1] if mine else None) != old:
            return True
    return False


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
        # True only when this release's nginx template differs from the previous tag's. The updater still compares the
        # baked template with the live site itself and touches nginx only when they differ. `nginx_change_required` is for
        # the rare release that cannot work without the new site (then an unbakeable site refuses the upgrade).
        "nginx_template_changed": _nginx_template_changed(repo, files, version),
        "nginx_change_required": False,
        # The units, the wrapper and install.sh are not self-updated: when they changed the updater refuses and says to
        # run server/install.sh from the new release first.
        "requires_install_sh": _requires_install_sh(repo, files, version),
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


# --- offline bundle (5.49.0) ------------------------------------------------------------


# Python versions the project supports (CI runs 3.9, 3.12 and 3.14; README documents 3.9 and newer).
OFFLINE_PYTHONS = ("3.9", "3.10", "3.11", "3.12", "3.13", "3.14")
# Where an air-gapped computer can run it. `pip download` is given these platform tags explicitly, because it cannot
# probe a machine it is not running on. Linux wheels need glibc 2.17-2.34 depending on the package (cryptography now
# ships manylinux_2_28); Alpine/musl is not covered.
OFFLINE_PLATFORMS = {
    "linux-x86_64": {"os_name": "posix", "platform_system": "Linux", "sys_platform": "linux", "platform_machine": "x86_64",
                     "tags": ["manylinux2014_x86_64", "manylinux_2_17_x86_64", "manylinux_2_28_x86_64", "manylinux_2_34_x86_64"]},
    "linux-aarch64": {"os_name": "posix", "platform_system": "Linux", "sys_platform": "linux", "platform_machine": "aarch64",
                      "tags": ["manylinux2014_aarch64", "manylinux_2_17_aarch64", "manylinux_2_28_aarch64", "manylinux_2_34_aarch64"]},
    "macos-arm64": {"os_name": "posix", "platform_system": "Darwin", "sys_platform": "darwin", "platform_machine": "arm64",
                    "tags": ["macosx_11_0_arm64", "macosx_12_0_arm64", "macosx_13_0_arm64", "macosx_14_0_arm64",
                             "macosx_10_13_universal2", "macosx_10_9_universal2", "macosx_11_0_universal2"]},
    "macos-x86_64": {"os_name": "posix", "platform_system": "Darwin", "sys_platform": "darwin", "platform_machine": "x86_64",
                     "tags": ["macosx_10_9_x86_64", "macosx_10_13_x86_64", "macosx_10_15_x86_64", "macosx_11_0_x86_64",
                              "macosx_10_13_universal2", "macosx_10_9_universal2", "macosx_11_0_universal2"]},
    "windows-amd64": {"os_name": "nt", "platform_system": "Windows", "sys_platform": "win32", "platform_machine": "AMD64",
                      "tags": ["win_amd64"]},
}


def _marker_class():
    try:
        from packaging.markers import Marker
        return Marker
    except ImportError:
        try:
            from pip._vendor.packaging.markers import Marker
            return Marker
        except ImportError:
            raise ReleaseError("build-offline needs the 'packaging' package (pip install packaging) to read requirements.lock markers")


def parse_lock(text):
    """requirements.lock (pip --generate-hashes format) -> [{name, version, marker, hashes}]."""
    joined = re.sub(r"\\\n\s*", " ", text)
    entries = []
    for line in joined.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        head, _, rest = line.partition(" --hash=")
        hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})", " --hash=" + rest) if rest else []
        spec, _, marker = head.partition(";")
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s]+)$", spec.strip())
        if not m:
            raise ReleaseError(f"requirements.lock has a line build-offline cannot read: {line[:80]!r}")
        if not hashes:
            raise ReleaseError(f"requirements.lock entry {m.group(1)} has no sha256 hashes; the lock must be hash-pinned")
        entries.append({"name": m.group(1), "version": m.group(2), "marker": marker.strip() or None, "hashes": hashes})
    if not entries:
        raise ReleaseError("requirements.lock lists no packages")
    return entries


def _norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def _marker_env(py, platform):
    spec = OFFLINE_PLATFORMS[platform]
    base = {"implementation_name": "cpython", "platform_python_implementation": "CPython", "python_version": py,
            "os_name": spec["os_name"], "platform_system": spec["platform_system"], "sys_platform": spec["sys_platform"],
            "platform_machine": spec["platform_machine"], "platform_release": "", "platform_version": ""}
    # python_full_version / implementation_version: the marker may split a minor version (>= 3.9.2); take the union of an
    # early and a late patch release so no package that could apply is left out. Extra wheels are harmless.
    return [dict(base, python_full_version=f"{py}.{micro}", implementation_version=f"{py}.{micro}") for micro in (0, 99)]


def entries_for(entries, py, platform):
    marker_cls = _marker_class()
    out = []
    for e in entries:
        if e["marker"] is None:
            out.append(e)
            continue
        marker = marker_cls(e["marker"])
        if any(marker.evaluate(env) for env in _marker_env(py, platform)):
            out.append(e)
    return out


def _wheel_project_version(filename):
    parts = filename[:-4].split("-")
    if len(parts) < 5:
        raise ReleaseError(f"{filename} is not a wheel file name")
    return _norm(parts[0]), parts[1]


def default_pip_runner(argv):
    proc = subprocess.run([sys.executable, "-m", "pip", *argv], capture_output=True, text=True)
    if proc.returncode != 0:
        raise ReleaseError("pip download failed: " + (proc.stderr or proc.stdout).strip()[-600:])


def build_offline(tar_path, out_dir=None, pythons=OFFLINE_PYTHONS, platforms=tuple(OFFLINE_PLATFORMS), keys_path=None,
                  runner=default_pip_runner):
    """Collect the hash-pinned wheels for `tar_path`'s requirements.lock and pack them with the signed release into
    ocw-<version>-offline.tar.gz. The release must already be signed (release.py sign): its signature is checked here
    against the pinned keys, and requirements.lock must be one of the files its signed manifest lists. `runner(argv)`
    runs `pip <argv>` (tests replace it; nothing else here touches the network)."""
    tar_path = Path(tar_path)
    sig_path = Path(str(tar_path) + ".minisig")
    if not sig_path.is_file():
        raise ReleaseError(f"{sig_path} is missing: sign the release first (release.py sign), then build the offline bundle")
    for py in pythons:
        if not re.match(r"^3\.\d{1,2}$", py):
            raise ReleaseError(f"--python must look like 3.12 (got {py!r})")
    for plat in platforms:
        if plat not in OFFLINE_PLATFORMS:
            raise ReleaseError(f"unknown platform {plat!r}; choose from {', '.join(OFFLINE_PLATFORMS)}")
    keys_path = Path(keys_path or REPO / "server" / "release_keys.json")
    eff = keylib.effective_from(keylib.load_key_list(keys_path))
    info = verifylib.verify_release(str(tar_path), str(sig_path), eff, None)
    version = info.version
    if tar_path.name != f"ocw-{version}.tar.gz":
        raise ReleaseError(f"file name must be ocw-{version}.tar.gz (it is {tar_path.name})")
    with tarfile.open(tar_path, "r:gz") as tar:
        lock_bytes = tar.extractfile("requirements.lock").read()
        manifest_bytes = tar.extractfile("manifest.json").read()
    lock_sha = hashlib.sha256(lock_bytes).hexdigest()
    if info.manifest["files"].get("requirements.lock") != lock_sha:
        raise ReleaseError("requirements.lock inside the release does not match its signed manifest")
    entries = parse_lock(lock_bytes.decode("utf-8"))
    out_dir = Path(out_dir or tar_path.parent)
    out_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ocw-offline-") as tmp:
        wheels = Path(tmp) / "wheels"
        wheels.mkdir()
        for py in pythons:
            for plat in platforms:
                chosen = entries_for(entries, py, plat)
                reqs = Path(tmp) / f"req-{py}-{plat}.txt"
                reqs.write_text("".join(f"{e['name']}=={e['version']} " + " ".join(f"--hash=sha256:{h}" for h in e["hashes"]) + "\n"
                                        for e in chosen), encoding="utf-8")
                print(f"==> pip download for Python {py}, {plat} ({len(chosen)} packages)")
                argv = ["download", "-q", "--no-deps", "--only-binary=:all:", "--require-hashes", "-r", str(reqs), "-d", str(wheels),
                        "--python-version", py, "--implementation", "cp"]
                for tag in OFFLINE_PLATFORMS[plat]["tags"]:
                    argv += ["--platform", tag]
                runner(argv)
        # Defence in depth: whatever pip left in the folder must be a wheel whose hash the signed lock records, and every
        # package any target needs must be present.
        allowed = {h: (_norm(e["name"]), e["version"]) for e in entries for h in e["hashes"]}
        listed = {}
        for f in sorted(wheels.iterdir()):
            if f.suffix != ".whl" or not offlinelib.WHEEL_RE.match(f.name):
                raise ReleaseError(f"unexpected file in the wheel folder: {f.name}")
            sha = hashlib.sha256(f.read_bytes()).hexdigest()
            if sha not in allowed:
                raise ReleaseError(f"{f.name} is not recorded in requirements.lock (sha256 {sha[:12]}…); refusing to bundle it")
            if allowed[sha] != _wheel_project_version(f.name):
                raise ReleaseError(f"{f.name} does not match the package its hash belongs to in requirements.lock")
            listed[f.name] = sha
        have = {_wheel_project_version(n) for n in listed}
        for py in pythons:
            for plat in platforms:
                for e in entries_for(entries, py, plat):
                    if (_norm(e["name"]), e["version"]) not in have:
                        raise ReleaseError(f"no wheel for {e['name']}=={e['version']} ({py}, {plat}) was collected")
        offline = {"schema": 1, "version": version, "requirements_lock_sha256": lock_sha, "python_versions": list(pythons),
                   "platforms": list(platforms), "wheels": listed,
                   "note": "Safety rests on requirements.lock (signed via the release manifest) and pip --require-hashes."}
        offline_bytes = (json.dumps(offline, indent=2, sort_keys=True) + "\n").encode()
        bundle = out_dir / f"ocw-{version}-offline.tar.gz"
        members = [(tar_path.name, tar_path.read_bytes()), (sig_path.name, sig_path.read_bytes()),
                   ("manifest.json", manifest_bytes),
                   ("offline.json", offline_bytes)] + [(f"wheels/{n}", (wheels / n).read_bytes()) for n in sorted(listed)]
        with open(bundle, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as gz, \
                tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tar:
            for name, data in members:
                ti = tarfile.TarInfo(name)
                ti.size, ti.mode, ti.mtime = len(data), 0o644, 0
                ti.uid = ti.gid = 0
                ti.uname = ti.gname = ""
                tar.addfile(ti, io.BytesIO(data))
    # The bundle must open with the same code the installer uses.
    with tempfile.TemporaryDirectory(prefix="ocw-offline-check-") as chk:
        try:
            offlinelib.open_bundle(bundle, chk)
        except offlinelib.BundleError as exc:
            bundle.unlink(missing_ok=True)
            raise ReleaseError(f"the bundle just built does not pass its own check: {exc}")
    digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
    (out_dir / (bundle.name + ".sha256")).write_text(f"{digest}  {bundle.name}\n", encoding="utf-8")
    return bundle, offline, digest


def cmd_build_offline(a):
    bundle, offline, digest = build_offline(a.tarball, a.out, tuple(a.python or OFFLINE_PYTHONS),
                                            tuple(a.platform or OFFLINE_PLATFORMS), a.keys)
    print(f"Built {bundle} ({len(offline['wheels'])} wheels, {bundle.stat().st_size // 1024 // 1024} MB) sha256 {digest}")
    print("The release inside is the signed one, unchanged; the wheels are checked by pip against the signed requirements.lock.")
    print("Upload it to the GitHub release next to the three signed files, with its .sha256 file.")


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
    s = sub.add_parser("build-offline", help="pack a signed release with its hash-pinned Python packages, for computers without internet")
    s.add_argument("tarball")
    s.add_argument("--out", help="output directory (default: next to the tarball)")
    s.add_argument("--python", action="append", help="Python minor version to include, e.g. 3.12 (repeatable; default 3.9-3.14)")
    s.add_argument("--platform", action="append", choices=tuple(OFFLINE_PLATFORMS), help="platform to include (repeatable; default all)")
    s.add_argument("--keys", help="key list to verify the signature against (default server/release_keys.json)")
    s.set_defaults(fn=cmd_build_offline)
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
    except (ReleaseError, keylib.KeyListError, minisign.SignatureError, verifylib.VerifyError, offlinelib.BundleError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except (OSError, tarfile.TarError, KeyError, ValueError) as exc:
        print(f"ERROR: {getattr(exc, 'strerror', None) or exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
