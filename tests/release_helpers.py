"""Test-only signers and release-tarball builder.

The code under test (server/updater) only verifies. Signing here is a second,
independent implementation of the two formats (minisign `ED` for releases,
the ocw-revocation/1 envelope with ES256 for revocations), used to make vectors
with chosen defects. Vectors made by the REAL `minisign` program live in
tests/fixtures/minisign_real/. All keys are throwaway, generated in the test;
nothing here touches a cloud service.
"""

import base64
import gzip
import hashlib
import io
import json
import os
import tarfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature

from server.updater import keys as keylib
from server.updater import p256

TS = "2026-01-15T10:00:00Z"


class TestKey:
    """An Ed25519 release key (minisign format)."""
    __test__ = False

    def __init__(self, status="active", since="5.46.0"):
        self.priv = Ed25519PrivateKey.generate()
        self.raw = self.priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.stored_id = os.urandom(8)
        self.key_id = self.stored_id[::-1].hex().upper()
        self.status, self.since = status, since

    def entry(self, status=None):
        return {"key_id": self.key_id, "alg": "ed25519-minisign", "public_key": base64.b64encode(self.raw).decode(),
                "role": "release", "status": status or self.status, "since": self.since}

    def sign_bytes(self, data, trusted_comment, alg=b"ED"):
        msg = hashlib.blake2b(data, digest_size=64).digest() if alg == b"ED" else data
        sig = self.priv.sign(msg)
        global_sig = self.priv.sign(sig + trusted_comment.encode())
        return ("untrusted comment: test signature\n" + base64.b64encode(alg + self.stored_id + sig).decode() +
                "\ntrusted comment: " + trusted_comment + "\n" + base64.b64encode(global_sig).decode() + "\n")

    # the seam tools/signing_backends.RawSignerBackend uses
    def sign_raw(self, message):
        return self.priv.sign(message)


class TestStandby:
    """The standby key: EC P-256, ES256 over a digest, R || S."""
    __test__ = False

    def __init__(self, status="active", since="5.46.0"):
        self.priv = ec.generate_private_key(ec.SECP256R1())
        self.public_key = p256.spki_b64(self.priv.public_key())
        self.key_id = p256.parse_public_key(self.public_key)[0]
        self.status, self.since = status, since

    def entry(self, status=None):
        return {"key_id": self.key_id, "alg": "es256", "public_key": self.public_key, "role": "standby",
                "status": status or self.status, "since": self.since}

    def sign_digest(self, digest):
        r, s = decode_dss_signature(self.priv.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256()))))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def key_list(keys=()):
    """A shipped release_keys.json object."""
    return {"schema": 1, "keys": [k if isinstance(k, dict) else k.entry() for k in keys]}


def effective(keys=(), revoked=(), serial=0, extra_state_keys=()):
    """The effective list an install would hold (shipped list + local state)."""
    shipped = keylib.validate_key_list(key_list(keys))
    state = keylib.validate_state({"schema": 1, "serial": serial, "keys": [k if isinstance(k, dict) else k.entry() for k in extra_state_keys],
                                   "revoked": list(revoked)})
    return keylib.effective_from(shipped, state)


def make_release_tar(path, version, kl, extra_files=None, manifest_over=None, script_version=None,
                     built_at=TS, drop=(), min_upgrade_from="5.41.0", unlisted=()):
    """Writes a tarball shaped like tools/release.py's. `kl` is the shipped-format
    key list the release carries. Returns the path."""
    files = {
        "create_secret_folders.py": f'SCRIPT_VERSION = "{script_version or version}"\n'.encode(),
        "server/release_keys.json": (json.dumps(kl) + "\n").encode(),
        "server/deploy.sh": b"#!/bin/bash\n# deploy.sh handoff protocol: 2\n",
        "CHANGELOG.md": f"{version} — **test**\n".encode(),
        "frontend/dist/index.html": b"<html>built</html>\n",
    }
    files.update({k: (v if isinstance(v, bytes) else v.encode()) for k, v in (extra_files or {}).items()})
    manifest = {"schema": 1, "version": version, "commit": "c" * 40, "built_at": built_at,
                "min_upgrade_from": min_upgrade_from, "downtime_estimate_seconds": 60, "migrations": [],
                "frontend_lock_sha256": None, "changelog_excerpt": "x",
                "files": {n: hashlib.sha256(d).hexdigest() for n, d in sorted(files.items()) if n not in unlisted}}
    manifest.update(manifest_over or {})
    members = {**{n: d for n, d in files.items() if n not in drop}, "manifest.json": json.dumps(manifest).encode()}
    with open(path, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as gz, \
            tarfile.open(fileobj=gz, mode="w") as tar:
        for name, data in sorted(members.items()):
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(data), 0o755 if name.endswith(".sh") else 0o644, 1
            tar.addfile(info, io.BytesIO(data))
    return path


def sign_release(tar_path, key, version, timestamp=TS, name=None, sha=None, alg=b"ED"):
    data = open(tar_path, "rb").read()
    sha = sha or hashlib.sha256(data).hexdigest()
    comment = f"file={name or os.path.basename(str(tar_path))} version={version} sha256={sha}"
    if timestamp:
        comment += f" timestamp={timestamp}"
    sig_path = str(tar_path) + ".minisig"
    with open(sig_path, "w") as fh:
        fh.write(key.sign_bytes(data, comment, alg))
    return sig_path


def revocation_payload(serial, revoke=(), add_keys=(), issued="2026-02-01T00:00:00Z", reason="test revocation",
                       advisory_url="https://example.com/advisory"):
    return {"serial": serial, "issued_at": issued, "revoke": list(revoke),
            "add_keys": [k if isinstance(k, dict) else k.entry() for k in add_keys], "reason": reason,
            "advisory_url": advisory_url}


def make_revocation(path, signers, payload, tamper=None, alg="es256"):
    """Writes revocation.json (the envelope) signed by each of `signers` (TestStandby).
    `tamper`: 'payload' flips a payload byte after signing; 'format' changes the format string."""
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(b"ocw-revocation/1\n" + payload_bytes).digest()
    signatures = [{"key_id": s.key_id, "alg": alg, "sig": p256.b64url_encode(s.sign_digest(digest))} for s in signers]
    shown = payload_bytes
    if tamper == "payload":
        shown = payload_bytes.replace(b'"serial":', b'"serial": ', 1)
    env = {"format": "ocw-revocation/ZZ" if tamper == "format" else "ocw-revocation/1",
           "payload": p256.b64url_encode(shown), "signatures": signatures}
    with open(path, "w") as fh:
        fh.write(json.dumps(env, indent=2) + "\n")
    return path
