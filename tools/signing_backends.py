"""Signing backends for the maintainer tools (tools/release.py, tools/revoke.py).

Production keys never exist as files:
  * the primary (Ed25519, signs releases) is an AWS KMS key, key spec
    ECC_NIST_EDWARDS25519, algorithm ED25519_SHA_512 with MessageType RAW, which
    is PURE Ed25519 (NIST FIPS 186-5 section 7.6 = RFC 8032) over the bytes it is
    given (never Ed25519ph; never pre-hash with SHA-512);
  * the standby (ES256 / ECDSA P-256, signs revocations only) is an Azure Key
    Vault key; Key Vault signs a digest computed locally.
boto3 and the Azure SDK are OPTIONAL dependencies of these tools only, imported
when used, never of the app. Whatever produced a signature, the output is the
standard file format and the in-process verifier in server/updater checks it.

Tests use fake clients (a class with the same few methods); no test calls a cloud.
"""

import base64
import datetime
import hashlib
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from server.updater import keys as keylib  # noqa: E402
from server.updater import minisign  # noqa: E402
from server.updater import p256  # noqa: E402

MAX_TRUSTED_COMMENT_BYTES = 4000  # KMS Sign takes at most 4096 bytes: 64 (signature) + comment


class ReleaseError(Exception):
    pass


def current_version():
    m = re.search(r'^SCRIPT_VERSION = "([^"]+)"', (REPO / "create_secret_folders.py").read_text(encoding="utf-8"), re.M)
    return m.group(1) if m else "0.0.0"


def _require(module, extra):
    try:
        return __import__(module, fromlist=["x"])
    except ImportError:
        raise ReleaseError(f"{module.split('.')[0]} is needed for this signer ({extra}); it is an optional dependency of "
                           "the maintainer tools only, never of the app")


def run_command(cmd, check=True):
    """Indirection so tests can stub the aws CLI / minisign."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        raise ReleaseError(f"required program not found: {cmd[0]}")
    if check and proc.returncode != 0:
        raise ReleaseError(f"{cmd[0]} failed (exit {proc.returncode}): {(proc.stderr or '').strip()[:300]}")
    return proc


def aws_client(profile=None, region=None):
    """A KMS client. With `profile` (an IAM Identity Center profile) the tool first
    makes sure there is a valid MFA-backed SSO session, starting `aws sso login`
    (interactive, in your browser) if not. No long-lived key is read or stored."""
    boto3 = _require("boto3", "pip install boto3")
    if profile:
        probe = run_command(["aws", "sts", "get-caller-identity", "--profile", profile], check=False)
        if probe.returncode != 0:
            print(f"No valid AWS session for profile '{profile}'; starting `aws sso login` (complete the MFA prompt)...")
            run_command(["aws", "sso", "login", "--profile", profile])
        return boto3.Session(profile_name=profile, region_name=region).client("kms")
    return boto3.client("kms", region_name=region)


# --- Ed25519 release signer (AWS KMS) --------------------------------------------


def ed25519_entry_from_spki(der, since=None):
    """(key list entry) for an Ed25519 SubjectPublicKeyInfo (what KMS
    GetPublicKey returns): the raw key is its last 32 bytes. The key id is
    derived from the key (first 8 bytes of SHA-256 of the raw key, shown the way
    minisign shows ids), so it is the same on every computer."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        key = serialization.load_der_public_key(der)
    except ValueError:
        key = None
    if not isinstance(key, Ed25519PublicKey):
        raise ReleaseError("that key is not an Ed25519 key (KMS key spec ECC_NIST_EDWARDS25519)")
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    stored = hashlib.sha256(raw).digest()[:8]
    return {"key_id": minisign.key_id_hex(stored), "alg": "ed25519-minisign", "public_key": base64.b64encode(raw).decode(),
            "role": "release", "status": "active", "since": since or current_version()}


class RawSignerBackend:
    """Seam for signers that return a raw 64-byte Ed25519 signature over the
    exact bytes they are given. Subclasses set `key_id` and implement `sign_raw`.
    minisign `ED` signs the 64-byte BLAKE2b-512 digest of the file; the
    trusted-comment signature signs signature + trusted comment; this class does
    both and writes the standard four-line file."""

    key_id = None

    def sign_raw(self, message):
        raise NotImplementedError

    def sign_file(self, path, trusted_comment, sig_out):
        if len(trusted_comment.encode("utf-8")) > MAX_TRUSTED_COMMENT_BYTES:
            raise ReleaseError(f"the trusted comment is longer than {MAX_TRUSTED_COMMENT_BYTES} bytes")
        prehash, _sha, _size = minisign.hash_file(path)
        sig = self.sign_raw(prehash)
        global_sig = self.sign_raw(sig + trusted_comment.encode("utf-8"))
        Path(sig_out).write_text(minisign.format_signature(self.key_id, sig, trusted_comment, global_sig), encoding="utf-8")
        return minisign.parse_signature(Path(sig_out).read_text(encoding="utf-8"))


class AwsKmsBackend(RawSignerBackend):
    """`client` is a boto3 KMS client (a fake in tests)."""

    def __init__(self, key, client=None, profile=None, since=None):
        self.key = key
        self.client = client or aws_client(profile)
        info = self.client.get_public_key(KeyId=key)
        algs = info.get("SigningAlgorithms")
        if algs is not None and "ED25519_SHA_512" not in algs:
            raise ReleaseError("that KMS key cannot sign with ED25519_SHA_512 (use key spec ECC_NIST_EDWARDS25519, usage SIGN_VERIFY)")
        self.entry = ed25519_entry_from_spki(info["PublicKey"], since)
        self.key_id = self.entry["key_id"]
        self.request_ids = []

    def sign_raw(self, message):
        resp = self.client.sign(KeyId=self.key, Message=message, MessageType="RAW", SigningAlgorithm="ED25519_SHA_512")
        sig = resp["Signature"]
        if len(sig) != 64:
            raise ReleaseError("KMS returned a signature that is not the 64-byte raw Ed25519 form; refusing to use it")
        self.request_ids.append((resp.get("ResponseMetadata") or {}).get("RequestId"))
        return bytes(sig)


# --- ES256 revocation signer (Azure Key Vault) -------------------------------------


def p256_entry_from_spki(der, since=None):
    b64 = base64.b64encode(der).decode()
    key_id, _key = p256.parse_public_key(b64)
    return {"key_id": key_id, "alg": "es256", "public_key": b64, "role": "standby", "status": "active",
            "since": since or current_version()}


class AzureAdapter:
    """Thin wrapper over the Azure SDK exposing exactly what AzureKeyVaultSigner
    uses (spki_der(), sign_digest(digest)); tests pass a fake with the same two
    methods. Not exercised against a live vault by the test suite."""

    def __init__(self, key_url):
        identity = _require("azure.identity", "pip install azure-identity")
        keys = _require("azure.keyvault.keys", "pip install azure-keyvault-keys")
        crypto = _require("azure.keyvault.keys.crypto", "pip install azure-keyvault-keys")
        from urllib.parse import urlparse
        parts = urlparse(key_url)
        segments = [x for x in parts.path.split("/") if x]
        if parts.scheme != "https" or len(segments) < 2 or segments[0] != "keys":
            raise ReleaseError("--azure-key expects the key identifier URL: https://<vault>/keys/<name>[/<version>]")
        credential = identity.DefaultAzureCredential()
        self._crypto = crypto.CryptographyClient(key_url, credential)
        self._vault = f"{parts.scheme}://{parts.netloc}"
        self._name = segments[1]
        self._version = segments[2] if len(segments) > 2 else None
        self._credential, self._keys, self._crypto_mod = credential, keys, crypto

    def spki_der(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        jwk = self._keys.KeyClient(self._vault, self._credential).get_key(self._name, self._version).key
        numbers = ec.EllipticCurvePublicNumbers(int.from_bytes(jwk.x, "big"), int.from_bytes(jwk.y, "big"), ec.SECP256R1())
        return numbers.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    def sign_digest(self, digest):
        """Key Vault signs a hash: ES256 over this 32-byte SHA-256 digest; the
        answer is the RFC 7518 form R || S (64 bytes)."""
        return self._crypto.sign(self._crypto_mod.SignatureAlgorithm.es256, digest).signature


class AzureKeyVaultSigner:
    def __init__(self, key_url=None, client=None, since=None):
        self.client = client or AzureAdapter(key_url)
        self.entry = p256_entry_from_spki(self.client.spki_der(), since)
        self.key_id = self.entry["key_id"]

    def sign_digest(self, digest):
        raw = self.client.sign_digest(digest)
        if len(raw) != 64:
            raise ReleaseError("Key Vault returned a signature that is not 64 bytes (R || S); refusing to use it")
        return bytes(raw)


def today():
    return datetime.date.today().isoformat()
