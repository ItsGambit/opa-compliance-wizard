#!/usr/bin/env python3
"""Standby operator tool: build and sign a key revocation. NEVER automated.

    revoke.py --azure-key https://<vault>/keys/<name>/<version> \\
              --revoke <key id>:<last good version> [--revoke ...] \\
              [--add-key entry.json ...] --reason "..." --advisory-url https://... \\
              [--serial N] [--keys server/release_keys.json] [--out DIR]

Use it from a clean computer, signed in to the standby's cloud account with MFA, and
`az logout` afterwards (a stolen CLI token cache is itself a standing credential).
It refuses to run without a terminal, shows what it is about to do and asks you to
type REVOKE. The standby key signs a SHA-256 digest of the payload (Key Vault
signs hashes; ES256, answer R || S); the tool then runs the app's own revocation
verifier on the result against the pinned keys and refuses to write a file that
installs would refuse. Output: revocation.json (upload to the release tagged
`revocation` and to the owner-controlled static URL) and release_keys.next.json
(the list to commit before the next release, which a NEW release key must sign).

The envelope: {format: "ocw-revocation/1", payload: base64url(JSON), signatures:
[{key_id, alg: "es256", sig: base64url(R||S)}]}; signed digest =
SHA-256("ocw-revocation/1\\n" || payload bytes). See server/updater/keys.py.
"""

import argparse
import datetime
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from signing_backends import AzureKeyVaultSigner, ReleaseError  # noqa: E402
from server.updater import keys as keylib  # noqa: E402
from server.updater import p256  # noqa: E402


def parse_revoke(item, eff):
    key_id, _, lgv = item.partition(":")
    entry = next((k for k in eff["keys"] if k["key_id"] == key_id), None)
    if entry is None:
        raise ReleaseError(f"{key_id} is not a pinned key")
    if entry["role"] == "release" and not lgv:
        raise ReleaseError(f"revoking the release key {key_id} needs its last good version: --revoke {key_id}:<version> "
                           "(the newest release you are certain was signed before the key was exposed; a thief can back-date "
                           "a time but cannot lower a version number)")
    return {"key_id": key_id, "last_good_version": lgv} if lgv else key_id


def build_envelope(payload, signer):
    """(envelope bytes) for `payload` signed by `signer` (has .key_id, .sign_digest)."""
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    rs = signer.sign_digest(keylib.revocation_digest(payload_bytes))
    envelope = {"format": keylib.REVOCATION_FORMAT, "payload": p256.b64url_encode(payload_bytes),
                "signatures": [{"key_id": signer.key_id, "alg": "es256", "sig": p256.b64url_encode(rs)}]}
    return (json.dumps(envelope, indent=2) + "\n").encode("utf-8")


def run(args, signer, confirm):
    keys_path = Path(args.keys)
    eff = keylib.effective_key_list(keys_path, Path(args.state) if args.state else None)
    if not eff["keys"]:
        raise ReleaseError(f"{keys_path} pins no keys; there is nothing to revoke")
    standby = next((k for k in eff["keys"] if k["key_id"] == signer.key_id), None)
    if standby is None or not keylib.usable(standby, "standby"):
        raise ReleaseError(f"the signing key {signer.key_id} is not an active standby key in {keys_path}; check --azure-key")
    revoke = [parse_revoke(item, eff) for item in args.revoke]
    add_keys = [json.loads(Path(p).read_text(encoding="utf-8")) for p in args.add_key or []]
    serial = args.serial or eff["serial"] + 1
    issued = args.issued or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = {"serial": serial, "issued_at": issued, "revoke": revoke, "add_keys": add_keys,
               "reason": args.reason, "advisory_url": args.advisory_url}
    print("About to sign a REVOCATION with the standby key:")
    print(f"  serial {serial}, issued {issued}")
    print(f"  revoke : {json.dumps(revoke)}")
    print(f"  add    : {[k.get('key_id') for k in add_keys]}")
    print(f"  reason : {args.reason}")
    print(f"  advisory: {args.advisory_url}")
    if not confirm():
        raise ReleaseError("not confirmed; nothing was signed")
    raw = build_envelope(payload, signer)
    try:
        state, _details = keylib.apply_revocation(eff, raw)
    except keylib.KeyListError as exc:
        raise ReleaseError(f"the revocation was made but would be REFUSED by installs: {exc}\nDo not publish it.")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / keylib.REVOCATION_FILE_NAME).write_bytes(raw)
    (out / "release_keys.next.json").write_text(json.dumps({"schema": keylib.SCHEMA, "keys": state["keys"]}, indent=2) + "\n",
                                                 encoding="utf-8")
    print(f"Wrote {out / keylib.REVOCATION_FILE_NAME} (serial {serial}); the app's verifier accepts it against {keys_path}.")
    print(f"Wrote {out / 'release_keys.next.json'}: commit it as server/release_keys.json BEFORE the next release, which must be")
    print("signed by a NEW release key. Then:")
    print("  1. upload revocation.json to the release tagged 'revocation' (replace the old asset) and to the static URL;")
    print("  2. publish the security advisory named above;")
    print("  3. sign out of the standby's cloud account now (az logout).")


def build_parser():
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--azure-key", required=True, help="Azure Key Vault key identifier URL of the standby key")
    p.add_argument("--revoke", action="append", required=True, metavar="KEY_ID[:LAST_GOOD_VERSION]")
    p.add_argument("--add-key", action="append", metavar="ENTRY_JSON", help="key entry to add (from release.py pubkey --out)")
    p.add_argument("--reason", required=True)
    p.add_argument("--advisory-url", required=True)
    p.add_argument("--serial", type=int)
    p.add_argument("--issued", help="RFC 3339 UTC time (default: now)")
    p.add_argument("--keys", default=str(HERE.parent / "server" / "release_keys.json"))
    p.add_argument("--state", help="this checkout's release_keys.local.json (default: next to the app)")
    p.add_argument("--out", default="release-out")
    return p


def require_interactive():
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise ReleaseError("revoke.py is interactive-only: run it yourself in a terminal; it is never automated")


def typed_confirmation():
    return input("Type REVOKE to sign: ").strip() == "REVOKE"


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        require_interactive()
        signer = AzureKeyVaultSigner(args.azure_key)
        run(args, signer, typed_confirmation)
        return 0
    except (ReleaseError, keylib.KeyListError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError) as exc:
        print(f"ERROR: {getattr(exc, 'strerror', None) or exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
