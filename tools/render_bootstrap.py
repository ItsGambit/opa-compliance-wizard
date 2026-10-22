"""Renders get-ocw.sh (the one-line installer) from its template and the repository files it embeds.

Pure and deterministic: the same template, verifier files and key list always give the same bytes, so
`release.py verify` can re-render from a tag and compare, and a test can check that every embedded file is a byte-for-byte
copy of its source. Used by tools/release.py (build, verify) and by the tests; nothing here runs on a server.

The template (server/get-ocw.sh.in) has three placeholders:
    @@VERSION@@         the release version
    @@KEY_SUMMARY@@     "<key id> (release), <key id> (standby)" from the embedded key list, for `get-ocw.sh --version`
    @@EMBEDDED_FILES@@  one heredoc per embedded file, written into the function write_verifier
"""

import json
import re
import sys
from pathlib import Path

TEMPLATE_PATH = "server/get-ocw.sh.in"
# (published name inside the work directory, path in the repository), in the order they are written
EMBEDDED = (
    ("ocw_crypto.py", "server/updater/root/ocw_crypto.py"),
    ("ocw_trust.py", "server/updater/root/ocw_trust.py"),
    ("ocw_bootstrap_verify.py", "server/updater/root/ocw_bootstrap_verify.py"),
    ("release_keys.json", "server/release_keys.json"),
)
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")


class RenderError(Exception):
    pass


def delimiter_for(name):
    return "OCW_EMBEDDED_" + re.sub(r"[^A-Za-z0-9]", "_", name)


def heredoc(name, data):
    if not data.endswith(b"\n"):
        raise RenderError(f"{name} must end with a newline to be embedded")
    delim = delimiter_for(name).encode()
    if any(line == delim for line in data.split(b"\n")):
        raise RenderError(f"{name} contains the heredoc delimiter {delim.decode()}")
    if b"\r" in data:
        raise RenderError(f"{name} contains a carriage return; embedded files must use plain line ends")
    return b"  cat >\"$_d/" + name.encode() + b"\" <<'" + delim + b"'\n" + data + delim + b"\n"


def key_summary(keys_bytes):
    keys = json.loads(keys_bytes.decode("utf-8"))["keys"]
    return ", ".join(f"{k['key_id']} ({k['role']})" for k in keys if k.get("status") == "active")


def render(version, files):
    """`files`: {repository path: bytes} holding the template and every embedded file. Returns the script bytes."""
    if not _VERSION_RE.match(version):
        raise RenderError("version must look like 5.52.0")
    try:
        template = files[TEMPLATE_PATH]
    except KeyError:
        raise RenderError(f"{TEMPLATE_PATH} is missing")
    for marker in (b"@@VERSION@@", b"@@KEY_SUMMARY@@", b"@@EMBEDDED_FILES@@"):
        if marker not in template:
            raise RenderError(f"{TEMPLATE_PATH} has no {marker.decode()} placeholder")
    embedded = b""
    for name, path in EMBEDDED:
        if path not in files:
            raise RenderError(f"{path} is missing (get-ocw.sh embeds it)")
        embedded += heredoc(name, files[path])
    summary = key_summary(files["server/release_keys.json"]).encode()
    # the placeholders in the template are filled first, the embedded files last: their text is never searched again
    out = template.replace(b"@@VERSION@@", version.encode()).replace(b"@@KEY_SUMMARY@@", summary)
    marker = b"@@EMBEDDED_FILES@@\n"
    if out.count(marker) != 1:
        raise RenderError(f"{TEMPLATE_PATH} must have @@EMBEDDED_FILES@@ alone on exactly one line")
    return out.replace(marker, embedded)


def embedded_copies(script):
    """{name: bytes} of the files embedded in a rendered script (for the byte-for-byte check)."""
    found = {}
    for name, _path in EMBEDDED:
        delim = delimiter_for(name).encode()
        m = re.search(rb"<<'" + delim + rb"'\n(.*?)^" + delim + rb"$", script, re.S | re.M)
        if m:
            found[name] = m.group(1)
    return found


def bootstrap_version(script):
    m = re.search(rb'^OCW_BOOTSTRAP_VERSION="(\d+\.\d+\.\d+)"$', script, re.M)
    if not m:
        raise RenderError("the script does not carry OCW_BOOTSTRAP_VERSION")
    return m.group(1).decode()


def main(argv=None):
    """`python tools/render_bootstrap.py <version> <out file>`: renders get-ocw.sh from the working tree (CI uses it to check the
    template with ShellCheck; releases are rendered from the tag by release.py)."""
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2:
        print("usage: render_bootstrap.py <version> <out file>", file=sys.stderr)
        return 2
    repo = Path(__file__).resolve().parent.parent
    files = {TEMPLATE_PATH: (repo / TEMPLATE_PATH).read_bytes()}
    for _name, path in EMBEDDED:
        files[path] = (repo / path).read_bytes()
    try:
        Path(argv[1]).write_bytes(render(argv[0], files))
    except RenderError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
