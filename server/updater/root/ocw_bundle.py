"""The redacted support bundle (stdlib only; built by the root-owned updater).

An operator who has no shell on the server can still hand the maintainers
everything needed to reproduce a failed upgrade: a small .tar.gz, built by the
updater the moment an upgrade fails (or on request), offered for download from
the failed upgrade's entry in the Audit Log. It is never uploaded anywhere.

What goes in (the caller passes these; this module only scrubs and packs):
  summary.json            versions, reason code, failed step, timings, system
                          versions, free space, the manifest, health results,
                          schema and audit-chain-head comparison, state history
  journal-<unit>.txt      last lines of each OPA unit and of the updater
  nginx-test.txt          `nginx -t` output
  status-<unit>.txt       `systemctl status`
  audit-<correlation>.jsonl   only the audit entries of this upgrade
  redaction-report.txt    what was redacted and how many times (never the values)

What never goes in: the environment file, anything from the keyring, the
session key, the archive database or any row from it, environment (tenant)
metadata, the nginx site file (it holds the proxy secret), request bodies,
cookies. This module cannot add them because it is only ever handed the
texts above; tests seed secrets into every input and check they are absent.

Redaction (applied to EVERY text before it is packed):
  * the literal values of this server's secrets (every variable of the
    environment file whose name ends in SECRET, TOKEN, PASSWORD or KEY) wherever
    they appear, and `NAME=value` / `"name": "value"` forms of such names;
  * Authorization / Cookie / Set-Cookie / X-Nginx-Proxy-Secret header values;
  * Okta SSWS tokens, JWT-shaped strings, and any 32+ character base64/hex run;
  * e-mail addresses -> user-<hash6>@redacted; Okta subject ids -> sub-<hash6>;
  * host names and IP addresses -> host-<hash6>, and environment / tenant names
    (values of the keys in ENV_KEYS found in the audit entries) -> env-<hash6>,
    UNLESS the admin ticked "include host names and environment names".
The hash uses a random per-bundle salt: the same value maps to the same
placeholder inside one bundle but cannot be linked across bundles.
"""

import hashlib
import io
import json
import os
import re
import secrets as _secrets
import tarfile
import time

MAX_BUNDLE_BYTES = 5 * 1024 * 1024
SENSITIVE_NAME = re.compile(r"(SECRET|TOKEN|PASSWORD|KEY)$", re.I)
ENV_KEYS = ("environment", "environment_name", "env", "env_name", "tenant", "team_name", "base_domain", "org_url",
            "okta_url", "domain", "environment_id")
# A dotted name is treated as a host only when its last label is a real top-level domain: audit action names
# ("upgrade.step"), unit names and file names are dotted too and must stay readable.
HOST_TLDS = frozenset(
    "com net org io dev edu gov mil int info biz co app cloud tech xyz online site store us uk de fr nl se no fi dk es it pl cz ch at be ie "
    "eu ca au nz jp cn in br mx za ru ua tr il ae sg hk kr tw local internal lan corp intranet home localdomain test example invalid".split())
FILE_LIKE_TLDS = frozenset(
    "py db json jsonl service path timer socket target conf sh txt log lock gz html js md pyc so key pem yml yaml cfg ini "
    "tar minisig css map png svg ico csv sqlite wal shm bak tmp new old staging staged rejected pid".split())

_EMAIL = re.compile(r"[A-Za-z0-9._%+'-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_SUB = re.compile(r"\b00[uUgG][A-Za-z0-9]{16,20}\b")
_SSWS = re.compile(r"\b00[A-Za-z0-9_-]{40}\b")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
_LONG_RUN = re.compile(r"(?<![A-Za-z0-9=_+-])(?:[A-Fa-f0-9]{32,}|[A-Za-z0-9_+-]{32,}={0,2})(?![A-Za-z0-9=_+-])")
_HEADER = re.compile(r"(?im)^(\s*(?:authorization|cookie|set-cookie|x-nginx-proxy-secret|proxy-authorization)\s*:\s*).*$")
_HEADER_JSON = re.compile(r'(?i)("(?:authorization|cookie|set-cookie|x-nginx-proxy-secret)"\s*:\s*)"(?:[^"\\]|\\.)*"')
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_IPV6 = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){4,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")
_HOST = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+([A-Za-z]{2,24})\b")


class Redactor:
    def __init__(self, salt=None, secret_values=(), include_hosts=False, env_names=()):
        self.salt = salt or _secrets.token_bytes(16)
        self.include_hosts = bool(include_hosts)
        self.secret_values = sorted({v for v in secret_values if isinstance(v, str) and len(v) >= 6}, key=len, reverse=True)
        self.env_names = sorted({n for n in env_names if isinstance(n, str) and len(n) >= 3}, key=len, reverse=True)
        self.counts = {}

    def _h(self, value):
        return hashlib.sha256(self.salt + value.encode("utf-8", "replace")).hexdigest()[:6]

    def _count(self, kind, n=1):
        self.counts[kind] = self.counts.get(kind, 0) + n

    def _sub(self, pattern, repl, text, kind):
        def fn(m):
            self._count(kind)
            return repl(m)
        return pattern.sub(fn, text)

    def redact(self, text):
        if not isinstance(text, str):
            text = str(text)
        for value in self.secret_values:
            if value in text:
                self._count("secrets", text.count(value))
                text = text.replace(value, "[REDACTED:secret]")
        text = self._sub(_HEADER, lambda m: m.group(1) + "[REDACTED:header]", text, "headers")
        text = self._sub(_HEADER_JSON, lambda m: m.group(1) + '"[REDACTED:header]"', text, "headers")
        text = self._sub(re.compile(r"(?i)\b([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|KEY))\s*=\s*(\"[^\"]*\"|'[^']*'|\S+)"),
                         lambda m: f"{m.group(1)}=[REDACTED:secret]", text, "secrets")
        text = self._sub(re.compile(r'(?i)("[A-Za-z0-9_]*(?:secret|token|password|key)")\s*:\s*"(?:[^"\\]|\\.)*"'),
                         lambda m: f'{m.group(1)}: "[REDACTED:secret]"', text, "secrets")
        text = self._sub(_JWT, lambda m: "[REDACTED:token]", text, "tokens")
        text = self._sub(_SSWS, lambda m: "[REDACTED:token]", text, "tokens")
        def email(m):
            if m.group(0).rsplit(".", 1)[-1].lower() in FILE_LIKE_TLDS or not m.group(0).rsplit(".", 1)[-1].isalpha():
                return m.group(0)  # ocw-stage@5.47.0.service is a unit instance, not an address
            self._count("emails")
            return f"user-{self._h(m.group(0).lower())}@redacted"
        text = _EMAIL.sub(email, text)
        text = self._sub(_SUB, lambda m: f"sub-{self._h(m.group(0))}", text, "sub_ids")
        if not self.include_hosts:
            for name in self.env_names:
                pat = re.compile(r"(?<![A-Za-z0-9])" + re.escape(name) + r"(?![A-Za-z0-9])")
                text = self._sub(pat, lambda m: f"env-{self._h(m.group(0))}", text, "env_names")
            text = self._sub(_IPV4, lambda m: f"host-{self._h(m.group(0))}", text, "hosts")
            text = self._sub(_IPV6, lambda m: f"host-{self._h(m.group(0))}", text, "hosts")

            def host(m):
                if m.group(1).lower() not in HOST_TLDS:
                    return m.group(0)
                self._count("hosts")
                return f"host-{self._h(m.group(0).lower())}"
            text = _HOST.sub(host, text)
        return _LONG_RUN.sub(self._long_run, text)

    def _long_run(self, m):
        run = m.group(0)
        # Words joined by hyphens (a unit or file name) are not secrets; a long run
        # with a digit and at most two separators is treated as one.
        if len(re.findall(r"[-_]", run)) >= 3 and not re.fullmatch(r"[A-Fa-f0-9]+", run):
            return run
        if not re.search(r"\d", run):
            return run
        self._count("tokens")
        return "[REDACTED:token]"

    def report(self):
        lines = ["Redaction report (counts only; the values are not recorded)", ""]
        for kind in ("secrets", "headers", "tokens", "emails", "sub_ids", "hosts", "env_names"):
            lines.append(f"{kind:10} {self.counts.get(kind, 0)}")
        lines += ["", "host names / IP addresses / environment names: " +
                  ("INCLUDED unredacted (the administrator chose this)" if self.include_hosts else "replaced by host-xxxxxx / env-xxxxxx"),
                  "The hash salt is random per bundle: placeholders cannot be linked to another bundle."]
        return "\n".join(lines) + "\n"


APP_LOG_LEVELS = ("WARN", "WARNING", "ERROR", "CRIT", "CRITICAL", "FATAL")


def filter_app_journal(text, correlation_id=None, cap=200):
    """The application's own log is free text we cannot fully scrub (sync progress, display names, folder names). Keep only
    JSON lines at WARN or above, or carrying this upgrade's correlation id, at most `cap` (the newest)."""
    keep = []
    for line in text.splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if not isinstance(rec, dict):
            continue
        level = str(rec.get("level", "")).upper()
        if level in APP_LOG_LEVELS or (correlation_id and rec.get("correlation_id") == correlation_id):
            keep.append(line)
    return "\n".join(keep[-cap:]) + ("\n" if keep else "")


def collect_env_names(audit_entries):
    """Environment / tenant names found in audit entries' details (values of ENV_KEYS)."""
    found = set()

    def walk(obj, depth=0):
        if depth > 6:
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in ENV_KEYS and isinstance(v, str):
                    found.add(v)
                else:
                    walk(v, depth + 1)
        elif isinstance(obj, list):
            for v in obj[:200]:
                walk(v, depth + 1)
    for e in audit_entries:
        walk(e.get("details") if isinstance(e, dict) else None)
    return found


def truncate_middle(text, limit):
    if len(text) <= limit:
        return text
    half = max(0, (limit - 80) // 2)
    cut = len(text) - 2 * half
    return text[:half] + f"\n[... {cut} characters omitted to keep the bundle small ...]\n" + text[-half:]


def _tar_bytes(files, now):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", compresslevel=9) as tar:
        for name in sorted(files):
            data = files[name].encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode, info.uid, info.gid = len(data), int(now), 0o600, 0, 0
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def build(dest_dir, stem, summary, texts, audit_entries, redactor, now=None, cap=MAX_BUNDLE_BYTES, gid=None):
    """Writes <dest_dir>/<stem>-<random>.tar.gz and returns
    {"name", "path", "size", "sha256", "redaction": counts}.
    `texts` maps member names (journal-*.txt etc.) to raw text; they and the
    summary and audit entries are redacted here, then the archive is shrunk
    (journals truncated head+tail) until it fits `cap`."""
    now = now or time.time()
    audit_text = "".join(json.dumps(e, sort_keys=True, separators=(",", ":")) + "\n" for e in audit_entries)
    members = {n: redactor.redact(t) for n, t in texts.items()}
    members["summary.json"] = redactor.redact(json.dumps(summary, indent=2, sort_keys=True, default=str))
    cid = summary.get("correlation_id") or "none"
    members[f"audit-{cid}.jsonl"] = redactor.redact(audit_text)
    members["redaction-report.txt"] = redactor.report()
    def shape(name, text, limit):
        if name.startswith("journal-"):
            return truncate_middle(text, limit) if limit else f"[omitted: the bundle would exceed {cap} bytes]\n"
        if name.startswith(("status-", "nginx-")):
            return truncate_middle(text, max(limit, 4096))
        return text
    blob = b""
    for limit in (1 << 20, 256 << 10, 64 << 10, 16 << 10, 4 << 10, 0):
        blob = _tar_bytes({n: shape(n, t, limit) for n, t in members.items()}, now)
        if len(blob) <= cap:
            break
    if len(blob) > cap:
        raise ValueError("support bundle cannot be made smaller than the cap")
    name = f"{stem}-{_secrets.token_hex(2)}.tar.gz"
    os.makedirs(dest_dir, exist_ok=True)
    path = os.path.join(dest_dir, name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o640)
    os.fchmod(fd, 0o640)   # not at the mercy of the umask
    with os.fdopen(fd, "wb") as fh:
        fh.write(blob)
        fh.flush()
        os.fsync(fh.fileno())
    if gid is not None:
        try:
            os.chown(path, -1, gid)
        except OSError:
            os.chmod(path, 0o600)
    return {"name": name, "path": path, "size": len(blob), "sha256": hashlib.sha256(blob).hexdigest(),
            "redaction": dict(redactor.counts)}
