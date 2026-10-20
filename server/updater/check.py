"""The update check's network half: ask GitHub (or a configured mirror) for
the latest stable release and parse the answer. Pure functions, no state, no
logging -- service.py decides when to call this and records the outcome.

What a check sends: one HTTPS GET to the release API, carrying only the fixed
User-Agent `opa-compliance-wizard-update-check` (plus `/<installed version>`
only when the admin turned "share my version" on), the usual Accept header and
an If-None-Match ETag. GitHub sees the server's egress IP address; nothing
about the tenant, users, data or host name is sent.

Safety limits: https only (http only to a loopback host, for tests); 10 s
timeout; at most 1 MiB read; a body shorter than its Content-Length is
"truncated"; redirects only to GitHub's own hosts (or, when a mirror is
configured, only to the mirror's host), at most 3; proxies from the standard
https_proxy / no_proxy environment variables (urllib's default).
Everything remote is validated before use; nothing remote is ever executed.
"""

import json
import re
import urllib.error
import urllib.request
from collections import namedtuple
from urllib.parse import urlparse

DEFAULT_REPO = "ItsGambit/opa-compliance-wizard"
DEFAULT_API_URL = f"https://api.github.com/repos/{DEFAULT_REPO}/releases/latest"
# The one release tagged "revocation" holds revocation.json + revocation.json.sig assets.
DEFAULT_REVOCATION_BASE = f"https://github.com/{DEFAULT_REPO}/releases/download/revocation/"
DEFAULT_RELEASE_DOWNLOAD_BASE = f"https://github.com/{DEFAULT_REPO}/releases/download"
GITHUB_HOSTS = frozenset({"api.github.com", "github.com", "objects.githubusercontent.com",
                          "release-assets.githubusercontent.com"})
USER_AGENT = "opa-compliance-wizard-update-check"
TIMEOUT_SECONDS = 10
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_REDIRECTS = 3
_LOOPBACK = frozenset({"127.0.0.1", "localhost", "::1"})
_TAG_RE = re.compile(r"^v?(\d+\.\d+\.\d+)$")
_PUBLISHED_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

Fetched = namedtuple("Fetched", "status code detail body etag retry_after")
Latest = namedtuple("Latest", "version published_at release_url signed_artifact size notes_title notes")


def url_allowed(url, allowed_hosts):
    parts = urlparse(url)
    host = (parts.hostname or "").lower()
    if parts.scheme == "https":
        return host in allowed_hosts
    return parts.scheme == "http" and host in _LOOPBACK and host in allowed_hosts


def hosts_for(*urls):
    """Redirect allow-list: GitHub's hosts, or only the mirror's host(s)."""
    return frozenset((urlparse(u).hostname or "").lower() for u in urls)


class _GuardedRedirect(urllib.request.HTTPRedirectHandler):
    max_redirections = MAX_REDIRECTS

    def __init__(self, allowed_hosts):
        self._allowed = allowed_hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not url_allowed(newurl, self._allowed):
            raise urllib.error.URLError("redirect_refused")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _classify_url_error(exc):
    reason = getattr(exc, "reason", exc)
    if str(reason) == "redirect_refused":
        return "redirect_refused", "The server redirected to a host that is not allowed."
    if isinstance(reason, TimeoutError) or "timed out" in str(reason):
        return "timeout", "The release server did not answer in time."
    return "network", "The release server could not be reached (check DNS, firewall and proxy settings)."


def fetch(url, allowed_hosts, etag=None, user_agent=USER_AGENT, max_bytes=MAX_RESPONSE_BYTES,
          timeout=TIMEOUT_SECONDS, accept="application/vnd.github+json"):
    """GET `url`. Never raises: returns Fetched(status, code, detail, body, etag, retry_after)
    with status 'ok' | 'not_modified' | 'not_found' | 'rate_limited' | 'error'."""
    if not url_allowed(url, allowed_hosts):
        return Fetched("error", "bad_url", "The release URL must be https:// (and on an allowed host).", None, None, None)
    headers = {"User-Agent": user_agent, "Accept": accept, "X-GitHub-Api-Version": "2022-11-28"}
    if etag:
        headers["If-None-Match"] = etag
    opener = urllib.request.build_opener(_GuardedRedirect(allowed_hosts))
    try:
        with opener.open(urllib.request.Request(url, headers=headers), timeout=timeout) as resp:
            body = resp.read(max_bytes + 1)
            if len(body) > max_bytes:
                return Fetched("error", "too_large", "The release server's answer was larger than allowed.", None, None, None)
            declared = resp.headers.get("Content-Length")
            if declared and declared.isdigit() and len(body) < int(declared):
                return Fetched("error", "truncated", "The release server's answer was cut short.", None, None, None)
            return Fetched("ok", "ok", "", body, resp.headers.get("ETag"), None)
    except urllib.error.HTTPError as exc:
        code = exc.code
        if code == 304:
            return Fetched("not_modified", "not_modified", "", None, etag, None)
        if code == 404:
            return Fetched("not_found", "not_found", "", None, None, None)
        if code in (403, 429):
            retry = None
            ra = exc.headers.get("Retry-After") if exc.headers else None
            reset = exc.headers.get("X-RateLimit-Reset") if exc.headers else None
            if ra and ra.isdigit():
                retry = int(ra)
            elif reset and reset.isdigit():
                import time
                retry = max(0, int(reset) - int(time.time()))
            return Fetched("rate_limited", f"http_{code}", "The release server is rate limiting this address; "
                           "the check will retry later.", None, None, retry)
        return Fetched("error", f"http_{code}", f"The release server answered HTTP {code}.", None, None, None)
    except urllib.error.URLError as exc:
        code, detail = _classify_url_error(exc)
        return Fetched("error", code, detail, None, None, None)
    except (TimeoutError, OSError) as exc:
        code, detail = _classify_url_error(exc)
        return Fetched("error", code, detail, None, None, None)
    except Exception:  # noqa: BLE001 - http.client oddities must not escape the check
        return Fetched("error", "network", "The release server's answer could not be read.", None, None, None)


def _plain(value, limit):
    """Untrusted release text shown to admins: plain text only, bounded. (React
    escapes it too; this also drops control characters and keeps the first
    paragraph or two.)"""
    if not isinstance(value, str):
        return None
    text = "".join(ch for ch in value.replace("\r", "") if ch == "\n" or ch >= " ").strip()
    if len(text) > limit:
        text = text[:limit].rsplit(" ", 1)[0].rstrip() + "…"
    return text or None


def parse_latest(body):
    """Latest(...) from a GitHub 'latest release' JSON body, None if it is
    not a stable release, or raises ValueError('bad_response')."""
    try:
        data = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise ValueError("bad_json")
    if not isinstance(data, dict) or not isinstance(data.get("tag_name"), str):
        raise ValueError("bad_response")
    if data.get("draft") or data.get("prerelease"):
        return None
    match = _TAG_RE.match(data["tag_name"])
    if not match:
        raise ValueError("bad_response")
    version = match.group(1)
    published = data.get("published_at")
    published = published if isinstance(published, str) and _PUBLISHED_RE.match(published) else None
    url = data.get("html_url")
    url = url if isinstance(url, str) and len(url) <= 300 and url.startswith("https://") and " " not in url else None
    assets = [a for a in data.get("assets", []) if isinstance(a, dict)] if isinstance(data.get("assets"), list) else []
    names = {a.get("name") for a in assets}
    signed = {f"ocw-{version}.tar.gz", f"ocw-{version}.tar.gz.minisig", "manifest.json"} <= names
    size = next((a.get("size") for a in assets if a.get("name") == f"ocw-{version}.tar.gz"), None)
    size = size if isinstance(size, int) and not isinstance(size, bool) and 0 < size < 10 ** 10 else None
    return Latest(version, published, url, signed, size, _plain(data.get("name"), 120), _plain(data.get("body"), 800))
