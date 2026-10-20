"""The update check as a feature: settings, stored state, when to run, what to
tell the audit log. serve.py only wires this to its scheduler loop and routes.

Stored in one small JSON file (update_check.json, next to the app; override
with OPA_UPDATE_STATE_PATH), never in the archive database:
  settings  enabled (null = never answered, true, false), share_version
  state     latest version seen, its published date, release URL, whether a
            signed artifact is attached, last check time and result, plus the
            bookkeeping needed to be polite (ETag, next check time, failure
            counter). No host name, tenant, user or credential is stored.

Switches (operator, environment): OPA_UPDATE_CHECK=off always wins and
cannot be overridden from the UI; =on enables the check without any admin
action; unset leaves it to the admin setting, which defaults to OFF -- a
fresh or upgraded install never phones anywhere until it is switched on.
OPA_RELEASE_API_URL / OPA_REVOCATION_URL_BASE point the check at a mirror;
OPA_REVOCATION_URL adds a second, owner-controlled source of revocation.json.

Audit trail (the app's existing audit log, system events; each carries the
check's correlation_id so the JSON server log lines match):
  upgrade.settings          an admin turned the check or "share version" on/off
  upgrade.check             one row per check: up_to_date | update_available |
                            failed (reason code). An identical repeated failure
                            is NOT logged again; the next success says how many
                            failed since when.
  release_keys.*            see keys.py (revocations applied/rejected, updates)
Details keep room for a later "bundle" reference (a downloadable support
file) without a schema change.
"""

import hashlib
import os
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

from . import check
from . import keys as keylib

STATE_ENV = "OPA_UPDATE_STATE_PATH"
API_URL_ENV = "OPA_RELEASE_API_URL"
REVOCATION_BASE_ENV = "OPA_REVOCATION_URL_BASE"
REVOCATION_URL_ENV = "OPA_REVOCATION_URL"
SWITCH_ENV = "OPA_UPDATE_CHECK"
OK_INTERVAL = timedelta(hours=24)
ERROR_INTERVAL = timedelta(hours=6)
MIN_RATE_LIMIT_WAIT = timedelta(hours=1)
MAX_RATE_LIMIT_WAIT = timedelta(hours=24)

_lock = threading.RLock()
_running = threading.Event()


def _engine():
    return keylib._engine()


def state_path():
    override = os.environ.get(STATE_ENV)
    return override or str(Path(os.environ.get("OPA_DATA_DIR") or keylib.REPO_ROOT) / "update_check.json")


def _iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(text):
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


# --- the root-owned updater's output (5.47.0) --------------------------------------------------------
# The updater (updater/ocw_activate.py, root) writes upgrade/state.json (world-readable) and, on a failure,
# a redacted support bundle into upgrade/bundles/ (readable by this account). This module only READS them.
BUNDLE_NAME_RE = __import__("re").compile(r"^ocw-support-[A-Za-z0-9._-]{1,160}\.tar\.gz$")
MAX_BUNDLE_BYTES = 6 * 1024 * 1024
_RUN_FIELDS = ("correlation_id", "action", "version_from", "version_to", "step", "result", "reason_code", "started_at",
               "updated_at", "seconds", "failed_step", "operator_reason", "bundle", "schema_before", "schema_after")


def upgrade_dir():
    override = os.environ.get("OPA_UPGRADE_DIR")
    return Path(override) if override else Path(os.environ.get("OPA_DATA_DIR") or keylib.REPO_ROOT) / "upgrade"


def upgrade_run():
    """The updater's current/last run (fields only, no paths or manifest), or None when there is none or this
    install does not use the updater layout."""
    import json
    try:
        with open(upgrade_dir() / "state.json", encoding="utf-8") as fh:
            st = json.load(fh)
    except (OSError, ValueError):
        return None
    return {k: st.get(k) for k in _RUN_FIELDS} if isinstance(st, dict) else None


def read_bundle(name):
    """(status, bytes-or-error-text) for a support bundle by file name. Only a plain name in upgrade/bundles/ is
    ever opened: no path separators, no links, regular files up to 6 MB."""
    if not isinstance(name, str) or not BUNDLE_NAME_RE.match(name) or ".." in name:
        return 400, "Not a support bundle name."
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(upgrade_dir() / "bundles" / name), flags)
    except OSError:
        return 404, "No such support bundle."
    try:
        st = os.fstat(fd)
        import stat as _stat
        if not _stat.S_ISREG(st.st_mode) or st.st_size > MAX_BUNDLE_BYTES:
            return 404, "No such support bundle."
        with os.fdopen(fd, "rb", closefd=False) as fh:
            return 200, fh.read(MAX_BUNDLE_BYTES + 1)
    finally:
        os.close(fd)


def default_data():
    return {"settings": {"enabled": None, "share_version": False},
            "state": {"latest_version": None, "published_at": None, "release_url": None, "signed_artifact": None,
                      "last_check_at": None, "last_status": None, "last_code": None, "next_check_at": None,
                      "etag": None, "consecutive_failures": 0, "failing_since": None,
                      "revocation_etags": {}, "revocation_seen": {}}}


def load():
    """Always returns a complete structure; an unreadable or damaged file is
    treated as 'nothing stored yet' (the safe default is: check off)."""
    import json
    data = default_data()
    try:
        with open(state_path(), encoding="utf-8") as fh:
            stored = json.load(fh)
        if isinstance(stored, dict):
            for section in ("settings", "state"):
                if isinstance(stored.get(section), dict):
                    for k in data[section]:
                        if k in stored[section]:
                            data[section][k] = stored[section][k]
    except (OSError, ValueError):
        pass
    if data["settings"]["enabled"] not in (None, True, False):
        data["settings"]["enabled"] = None
    data["settings"]["share_version"] = data["settings"]["share_version"] is True
    return data


def save(data):
    _engine()._atomic_write_json(state_path(), data)


def env_switch():
    """('on'|'off'|None, invalid_text|None)."""
    raw = (os.environ.get(SWITCH_ENV) or "").strip().lower()
    if raw in ("on", "off"):
        return raw, None
    return None, (raw or None)


def is_enabled(data):
    """(enabled, source) with source env_off | env_on | setting | default_off."""
    switch, _bad = env_switch()
    if switch == "off":
        return False, "env_off"
    if switch == "on":
        return True, "env_on"
    if data["settings"]["enabled"] is True:
        return True, "setting"
    return False, "default_off" if data["settings"]["enabled"] is None else "setting"


def api_url():
    return os.environ.get(API_URL_ENV) or check.DEFAULT_API_URL


def revocation_base():
    base = os.environ.get(REVOCATION_BASE_ENV) or check.DEFAULT_REVOCATION_BASE
    return base if base.endswith("/") else base + "/"


def revocation_sources():
    """[(name, url)]: the revocation.json asset of the project's `revocation`
    release, and an optional owner-controlled static URL (OPA_REVOCATION_URL)."""
    sources = [("release_assets", revocation_base() + keylib.REVOCATION_FILE_NAME)]
    static = os.environ.get(REVOCATION_URL_ENV)
    if static:
        sources.append(("static_url", static))
    return sources


def _allowed_hosts():
    hosts = check.GITHUB_HOSTS
    if os.environ.get(API_URL_ENV) or os.environ.get(REVOCATION_BASE_ENV):
        hosts = check.hosts_for(api_url(), revocation_base())
    if os.environ.get(REVOCATION_URL_ENV):
        hosts = frozenset(hosts) | check.hosts_for(os.environ[REVOCATION_URL_ENV])
    return hosts


def newer(a, b):
    try:
        return keylib.parse_version(a) > keylib.parse_version(b)
    except keylib.KeyListError:
        return False


def status(data, installed_version):
    enabled, source = is_enabled(data)
    switch, bad = env_switch()
    st = data["state"]
    latest = None
    if st["latest_version"]:
        latest = {"version": st["latest_version"], "published_at": st["published_at"],
                  "release_url": st["release_url"], "signed_artifact": st["signed_artifact"]}
    try:
        kl = keylib.effective_key_list()
        keys = {"pinned": bool(kl["keys"]), "serial": kl["serial"], "error": None}
    except keylib.KeyListError as exc:
        keys = {"pinned": False, "serial": None, "error": str(exc)}
    return {
        "installed_version": installed_version,
        "check": {"enabled": enabled, "source": source, "env_locked": switch is not None,
                  "env_invalid_value": bad, "prompt_needed": data["settings"]["enabled"] is None and switch is None,
                  "share_version": data["settings"]["share_version"], "mirror": bool(os.environ.get(API_URL_ENV))},
        "latest": latest,
        "update_available": bool(latest and newer(latest["version"], installed_version)),
        "last_check": {"at": st["last_check_at"], "status": st["last_status"], "code": st["last_code"],
                       "next_at": st["next_check_at"] if enabled else None,
                       "consecutive_failures": st["consecutive_failures"], "failing_since": st["failing_since"]},
        "signing_keys": keys,
    }


def set_settings(enabled=None, share_version=None):
    """Returns the changes {name: [old, new]} (empty if nothing changed)."""
    with _lock:
        data = load()
        changes = {}
        if enabled is not None and enabled != data["settings"]["enabled"]:
            changes["enabled"] = [data["settings"]["enabled"], enabled]
            data["settings"]["enabled"] = enabled
        if share_version is not None and share_version != data["settings"]["share_version"]:
            changes["share_version"] = [data["settings"]["share_version"], share_version]
            data["settings"]["share_version"] = share_version
        if changes:
            if enabled is True:  # a fresh answer to "check now?" -> do not wait up to a day
                data["state"]["next_check_at"] = None
            save(data)
        return changes


def change_settings(enabled, share_version, installed_version, audit):
    """The one settings change used by the web route and the CLI (same rules,
    same audit event). `audit(action, details)` records who did it. Returns
    (http_status, body)."""
    switch, _bad = env_switch()
    if enabled is True and switch == "off":
        return 409, {"error": "The update check is switched off by OPA_UPDATE_CHECK=off in this server's environment, "
                              "which always wins. Remove that setting (and restart) to allow it.", "reason": "env_locked"}
    changes = set_settings(enabled, share_version)
    if changes:
        audit("upgrade.settings", {"changes": changes, "correlation_id": _engine().CORRELATION_ID.get()})
        if enabled is True and switch != "off":
            kick(installed_version)
    return 200, {"changed": changes, **status(load(), installed_version)}


def apply_settings_request(payload, installed_version, audit):
    """Validates a JSON body {enabled?: bool, share_version?: bool}."""
    if not isinstance(payload, dict) or not payload or set(payload) - {"enabled", "share_version"}:
        return 400, {"error": "Send {\"enabled\": true|false} and/or {\"share_version\": true|false}."}
    for key in payload:
        if not isinstance(payload[key], bool):
            return 400, {"error": f"{key} must be true or false."}
    return change_settings(payload.get("enabled"), payload.get("share_version"), installed_version, audit)


def due(data, now):
    enabled, _source = is_enabled(data)
    if not enabled:
        return False
    nxt = _parse_iso(data["state"]["next_check_at"])
    return nxt is None or now >= nxt


def _audit(action, details):
    engine = _engine()
    details = dict(details)
    details.setdefault("correlation_id", engine.CORRELATION_ID.get())
    engine.log("INFO", f"{action}: {details}")
    engine.log_audit_event(None, None, action, details)


def _revocation_step(st, installed_user_agent):
    """Fetch and apply a published revocation from each source. Returns a list
    of short outcome strings (one per source) for the audit row."""
    allowed = _allowed_hosts()
    outcomes = []
    for name, url in revocation_sources():
        got = check.fetch(url, allowed, st["revocation_etags"].get(name), installed_user_agent,
                          max_bytes=keylib.MAX_JSON_BYTES, accept="application/octet-stream")
        if got.status == "not_modified":
            outcomes.append(f"{name}:unchanged")
        elif got.status == "not_found":
            outcomes.append(f"{name}:none_published")
        elif got.status != "ok":
            outcomes.append(f"{name}:fetch_failed:{got.code}")
        else:
            st["revocation_etags"][name] = got.etag
            digest = hashlib.sha256(got.body).hexdigest()
            if st["revocation_seen"].get(name) == digest:
                outcomes.append(f"{name}:already_handled")
                continue
            st["revocation_seen"][name] = digest
            try:
                keylib.apply_revocation_bytes(got.body, source=name)
                outcomes.append(f"{name}:applied")
            except keylib.KeyListError as exc:
                if exc.code == "replayed":
                    outcomes.append(f"{name}:already_applied")
                else:
                    _audit("release_keys.revocation_rejected", {"reason": exc.code, "source": name, "message": str(exc)[:300]})
                    outcomes.append(f"{name}:rejected:{exc.code}")
    return outcomes


def run_check(installed_version, now=None, force=False, trigger="scheduler"):
    """One full check, persisted and audited. Never raises. Safe to call from
    a thread; a second concurrent call returns None. `force` runs it although
    the check is off (the CLI's --force; recorded as such) -- but never when
    OPA_UPDATE_CHECK=off, which always wins."""
    if _running.is_set():
        return None
    _running.set()
    try:
        engine = _engine()
        if engine.CORRELATION_ID.get() is None:
            engine.CORRELATION_ID.set(f"upd-{uuid.uuid4().hex[:8]}")
        now = now or datetime.now(timezone.utc)
        with _lock:
            data = load()
        enabled, source = is_enabled(data)
        if source == "env_off":
            return {"result": "blocked", "reason": "env_off"}
        if not enabled and not force:
            return None
        st = data["state"]
        ua = check.USER_AGENT + (f"/{installed_version}" if data["settings"]["share_version"] else "")
        got = check.fetch(api_url(), _allowed_hosts(), st["etag"], ua)
        previous_code = st["last_code"] if st["last_status"] != "ok" else None
        result = "failed"
        code = got.code
        next_at = now + ERROR_INTERVAL
        latest = None
        if got.status in ("ok", "not_modified", "not_found"):
            try:
                if got.status == "ok":
                    latest = check.parse_latest(got.body)
                    st["etag"] = got.etag
                    if latest is None:
                        st["latest_version"] = st["published_at"] = st["release_url"] = st["signed_artifact"] = None
                    else:
                        st.update(latest_version=latest.version, published_at=latest.published_at,
                                  release_url=latest.release_url, signed_artifact=latest.signed_artifact)
                elif got.status == "not_found":
                    st["latest_version"] = st["published_at"] = st["release_url"] = st["signed_artifact"] = None
                    st["etag"] = None
                result = "update_available" if (st["latest_version"] and newer(st["latest_version"], installed_version)) \
                    else "up_to_date"
                code = "ok" if got.status != "not_found" else "no_release"
                next_at = now + OK_INTERVAL
            except ValueError as exc:
                code = str(exc)
        elif got.status == "rate_limited":
            wait = timedelta(seconds=got.retry_after) if got.retry_after is not None else MIN_RATE_LIMIT_WAIT
            next_at = now + min(max(wait, MIN_RATE_LIMIT_WAIT), MAX_RATE_LIMIT_WAIT)
        revocation = None
        if result != "failed":
            revocation = _revocation_step(st, ua)
        st["last_check_at"] = _iso(now)
        st["next_check_at"] = _iso(next_at)
        st["last_status"] = "ok" if result != "failed" else ("rate_limited" if got.status == "rate_limited" else "error")
        st["last_code"] = code
        failures_before, since = st["consecutive_failures"], st["failing_since"]
        details = {"result": result, "installed_version": installed_version, "latest_version": st["latest_version"],
                   "reason": None if result != "failed" else code}
        if trigger != "scheduler":
            details["trigger"] = trigger
        if not enabled:
            details["forced"] = True
        notable = [o for o in (revocation or []) if o.split(":", 1)[1] not in
                   ("none_published", "unchanged", "already_handled", "already_applied")]
        if notable:
            details["revocation"] = notable
        log_row = True
        if result == "failed":
            st["consecutive_failures"] = failures_before + 1
            st["failing_since"] = since or _iso(now)
            log_row = previous_code != code  # identical repeated failure: stay quiet
        else:
            if failures_before:
                details["recovered_after_failures"] = failures_before
                details["failing_since"] = since
            st["consecutive_failures"], st["failing_since"] = 0, None
        with _lock:
            fresh = load()
            fresh["state"] = st
            save(fresh)
        if log_row:
            _audit("upgrade.check", details)
        return details
    except Exception as exc:  # noqa: BLE001 - the check must never take the scheduler down
        try:
            _engine().log("ERROR", f"update check crashed: {type(exc).__name__}")
        except Exception:  # noqa: BLE001
            pass
        return None
    finally:
        _running.clear()


def maybe_start(installed_version, now=None):
    """Called from the scheduler loop each poll: starts a check in its own
    thread when one is due (never blocks the loop's sync work)."""
    now = now or datetime.now(timezone.utc)
    try:
        with _lock:
            data = load()
        if _running.is_set() or not due(data, now):
            return False
    except Exception:  # noqa: BLE001
        return False
    threading.Thread(target=run_check, args=(installed_version, now), daemon=True, name="update-check").start()
    return True


def kick(installed_version):
    """Right after an admin switches the check on: run one soon."""
    threading.Thread(target=run_check, args=(installed_version,), daemon=True, name="update-check").start()
