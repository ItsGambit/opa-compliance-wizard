#!/usr/bin/env python3
# =============================================================================
# OPA Secret Folder Bulk Creator
# =============================================================================
# Description : Reads a CSV of vault folder paths (root/sub/sub-sub, any
#               depth) and creates the missing folders in Okta Privileged
#               Access under a given Resource Group + Project, using the
#               Secret Folders REST API.
#
# Model       : Resource Group -> Project -> Folder (Folder -> Folder for
#               nesting, via "parent_folder_id" on create). All endpoints and
#               field names below were LIVE-VERIFIED against a real OPA tenant
#               (not just inferred from docs) -- see the two confirmed facts
#               that matter most before you use this script:
#
#               1. Folder names must be unique PER PROJECT, not just per
#                  parent folder. Creating a folder whose name matches any
#                  other folder already in the same project -- even one
#                  nested elsewhere in the tree -- fails with:
#                    409 "secrets or folders that are in the same folder
#                         may not have the same name"
#                  Design your CSV so no two folders (at any depth) in the
#                  same project share a name. The script warns about this
#                  up front (see detect_name_collisions) but does not block.
#
#               2. The plain "list folders" endpoint only returns TOP-LEVEL
#                  folders, despite reading like it should return everything
#                  (its real name is ListTopLevelSecretFoldersForProject).
#                  Confirmed live 2026-08-14: a folder with 5 real
#                  sub-folders showed only itself in that list. Neither list
#                  nor get-single ever includes a parent_id field either way
#                  -- but there IS a per-folder children endpoint
#                  (.../secret_folders/{id}/items) that this script wasn't
#                  using before. fetch_all_folders() walks it recursively to
#                  see the whole tree; existing-folder detection
#                  (resolve_existing_folders) still matches by NAME ONLY,
#                  project-wide, which is safe given fact #1 (names are
#                  unique per project anyway) but means the script cannot
#                  verify a matched folder sits where the CSV intends; it
#                  can only confirm a folder with that name exists somewhere
#                  in the project.
#
#               3. Folder names may only contain letters, digits, hyphens,
#                  underscores, and periods -- NO SPACES or other characters.
#                  This is validated locally before any API call is made
#                  (see NAME_PATTERN / validate_names).
#
# Usage       : python create_secret_folders.py --csv folders.csv \
#                   --resource-group-id <rg_id> --project-id <proj_id>
#               (dry-run by default; add --execute to actually create)
#
# Auth        : Two-step service-user token exchange. Credentials are
#               resolved in this order: (1) OS environment variables
#               (OPA_BASE_DOMAIN / OPA_TEAM_NAME / OPA_KEY_ID /
#               OPA_KEY_SECRET), (2) a local .env file (legacy, plaintext,
#               opt-in -- only used if you create one yourself), (3) the
#               dashboard's encrypted environment store (environments.json
#               metadata + OS keychain secrets via `keyring`) -- whichever
#               environment is active in the dashboard. No secrets are ever
#               written to disk in plaintext by this script.
#
# Version     : 5.7.0
# =============================================================================

import argparse
import csv
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from datetime import datetime, timezone

SCRIPT_VERSION = "5.7.0"
NAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")

# ---------------------------------------------------------------------------
# Live-verified API constants
# ---------------------------------------------------------------------------
TOKEN_PATH = "/v1/teams/{team}/service_token"
RESOURCE_GROUPS_PATH = "/v1/teams/{team}/resource_groups"
PROJECTS_PATH = "/v1/teams/{team}/resource_groups/{resource_group_id}/projects"
GROUPS_PATH = "/v1/teams/{team}/groups"
FOLDERS_COLLECTION_PATH = (
    "/v1/teams/{team}/resource_groups/{resource_group_id}/projects/{project_id}/secret_folders"
)
FOLDER_ITEM_PATH = FOLDERS_COLLECTION_PATH + "/{folder_id}"
FOLDER_ITEMS_PATH = FOLDER_ITEM_PATH + "/items"
SECURITY_POLICY_PATH = "/v1/teams/{team}/security_policy"
SECURITY_POLICY_ITEM_PATH = SECURITY_POLICY_PATH + "/{security_policy_id}"
WORKLOAD_ROLES_PATH = "/v1/teams/{team}/workload-roles"
USERS_PATH = "/v1/teams/{team}/users"
USER_GROUPS_PATH = USERS_PATH + "/{user_name}/groups"
PROJECT_SERVERS_PATH = PROJECTS_PATH + "/{project_id}/servers"
PROJECT_SAAS_APP_ACCOUNTS_PATH = PROJECTS_PATH + "/{project_id}/saas_app_accounts"
PROJECT_OKTA_UD_ACCOUNTS_PATH = PROJECTS_PATH + "/{project_id}/okta_universal_directory_accounts"

FIELD_TYPE = "type"
TYPE_FOLDER = "folder"

# Confirmed live (2026-08-14) against a real tenant: creating a resource
# group requires at least one group in delegated_resource_admin_groups
# ("at least one user group should be associated with the resource group");
# creating a project needs only a name (no group field on Project itself).
# OPA's own POST /groups (local RBAC groups) is intentionally NOT used here
# -- groups must come from Okta (core API) and be pushed into the OPA app
# via Okta's Group Push Mapping API, per this tool's design.
OPA_APP_CATALOG_NAME = "okta_privileged_access_sso"

FIELD_NAME = "name"
FIELD_DESCRIPTION = "description"
# Confirmed live 2026-08-14 against the SecretFolderCreateRequest schema:
# the wire field is "parent_folder_id", NOT "parent_id" -- OPA silently
# ignores unknown body fields, so create_folder(..., parent_id=X) was
# never actually nesting anything; every folder the script created came
# out top-level regardless of the intended parent. Fixed here.
FIELD_PARENT_ID = "parent_folder_id"
FIELD_ID = "id"
LIST_ENVELOPE_KEY = "list"

# ---------------------------------------------------------------------------
# General config
# ---------------------------------------------------------------------------
ENV_BASE_DOMAIN = "OPA_BASE_DOMAIN"
ENV_TEAM_NAME = "OPA_TEAM_NAME"
ENV_KEY_ID = "OPA_KEY_ID"
ENV_KEY_SECRET = "OPA_KEY_SECRET"


def _load_dotenv():
    """If a .env file sits next to this script, load KEY=VALUE lines from it
    into os.environ (real environment variables always take priority --
    this only fills in values that aren't already set). Lets the CLI and
    the dashboard server both pick up credentials without the user having
    to fuss with OS-level environment variable settings. No external
    dependency -- this is intentionally a minimal parser, not python-dotenv."""
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.isfile(env_path):
        return
    with open(env_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)


_load_dotenv()

# ---------------------------------------------------------------------------
# Encrypted multi-environment credential store
# ---------------------------------------------------------------------------
# Non-secret metadata (base_domain, team_name, key_id, okta_url) lives in
# environments.json next to this script. Secrets (key_secret,
# okta_api_token) are NEVER written there -- they go to the OS keychain via
# the `keyring` package (Windows Credential Locker / macOS Keychain / Linux
# Secret Service), keyed per environment name. This is the dashboard's
# storage for named environments (dev/uat/prod); the CLI also reads from it
# as a fallback (see main()) so "whichever environment is active in the
# dashboard" is automatically usable from the command line too, without
# ever touching a plaintext file.
try:
    import keyring
    KEYRING_AVAILABLE = True
except ImportError:
    KEYRING_AVAILABLE = False

KEYRING_SERVICE_PREFIX = "opa-secrets-wizard"
ENVIRONMENT_METADATA_FIELDS = ("base_domain", "team_name", "key_id", "okta_url")
ENVIRONMENT_SECRET_FIELDS = ("key_secret", "okta_api_token")


def _environments_file_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "environments.json")


def load_environments():
    path = _environments_file_path()
    if not os.path.isfile(path):
        return {"active": None, "environments": {}}
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    data.setdefault("active", None)
    data.setdefault("environments", {})
    return data


def save_environments(data):
    with open(_environments_file_path(), "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _keyring_service(env_name):
    return f"{KEYRING_SERVICE_PREFIX}:{env_name}"


def _require_keyring():
    if not KEYRING_AVAILABLE:
        raise RuntimeError(
            "The 'keyring' package is required for encrypted credential storage. "
            "Install it with: pip install keyring"
        )


def keyring_set(env_name, field, value):
    _require_keyring()
    keyring.set_password(_keyring_service(env_name), field, value)


def keyring_get(env_name, field):
    if not KEYRING_AVAILABLE:
        return None
    try:
        return keyring.get_password(_keyring_service(env_name), field)
    except Exception:
        return None


def keyring_delete(env_name, field):
    if not KEYRING_AVAILABLE:
        return
    try:
        keyring.delete_password(_keyring_service(env_name), field)
    except Exception:
        pass


def upsert_environment(name, fields):
    """Saves non-secret metadata to environments.json and secret fields to
    the OS keychain. Blank secret fields on an update leave the previously
    stored secret untouched (so editing metadata doesn't force re-entering
    credentials). Raises ValueError if required fields end up missing."""
    if not name or not name.strip():
        raise ValueError("Environment name is required (e.g. dev, uat, prod).")
    name = name.strip()

    data = load_environments()
    meta = dict(data["environments"].get(name, {}))
    for field in ENVIRONMENT_SECRET_FIELDS:
        meta.pop(field, None)  # migrate away any pre-encryption plaintext secret left in metadata
    for field in ENVIRONMENT_METADATA_FIELDS:
        if field in fields:
            meta[field] = (fields.get(field) or "").strip()

    for field in ENVIRONMENT_SECRET_FIELDS:
        value = (fields.get(field) or "").strip()
        if value:
            keyring_set(name, field, value)
        # blank + already exists -> leave the previously stored secret alone

    missing = [f for f in ("base_domain", "team_name", "key_id") if not meta.get(f)]
    if missing:
        raise ValueError(f"Missing required field(s): {', '.join(missing)}")
    if not keyring_get(name, "key_secret"):
        raise ValueError("Missing required field: key_secret")

    data["environments"][name] = meta
    save_environments(data)
    return name


def delete_environment(name):
    """Removes an environment's metadata and both keychain secrets. Returns
    True if it was the active environment (caller should clear any live
    client). Raises KeyError if the name doesn't exist."""
    data = load_environments()
    if name not in data["environments"]:
        raise KeyError(f"No saved environment named '{name}'")
    del data["environments"][name]
    was_active = data.get("active") == name
    if was_active:
        data["active"] = None
    save_environments(data)
    for field in ENVIRONMENT_SECRET_FIELDS:
        keyring_delete(name, field)
    return was_active


def get_environment_credentials(name):
    """Returns the full merged credential dict (metadata + secrets from the
    keychain) for a saved environment. Raises KeyError if it doesn't exist."""
    data = load_environments()
    meta = data["environments"].get(name)
    if meta is None:
        raise KeyError(f"No saved environment named '{name}'")
    creds = dict(meta)
    for field in ENVIRONMENT_SECRET_FIELDS:
        creds[field] = keyring_get(name, field) or ""
    creds["name"] = name
    return creds


def get_active_environment_credentials():
    """Returns credentials for the currently-active saved environment, or
    None if none is set/active."""
    data = load_environments()
    name = data.get("active")
    if not name or name not in data.get("environments", {}):
        return None
    try:
        return get_environment_credentials(name)
    except KeyError:
        return None

REQUEST_TIMEOUT_SECS = 30
MAX_RETRIES = 3
RETRY_BACKOFF_SECS = 2
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}

# Okta/OPA APIs return standard rate-limit headers on every response
# (confirmed live 2026-08-14): x-ratelimit-limit, x-ratelimit-remaining,
# x-ratelimit-reset (unix seconds when the window resets). We track the
# latest known state per host and proactively wait out the window once
# few requests are left, rather than waiting to get hit with a 429.
RATE_LIMIT_MIN_REMAINING = 1
RATE_LIMIT_WAIT_BUFFER_SECS = 1
_rate_limit_lock = threading.Lock()
_rate_limit_state = {}  # host -> {"remaining": int, "reset": int}

COLOR = {
    "INFO": "\033[0m",
    "WARN": "\033[0;33m",
    "ERROR": "\033[0;31m",
    "SUCCESS": "\033[0;32m",
    "RESET": "\033[0m",
}


def log(level, message):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    color = COLOR.get(level, COLOR["INFO"])
    stream = sys.stderr if level in ("WARN", "ERROR") else sys.stdout
    print(f"{color}[{ts}] [{level}] {message}{COLOR['RESET']}", file=stream)


def die(message):
    log("ERROR", message)
    sys.exit(1)


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------
class OpaApiError(Exception):
    def __init__(self, status, url, body):
        self.status = status
        self.url = url
        self.body = body
        super().__init__(f"HTTP {status} calling {url}: {body}")


class OktaApiError(Exception):
    def __init__(self, status, url, body):
        self.status = status
        self.url = url
        self.body = body
        super().__init__(f"HTTP {status} calling {url}: {body}")


def _rate_limit_host(url):
    return urllib.parse.urlparse(url).netloc


def _record_rate_limit(url, headers):
    """Stash the latest x-ratelimit-* values for this host so the next
    request (possibly for a different endpoint on the same host) knows
    how much headroom is left before it needs to wait."""
    remaining = headers.get("x-ratelimit-remaining")
    reset = headers.get("x-ratelimit-reset")
    if remaining is None or reset is None:
        return
    try:
        remaining = int(remaining)
        reset = int(reset)
    except ValueError:
        return
    with _rate_limit_lock:
        _rate_limit_state[_rate_limit_host(url)] = {"remaining": remaining, "reset": reset}


def _wait_if_rate_limited(url):
    """Proactively sleep until the rate-limit window resets if the last
    response we saw for this host reported few requests left -- this is
    what keeps the recursive folder-tree walk (one API call per folder)
    from ever tripping a 429 in the first place."""
    with _rate_limit_lock:
        state = _rate_limit_state.get(_rate_limit_host(url))
    if not state or state["remaining"] > RATE_LIMIT_MIN_REMAINING:
        return
    wait_secs = state["reset"] - time.time() + RATE_LIMIT_WAIT_BUFFER_SECS
    if wait_secs > 0:
        log("WARN", f"Rate limit nearly exhausted for {_rate_limit_host(url)} "
                     f"({state['remaining']} request(s) left) -- waiting {wait_secs:.0f}s for the window to reset...")
        time.sleep(wait_secs)


def _retry_after_secs(headers):
    """On an actual 429, prefer an authoritative wait time over blind
    backoff: Retry-After (seconds) if present, else derive from
    x-ratelimit-reset (unix timestamp). Falls back to the fixed backoff
    only if neither header is present."""
    retry_after = headers.get("Retry-After")
    if retry_after is not None:
        try:
            return float(retry_after) + RATE_LIMIT_WAIT_BUFFER_SECS
        except ValueError:
            pass
    reset = headers.get("x-ratelimit-reset")
    if reset is not None:
        try:
            return max(0.0, int(reset) - time.time()) + RATE_LIMIT_WAIT_BUFFER_SECS
        except ValueError:
            pass
    return RETRY_BACKOFF_SECS * MAX_RETRIES


_LINK_HEADER_ENTRY_RE = re.compile(r'<([^>]+)>\s*;\s*rel="?([\w-]+)"?')


def _parse_next_link(link_header):
    """Extract the rel="next" URL from an RFC 8288 Link header (comma-
    separated <url>; rel="..." entries), or None if there isn't one."""
    if not link_header:
        return None
    for url, rel in _LINK_HEADER_ENTRY_RE.findall(link_header):
        if rel == "next":
            return url
    return None


def http_json_request(method, url, headers=None, body=None, error_cls=OpaApiError, return_headers=False):
    """Shared retrying HTTP-JSON helper used by both OpaClient and
    OktaClient, so the retry/backoff logic lives in exactly one place.
    Tracks x-ratelimit-* response headers per host and proactively waits
    out the window when few requests remain, so callers doing many
    sequential requests (e.g. the recursive folder-tree walk) shouldn't
    ever see a 429 in normal operation.

    With return_headers=True, returns (parsed_body, response_headers)
    instead of just parsed_body -- used for Link-header pagination."""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = dict(headers or {})
    headers.setdefault("Accept", "application/json")
    if data is not None:
        headers["Content-Type"] = "application/json"

    for attempt in range(1, MAX_RETRIES + 1):
        _wait_if_rate_limited(url)
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECS) as resp:
                _record_rate_limit(url, resp.headers)
                resp_headers = resp.headers
                raw = resp.read()
                parsed = json.loads(raw.decode("utf-8")) if raw else None
                return (parsed, resp_headers) if return_headers else parsed
        except urllib.error.HTTPError as e:
            _record_rate_limit(url, e.headers)
            raw_body = e.read().decode("utf-8", errors="replace")
            if e.code == 429 and attempt < MAX_RETRIES:
                wait_secs = _retry_after_secs(e.headers)
                log("WARN", f"{method} {url} -> HTTP 429 (rate limited); "
                            f"waiting {wait_secs:.0f}s before retry ({attempt}/{MAX_RETRIES})...")
                time.sleep(wait_secs)
                continue
            if e.code in RETRYABLE_STATUS_CODES and attempt < MAX_RETRIES:
                log("WARN", f"{method} {url} -> HTTP {e.code}, retrying ({attempt}/{MAX_RETRIES})...")
                time.sleep(RETRY_BACKOFF_SECS * attempt)
                continue
            raise error_cls(e.code, url, raw_body) from None
        except urllib.error.URLError as e:
            if attempt < MAX_RETRIES:
                log("WARN", f"{method} {url} -> network error ({e}), retrying ({attempt}/{MAX_RETRIES})...")
                time.sleep(RETRY_BACKOFF_SECS * attempt)
                continue
            raise


class OpaClient:
    def __init__(self, base_domain, team_name, key_id, key_secret):
        self.base_url = f"https://{base_domain}"
        self.team_name = team_name
        self.key_id = key_id
        self.key_secret = key_secret
        self.bearer_token = None
        self._fetch_token()

    def _fetch_token(self):
        path = TOKEN_PATH.format(team=self.team_name)
        body = {"key_id": self.key_id, "key_secret": self.key_secret}
        resp = self._raw_request("POST", path, body=body, authed=False)
        token = (resp or {}).get("bearer_token")
        if not token:
            raise OpaApiError("n/a", path, f"No 'bearer_token' in token response: {resp!r}")
        self.bearer_token = token

    def request(self, method, path, body=None, return_headers=False, _retried_auth=False):
        try:
            return self._raw_request(method, path, body=body, authed=True, return_headers=return_headers)
        except OpaApiError as e:
            if e.status == 401 and not _retried_auth:
                log("WARN", "Bearer token rejected (401); refreshing and retrying once...")
                self._fetch_token()
                return self.request(method, path, body=body, return_headers=return_headers, _retried_auth=True)
            raise

    def _raw_request(self, method, path, body=None, authed=True, return_headers=False):
        url = path if path.startswith("http://") or path.startswith("https://") else self.base_url + path
        headers = {"Authorization": f"Bearer {self.bearer_token}"} if authed else {}
        return http_json_request(method, url, headers=headers, body=body, error_cls=OpaApiError,
                                  return_headers=return_headers)

    def _list(self, path):
        """Fetches every page of a "list" envelope response, following the
        Link: rel="next" response header until exhausted -- no endpoint in
        this codebase ever wants only page 1, so pagination lives here
        once rather than being opted into per call site."""
        items = []
        next_path = path
        while next_path:
            resp, headers = self.request("GET", next_path, return_headers=True)
            if isinstance(resp, dict) and isinstance(resp.get(LIST_ENVELOPE_KEY), list):
                items.extend(resp[LIST_ENVELOPE_KEY])
            else:
                log("WARN", f"Unexpected list response shape, treating as empty: {resp!r}")
            next_path = _parse_next_link(headers.get("Link"))
        return items

    def list_resource_groups(self):
        path = RESOURCE_GROUPS_PATH.format(team=self.team_name)
        return self._list(path)

    def create_resource_group(self, name, description="", delegated_resource_admin_group_ids=None):
        """Confirmed live: OPA requires at least one group in
        delegated_resource_admin_groups to create a resource group."""
        path = RESOURCE_GROUPS_PATH.format(team=self.team_name)
        body = {FIELD_NAME: name}
        if description:
            body[FIELD_DESCRIPTION] = description
        if delegated_resource_admin_group_ids:
            body["delegated_resource_admin_groups"] = [
                {"id": gid} for gid in delegated_resource_admin_group_ids
            ]
        return self.request("POST", path, body=body)

    def list_projects(self, resource_group_id):
        path = PROJECTS_PATH.format(team=self.team_name, resource_group_id=resource_group_id)
        return self._list(path)

    def create_project(self, resource_group_id, name):
        path = PROJECTS_PATH.format(team=self.team_name, resource_group_id=resource_group_id)
        return self.request("POST", path, body={FIELD_NAME: name})

    def list_groups(self, contains=None):
        path = GROUPS_PATH.format(team=self.team_name)
        if contains:
            path += "?contains=" + urllib.parse.quote(contains)
        return self._list(path)

    def list_users(self):
        path = USERS_PATH.format(team=self.team_name)
        return self._list(path)

    def list_user_groups(self, user_name):
        path = USER_GROUPS_PATH.format(team=self.team_name, user_name=urllib.parse.quote(user_name, safe=""))
        return self._list(path)

    def list_security_policies(self):
        """Team-wide, not resource-group-scoped -- there's no server-side
        filter for resource group, so callers that need a subset filter
        this list themselves (see build_access_model)."""
        path = SECURITY_POLICY_PATH.format(team=self.team_name)
        return self._list(path)

    def get_security_policy(self, security_policy_id):
        path = SECURITY_POLICY_ITEM_PATH.format(team=self.team_name, security_policy_id=security_policy_id)
        return self.request("GET", path)

    def create_security_policy(self, policy_body):
        path = SECURITY_POLICY_PATH.format(team=self.team_name)
        return self.request("POST", path, body=policy_body)

    def update_security_policy(self, security_policy_id, policy_body):
        """PUT is a full replace, not a patch -- confirmed live 2026-08-14
        (returns 204, no body). Callers must GET the current policy first
        and submit the complete modified object; see
        upsert_folder_rule_in_policy for the one place that matters here."""
        path = SECURITY_POLICY_ITEM_PATH.format(team=self.team_name, security_policy_id=security_policy_id)
        return self.request("PUT", path, body=policy_body)

    def delete_security_policy(self, security_policy_id):
        path = SECURITY_POLICY_ITEM_PATH.format(team=self.team_name, security_policy_id=security_policy_id)
        return self.request("DELETE", path)

    def list_workload_roles(self, contains=None):
        path = WORKLOAD_ROLES_PATH.format(team=self.team_name)
        if contains:
            path += "?contains=" + urllib.parse.quote(contains)
        return self._list(path)

    def list_project_servers(self, resource_group_id, project_id):
        path = PROJECT_SERVERS_PATH.format(
            team=self.team_name, resource_group_id=resource_group_id, project_id=project_id
        )
        return self._list(path)

    def list_project_saas_app_accounts(self, resource_group_id, project_id):
        path = PROJECT_SAAS_APP_ACCOUNTS_PATH.format(
            team=self.team_name, resource_group_id=resource_group_id, project_id=project_id
        )
        return self._list(path)

    def list_project_okta_ud_accounts(self, resource_group_id, project_id):
        path = PROJECT_OKTA_UD_ACCOUNTS_PATH.format(
            team=self.team_name, resource_group_id=resource_group_id, project_id=project_id
        )
        return self._list(path)

    def list_folders(self, resource_group_id, project_id):
        """TOP-LEVEL (root) folders only -- despite its name, this endpoint
        (ListTopLevelSecretFoldersForProject) does not include nested
        folders. Confirmed live 2026-08-14: a folder with 5 real
        sub-folders showed only itself here; the sub-folders were entirely
        absent. Use fetch_all_folders() for the full tree -- see module
        docstring fact #2."""
        path = FOLDERS_COLLECTION_PATH.format(
            team=self.team_name, resource_group_id=resource_group_id, project_id=project_id
        )
        return self._list(path)

    def list_folder_items(self, resource_group_id, project_id, folder_id):
        """Direct children of one folder -- both sub-folders and secrets,
        distinguished by their "type" field (TYPE_FOLDER vs
        "key_value_secret"). This is the only way to discover nesting;
        there's no parent_id on any read response (see fetch_all_folders)."""
        path = FOLDER_ITEMS_PATH.format(
            team=self.team_name, resource_group_id=resource_group_id,
            project_id=project_id, folder_id=folder_id,
        )
        return self._list(path)

    def create_folder(self, resource_group_id, project_id, name, description, parent_id=None):
        path = FOLDERS_COLLECTION_PATH.format(
            team=self.team_name, resource_group_id=resource_group_id, project_id=project_id
        )
        body = {FIELD_NAME: name}
        if description:
            body[FIELD_DESCRIPTION] = description
        if parent_id:
            body[FIELD_PARENT_ID] = parent_id
        return self.request("POST", path, body=body)

    def delete_folder(self, resource_group_id, project_id, folder_id):
        """The API gives no cascade guarantee for a folder that still has
        children, and CreateSecretFolder's docs confirm nested creation is
        gated by a `folder_create` security-policy privilege separate from
        top-level creation -- there's no reason to assume delete is any
        less strict, and no safe way to find out by experiment (a wrong
        guess either orphans real data or mass-deletes it). Callers MUST
        check list_folder_items() first and refuse to delete a non-empty
        folder; see the server route."""
        path = FOLDER_ITEM_PATH.format(
            team=self.team_name, resource_group_id=resource_group_id, project_id=project_id, folder_id=folder_id
        )
        return self.request("DELETE", path)


class OktaClient:
    """Core Okta Identity Engine API (NOT OPA/PAM) -- used only to create a
    group in Okta and push it into the OPA app's Group Push mapping, per
    this tool's explicit design (groups must originate in Okta, not OPA's
    own local-group endpoint)."""

    def __init__(self, org_url, api_token):
        self.base_url = org_url.rstrip("/")
        self.api_token = api_token

    def request(self, method, path, body=None):
        url = self.base_url + path
        headers = {"Authorization": f"SSWS {self.api_token}"}
        return http_json_request(method, url, headers=headers, body=body, error_cls=OktaApiError)

    def create_group(self, name, description=""):
        body = {"profile": {"name": name, "description": description or ""}}
        return self.request("POST", "/api/v1/groups", body=body)

    def find_apps_by_catalog_name(self, catalog_name):
        query = urllib.parse.quote(f'name eq "{catalog_name}"')
        return self.request("GET", f"/api/v1/apps?filter={query}") or []

    def find_privileged_access_app(self):
        """Confirmed live: the Okta Privileged Access app integration has a
        stable catalog name (OPA_APP_CATALOG_NAME) regardless of its
        user-visible label, and its `features` list includes GROUP_PUSH
        when that feature is enabled."""
        apps = self.find_apps_by_catalog_name(OPA_APP_CATALOG_NAME)
        if not apps:
            raise OktaApiError(
                "n/a", "find_privileged_access_app",
                f"No Okta app found with catalog name '{OPA_APP_CATALOG_NAME}'. "
                "Is Okta Privileged Access installed in this org?",
            )
        if len(apps) > 1:
            raise OktaApiError(
                "n/a", "find_privileged_access_app",
                f"Found {len(apps)} apps matching '{OPA_APP_CATALOG_NAME}'; expected exactly one.",
            )
        app = apps[0]
        if "GROUP_PUSH" not in (app.get("features") or []):
            raise OktaApiError(
                "n/a", "find_privileged_access_app",
                "The Okta Privileged Access app does not have Group Push enabled.",
            )
        return app

    def create_group_push_mapping(self, app_id, source_group_id, target_group_name):
        path = f"/api/v1/apps/{app_id}/group-push/mappings"
        body = {"sourceGroupId": source_group_id, "status": "ACTIVE", "targetGroupName": target_group_name}
        return self.request("POST", path, body=body)


# ---------------------------------------------------------------------------
# Row parsing -> ordered folder tree
# ---------------------------------------------------------------------------
def parse_rows(rows, warn=True):
    """Shared core used by both the CLI (rows read from a CSV file) and the
    dashboard server (rows built interactively and submitted as JSON). Each
    row is a dict with 'path' (required, '/'-delimited) and optional
    'description'.

    Returns an ordered list of path tuples (parents before children) and a
    dict mapping path tuple -> description (only set where a row gave one
    explicitly; implied ancestor folders default to "")."""
    descriptions = {}
    seen_paths = set()

    for row_num, row in enumerate(rows, start=1):
        raw_path = (row.get("path") or "").strip()
        if not raw_path:
            if warn:
                log("WARN", f"Row {row_num}: empty path, skipping.")
            continue
        segments = tuple(seg.strip() for seg in raw_path.split("/") if seg.strip())
        if not segments:
            if warn:
                log("WARN", f"Row {row_num}: path '{raw_path}' has no usable segments, skipping.")
            continue

        description = (row.get("description") or "").strip()
        if segments in seen_paths and description and warn:
            log("WARN", f"Row {row_num}: duplicate path '{'/'.join(segments)}', keeping first description.")
        seen_paths.add(segments)
        if description and segments not in descriptions:
            descriptions[segments] = description

        # Register every ancestor too, so intermediate folders always get created.
        for depth in range(1, len(segments)):
            seen_paths.add(segments[:depth])

    ordered = sorted(seen_paths, key=lambda p: (len(p), p))
    return ordered, descriptions


def parse_csv(csv_path):
    """Reads a CSV file (columns: path, description) and delegates to
    parse_rows for the actual tree-building logic."""
    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames or "path" not in [c.strip() for c in reader.fieldnames]:
            die(f"CSV must have a 'path' column header. Found: {reader.fieldnames}")
        rows = list(reader)
    return parse_rows(rows)


def rows_from_tree(ordered_paths, descriptions):
    """Inverse of parse_rows: flattens the tree back into CSV-shaped rows,
    used when the dashboard saves an interactively-built tree to disk."""
    return [
        {"path": "/".join(path), "description": descriptions.get(path, "")}
        for path in ordered_paths
    ]


def validate_names(ordered_paths):
    """OPA rejects folder names containing anything but letters, digits,
    '-', '_', '.' (see module docstring fact #3). Check locally so a bad
    name fails fast with every offender listed, instead of a mid-run 400
    that aborts whatever hasn't been created yet."""
    invalid = [path for path in ordered_paths if not NAME_PATTERN.match(path[-1])]
    if invalid:
        log("ERROR", "These folder names contain characters OPA will reject (only A-Z a-z 0-9 . _ - are allowed):")
        for path in invalid:
            log("ERROR", f"  '{path[-1]}' (from path '{'/'.join(path)}')")
        die("Fix the CSV and re-run.")


def detect_name_collisions(ordered_paths):
    """OPA enforces folder-name uniqueness per PROJECT, not per parent (see
    module docstring fact #1). Warn if the CSV implies two different tree
    positions sharing the same folder name -- the second create will 409."""
    name_to_paths = {}
    for path in ordered_paths:
        name_to_paths.setdefault(path[-1], []).append(path)
    return {name: paths for name, paths in name_to_paths.items() if len(paths) > 1}


# ---------------------------------------------------------------------------
# Full folder tree (recursive -- see module docstring fact #2)
# ---------------------------------------------------------------------------
TYPE_SECRET = "key_value_secret"


def _walk_folder_tree(client, resource_group_id, project_id):
    """Shared BFS core for fetch_all_folders() and
    fetch_all_folders_and_secrets(): list_folders() alone only sees
    top-level folders, so this walks list_folder_items() breadth-first
    from each root to see the whole tree (any depth), tracking parent_id
    from the traversal itself since no read response ever includes it.
    One API call per folder discovered -- http_json_request's rate-limit
    handling keeps this safe for reasonably large trees.

    Returns (folders, secrets), each a flat list of dicts with
    {"id", "name", "description", "parent_id"}.
    """
    folders, secrets = [], []
    roots = client.list_folders(resource_group_id, project_id)
    queue = deque((folder, None) for folder in roots)
    while queue:
        folder, parent_id = queue.popleft()
        fid = folder.get(FIELD_ID)
        folders.append({
            "id": fid,
            "name": folder.get(FIELD_NAME),
            "description": folder.get(FIELD_DESCRIPTION, ""),
            "parent_id": parent_id,
        })
        if not fid:
            continue
        for child in client.list_folder_items(resource_group_id, project_id, fid):
            if child.get(FIELD_TYPE) == TYPE_FOLDER:
                queue.append((child, fid))
            elif child.get(FIELD_TYPE) == TYPE_SECRET:
                secrets.append({
                    "id": child.get(FIELD_ID),
                    "name": child.get(FIELD_NAME),
                    "description": child.get(FIELD_DESCRIPTION, ""),
                    "parent_id": fid,
                })
    return folders, secrets


def fetch_all_folders(client, resource_group_id, project_id):
    """Every folder in the project, any depth -- see _walk_folder_tree."""
    folders, _secrets = _walk_folder_tree(client, resource_group_id, project_id)
    return folders


def fetch_all_folders_and_secrets(client, resource_group_id, project_id):
    """Every folder AND secret in the project, any depth -- see
    _walk_folder_tree. Used by build_access_model to resolve
    secret_based_resource policy selectors down to a specific project."""
    return _walk_folder_tree(client, resource_group_id, project_id)


# ---------------------------------------------------------------------------
# Access model (Resource Groups / Projects / Policies / Users / Groups)
# ---------------------------------------------------------------------------
# Security policies are scoped to a Resource Group, never a Project -- there
# is no "what does this project have access to" endpoint. Attribution to a
# specific project has to be derived by resolving each rule's resource
# selector:
#
#   RESOLVABLE (the selector names one specific resource; matched below
#   against an index built by listing each project's own resources):
#     secret_folder / secret          -> matched by id directly
#     individual_server(_account)     -> matched by id directly
#     individual_*_saas_app_account   -> selector id is an Okta/SaaS ID, NOT
#                                         the OPA account's own id -- matched
#                                         against that account's
#                                         privileged_resource_id field
#                                         (live-confirmed 2026-08-14: the ids
#                                         differ, the names matched, and
#                                         privileged_resource_id was the key
#                                         that actually lined up)
#     individual_okta_account         -> same indirection, via okta_user_id
#
#   NOT RESOLVABLE (the selector is a dynamic pattern match, not a specific
#   resource -- live-confirmed against this tenant, not assumed):
#     server_label                    -> matches servers by label, live
#     active_directory                -> "name CONTAINS X" / "domain IN [Y]",
#                                         never a specific account
#     database                        -> same condition shape as AD
#   These are described as plain-English text instead (describe_dynamic_selector)
#   and surface at the resource-group level, not attributed to one project.
RESOURCE_TYPE_LABELS = {
    "secret_based_resource": "Secrets",
    "server_based_resource": "Servers",
    "managed_saas_app_based_resource": "Managed SaaS app accounts",
    "unmanaged_saas_app_based_resource": "Unmanaged SaaS app accounts",
    "okta_app_based_resource": "Okta app accounts",
    "active_directory_based_resource": "Active Directory accounts",
    "database_based_resource": "Database accounts",
}

_CONDITION_WORDS = {"CONTAINS": "contains", "STARTS_WITH": "starts with", "ENDS_WITH": "ends with", "EQUALS": "equals"}


def _condition_phrase(fmt, value):
    word = _CONDITION_WORDS.get(fmt, (fmt or "?").lower())
    return f"name {word} '{value}'"


def describe_dynamic_selector(resource_type, selector_type, selector):
    """Best-effort human-readable description of a selector that can't be
    resolved to a specific project (label/pattern-based, or a shape this
    script doesn't recognize -- never raises, since live selector shapes
    have already diverged from the downloaded OpenAPI spec more than once
    on this project; an unrecognized shape should degrade to a generic
    label, not break the whole access model)."""
    try:
        if selector_type == "server_label":
            labels = ((selector.get("server_selector") or {}).get("labels")) or {}
            label_text = ", ".join(f"{k}={v}" for k, v in labels.items()) or "(no labels)"
            return f"Servers labeled {label_text}"
        if selector_type == "active_directory":
            accounts = selector.get("individual_accounts") or {}
            by_condition = accounts.get("by_condition")
            by_domain = accounts.get("by_domain")
            if by_condition:
                return f"AD accounts where {_condition_phrase(by_condition.get('account_name_format'), by_condition.get('value'))}"
            if by_domain:
                return f"AD accounts in domain(s): {', '.join(by_domain)}"

            # "Shared" AD accounts (live-confirmed 2026-08-14): a distinct
            # sub-shape from individual_accounts above -- names specific
            # accounts by SID/domain rather than a name pattern. The
            # optional "servers" field scoping which servers the shared
            # account applies to is a SIBLING of shared_accounts on the
            # selector itself, not nested inside it.
            shared = selector.get("shared_accounts") or {}
            specific = shared.get("specific_accounts")
            if specific:
                names = ", ".join(a.get("account_name", "?") for a in specific)
                scope = ((selector.get("servers") or {}).get("selectors") or [{}])[0].get("selector") or {}
                scope_labels = scope.get("labels") or {}
                scope_text = f", on servers labeled {', '.join(f'{k}={v}' for k, v in scope_labels.items())}" if scope_labels else ""
                return f"Shared AD account(s): {names}{scope_text}"
            if shared.get("by_domain"):
                return f"Shared AD accounts in domain(s): {', '.join(shared['by_domain'])}"
            if shared.get("by_matching_names"):
                return "Shared AD accounts matching configured name rules"
        if selector_type == "database":
            conns = selector.get("database_connections") or []
            conn_names = ", ".join(c.get("name", "?") for c in conns) or "(any connection)"
            accts = selector.get("database_accounts") or []
            conds = "; ".join(_condition_phrase(a.get("account_name_format"), a.get("value")) for a in accts)
            return f"Database accounts in {conn_names}" + (f" where {conds}" if conds else "")
    except Exception:
        pass
    return f"{RESOURCE_TYPE_LABELS.get(resource_type, resource_type)} ({selector_type})"


def _privilege_flags(privilege_value):
    """Extract the granted permission flags from a privilege_value object,
    e.g. {"_type":"secret","list":true,"secret_reveal":true,"secret_update":false}
    -> ["list","secret_reveal"]. Works uniformly across every privilege
    type -- most have a single boolean, "secret" has eight."""
    if not isinstance(privilege_value, dict):
        return []
    return [k for k, v in privilege_value.items() if k != "_type" and v is True]


# ---------------------------------------------------------------------------
# Folder Builder policy assignment (display + create/attach a secret_folder
# rule) -- a lighter sibling of the Access Explorer machinery above. This
# context already knows which resource group/project it's in, so it never
# needs the cross-project resolution indexes build_access_model builds;
# it only needs the raw target name/id (or a condition description for
# dynamic selectors, reusing describe_dynamic_selector for consistency).
# ---------------------------------------------------------------------------
SECRET_PRIVILEGE_FIELDS = (
    "list", "secret_create", "secret_update", "secret_delete", "secret_reveal",
    "folder_create", "folder_update", "folder_delete",
)


def build_secret_privilege(flags):
    """flags is a dict of {field: bool}, possibly partial -- any of the 8
    required SecurityPolicySecretPrivilege fields not present default to
    False (the API requires all 8 present on every write)."""
    value = {f: bool((flags or {}).get(f)) for f in SECRET_PRIVILEGE_FIELDS}
    value["_type"] = "secret"
    return value


def build_secret_folder_selector(folder_id, folder_name):
    return {
        "_type": "secret_based_resource",
        "selectors": [
            {
                "selector_type": "secret_folder",
                "selector": {"_type": "secret_folder", "secret_folder": {"id": folder_id, "name": folder_name}},
            }
        ],
    }


def build_mfa_condition(reauth_seconds, acr_values):
    return {
        "condition_type": "mfa",
        "condition_value": {
            "_type": "mfa",
            "re_auth_frequency_in_seconds": reauth_seconds,
            "acr_values": acr_values,
        },
    }


def _rule_targets_folder(rule, folder_id):
    for entry in (rule.get("resource_selector") or {}).get("selectors") or []:
        if entry.get("selector_type") == "secret_folder":
            ref = (entry.get("selector") or {}).get("secret_folder") or {}
            if ref.get("id") == folder_id:
                return True
    return False


def upsert_folder_rule_in_policy(policy, folder_id, folder_name, rule_name, privilege_flags, mfa=None):
    """Mutates and returns policy["rules"]: replaces the rule that already
    targets this exact folder (by secret_folder id), or appends a new one.
    `policy` must be the full object from get_security_policy -- PUT is a
    full replace (see OpaClient.update_security_policy), never a patch."""
    new_rule = {
        "name": rule_name,
        "resource_type": "secret_based_resource",
        "resource_selector": build_secret_folder_selector(folder_id, folder_name),
        "privileges": [{"privilege_type": "secret", "privilege_value": build_secret_privilege(privilege_flags)}],
        "conditions": [build_mfa_condition(**mfa)] if mfa else [],
    }
    rules = policy.setdefault("rules", [])
    for i, rule in enumerate(rules):
        if _rule_targets_folder(rule, folder_id):
            rules[i] = new_rule
            return policy
    rules.append(new_rule)
    return policy


def merge_principals(principals, group_refs, workload_role_refs):
    """Dedups by id, adding any of group_refs/workload_role_refs
    ({"id","name"} dicts, already resolved by the caller) not already
    present. Principals apply to the WHOLE policy, not per-rule -- adding
    a group here grants it every other rule already in the policy too."""
    principals = principals or {}
    user_groups = list(principals.get("user_groups") or [])
    seen_group_ids = {g["id"] for g in user_groups}
    for ref in group_refs or []:
        if ref["id"] not in seen_group_ids:
            user_groups.append(ref)
            seen_group_ids.add(ref["id"])

    workload_roles = list(principals.get("workload_roles") or [])
    seen_role_ids = {r["id"] for r in workload_roles}
    for ref in workload_role_refs or []:
        if ref["id"] not in seen_role_ids:
            workload_roles.append(ref)
            seen_role_ids.add(ref["id"])

    return {"user_groups": user_groups, "workload_roles": workload_roles}


def _summarize_rule_targets(rule):
    """Like build_access_model's rule resolution, but without the
    cross-project indexes -- just the raw target name/id for individual-
    resource selectors, or a condition description for dynamic ones."""
    resource_type = rule.get("resource_type")
    entries = (rule.get("resource_selector") or {}).get("selectors") or []
    targets = []
    for entry in entries:
        selector_type = entry.get("selector_type")
        selector = entry.get("selector") or {}
        ref = None
        try:
            if selector_type == "secret_folder":
                ref = selector.get("secret_folder")
            elif selector_type == "secret":
                ref = selector.get("secret")
            elif selector_type in ("individual_server", "individual_server_account"):
                ref = selector.get("server")
            elif selector_type in (
                "individual_managed_saas_app_account", "individual_unmanaged_saas_app_account", "individual_okta_account",
            ):
                ref = selector.get("service_account")
        except Exception:
            ref = None
        if ref:
            targets.append({"kind": "resolved", "id": ref.get("id"), "name": ref.get("name")})
        else:
            targets.append({"kind": "condition", "description": describe_dynamic_selector(resource_type, selector_type, selector)})
    return targets or [{"kind": "condition", "description": RESOURCE_TYPE_LABELS.get(resource_type, resource_type)}]


def summarize_security_policy(policy):
    """Presentation-friendly shape for Folder Builder's policy picker/
    badge -- same field names as build_access_model's policies for
    familiarity, but "targets" (not "resolutions") since there's no
    project attribution here, and no dedicated TS type shares this with
    Access Explorer's (kept deliberately separate, see module notes)."""
    return {
        "id": policy.get("id"),
        "name": policy.get("name"),
        "description": policy.get("description", ""),
        "active": policy.get("active", False),
        "type": policy.get("type"),
        "resource_group": policy.get("resource_group"),
        "principals": policy.get("principals", {"user_groups": [], "workload_roles": []}),
        "rules": [
            {
                "name": rule.get("name"),
                "resource_type": rule.get("resource_type"),
                "resource_type_label": RESOURCE_TYPE_LABELS.get(rule.get("resource_type"), rule.get("resource_type")),
                "privileges": [
                    {"privilege_type": p.get("privilege_type"), "flags": _privilege_flags(p.get("privilege_value"))}
                    for p in rule.get("privileges", [])
                ],
                "conditions": rule.get("conditions", []),
                "targets": _summarize_rule_targets(rule),
            }
            for rule in policy.get("rules", [])
        ],
    }


def _resolve_selector_entry(resource_type, selector_type, selector, indexes):
    """Resolve one selector entry to a concrete project-attributed resource
    (kind="resolved") when its type names an individual resource, else
    describe it as a condition (kind="condition"). Never raises -- a
    resolvable type whose fields aren't where expected falls back to a
    condition description rather than breaking the whole model."""
    try:
        ref, hit = None, None
        if selector_type == "secret_folder":
            ref = selector.get("secret_folder") or {}
            hit = indexes["secret_folders"].get(ref.get("id"))
        elif selector_type == "secret":
            ref = selector.get("secret") or {}
            hit = indexes["secrets"].get(ref.get("id"))
        elif selector_type in ("individual_server", "individual_server_account"):
            ref = selector.get("server") or {}
            hit = indexes["servers"].get(ref.get("id"))
        elif selector_type in ("individual_managed_saas_app_account", "individual_unmanaged_saas_app_account"):
            ref = selector.get("service_account") or {}
            hit = indexes["saas_accounts"].get(ref.get("id"))
        elif selector_type == "individual_okta_account":
            ref = selector.get("service_account") or {}
            hit = indexes["okta_accounts"].get(ref.get("id"))

        if ref is not None:
            resolved = {"kind": "resolved", "id": ref.get("id"), "name": ref.get("name"),
                        "project_id": None, "project_name": None, "resource_group_id": None}
            if hit:
                resolved.update(hit)
            return resolved
    except Exception:
        pass
    return {"kind": "condition", "description": describe_dynamic_selector(resource_type, selector_type, selector)}


def _resolve_rule(rule, indexes):
    resource_type = rule.get("resource_type")
    entries = (rule.get("resource_selector") or {}).get("selectors") or []
    resolutions = [
        _resolve_selector_entry(resource_type, entry.get("selector_type"), entry.get("selector") or {}, indexes)
        for entry in entries
    ]
    return resolutions or [{"kind": "condition",
                             "description": RESOURCE_TYPE_LABELS.get(resource_type, resource_type)}]


# Canonical step sequence for progress reporting -- shared with the
# server's job runner so the frontend can render "step N of len(STEPS)"
# and know which label goes with which key. Steps with per-item detail
# (index_resources, user_groups) also emit "progress" events between
# their "start" and "done".
ACCESS_MODEL_STEPS = [
    ("resource_groups", "Fetching resource groups"),
    ("groups", "Fetching groups"),
    ("users", "Fetching users"),
    ("projects", "Fetching projects"),
    ("index_resources", "Indexing project resources (folders, secrets, servers, accounts)"),
    ("user_groups", "Fetching user group memberships"),
    ("policies", "Fetching security policies"),
    ("resolve", "Resolving policy access"),
]


def _report(on_progress, key, status, detail=None):
    """Progress reporting must never break the actual job -- a broken
    callback (e.g. a dropped websocket) shouldn't take down the fetch
    it's just supposed to be narrating."""
    if on_progress is None:
        return
    try:
        on_progress(key, status, detail)
    except Exception:
        pass


def build_access_model(client, on_progress=None):
    """Fetches resource groups, projects, groups, users (+ their groups),
    and every security policy, then resolves each policy rule's selectors
    down to a specific project where possible (see module notes above).

    Returns one JSON-able dict: {resource_groups, projects, groups, users,
    policies}. This is the whole payload behind the dashboard's Access
    Explorer -- one bootstrap call, meant to be cached client-side and
    refreshed on demand. Not cheap: roughly one API call per folder/secret
    discovered, per project's server/SaaS/Okta-UD list, and per user's
    group membership -- http_json_request's rate-limit handling is what
    keeps this safe on a tenant with real data volume.

    on_progress(key, status, detail), if given, is called as
    ("start"|"progress"|"done") events matching ACCESS_MODEL_STEPS above --
    see the server's job runner for how this drives a pollable status
    endpoint. If this function raises, the last step reported "start"
    without a matching "done" is the one that failed.
    """
    _report(on_progress, "resource_groups", "start")
    resource_groups = client.list_resource_groups()
    _report(on_progress, "resource_groups", "done", f"{len(resource_groups)} resource group(s)")

    _report(on_progress, "groups", "start")
    groups = client.list_groups()
    _report(on_progress, "groups", "done", f"{len(groups)} group(s)")

    _report(on_progress, "users", "start")
    users = client.list_users()
    _report(on_progress, "users", "done", f"{len(users)} user(s)")

    _report(on_progress, "projects", "start")
    projects_by_rg = [(rg, client.list_projects(rg["id"])) for rg in resource_groups]
    total_projects = sum(len(ps) for _rg, ps in projects_by_rg)
    _report(on_progress, "projects", "done",
            f"{total_projects} project(s) across {len(resource_groups)} resource group(s)")

    indexes = {"secret_folders": {}, "secrets": {}, "servers": {}, "saas_accounts": {}, "okta_accounts": {}}
    projects = []

    _report(on_progress, "index_resources", "start")
    indexed_count = 0
    for rg, rg_projects in projects_by_rg:
        for project in rg_projects:
            project = dict(project)
            project["resource_group_id"] = rg["id"]
            projects.append(project)
            proj_ref = {"project_id": project["id"], "project_name": project["name"], "resource_group_id": rg["id"]}

            folders, secrets = fetch_all_folders_and_secrets(client, rg["id"], project["id"])
            for f in folders:
                if f.get("id"):
                    indexes["secret_folders"][f["id"]] = proj_ref
            for s in secrets:
                if s.get("id"):
                    indexes["secrets"][s["id"]] = proj_ref

            for server in client.list_project_servers(rg["id"], project["id"]):
                if server.get("id"):
                    indexes["servers"][server["id"]] = proj_ref

            for acct in client.list_project_saas_app_accounts(rg["id"], project["id"]):
                key = acct.get("privileged_resource_id")
                if key:
                    indexes["saas_accounts"][key] = proj_ref

            for acct in client.list_project_okta_ud_accounts(rg["id"], project["id"]):
                key = acct.get("okta_user_id")
                if key:
                    indexes["okta_accounts"][key] = proj_ref

            indexed_count += 1
            _report(on_progress, "index_resources", "progress",
                    f"{indexed_count}/{total_projects} projects ({project['name']})")
    _report(on_progress, "index_resources", "done", f"{indexed_count} project(s) indexed")

    _report(on_progress, "user_groups", "start")
    users_with_groups = []
    for i, user in enumerate(users):
        user = dict(user)
        try:
            user["groups"] = client.list_user_groups(user.get("name"))
        except OpaApiError as exc:
            user["groups"] = []
            log("WARN", f"Could not fetch groups for user '{user.get('name')}': {exc}")
        users_with_groups.append(user)
        _report(on_progress, "user_groups", "progress", f"{i + 1}/{len(users)} users ({user.get('name')})")
    _report(on_progress, "user_groups", "done", f"{len(users)} user(s)")

    _report(on_progress, "policies", "start")
    all_policies = client.list_security_policies()
    _report(on_progress, "policies", "done", f"{len(all_policies)} polic(ies)")

    _report(on_progress, "resolve", "start")
    policies_out = []
    for policy in all_policies:
        rules_out = []
        for rule in policy.get("rules", []):
            rules_out.append({
                "name": rule.get("name"),
                "resource_type": rule.get("resource_type"),
                "resource_type_label": RESOURCE_TYPE_LABELS.get(rule.get("resource_type"), rule.get("resource_type")),
                "privileges": [
                    {"privilege_type": p.get("privilege_type"), "flags": _privilege_flags(p.get("privilege_value"))}
                    for p in rule.get("privileges", [])
                ],
                "conditions": rule.get("conditions", []),
                "resolutions": _resolve_rule(rule, indexes),
            })
        policies_out.append({
            "id": policy.get("id"),
            "name": policy.get("name"),
            "description": policy.get("description", ""),
            "active": policy.get("active", False),
            "type": policy.get("type"),
            "resource_group": policy.get("resource_group"),
            "principals": policy.get("principals", {}),
            "rules": rules_out,
        })
    _report(on_progress, "resolve", "done", f"{len(policies_out)} polic(ies) resolved")

    return {
        "resource_groups": resource_groups,
        "projects": projects,
        "groups": groups,
        "users": users_with_groups,
        "policies": policies_out,
    }


# ---------------------------------------------------------------------------
# Existing-folder resolution
# ---------------------------------------------------------------------------
def resolve_existing_folders(client, resource_group_id, project_id, ordered_paths):
    """Returns dict: path tuple -> folder_id, for folders that already exist.

    Matches by NAME ONLY (project-wide), which is safe as long as fact #1
    (per-project name uniqueness) holds in your tenant -- but the folders
    themselves now come from fetch_all_folders() so nested existing folders
    are found too, not just top-level ones (see module docstring fact #2).
    """
    folders = fetch_all_folders(client, resource_group_id, project_id)
    log("INFO", f"Scanned {len(folders)} existing folder(s) in project (recursive, all depths).")
    name_to_id = {}
    for f in folders:
        name = f.get(FIELD_NAME)
        fid = f.get(FIELD_ID)
        if not name or not fid:
            continue
        if name in name_to_id:
            log("WARN", f"Tenant already has more than one folder named '{name}' in this project; using the first one found.")
            continue
        name_to_id[name] = fid

    existing = {}
    for path in ordered_paths:
        fid = name_to_id.get(path[-1])
        if fid:
            existing[path] = fid
    return existing


# ---------------------------------------------------------------------------
# Plan / execute
# ---------------------------------------------------------------------------
def print_plan(ordered_paths, existing, collisions):
    if collisions:
        log("WARN", "Name collisions detected -- OPA requires folder names to be unique per project:")
        for name, paths in collisions.items():
            where = ", ".join("/".join(p) for p in paths)
            log("WARN", f"  '{name}' is used at multiple positions: {where}")
        log("WARN", "Only the first folder created with each name will succeed; the rest will error with 409.")

    log("INFO", "Planned folder tree:")
    for path in ordered_paths:
        indent = "  " * (len(path) - 1)
        marker = "[exists]     " if path in existing else "[will create]"
        log("INFO", f"  {indent}{marker} {path[-1]}  (full path: {'/'.join(path)})")


def execute_plan(client, resource_group_id, project_id, ordered_paths, descriptions, existing):
    results = []
    folder_ids = dict(existing)

    for path in ordered_paths:
        if path in folder_ids:
            results.append((path, folder_ids[path], "skipped_exists", ""))
            continue

        parent_id = folder_ids.get(path[:-1]) if len(path) > 1 else None
        if len(path) > 1 and not parent_id:
            msg = f"Parent path '{'/'.join(path[:-1])}' was not created successfully; skipping."
            log("ERROR", msg)
            results.append((path, "", "error", msg))
            continue

        name = path[-1]
        description = descriptions.get(path, "")
        try:
            created = client.create_folder(
                resource_group_id, project_id, name, description, parent_id=parent_id
            )
            new_id = (created or {}).get(FIELD_ID, "")
            if not new_id:
                raise OpaApiError("n/a", "create_folder", f"No '{FIELD_ID}' in response: {created!r}")
            folder_ids[path] = new_id
            results.append((path, new_id, "created", ""))
            log("SUCCESS", f"Created '{'/'.join(path)}' (id={new_id})")
        except OpaApiError as e:
            log("ERROR", f"Failed to create '{'/'.join(path)}': {e}")
            results.append((path, "", "error", str(e)))

    return results


def write_results_csv(output_path, results):
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["path", "folder_id", "status", "error_message"])
        for path, folder_id, status, error_message in results:
            writer.writerow(["/".join(path), folder_id, status, error_message])
    log("INFO", f"Results written to {output_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Bulk-create Okta Privileged Access secret folders from a CSV of paths."
    )
    parser.add_argument("--csv", required=True, help="Path to input CSV (columns: path, description)")
    parser.add_argument("--resource-group-id", required=True)
    parser.add_argument("--project-id", required=True)
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually create folders. Without this flag, only a dry-run preview is shown.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output results CSV path (default: folders_result_<timestamp>.csv)",
    )
    args = parser.parse_args()

    if not os.path.isfile(args.csv):
        die(f"CSV file not found: {args.csv}")

    base_domain = os.environ.get(ENV_BASE_DOMAIN, "").strip()
    team_name = os.environ.get(ENV_TEAM_NAME, "").strip()
    key_id = os.environ.get(ENV_KEY_ID, "").strip()
    key_secret = os.environ.get(ENV_KEY_SECRET, "").strip()

    if not all([base_domain, team_name, key_id, key_secret]):
        active = get_active_environment_credentials()
        if active:
            base_domain = base_domain or active.get("base_domain", "")
            team_name = team_name or active.get("team_name", "")
            key_id = key_id or active.get("key_id", "")
            key_secret = key_secret or active.get("key_secret", "")
            log("INFO", f"Using credentials from the dashboard's active environment ('{active.get('name')}').")

    missing = [name for name, val in [
        (ENV_BASE_DOMAIN, base_domain), (ENV_TEAM_NAME, team_name),
        (ENV_KEY_ID, key_id), (ENV_KEY_SECRET, key_secret),
    ] if not val]
    if missing:
        die(
            f"Missing required credential(s): {', '.join(missing)}. "
            "Set them as environment variables, in a local .env file, or activate an "
            "environment in the dashboard."
        )

    log("INFO", f"OPA Secret Folder Bulk Creator v{SCRIPT_VERSION}")
    log("INFO", f"Mode: {'EXECUTE' if args.execute else 'DRY-RUN (no changes will be made)'}")

    ordered_paths, descriptions = parse_csv(args.csv)
    if not ordered_paths:
        die("No usable paths found in CSV.")

    validate_names(ordered_paths)
    collisions = detect_name_collisions(ordered_paths)

    try:
        client = OpaClient(base_domain, team_name, key_id, key_secret)
        existing = resolve_existing_folders(client, args.resource_group_id, args.project_id, ordered_paths)
    except OpaApiError as e:
        die(f"Failed during setup/lookup: {e}")

    print_plan(ordered_paths, existing, collisions)

    if not args.execute:
        log("INFO", "Dry-run complete. Re-run with --execute to actually create the folders above.")
        return

    results = execute_plan(client, args.resource_group_id, args.project_id, ordered_paths, descriptions, existing)

    output_path = args.output or f"folders_result_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    write_results_csv(output_path, results)

    created = sum(1 for r in results if r[2] == "created")
    skipped = sum(1 for r in results if r[2] == "skipped_exists")
    errors = sum(1 for r in results if r[2] == "error")
    log("SUCCESS", f"Done. Created={created} Skipped(existing)={skipped} Errors={errors}")
    if errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
