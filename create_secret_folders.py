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
# Version     : 5.26.0
# =============================================================================

import argparse
import csv
import email.utils
import json
import os
import re
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

SCRIPT_VERSION = "5.26.0"
NAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")

# ---------------------------------------------------------------------------
# Live-verified API constants
# ---------------------------------------------------------------------------
TOKEN_PATH = "/v1/teams/{team}/service_token"
RESOURCE_GROUPS_PATH = "/v1/teams/{team}/resource_groups"
PROJECTS_PATH = "/v1/teams/{team}/resource_groups/{resource_group_id}/projects"
GROUPS_PATH = "/v1/teams/{team}/groups"
GROUP_MEMBERS_PATH = GROUPS_PATH + "/{group_name}/users"
GROUP_MEMBER_ITEM_PATH = GROUP_MEMBERS_PATH + "/{user_name}"
CURRENT_USER_PATH = "/v1/teams/{team}/current_user"
FOLDERS_COLLECTION_PATH = (
    "/v1/teams/{team}/resource_groups/{resource_group_id}/projects/{project_id}/secret_folders"
)
FOLDER_ITEM_PATH = FOLDERS_COLLECTION_PATH + "/{folder_id}"
FOLDER_ITEMS_PATH = FOLDER_ITEM_PATH + "/items"
SECURITY_POLICY_PATH = "/v1/teams/{team}/security_policy"
SECURITY_POLICY_ITEM_PATH = SECURITY_POLICY_PATH + "/{security_policy_id}"
WORKLOAD_ROLES_PATH = "/v1/teams/{team}/workload-roles"
# Confirmed live 2026-09-30 via the real OPA API's own live OpenAPI spec
# (GET /v1/openapi.json) -- tenant-wide, not resource_group/project-scoped,
# same as WORKLOAD_ROLES_PATH. Distinct resource from a workload ROLE: a
# connection is the actual JWT/JWT_STATIC trust config (issuer, audience,
# JWKS URL, matcher conditions) a role's `requirements[].workload_connection`
# points at.
WORKLOAD_CONNECTIONS_PATH = "/v1/teams/{team}/connections/workloads"
# Confirmed live 2026-09-30 (found via the same GET /v1/openapi.json spec
# discovery) -- tenant-wide. A gateway here is the actual gateway
# CONFIGURATION resource (access_address, infrastructure_orchestrator,
# refuse_connections, labels) -- distinct from the server object hosting
# it (list_project_servers, which shows the same gateway host but only
# via a "broker" entry in its services[] list, with none of these
# gateway-specific fields).
GATEWAYS_PATH = "/v1/teams/{team}/gateways"
# The rest of the "connections" family, confirmed live 2026-09-30 -- all
# tenant-wide, all distinct from the per-project ACCOUNT resources they
# back (a connection is the integration config; an account is one
# discovered identity reachable through it):
DATABASE_CONNECTIONS_PATH = "/v1/teams/{team}/connections/databases"
SAAS_APP_CONNECTIONS_PATH = "/v1/teams/{team}/connections/saas_apps"
ACTIVE_DIRECTORY_CONNECTIONS_PATH = "/v1/teams/{team}/connections/active_directory"
# Confirmed live 2026-09-30 against the real opa-minimal.yaml OpenAPI spec
# AND a real tenant (patlabs) -- tenant-wide, same family as the
# connections/* paths above. A Client is an END USER's local OPA client
# install (laptop/workstation running the OPA desktop app or `sft`), NOT
# a managed server/gateway resource -- it's what a human enrolls to be
# able to make SSH/RDP connections at all. Real fields confirmed live:
# id, user_name, description, hostname, os, encrypted, deleted_at, state
# (state is ACTIVE/PENDING/DELETED). ?all=true is required to see every
# client across the team rather than just the caller's own.
CLIENTS_PATH = "/v1/teams/{team}/clients"
USERS_PATH = "/v1/teams/{team}/users"
USER_GROUPS_PATH = USERS_PATH + "/{user_name}/groups"
PROJECT_SERVERS_PATH = PROJECTS_PATH + "/{project_id}/servers"
PROJECT_SAAS_APP_ACCOUNTS_PATH = PROJECTS_PATH + "/{project_id}/saas_app_accounts"
PROJECT_OKTA_UD_ACCOUNTS_PATH = PROJECTS_PATH + "/{project_id}/okta_universal_directory_accounts"
# Both confirmed live 2026-09-30 against a real tenant (patlabs) -- neither
# was previously used anywhere in this codebase. Same {"list": [...]}
# collection shape as the three siblings above.
PROJECT_ACTIVE_DIRECTORY_ACCOUNTS_PATH = PROJECTS_PATH + "/{project_id}/active_directory_accounts"
PROJECT_DATABASE_ACCOUNTS_PATH = PROJECTS_PATH + "/{project_id}/database_accounts"
# Confirmed live 2026-09-30 -- a SEPARATE access-grant mechanism from
# security policies (AccessPolicy/PolicyRule): a "relationship" is a named
# grant type (e.g. "Service Account Users"), and an "assignment" links one
# relationship to a principal (a real user_group in this tenant) plus the
# specific resource(s) it grants (e.g. one SaaS service account). Both are
# tenant-wide -- no resource_group_id in the real response, unlike every
# per-project resource above.
ASSIGNMENTS_PATH = "/v1/teams/{team}/assignments"
RELATIONSHIPS_PATH = "/v1/teams/{team}/relationships"
# Confirmed live 2026-09-30 -- explains WHY an individual AD account (e.g.
# a1ruchir.parikh@usp.atkoepd.com) exists as a discovered resource at all:
# an AD connection's discovery `rules` (OU-scoped SHARED/INDIVIDUAL scans)
# plus its `rule_settings` (matching_criteria -- which real Okta user
# fields it matches by, e.g. username -- and partial_matching_criteria,
# e.g. "STARTS WITH a1") together are the real config that produced the
# match. No database-connection equivalent exists (confirmed live via a
# real 404 on the analogous path) -- this is AD-only.
AD_CONNECTION_RULES_PATH = "/v1/teams/{team}/resource_assignment/active_directory/{ad_connection_id}/rules"
AD_CONNECTION_RULE_SETTINGS_PATH = "/v1/teams/{team}/resource_assignment/active_directory/{ad_connection_id}/rule_settings"

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

SYSTEM_LOG_PATH = "/api/v1/logs"

def _target_ids(event):
    """Default id-extraction: every id in the event's target[] array. Right
    for eventTypes where the resource being accessed is a first-class
    target, e.g. pam.secret.reveal (target[] includes the secret's own
    id)."""
    return {t.get("id") for t in (event.get("target") or [])}


def _gateway_creds_server_ids(event):
    """id-extraction for pam.gateway_creds.issue: confirmed live 2026-08-14
    that this eventType's target[] NEVER includes the server (only
    Client/Gateway/Team) -- the server being connected to instead lives in
    debugContext.debugData.nextHopServerIds, a comma-separated string (the
    plural name suggests multi-hop is possible, even though every real
    sample seen so far had exactly one id)."""
    debug_data = (event.get("debugContext") or {}).get("debugData") or {}
    raw = debug_data.get("nextHopServerIds") or ""
    return {part.strip() for part in raw.split(",") if part.strip()}


# Each entry: eventType(s) to query for, and how to pull the matched
# resource id(s) back out of a returned event (defaults to target[] ids,
# since that's right for most PAM events -- only override extract_ids when
# an eventType puts the resource id somewhere else instead, as confirmed
# for individual_server_account below).
#
# Confirmed live 2026-08-14 against a real tenant's actual System Log data
# (not guessed from docs): "secret" resources have a working, ID-matchable
# access event -- pam.secret.reveal's target[] includes the secret's own
# id. "secret_folder" resources do NOT: browsing/listing a folder isn't
# logged as a distinct event, and secret-reveal events under a folder
# reference the SECRET's id in target[], never the folder's, so there's no
# way to attribute a reveal back to "this folder was accessed" (folder
# grants are instead expanded to their child secrets -- see
# _folder_descendant_secrets).
#
# Confirmed live 2026-08-14 against a SECOND, busier tenant with individual
# server/SaaS-app/Okta-account grants actually configured:
# - individual_server_account: pam.server.ssh_login's target[] DOES match
#   the server's own id directly, but its actor.id is the OS-level SSH
#   username (e.g. "rootadmin", or a per-user-provisioned name like
#   "a1jane.doe@example.com") -- NEVER the Okta identity id that
#   find_last_access_for_user filters by, so an actor-based query against
#   that eventType would silently match nothing for a real human user,
#   shared or individual account alike. pam.gateway_creds.issue is the
#   real fix: its actor.id IS a genuine Okta identity (same "00u..." id
#   confirmed used by pam.secret.reveal), and the server being connected to
#   is recoverable via nextHopServerIds (see _gateway_creds_server_ids) --
#   66 of 123 real events in the discovery sample matched one of 4 known
#   server grants this way.
# - individual_managed_saas_app_account, individual_unmanaged_saas_app_account,
#   and individual_okta_account: an initial 90-day System Log scan (both
#   unfiltered and filtered) found zero matches against the resolved
#   selector's own id -- but that id is the Okta-side identifier
#   (privileged_resource_id / okta_user_id, e.g. an AppUser id starting
#   "opr..."), and confirmed via a full-export CSV (65,972 rows, no
#   pagination/rate-limit gaps) that object type is NEVER logged as a
#   System Log target at all, for ANY account in the org -- not a
#   these-specific-4-accounts-were-unlucky situation, but a structural gap
#   in what Okta logs. The account's OWN OPA-internal id (a separate uuid,
#   fetched from list_project_saas_app_accounts/list_project_okta_ud_accounts
#   and stored as access_tracking_id -- see the indexing code below) DOES
#   show up as a "Service Account" target, on pam.service_account.password.reveal
#   (44 matches in the CSV, actor always genuine Okta "User") and
#   pam.resource.checkout (30 matches, same). pam.resource.checkin.start
#   duplicates checkout's counts exactly (same sessions, redundant) and
#   checkin.end's actor is almost always a SystemPrincipal/Server, not the
#   requesting human, so neither is included. individual_unmanaged_saas_app_account
#   shares the exact same indexing code path as individual_managed_saas_app_account
#   (both come from the same list_project_saas_app_accounts call, just a
#   different Okta OIN lifecycle-management category) -- included on that
#   basis even though this tenant only had "managed" ones configured to
#   test directly.
RESOURCE_ACCESS_EVENT_TYPES = {
    "secret": {"event_types": ["pam.secret.reveal"], "extract_ids": _target_ids},
    "individual_server_account": {"event_types": ["pam.gateway_creds.issue"], "extract_ids": _gateway_creds_server_ids},
    "individual_managed_saas_app_account": {
        "event_types": ["pam.service_account.password.reveal", "pam.resource.checkout"], "extract_ids": _target_ids,
    },
    "individual_unmanaged_saas_app_account": {
        "event_types": ["pam.service_account.password.reveal", "pam.resource.checkout"], "extract_ids": _target_ids,
    },
    "individual_okta_account": {
        "event_types": ["pam.service_account.password.reveal", "pam.resource.checkout"], "extract_ids": _target_ids,
    },
}

# Confirmed live 2026-09-09 against the dev tenant's real 90-day System Log
# (a full unfiltered `eventType sw "pam."` scan, not guessed from docs) --
# unlike RESOURCE_ACCESS_EVENT_TYPES above (which only tracks *reveals* for
# the Access Explorer "last accessed" feature), the Secrets Access Dashboard
# needs the full lifecycle: pam.secret.create/.update/.delete/.reveal and
# pam.secret_folder.create/.update/.delete all exist as real, distinct
# eventTypes, and every one of them carries the resource's own id +
# displayName (target type "Secret"/"Secret Folder"), its full path (target
# type "Secret Path"), and its Resource Group/Project as co-targets --
# confirmed by inspecting real event payloads directly. This means a single
# System Log query scoped to a project (`target.id eq "{project_id}"`, which
# a co-target match satisfies without needing the Resource Group id too --
# also confirmed live) covers the whole report with zero per-secret calls.
SECRETS_ACCESS_REPORT_EVENT_TYPES = {
    "secret": ["pam.secret.create", "pam.secret.update", "pam.secret.delete", "pam.secret.reveal"],
    "secret_folder": ["pam.secret_folder.create", "pam.secret_folder.update", "pam.secret_folder.delete"],
}

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


def _strip_inline_comment(value):
    """Removes a trailing ' #...' comment from an UNQUOTED .env value. Only
    a '#' preceded by whitespace (or at position 0) is treated as a comment
    start -- a secret that legitimately contains '#' with no space before it
    (e.g. "my#secret") passes through untouched."""
    idx = 0
    while True:
        idx = value.find("#", idx)
        if idx == -1:
            return value
        if idx == 0 or value[idx - 1].isspace():
            return value[:idx]
        idx += 1


def _parse_dotenv_value(raw_value):
    """A quoted value ("..." or '...') is taken verbatim between the quotes
    -- anything after the closing quote (e.g. a trailing comment) is
    discarded. An unquoted value only has a trailing inline comment
    stripped; it is never truncated at an unquoted '#' with no preceding
    whitespace, so real secrets containing '#' survive either way."""
    value = raw_value.strip()
    if len(value) >= 2 and value[0] in "\"'":
        quote = value[0]
        end = value.find(quote, 1)
        if end != -1:
            return value[1:end]
    return _strip_inline_comment(value).strip()


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
            key, _, raw_value = line.partition("=")
            key = key.strip()
            value = _parse_dotenv_value(raw_value)
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

KEYRING_SERVICE_PREFIX = "opa-compliance-wizard"
# Every credential this project ever stored before the 5.20.0 rename used
# this prefix -- kept as a read-only fallback (see keyring_get below) so an
# existing install's already-stored OPA keys/Okta tokens/etc. keep working
# with zero changes required on upgrade. Never written to going forward;
# a value that gets updated on an old install naturally migrates itself to
# the new KEYRING_SERVICE_PREFIX the next time it's saved.
_LEGACY_KEYRING_SERVICE_PREFIX = "opa-secrets-wizard"
ENVIRONMENT_METADATA_FIELDS = ("base_domain", "team_name", "key_id", "okta_url")
ENVIRONMENT_SECRET_FIELDS = ("key_secret", "okta_api_token")


def _environments_file_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "environments.json")


LOCAL_OWNER_KEY = None  # sentinel for "no verified identity" -- local/direct runs, and every CLI call


def _owner_storage_key(owner):
    """The dict key used for both `data["active"]` and, combined with an
    environment name, the keyring/metadata storage key below. Never emit
    the JSON token "null" as an actual key string -- use a stable literal
    instead, since JSON object keys are always strings anyway and `None`
    would otherwise round-trip as the 4-character string "null"."""
    return owner if owner else "__local__"


def environment_storage_name(owner, name):
    """The real, owner-namespaced storage key for an environment. `name` is
    just the user-facing label (two different users can each have a "dev");
    this is what actually keys environments.json's `environments` dict and
    the keyring service name, so names never collide across owners."""
    return f"{_owner_storage_key(owner)}::{name}"


_LEGACY_STORAGE_PREFIX = f"{_owner_storage_key(LOCAL_OWNER_KEY)}::"


def load_environments():
    """Loads the whole store and migrates it to the current shape in memory
    (does not write the migration back until the next save_environments
    call by some other code path -- load is otherwise side-effect-free).

    Migrations handled here, both one-way and permanent in spirit (every
    legacy environment becomes indistinguishable from one explicitly
    created under LOCAL_OWNER_KEY once this runs):
    - `"active"` used to be a single environment-name string
      (pre-multi-user). It's now a dict keyed by owner (Okta `sub`, or
      LOCAL_OWNER_KEY for unscoped/local/CLI use) so each user's active
      environment is independent. A legacy string value becomes the
      LOCAL_OWNER_KEY-owner's active environment, matching exactly what it
      meant before this change existed.
    - `environments` used to be keyed by plain name (e.g. "dev"). Any key
      that isn't already namespaced (doesn't contain "::") is a legacy
      entry -- rekeyed to `LOCAL_OWNER_KEY::<name>` and given
      owner=LOCAL_OWNER_KEY, shared=True (every pre-existing environment
      was, in effect, usable by anyone who could reach this file/process,
      so shared=True is what actually preserves that instead of silently
      hiding it from every logged-in user once per-user scoping goes live)."""
    path = _environments_file_path()
    if not os.path.isfile(path):
        return {"active": {}, "environments": {}}
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    active = data.get("active")
    if isinstance(active, str):
        data["active"] = {_owner_storage_key(LOCAL_OWNER_KEY): active}
    elif not isinstance(active, dict):
        data["active"] = {}

    migrated_environments = {}
    for key, meta in data.get("environments", {}).items():
        if "::" not in key:
            meta = dict(meta)
            meta.setdefault("owner", LOCAL_OWNER_KEY)
            meta.setdefault("shared", True)
            migrated_environments[environment_storage_name(LOCAL_OWNER_KEY, key)] = meta
        else:
            migrated_environments[key] = meta
    data["environments"] = migrated_environments
    return data


def _atomic_write_json(path, value, mode=0o600):
    """SECURITY FIX (external review, 2026-09-30): every mutable JSON file
    this project writes (environments.json, banner_config.json,
    access_control.json) previously used a plain truncating `open(path,
    "w")` -- a reader (in this case, a SEPARATE process:
    server/auth_gate.py reading access_control.json) hitting that file
    mid-write sees a truncated/partial file, gets a JSONDecodeError, and
    (for access_control.json specifically) falls back to the unrestricted
    login-bootstrap default -- confirmed exploitable: a crash or a login
    landing exactly during a write can transiently or permanently disable
    the login-restriction gate.

    Standard write-new-file-then-rename pattern: write to a temp file in
    the SAME directory (so the final os.replace is on the same filesystem,
    making it atomic -- a cross-filesystem "rename" would silently
    fall back to copy+delete, which is NOT atomic), fsync it before the
    rename so the write is durable even across a crash between the write
    and the rename, then os.replace -- POSIX guarantees a concurrent
    reader always sees either the complete old file or the complete new
    one, never a partial write, no matter when it opens the path."""
    directory = os.path.dirname(path) or "."
    fd, temp_path = tempfile.mkstemp(dir=directory, prefix=".tmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(value, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(temp_path, mode)
        os.replace(temp_path, path)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def _atomic_write_bytes(path, data, mode=0o600):
    """Binary-content sibling of _atomic_write_json -- same reasoning,
    used for save_secrets_log_cache (writes Fernet-encrypted bytes, not
    JSON)."""
    directory = os.path.dirname(path) or "."
    fd, temp_path = tempfile.mkstemp(dir=directory, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(temp_path, mode)
        os.replace(temp_path, path)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def save_environments(data):
    _atomic_write_json(_environments_file_path(), data)


# ---------------------------------------------------------------------------
# Announcement banner
# ---------------------------------------------------------------------------
# A single, dashboard-wide banner (not per-environment/per-owner) shown at
# the top of every page -- mirrors Okta's own admin console banners
# ("Preview Sandbox", incident notices) which are one announcement for the
# whole org, not one per admin. Stored in its own file since it holds no
# secrets and has nothing to do with which environment is active.
BANNER_VARIANTS = ("info", "warning", "danger")
_BANNER_DEFAULTS = {"enabled": False, "message": "", "variant": "warning", "dismissible": True}


def _banner_config_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "banner_config.json")


def get_banner_config():
    path = _banner_config_path()
    if not os.path.isfile(path):
        return dict(_BANNER_DEFAULTS)
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return {
        "enabled": bool(data.get("enabled", False)),
        "message": data.get("message", ""),
        "variant": data.get("variant") if data.get("variant") in BANNER_VARIANTS else "warning",
        "dismissible": bool(data.get("dismissible", True)),
    }


def set_banner_config(enabled, message, variant, dismissible):
    if variant not in BANNER_VARIANTS:
        raise ValueError(f"variant must be one of {', '.join(BANNER_VARIANTS)}")
    message = (message or "").strip()
    if enabled and not message:
        raise ValueError("message is required when the banner is enabled")
    config = {"enabled": bool(enabled), "message": message, "variant": variant, "dismissible": bool(dismissible)}
    _atomic_write_json(_banner_config_path(), config)
    return config


# ---------------------------------------------------------------------------
# Access control (Okta admin/user group IDs for the login gate)
# ---------------------------------------------------------------------------
# Read by server/auth_gate.py (a separate process -- see its own module
# docstring) to decide who may log in at all and who gets admin rights,
# once an admin has saved settings here via POST /api/access_control/save.
# Before that first save, auth_gate.py falls back to its own OKTA_ADMIN_GROUP_ID
# env var with restrict_login=False, so a fresh deployment never locks anyone
# out by default. This module is the sole writer of this file -- auth_gate.py
# only ever reads it, avoiding any dual-writer race between the two processes.
_ACCESS_CONTROL_DEFAULTS = {"admin_group_id": None, "user_group_id": None, "restrict_login": False}


def _access_control_file_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "access_control.json")


def get_access_control_config():
    path = _access_control_file_path()
    if not os.path.isfile(path):
        return dict(_ACCESS_CONTROL_DEFAULTS)
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return {
        "admin_group_id": data.get("admin_group_id") or None,
        "user_group_id": data.get("user_group_id") or None,
        "restrict_login": bool(data.get("restrict_login", False)),
    }


def set_access_control_config(admin_group_id, user_group_id, restrict_login):
    admin_group_id = (admin_group_id or "").strip() or None
    user_group_id = (user_group_id or "").strip() or None
    if restrict_login and not admin_group_id and not user_group_id:
        raise ValueError("at least one group ID is required to restrict login")
    config = {
        "admin_group_id": admin_group_id,
        "user_group_id": user_group_id,
        "restrict_login": bool(restrict_login),
    }
    _atomic_write_json(_access_control_file_path(), config)
    return config


def _keyring_service(storage_name, prefix=KEYRING_SERVICE_PREFIX):
    return f"{prefix}:{storage_name}"


def _require_keyring():
    if not KEYRING_AVAILABLE:
        raise RuntimeError(
            "The 'keyring' package is required for encrypted credential storage. "
            "Install it with: pip install keyring"
        )


def keyring_set(storage_name, field, value):
    _require_keyring()
    keyring.set_password(_keyring_service(storage_name), field, value)


def _keyring_get_raw(service, field):
    try:
        return keyring.get_password(service, field)
    except Exception:
        return None


def keyring_get(storage_name, field):
    """Reads a secret, with two independent, composable backward-compat
    fallbacks -- an install that predates BOTH the multi-user change and
    the 5.20.0 rename needs both to still resolve:
    1. Service-name prefix: this project's keyring service prefix was
       renamed from "opa-secrets-wizard" to "opa-compliance-wizard" at
       5.20.0 (see KEYRING_SERVICE_PREFIX/_LEGACY_KEYRING_SERVICE_PREFIX
       above) -- try the current prefix first, fall back to the legacy
       one. Read-only: nothing is ever written back under the legacy
       prefix, so a value naturally migrates to the new prefix the next
       time it's saved (no migration script needed).
    2. Storage-name shape: if `storage_name` is namespaced under the
       local/unscoped owner (`__local__::<name>`) and nothing's stored
       under that namespaced service name, also try the pre-multi-user
       storage name (bare `<name>`, no owner prefix at all) -- every
       environment that existed before THAT change has its real secret
       sitting there.
    Tries (current prefix, current name) -> (current prefix, legacy name)
    -> (legacy prefix, current name) -> (legacy prefix, legacy name)."""
    if not KEYRING_AVAILABLE:
        return None

    names = [storage_name]
    if storage_name.startswith(_LEGACY_STORAGE_PREFIX):
        names.append(storage_name[len(_LEGACY_STORAGE_PREFIX):])
    prefixes = [KEYRING_SERVICE_PREFIX, _LEGACY_KEYRING_SERVICE_PREFIX]

    for prefix in prefixes:
        for name in names:
            value = _keyring_get_raw(_keyring_service(name, prefix), field)
            if value is not None:
                return value
    return None


def keyring_delete(storage_name, field):
    if not KEYRING_AVAILABLE:
        return
    try:
        keyring.delete_password(_keyring_service(storage_name), field)
    except Exception:
        pass
    # Also clean up the legacy (pre-multi-user, unnamespaced) entry if this
    # is a local/unscoped environment -- see keyring_get's matching fallback.
    if storage_name.startswith(_LEGACY_STORAGE_PREFIX):
        legacy_name = storage_name[len(_LEGACY_STORAGE_PREFIX):]
        try:
            keyring.delete_password(_keyring_service(legacy_name), field)
        except Exception:
            pass


def list_environments_for(owner):
    """Returns {name: meta} visible to `owner`: their own environments plus
    anything explicitly marked shared=True. LOCAL_OWNER_KEY is treated as
    just another owner value here -- NOT a bypass that sees every other
    owner's private environments. This matters for two reasons found while
    testing this function against real same-named environments owned by
    different users: (1) a bypass would let anyone with local/CLI access on
    a shared server read every logged-in user's private credentials, which
    directly violates "shouldn't be shared unless explicitly allowed";
    (2) collapsing every owner's environments into one flat {name: meta}
    dict silently drops entries whenever two owners happen to pick the same
    name -- whichever iterates last wins, with no error. Every pre-existing
    (pre-multi-user) environment was migrated to owner=LOCAL_OWNER_KEY,
    shared=True by load_environments(), so LOCAL_OWNER_KEY/the CLI still
    sees exactly what it used to -- via the shared=True path below, not a
    special case.

    Own environments are applied AFTER shared ones so a same-named
    environment `owner` actually owns always wins over a like-named
    environment merely shared by someone else -- without this ordering,
    dict iteration order alone would decide which one a caller's own
    credential lookup resolves to, which could silently authenticate
    against the wrong tenant."""
    data = load_environments()
    visible = {}
    for storage_name, meta in data["environments"].items():
        _, _, name = storage_name.partition("::")
        if meta.get("shared") and meta.get("owner") != owner:
            visible[name] = meta
    for storage_name, meta in data["environments"].items():
        _, _, name = storage_name.partition("::")
        if meta.get("owner") == owner:
            visible[name] = meta
    return visible


def list_all_environments():
    """Returns {name: meta} for EVERY stored environment, across every
    owner -- unlike list_environments_for(owner), which deliberately
    scopes to what one requesting identity is allowed to see. This
    exists for server-side background work with no requesting identity
    of its own (the daily sync scheduler): it needs to find and run
    every saved environment's sync schedule, including a non-shared
    environment privately owned by some other logged-in user, not just
    LOCAL_OWNER_KEY's own/shared ones. Never expose this dict directly
    to an HTTP response -- it carries every owner's metadata (though
    still no secrets; those stay in the keychain either way).

    On a genuine owner collision (two different owners each have an
    environment named the same, e.g. two users both naming one "dev"),
    both are still returned -- keyed by their real storage_name (which
    is already owner-namespaced), not the bare display name, so a
    caller here always disambiguates by storage_name and never
    silently drops one like list_environments_for's flat {name: meta}
    would if collapsed the same way."""
    data = load_environments()
    return dict(data["environments"])


def get_active_environment_name(owner):
    data = load_environments()
    return data["active"].get(_owner_storage_key(owner))


def set_active_environment(owner, name):
    data = load_environments()
    data["active"][_owner_storage_key(owner)] = name
    save_environments(data)


def upsert_environment(name, fields, owner=LOCAL_OWNER_KEY, is_admin=False, environment_id=None):
    """Saves non-secret metadata to environments.json and secret fields to
    the OS keychain. Blank secret fields on an update leave the previously
    stored secret untouched (so editing metadata doesn't force re-entering
    credentials). Raises ValueError if required fields end up missing.

    `owner` defaults to LOCAL_OWNER_KEY (no verified identity) so every
    existing call site -- the CLI, and any code that doesn't know about
    per-user scoping -- keeps working unchanged. Creating a new environment
    always sets its `owner` to this value; updating an EXISTING environment
    owned by someone else is refused (PermissionError) unless `is_admin`
    is True -- an admin override edits the environment IN PLACE under its
    own existing owner, it does not transfer ownership to the admin (an
    admin fixing another user's broken credentials shouldn't silently
    become that environment's new owner).

    `environment_id`, when supplied (an admin editing an EXISTING
    environment via the UI, which always knows its real storage_name),
    resolves the target directly via an O(1) dict lookup -- unambiguous
    even when two different owners share a display name. Without it (a
    create, where no id exists yet, or a legacy caller), an admin edit
    falls back to a by-name scan across every owner, which is genuinely
    ambiguous in that same-display-name case (confirmed exploitable,
    external review 2026-09-30) -- kept only for backward compatibility."""
    if not name or not name.strip():
        raise ValueError("Environment name is required (e.g. dev, uat, prod).")
    name = name.strip()
    data = load_environments()

    # Resolve which storage_name/owner this update actually targets. A
    # normal (non-admin) call always targets the CALLING owner's own copy
    # -- environment_storage_name(owner, name) is correct even if no such
    # environment exists yet (a create). An admin override editing an
    # EXISTING environment must target whichever owner's copy actually
    # already exists (there's no such thing as an admin "creating"
    # someone else's environment -- only editing one that's already
    # there) -- environment_id disambiguates this directly when supplied;
    # otherwise falls back to the old by-name scan (ambiguous, see above).
    target_owner = owner
    if is_admin:
        if environment_id and environment_id in data["environments"]:
            target_owner = data["environments"][environment_id].get("owner")
        else:
            for storage_key, meta in data["environments"].items():
                _, _, stored_name = storage_key.partition("::")
                if stored_name == name:
                    target_owner = meta.get("owner")
                    break
    storage_name = environment_storage_name(target_owner, name)

    existing_meta = data["environments"].get(storage_name)
    if existing_meta is not None and existing_meta.get("owner") != owner and not is_admin:
        raise PermissionError(f"Environment '{name}' is not owned by this user.")

    meta = dict(existing_meta or {})
    for field in ENVIRONMENT_SECRET_FIELDS:
        meta.pop(field, None)  # migrate away any pre-encryption plaintext secret left in metadata
    for field in ENVIRONMENT_METADATA_FIELDS:
        if field in fields:
            meta[field] = (fields.get(field) or "").strip()
    meta["owner"] = target_owner
    meta.setdefault("shared", False)

    for field in ENVIRONMENT_SECRET_FIELDS:
        value = (fields.get(field) or "").strip()
        if value:
            keyring_set(storage_name, field, value)
        # blank + already exists -> leave the previously stored secret alone

    missing = [f for f in ("base_domain", "team_name", "key_id") if not meta.get(f)]
    if missing:
        raise ValueError(f"Missing required field(s): {', '.join(missing)}")
    if not keyring_get(storage_name, "key_secret"):
        raise ValueError("Missing required field: key_secret")

    data["environments"][storage_name] = meta
    save_environments(data)
    return name


def _find_environment_by_name(data, name):
    """Returns (storage_name, meta) for the first stored environment whose
    display name matches, across every owner, or (None, None) if none
    exists.

    SECURITY: first-match-wins across EVERY owner -- confirmed exploitable
    (external review, 2026-09-30): if two different owners each have an
    environment named "dev", an admin override targeting "dev" by this
    function silently acts on whichever one happens to iterate first,
    never the one the admin actually meant. Kept ONLY as a fallback for
    legacy admin API callers that still pass a bare name with no real
    stable ID available (see the `environment_id` param on the callers
    below) -- every serve.py route has been updated to resolve and pass a
    real `environment_id` (the storage_name itself) instead, which is
    unambiguous. New code should never call this."""
    for storage_key, meta in data["environments"].items():
        _, _, stored_name = storage_key.partition("::")
        if stored_name == name:
            return storage_key, meta
    return None, None


def _resolve_admin_target(data, name, environment_id):
    """Shared resolution for every admin-override path below. Prefers the
    unambiguous `environment_id` (the real storage_name, e.g.
    "00u123::dev") whenever the caller has one -- an O(1) dict lookup,
    never a cross-owner scan. Falls back to the old, ambiguous by-name
    scan (_find_environment_by_name) ONLY when no id was supplied, for
    backward compatibility with any caller that hasn't been updated yet.
    Raises KeyError if nothing matches either way."""
    if environment_id:
        meta = data["environments"].get(environment_id)
        if meta is None:
            raise KeyError(f"No saved environment with id '{environment_id}'")
        return environment_id, meta
    storage_name, meta = _find_environment_by_name(data, name)
    if meta is None:
        raise KeyError(f"No saved environment named '{name}'")
    return storage_name, meta


def set_environment_shared(name, owner, shared, is_admin=False, environment_id=None):
    """Toggles an environment's `shared` flag. Only its owner may do this
    unless `is_admin` is True, in which case the target is resolved via
    `environment_id` when the caller has one (unambiguous), falling back
    to a by-name scan across every owner otherwise (see
    _resolve_admin_target -- ambiguous if two owners share a display
    name, kept only for backward compatibility). Raises PermissionError
    if not the owner and not an admin, KeyError if unknown."""
    data = load_environments()
    if is_admin:
        storage_name, meta = _resolve_admin_target(data, name, environment_id)
    else:
        storage_name = environment_storage_name(owner, name)
        meta = data["environments"].get(storage_name)
        if meta is None:
            raise KeyError(f"No environment named '{name}' owned by this user.")
        if meta.get("owner") != owner:
            raise PermissionError(f"Environment '{name}' is not owned by this user.")
    meta["shared"] = bool(shared)
    save_environments(data)


def delete_environment(name, owner=LOCAL_OWNER_KEY, is_admin=False, environment_id=None):
    """Removes an environment's metadata and both keychain secrets. Returns
    True if it was the active environment for THIS caller (caller should
    clear any live client for this owner). Raises KeyError if the name
    doesn't exist (for this owner, unless `is_admin`), PermissionError if
    it exists but is owned by someone else and `is_admin` is False. See
    _resolve_admin_target for how `environment_id` disambiguates an admin
    override across same-named environments from different owners."""
    data = load_environments()
    if is_admin:
        storage_name, meta = _resolve_admin_target(data, name, environment_id)
    else:
        storage_name = environment_storage_name(owner, name)
        meta = data["environments"].get(storage_name)
        if meta is None:
            raise KeyError(f"No saved environment named '{name}'")
        if meta.get("owner") != owner:
            raise PermissionError(f"Environment '{name}' is not owned by this user.")
    real_owner = meta.get("owner")
    del data["environments"][storage_name]
    # Return value ("was it active") is about the CALLING owner's own
    # active slot specifically -- that's what tells serve.py whether to
    # clear the calling owner's own live client.
    owner_key = _owner_storage_key(owner)
    was_active = data["active"].get(owner_key) == name
    if was_active:
        del data["active"][owner_key]
    # SEPARATELY, and regardless of who called this: if this was an admin
    # override deleting someone ELSE's environment, that real owner's own
    # active pointer needs clearing too if it pointed here -- otherwise it
    # dangles, pointing at an environment that no longer exists, and that
    # owner sees a failed auto-activation / appears unconfigured on their
    # next login with no obvious cause (external review finding,
    # 2026-09-30). Guarded by `real_owner != owner` so the non-admin path
    # above (which already handled its own single owner_key) never
    # double-clears the same key it just cleared.
    real_owner_key = _owner_storage_key(real_owner)
    if real_owner_key != owner_key and data["active"].get(real_owner_key) == name:
        del data["active"][real_owner_key]
    save_environments(data)
    for field in ENVIRONMENT_SECRET_FIELDS:
        keyring_delete(storage_name, field)
    return was_active


def get_environment_credentials(name, owner=LOCAL_OWNER_KEY):
    """Returns the full merged credential dict (metadata + secrets from the
    keychain) for a saved environment. `owner` should be the CALLER's
    identity, not necessarily the environment's owner -- this looks the
    environment up under its own recorded owner (falling back across all
    owners when `owner is LOCAL_OWNER_KEY`, matching unscoped/local
    visibility) so a shared environment resolves correctly for a non-owner
    caller. Raises KeyError if it doesn't exist or isn't visible to `owner`."""
    visible = list_environments_for(owner)
    meta = visible.get(name)
    if meta is None:
        raise KeyError(f"No saved environment named '{name}'")
    storage_name = environment_storage_name(meta.get("owner"), name)
    creds = dict(meta)
    for field in ENVIRONMENT_SECRET_FIELDS:
        creds[field] = keyring_get(storage_name, field) or ""
    creds["name"] = name
    return creds


def get_active_environment_credentials(owner=LOCAL_OWNER_KEY):
    """Returns credentials for the currently-active saved environment for
    `owner`, or None if none is set/active. Default `owner` preserves the
    CLI's and every pre-existing caller's exact behavior."""
    name = get_active_environment_name(owner)
    if not name:
        return None
    try:
        return get_environment_credentials(name, owner=owner)
    except KeyError:
        return None


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------
# Append-only, one JSON object per line -- audit_log.jsonl next to this
# script, same "simple flat file over a database" pattern this project
# already uses for secrets_log_cache.json. Written for every write/mutating
# action (see server/serve.py's callers), local/CLI-triggered actions
# included (with actor_email/actor_sub left None) so local usage is
# auditable too, not just logged-in dashboard usage.
_audit_log_lock = threading.Lock()


def _audit_log_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "audit_log.jsonl")


def log_audit_event(actor_email, actor_sub, action, details=None, client_ip=None, user_agent=None):
    """client_ip/user_agent are new as of 2026-09-30 (Okta's own System
    Log always captures both; this log never did) -- optional so every
    existing call site keeps working unchanged until updated to pass
    them. Older entries in audit_log.jsonl predate these fields entirely
    (not backfilled -- there's no real data to backfill, since neither
    was ever captured) and simply won't have the keys; read_audit_log's
    callers should treat a missing key the same as an explicit None."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "actor_email": actor_email,
        "actor_sub": actor_sub,
        "action": action,
        "details": details or {},
        "client_ip": client_ip,
        "user_agent": user_agent,
    }
    line = json.dumps(entry, separators=(",", ":"))
    with _audit_log_lock:
        with open(_audit_log_path(), "a", encoding="utf-8") as f:
            f.write(line + "\n")
    return entry


def read_audit_log(limit=200, offset=0):
    """Returns the most recent `limit` entries (most-recent-first), skipping
    `offset` from the top. Reads the whole file -- audit_log.jsonl is a
    plain-text, human-scale operational log for a small team's tool, not a
    high-volume dataset needing an index."""
    path = _audit_log_path()
    if not os.path.isfile(path):
        return []
    entries = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    entries.reverse()
    return entries[offset:offset + limit]


def backfill_mfa_log_events(lookup_fn, max_lookups=20):
    """Closes the Okta System-Log-indexing-lag gap confirmed live 2026-09-30
    (see server/auth_gate.py's _find_stepup_mfa_log_event docstring):
    access_control.update entries whose okta_mfa_log_event is still None
    (the corroborating event hadn't been indexed by Okta yet at save time)
    get a fresh lookup attempt every time an admin clicks Refresh on the
    Audit Log page, not just once at save time.

    `lookup_fn(actor_sub, near_iso_timestamp) -> dict | None` is injected
    (see server/serve.py's caller) rather than this module calling
    auth_gate.py directly -- this module has no Okta org URL/token of its
    own for this purpose (that lives in auth_gate.py's separate process/
    keyring entry, see this project's existing deliberate isolation
    between the two), so the actual Okta call is always made by whichever
    caller HAS that access; this function only knows how to find/rewrite
    audit_log.jsonl rows.

    `max_lookups` bounds how many entries get a fresh Okta call in one
    Refresh click -- a real cap, not just a nice-to-have: someone
    repeatedly clicking Refresh while several old entries are all still
    missing corroboration (e.g. after a period this feature was down)
    shouldn't be able to trigger unbounded Okta API calls per click.

    Returns the number of entries actually updated (0 if none needed it or
    every lookup came back empty) -- rewrites the whole file only if at
    least one entry changed, using the same lock as log_audit_event so a
    concurrent append from a live save can't be lost mid-rewrite."""
    path = _audit_log_path()
    if not os.path.isfile(path):
        return 0

    with _audit_log_lock:
        lines = []
        with open(path, encoding="utf-8") as f:
            for line in f:
                stripped = line.rstrip("\n")
                if stripped:
                    lines.append(stripped)

        updated_count = 0
        lookups_used = 0
        for i, line in enumerate(lines):
            if lookups_used >= max_lookups:
                break
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("action") != "access_control.update":
                continue
            details = entry.get("details") or {}
            if details.get("okta_mfa_log_event") is not None:
                continue
            actor_sub = entry.get("actor_sub")
            timestamp = entry.get("timestamp")
            if not actor_sub or not timestamp:
                continue
            lookups_used += 1
            found = lookup_fn(actor_sub, timestamp)
            if found is not None:
                details["okta_mfa_log_event"] = found
                entry["details"] = details
                lines[i] = json.dumps(entry, separators=(",", ":"))
                updated_count += 1

        if updated_count:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
    return updated_count


REQUEST_TIMEOUT_SECS = 30
MAX_RETRIES = 3  # genuine errors (5xx / network) -- these usually mean something's actually wrong, so a low cap is right
# 429s are NOT the same kind of failure as a 5xx/network error -- the
# response tells us exactly how long to wait, so retrying is always the
# correct move, not just a hopeful one. Sharing MAX_RETRIES between "real
# errors" and "rate limited" meant a sustained burst (a large tenant, or
# several people/processes sharing this same service-user credential) could
# exhaust the budget and fail outright even though every individual wait
# was accurately calculated. Give 429s their own, much more generous
# allowance -- still bounded, as a safety valve against a server that never
# stops 429ing, but high enough that normal large-tenant/shared-credential
# bursts never hit it.
MAX_RATE_LIMIT_RETRIES = 20
RETRY_BACKOFF_SECS = 2
RETRYABLE_STATUS_CODES = {500, 502, 503, 504}  # 429 is handled separately -- see MAX_RATE_LIMIT_RETRIES

# Okta/OPA APIs return standard rate-limit headers on every response
# (confirmed live 2026-08-14): x-ratelimit-limit, x-ratelimit-remaining,
# x-ratelimit-reset (unix seconds when the window resets). We track the
# latest known state per host and proactively wait out the window once
# few requests are left, rather than waiting to get hit with a 429.
# Deliberately NOT down to the last request (was 1): if this same
# service-user credential is used concurrently -- multiple dashboard/CLI
# instances, multiple people on a large team sharing one credential -- two
# processes can each independently see "still have headroom" from their own
# last-seen state and both fire, tipping a shared budget into a real 429
# anyway. A wider margin leaves room for that without changing single-client
# behavior in any meaningful way (a few extra requests' worth of headroom
# out of the tenant's full window).
RATE_LIMIT_MIN_REMAINING = 5
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


def _server_time_from_headers(headers):
    """Parses the response's own 'Date' header (RFC 7231) into Unix epoch
    seconds, or None if missing/unparseable. Anchoring rate-limit math to
    the SERVER's clock (not this machine's time.time()) is what makes it
    immune to local clock skew -- see _record_rate_limit."""
    date_str = headers.get("Date")
    if not date_str:
        return None
    try:
        parsed = email.utils.parsedate_tz(date_str)
        return email.utils.mktime_tz(parsed) if parsed else None
    except (TypeError, ValueError):
        return None


def _record_rate_limit(url, headers):
    """Stash the latest x-ratelimit-* values for this host so the next
    request (possibly for a different endpoint on the same host) knows
    how much headroom is left before it needs to wait. The countdown is
    computed once here using the SERVER's own 'Date' header as the clock
    reference (falling back to local wall time only if 'Date' is somehow
    absent), then stored as a time.monotonic() deadline -- monotonic time
    can't be affected by wall-clock skew or adjustment either, so neither
    a skewed local clock nor one that's merely slow/fast relative to the
    server can cause an under/over-sleep in _wait_if_rate_limited."""
    remaining = headers.get("x-ratelimit-remaining")
    reset = headers.get("x-ratelimit-reset")
    if remaining is None or reset is None:
        return
    try:
        remaining = int(remaining)
        reset = int(reset)
    except ValueError:
        return
    server_now = _server_time_from_headers(headers)
    if server_now is None:
        server_now = time.time()
    reset_in_secs = reset - server_now
    with _rate_limit_lock:
        _rate_limit_state[_rate_limit_host(url)] = {
            "remaining": remaining,
            "reset_monotonic": time.monotonic() + reset_in_secs,
        }


def _wait_if_rate_limited(url):
    """Proactively sleep until the rate-limit window resets if the last
    response we saw for this host reported few requests left -- this is
    what keeps the recursive folder-tree walk (one API call per folder)
    from ever tripping a 429 in the first place."""
    with _rate_limit_lock:
        state = _rate_limit_state.get(_rate_limit_host(url))
    if not state or state["remaining"] > RATE_LIMIT_MIN_REMAINING:
        return
    wait_secs = state["reset_monotonic"] - time.monotonic() + RATE_LIMIT_WAIT_BUFFER_SECS
    if wait_secs > 0:
        log("WARN", f"Rate limit nearly exhausted for {_rate_limit_host(url)} "
                     f"({state['remaining']} request(s) left) -- waiting {wait_secs:.0f}s for the window to reset...")
        time.sleep(wait_secs)


def _retry_after_secs(headers):
    """On an actual 429, prefer an authoritative wait time over blind
    backoff: Retry-After (seconds, a relative delta -- immune to clock skew
    by construction) if present, else derive from x-ratelimit-reset (an
    absolute unix timestamp), anchored to the response's own 'Date' header
    rather than local wall time for the same clock-skew reasons as
    _record_rate_limit. Falls back to the fixed backoff only if none of
    Retry-After, x-ratelimit-reset, or Date are present."""
    retry_after = headers.get("Retry-After")
    if retry_after is not None:
        try:
            return float(retry_after) + RATE_LIMIT_WAIT_BUFFER_SECS
        except ValueError:
            pass
    reset = headers.get("x-ratelimit-reset")
    if reset is not None:
        try:
            server_now = _server_time_from_headers(headers)
            if server_now is None:
                server_now = time.time()
            return max(0.0, int(reset) - server_now) + RATE_LIMIT_WAIT_BUFFER_SECS
        except ValueError:
            pass
    return RETRY_BACKOFF_SECS * MAX_RETRIES


_LINK_HEADER_ENTRY_RE = re.compile(r'<([^>]+)>\s*;\s*rel="?([\w-]+)"?')


def _parse_next_link(headers):
    """Extract the rel="next" URL from the response's Link header(s), or
    None if there isn't one.

    Takes the response headers object (not a pre-extracted string):
    confirmed live against this org's System Log API that a server can send
    Link as multiple separate header lines (one per rel) rather than one
    RFC 8288 comma-joined value -- headers.get("Link") only returns the
    first line, silently dropping "next" whenever it wasn't first. Using
    get_all("Link") (falling back to get() for header objects that don't
    have it) and joining every line found is a strict superset of the old
    single-value behavior, so it's safe even against servers that do send
    one joined value."""
    lines = headers.get_all("Link") if hasattr(headers, "get_all") else [headers.get("Link")]
    combined = ", ".join(line for line in (lines or []) if line)
    if not combined:
        return None
    for url, rel in _LINK_HEADER_ENTRY_RE.findall(combined):
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

    # Two independent retry budgets: `error_attempt` for genuine failures
    # (5xx/network, capped low by MAX_RETRIES since repeated failure likely
    # means something's actually wrong) and `rate_limit_attempt` for 429s
    # (capped much higher by MAX_RATE_LIMIT_RETRIES since each wait is
    # authoritative, not a guess) -- see the constants above for why these
    # are no longer the same counter.
    error_attempt = 0
    rate_limit_attempt = 0
    while True:
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
            if e.code == 429:
                rate_limit_attempt += 1
                if rate_limit_attempt <= MAX_RATE_LIMIT_RETRIES:
                    wait_secs = _retry_after_secs(e.headers)
                    log("WARN", f"{method} {url} -> HTTP 429 (rate limited); "
                                f"waiting {wait_secs:.0f}s before retry "
                                f"({rate_limit_attempt}/{MAX_RATE_LIMIT_RETRIES})...")
                    time.sleep(wait_secs)
                    continue
                raise error_cls(e.code, url, raw_body) from None
            if e.code in RETRYABLE_STATUS_CODES:
                error_attempt += 1
                if error_attempt <= MAX_RETRIES:
                    log("WARN", f"{method} {url} -> HTTP {e.code}, retrying ({error_attempt}/{MAX_RETRIES})...")
                    time.sleep(RETRY_BACKOFF_SECS * error_attempt)
                    continue
            raise error_cls(e.code, url, raw_body) from None
        except urllib.error.URLError as e:
            error_attempt += 1
            if error_attempt <= MAX_RETRIES:
                log("WARN", f"{method} {url} -> network error ({e}), retrying ({error_attempt}/{MAX_RETRIES})...")
                time.sleep(RETRY_BACKOFF_SECS * error_attempt)
                continue
            raise


class OpaClient:
    def __init__(self, base_domain, team_name, key_id, key_secret):
        self.base_url = f"https://{base_domain}"
        self.team_name = team_name
        self.key_id = key_id
        self.key_secret = key_secret
        self.bearer_token = None
        self._current_user = None  # see get_current_user()
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
            next_path = _parse_next_link(headers)
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

    def list_users(self, include_service_users=True):
        """Defaults to including service users (user_type: "service") --
        confirmed live that /users takes the exact same include_service_users
        flag as the separate /service_users collection and returns both
        kinds unified. Every caller in this codebase wants the full picture
        (a service-user API key is a real principal with real access, same
        as a human), so True is the default rather than something every
        caller has to remember to opt into."""
        path = USERS_PATH.format(team=self.team_name)
        if include_service_users:
            path += "?include_service_users=true"
        return self._list(path)

    def list_user_groups(self, user_name):
        path = USER_GROUPS_PATH.format(team=self.team_name, user_name=urllib.parse.quote(user_name, safe=""))
        return self._list(path)

    def get_current_user(self):
        """Identifies whoever this OpaClient is authenticated as -- for a
        service-user API key (the only kind this tool uses), this is the
        OPA-native Service User itself, NOT an Okta identity (confirmed
        live: no Okta linkage on the returned object at all). Cached after
        the first call since it never changes mid-session for a given
        client."""
        if self._current_user is None:
            path = CURRENT_USER_PATH.format(team=self.team_name)
            self._current_user = self.request("GET", path)
        return self._current_user

    def add_user_to_group(self, group_name, user_name):
        """Adds a user (human OR service) to a group directly via OPA's own
        membership API -- independent of, and in addition to, whatever
        membership a group already has via Okta Group Push. This is how a
        service-user API key (which has no Okta identity and so can never
        be an Okta group member) can still gain a security-policy grant
        that targets a user_group principal. Requires the caller to hold
        the `pam_admin` role (per the API spec) -- raises OpaApiError (403)
        if it doesn't."""
        path = GROUP_MEMBERS_PATH.format(team=self.team_name, group_name=urllib.parse.quote(group_name, safe=""))
        return self.request("POST", path, body={"name": user_name})

    def remove_user_from_group(self, group_name, user_name):
        """Symmetric counterpart to add_user_to_group(). Not currently
        wired into the dashboard UI (nothing asked for it yet), but kept
        alongside it since the API supports it and every other create/
        delete pair in this engine is symmetric too."""
        path = GROUP_MEMBER_ITEM_PATH.format(
            team=self.team_name,
            group_name=urllib.parse.quote(group_name, safe=""),
            user_name=urllib.parse.quote(user_name, safe=""),
        )
        return self.request("DELETE", path)

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

    def list_workload_connections(self):
        """Confirmed live 2026-09-30 via GET /v1/openapi.json (the real
        API's own live spec) -- tenant-wide, same as list_workload_roles.
        A connection is the JWT/JWT_STATIC trust config (issuer/audience/
        JWKS URL/matcher conditions) a workload role's
        requirements[].workload_connection references."""
        path = WORKLOAD_CONNECTIONS_PATH.format(team=self.team_name)
        return self._list(path)

    def list_gateways(self):
        """Confirmed live 2026-09-30, tenant-wide -- the gateway
        CONFIGURATION resource itself, distinct from the server object
        that hosts it (see GATEWAYS_PATH's docstring above)."""
        path = GATEWAYS_PATH.format(team=self.team_name)
        return self._list(path)

    def list_database_connections(self):
        """Confirmed live 2026-09-30, tenant-wide -- the DB integration
        config (auth_type/auth_details/health_issues/
        discovered_accounts_count) that database accounts are discovered
        through, distinct from a database ACCOUNT itself."""
        path = DATABASE_CONNECTIONS_PATH.format(team=self.team_name)
        return self._list(path)

    def list_saas_app_connections(self):
        """Confirmed live 2026-09-30, tenant-wide -- the Okta app
        integration (app_instance_id/app_instance_name/global_app_name)
        that SaaS service accounts are discovered through."""
        path = SAAS_APP_CONNECTIONS_PATH.format(team=self.team_name)
        return self._list(path)

    def list_active_directory_connections(self):
        """Confirmed live 2026-09-30, tenant-wide -- the AD domain
        connection (domain/okta_app_instance_id/status) that Active
        Directory accounts are discovered through. NOT the same as
        GET /integrations/ad_connections, which returned 401 "Missing
        capability: ad_connection.list" for this tenant's service account
        -- this connections/active_directory path is separately
        accessible and returns real data."""
        path = ACTIVE_DIRECTORY_CONNECTIONS_PATH.format(team=self.team_name)
        return self._list(path)

    def list_clients(self):
        """Confirmed live 2026-09-30 against a real tenant (patlabs, 10 real
        enrolled clients returned) -- every end-user OPA client (laptop/
        workstation) enrolled for this team, not just the caller's own
        (requires ?all=true, per the spec's own ListClients description:
        'By default, this only returns clients associated with the
        requesting user')."""
        path = CLIENTS_PATH.format(team=self.team_name) + "?all=true"
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

    def list_project_active_directory_accounts(self, resource_group_id, project_id):
        """Confirmed live 2026-09-30 against a real tenant (patlabs, project
        Test_User_A_Project) -- real shape includes account_name,
        sam_account_name, distinguished_name, sid, domain.name, email,
        account_status_detail."""
        path = PROJECT_ACTIVE_DIRECTORY_ACCOUNTS_PATH.format(
            team=self.team_name, resource_group_id=resource_group_id, project_id=project_id
        )
        return self._list(path)

    def list_project_database_accounts(self, resource_group_id, project_id):
        """Confirmed live 2026-09-30 against a real tenant (patlabs, projects
        Postgresql-DB-Accounts/SQL-DB-Accounts) -- real shape includes
        account_name, database_connection.name,
        database_connection_auth_type, account_status_detail."""
        path = PROJECT_DATABASE_ACCOUNTS_PATH.format(
            team=self.team_name, resource_group_id=resource_group_id, project_id=project_id
        )
        return self._list(path)

    def list_assignments(self):
        """Confirmed live 2026-09-30, tenant-wide -- links a relationship
        (see list_relationships) to a principal (a real user_group in this
        tenant) plus the specific resource(s) it grants. See
        ASSIGNMENTS_PATH's docstring.

        REAL GOTCHA confirmed live: this list response's
        `resource_assignments` is always null and `relationship_assignments`
        is absent entirely -- only get_assignment (the per-item detail
        fetch) has the real data. Never rely on this list alone for
        resolving what an assignment actually grants."""
        path = ASSIGNMENTS_PATH.format(team=self.team_name)
        return self._list(path)

    def get_assignment(self, assignment_id):
        """The per-item detail fetch -- see list_assignments' docstring for
        why this is required (the list endpoint alone omits
        resource_assignments/relationship_assignments)."""
        path = f"{ASSIGNMENTS_PATH.format(team=self.team_name)}/{assignment_id}"
        return self.request("GET", path)

    def list_relationships(self):
        """Confirmed live 2026-09-30, tenant-wide -- see
        RELATIONSHIPS_PATH's docstring. An assignment's own embedded
        `relationships[]` is a stripped-down ref (id/name/type only); this
        is the full object."""
        path = RELATIONSHIPS_PATH.format(team=self.team_name)
        return self._list(path)

    def get_ad_connection_rules(self, ad_connection_id):
        """Confirmed live 2026-09-30 -- one AD connection's discovery rules
        (SHARED/INDIVIDUAL, OU-scoped). Plain list fetch, not paginated in
        practice for a real tenant's AD connection count, but uses _list
        for consistency with every other collection endpoint."""
        path = AD_CONNECTION_RULES_PATH.format(team=self.team_name, ad_connection_id=ad_connection_id)
        return self._list(path)

    def get_ad_connection_rule_settings(self, ad_connection_id):
        """Confirmed live 2026-09-30 -- a single object (is_configured/
        matching_criteria/partial_matching_criteria/allow_partial_matches),
        not a collection -- plain GET, not _list."""
        path = AD_CONNECTION_RULE_SETTINGS_PATH.format(team=self.team_name, ad_connection_id=ad_connection_id)
        return self.request("GET", path)

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

    def request(self, method, path, body=None, return_headers=False):
        url = self.base_url + path
        headers = {"Authorization": f"SSWS {self.api_token}"}
        return http_json_request(method, url, headers=headers, body=body, error_cls=OktaApiError,
                                  return_headers=return_headers)

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

    def find_user_by_login_or_email(self, identifier):
        """GET /api/v1/users/{id|login|email} -- Okta's Users API resolves
        the path segment against id, login, or email interchangeably.
        Needed because an OPA (PAM) user's own id is an OPA-internal UUID
        with no relationship to Okta's identity id, but PAM is built on
        top of Okta, so the same person's Okta identity can be found by
        their login/email -- and System Log's actor.id is that Okta
        identity id, not the PAM one."""
        return self.request("GET", f"/api/v1/users/{urllib.parse.quote(identifier, safe='')}")

    def get_device_authenticator_enrollments(self, device_id):
        """GET /api/v1/devices/{id}/authenticator-enrollments -- confirmed
        live 2026-10-01 (initially 401'd with "Missing capability" until
        the user enabled the underlying Okta feature flag mid-session;
        re-confirmed working immediately after). Real shape: a list of
        {id, type, key (e.g. "okta_verify"), name, status}, one per
        authenticator the device itself has verified/enrolled -- distinct
        from the user.authentication.auth_via_mfa event-level `factor`
        field (see audit_store._resource_fields), which only shows what
        was used in ONE sign-in, not every authenticator this device is
        capable of using going forward."""
        return self.request("GET", f"/api/v1/devices/{urllib.parse.quote(device_id, safe='')}/authenticator-enrollments")

    def list_devices(self):
        """GET /api/v1/devices, following Link: rel="next" (same generic
        _parse_next_link helper the System Log pagination already uses --
        confirmed live 2026-10-01 this header shape matches). This is
        Okta's own org-wide DEVICE inventory (laptops/phones enrolled for
        MFA/device-trust purposes) -- a genuinely separate thing from
        OpaClient.list_clients' OPA Clients (the PAM connection agent a
        human runs to make SSH/RDP connections). A person can have an
        Okta-managed device with zero OPA clients (never touches PAM) or
        an OPA client with no matching Okta-managed device (BYOD laptop,
        device trust not enforced) -- confirmed live by comparing this
        tenant's real device/client lists, which only partially overlap
        by hostname/serial. Real fields confirmed live: id, created,
        lastUpdated, status (ACTIVE/SUSPENDED/etc.), profile.displayName/
        platform/manufacturer/model/osVersion/serialNumber/registered/
        secureHardwarePresent/diskEncryptionType (not all present on every
        platform -- e.g. iOS devices had no diskEncryptionType).

        Each returned device gets an added `authenticator_enrollments` key
        (one extra API call per device -- confirmed live this is a small,
        per-end-user-headcount-bounded list, not per-resource like
        folders/secrets, so this doesn't scale badly the way a naive
        per-folder call would). A device whose enrollments can't be
        fetched (e.g. the underlying Okta feature isn't enabled for this
        org) gets an empty list rather than failing the whole bootstrap --
        confirmed live this really does 401 on orgs without the feature
        flag on, not something to let take down every other resource kind
        in the same bootstrap pass."""
        devices = []
        next_path = "/api/v1/devices?limit=200"
        while next_path:
            resp, headers = self.request("GET", next_path, return_headers=True)
            devices.extend(resp or [])
            next_path = _parse_next_link(headers)
            if next_path and next_path.startswith(self.base_url):
                next_path = next_path[len(self.base_url):]
        for d in devices:
            try:
                d["authenticator_enrollments"] = self.get_device_authenticator_enrollments(d["id"])
            except OktaApiError:
                d["authenticator_enrollments"] = []
        return devices

    def get_system_log(self, filter_expr=None, since=None, until=None, limit=1000, sort_order="DESCENDING", max_pages=50):
        """GET /api/v1/logs, following the Link: rel="next" header until
        exhausted (or max_pages, as a runaway-query backstop -- logged, not
        silent, if actually hit). Confirmed live 2026-08-14: this org's
        retention is exactly 90 days (earliest available event was
        published 90 days before "today" when queried with an older
        `since`) -- matches Okta's documented System Log retention, not
        assumed. `filter` uses the same SCIM-ish expression syntax as other
        Okta management APIs (e.g. 'actor.id eq "..." and eventType eq
        "..."'). `until` is Okta's own documented `/api/v1/logs` query
        param -- added so callers doing a day-by-day chunked walk (see
        audit_store.sync_okta_events) can bound each chunk instead of
        relying solely on max_pages, confirmed live 2026-09-29: a genuinely
        busy tenant's automatic OPA credential-rotation traffic alone can
        exceed max_pages=200 (200k events) within a single 90-day window,
        which would otherwise truncate a first-run backfill silently short
        of "now" even though the underlying API call succeeded every time.

        Single-page (limit<=1000) was fine against a low-volume tenant, but
        a busier one (e.g. high service-account rotation traffic) can
        exceed 1000 matching events inside a 90-day window even after
        actor+eventType filtering -- silently returning only page 1 would
        make find_last_access_for_user miss real, more-recent-than-shown
        events for no visible reason. Found via live testing against a
        second, busier tenant, not anticipated up front.

        Returns (events, complete) -- `complete` is False when max_pages
        was hit with more pages still remaining (the WARN below still
        fires either way, but FIX, external review 2026-09-30, "1.5": a
        caller that persists a watermark off this result (see
        audit_store.sync_okta_events) MUST know when results were
        truncated, since silently treating a truncated page as "this
        window is fully synced" and advancing the watermark past it
        permanently loses whatever events existed past the page cap --
        Okta's System Log has no way to re-fetch an already-aged-out
        window later. Every other existing caller of this method only
        ever used the bare list and has no watermark to protect, so they
        simply unpack `events, _complete = ...` and ignore it."""
        params = {"limit": str(limit), "sortOrder": sort_order}
        if filter_expr:
            params["filter"] = filter_expr
        if since:
            params["since"] = since
        if until:
            params["until"] = until
        query = urllib.parse.urlencode(params)
        events = []
        next_path = f"{SYSTEM_LOG_PATH}?{query}"
        pages = 0
        while next_path and pages < max_pages:
            resp, headers = self.request("GET", next_path, return_headers=True)
            events.extend(resp or [])
            next_path = _parse_next_link(headers)
            # Link URLs from Okta are absolute (https://org...) -- request()
            # always prefixes self.base_url, so strip it back down to a path.
            if next_path and next_path.startswith(self.base_url):
                next_path = next_path[len(self.base_url):]
            pages += 1
        complete = not next_path
        if not complete:
            log("WARN", f"get_system_log hit max_pages={max_pages} with more pages remaining; "
                         f"results are truncated to the first {len(events)} events.")
        return events, complete


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


def full_path(resource, by_id):
    """Reconstructs a "Root/Child/.../Leaf" path for a folder or secret from
    its parent_id chain, given a {id: resource} map of every folder in the
    same project (both fetch_all_folders and fetch_all_folders_and_secrets
    build ids/parent_id in the same shape). Shared by serve.py's /folders
    route and build_secrets_access_report so the path-reconstruction walk
    isn't duplicated between the two."""
    names = []
    current = resource
    while current is not None:
        names.append(current["name"])
        parent_id = current.get("parent_id")
        current = by_id.get(parent_id) if parent_id else None
    return "/".join(reversed(names))


def _folder_descendant_secrets(folders, secrets):
    """{folder_id: [{"id", "name"}, ...]} mapping each folder (from one
    project's flat folder/secret lists) to every secret nested anywhere
    beneath it, at any depth -- not just its direct children.

    Needed because a secret_folder policy grant applies to the whole
    subtree, but System Log access events are only attributable to
    individual secrets (see RESOURCE_ACCESS_EVENT_TYPES) -- so "last
    accessed" for a folder-level grant has to walk down to the secrets
    actually inside it."""
    children_folders = defaultdict(list)
    direct_secrets = defaultdict(list)
    for f in folders:
        if f.get("parent_id"):
            children_folders[f["parent_id"]].append(f["id"])
    for s in secrets:
        direct_secrets[s.get("parent_id")].append({"id": s.get("id"), "name": s.get("name")})

    result = {}
    for f in folders:
        root_id = f["id"]
        stack, seen, collected = [root_id], set(), []
        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.add(cur)
            collected.extend(direct_secrets.get(cur, []))
            stack.extend(children_folders.get(cur, []))
        result[root_id] = collected
    return result


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
            # resource_kind is the raw selector_type (e.g. "secret" vs.
            # "secret_folder") -- resource_type alone can't distinguish these
            # (both fall under "secret_based_resource"), but System Log
            # access-tracking only works for one of them (see
            # find_last_access_for_user), so the frontend needs this.
            resolved = {"kind": "resolved", "id": ref.get("id"), "name": ref.get("name"),
                        "resource_kind": selector_type,
                        "project_id": None, "project_name": None, "resource_group_id": None}
            if hit:
                resolved.update(hit)
            if selector_type == "secret_folder":
                # A folder grant covers every secret in its subtree, but
                # System Log events only attribute to individual secrets --
                # attach the folder's descendant secrets so the frontend can
                # look up (and roll up) per-secret access under this grant.
                resolved["child_secrets"] = indexes.get("secret_folder_children", {}).get(ref.get("id"), [])
            return resolved
    except Exception:
        pass
    return {"kind": "condition", "description": describe_dynamic_selector(resource_type, selector_type, selector)}


# One entry per real resource_assignments key seen live -- (id_field,
# name_field) into a resolved {"kind":"resolved", ...} entry. Deliberately
# a lookup table, not a hardcoded single-kind assumption: confirmed live
# against BOTH patlabs (saas_app_account_assignments) and dev
# (secret_or_folder_assignments) that this "this is a new feature, we'll
# see more of this" -- new kinds are expected to keep appearing. An
# unrecognized future key still resolves generically (see
# _resolve_relationship_assignment_resources below) rather than being
# silently dropped.
_RELATIONSHIP_ASSIGNMENT_ID_NAME_FIELDS = {
    # Confirmed live 2026-09-30 (patlabs) -- privileged_resource_id is the
    # SaaS account's real System Log-tracking id (same field this
    # codebase already relies on elsewhere for SaaS accounts -- see
    # RESOURCE_ACCESS_EVENT_TYPES' access_tracking_id precedent).
    "saas_app_account_assignments": ("privileged_resource_id", "account_name"),
    # Confirmed live 2026-09-30 (dev) -- a secret OR secret_folder grant,
    # distinguished by the item's own "type" field, not this dict key.
    "secret_or_folder_assignments": ("id", "name"),
}


def _resolve_relationship_assignment_resources(resource_assignments, relationship_name=None, assignment_name=None):
    """Resolves one assignment's `resource_assignments` (confirmed live to
    vary in shape by which real resource kind was granted -- see
    _RELATIONSHIP_ASSIGNMENT_ID_NAME_FIELDS above) into the same
    {"kind": "resolved", ...} shape _resolve_selector_entry already
    produces for ordinary policy-rule selectors, so the frontend renders
    both identically with zero special-casing. Generic over unrecognized
    future keys (falls back to whatever "id"/"name" fields the item
    happens to have) rather than dropping them.

    `relationship_name`/`assignment_name`, when given, are attached to
    every resolution so a caller (Users/Groups/Projects/etc. tabs, via
    PolicyRuleCard) can show WHICH relationship/assignment produced a
    relationship-derived grant -- omitted (not just None) when the caller
    doesn't have them yet, e.g. the assignment-level `resolved_resources`
    attached directly in build_access_model, which has no single
    relationship in scope (one assignment can span several)."""
    if not resource_assignments:
        return []
    out = []
    for key, items in resource_assignments.items():
        id_field, name_field = _RELATIONSHIP_ASSIGNMENT_ID_NAME_FIELDS.get(key, ("id", "name"))
        # secret_or_folder_assignments distinguishes secret vs. secret_folder
        # via the item's own "type" field (confirmed live) -- fall back to
        # the dict key itself for any kind with no such field.
        for item in items or []:
            inner_kind = item.get("type") or key
            resolved = {
                "kind": "resolved",
                "id": item.get(id_field),
                "name": item.get(name_field),
                "resource_kind": f"relationship_assignment:{inner_kind}",
                "project_id": None, "project_name": None, "resource_group_id": None,
            }
            if relationship_name is not None:
                resolved["relationship_name"] = relationship_name
            if assignment_name is not None:
                resolved["assignment_name"] = assignment_name
            out.append(resolved)
    return out


def _resolve_rule(rule, indexes):
    resource_type = rule.get("resource_type")
    entries = (rule.get("resource_selector") or {}).get("selectors") or []
    resolutions = [
        _resolve_selector_entry(resource_type, entry.get("selector_type"), entry.get("selector") or {}, indexes)
        for entry in entries
    ]
    return resolutions or [{"kind": "condition",
                             "description": RESOURCE_TYPE_LABELS.get(resource_type, resource_type)}]


def _extract_request_id(event):
    """Per Okta support's own guidance (how-to-find-x-okta-request-id):
    the x-okta-request-id header value is looked up in System Log as
    debugContext.debugData.requestId OR transaction.id -- both are treated
    as equally valid "the request ID" for a given event, and either can
    be used to search for the other. Falls back to the event's own uuid
    (always present) only if neither of those is."""
    debug_data = (event.get("debugContext") or {}).get("debugData") or {}
    return debug_data.get("requestId") or (event.get("transaction") or {}).get("id") or event.get("uuid")


def resolve_okta_actor_id(okta_client, email):
    """Translates an OPA (PAM) user into the Okta identity id that System
    Log's actor.id actually refers to -- see OktaClient.find_user_by_login_or_email
    for why the PAM user's own id can't be used directly. Raises
    OktaApiError if no matching Okta user exists (e.g. a PAM-only service
    account with no Okta identity behind it)."""
    if not email:
        raise OktaApiError("n/a", "resolve_okta_actor_id", "This PAM user has no email on file to resolve against Okta.")
    return okta_client.find_user_by_login_or_email(email)["id"]


def find_last_access_for_user(okta_client, actor_user_id, resources, limit_per_resource=5, since_days=90):
    """For each {resource_kind, resource_id} in `resources`, finds up to
    `limit_per_resource` most-recent System Log events (within the last
    `since_days`) where `actor_user_id` accessed that specific resource.

    One System Log call per distinct resource_kind present in `resources`
    (not one per resource) -- events are fetched filtered by actor+eventType
    only, then bucketed client-side by matching each event's target[] ids
    against the requested resource ids. This is the only viable approach:
    Okta's log `filter` doesn't support querying by target.id, so per-
    resource server-side filtering isn't possible; filtering by actor+
    eventType first keeps each query's result set small instead of scanning
    the org's entire log.

    Returns a dict keyed by resource_id:
        {"resource_kind": ..., "supported": bool, "events": [
            {"published": ..., "request_id": ..., "outcome": ...}, ...
        ]}
    `supported=False` (empty events, no query made) for any resource_kind
    not in RESOURCE_ACCESS_EVENT_TYPES -- see that constant's comment for
    why those are intentionally left unmapped rather than guessed."""
    results = {}
    by_kind = {}
    for r in resources:
        by_kind.setdefault(r["resource_kind"], []).append(r["resource_id"])

    since = (datetime.now(timezone.utc) - timedelta(days=since_days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    for resource_kind, resource_ids in by_kind.items():
        mapping = RESOURCE_ACCESS_EVENT_TYPES.get(resource_kind)
        if not mapping:
            for rid in resource_ids:
                results[rid] = {"resource_kind": resource_kind, "supported": False, "events": []}
            continue

        type_filter = " or ".join(f'eventType eq "{t}"' for t in mapping["event_types"])
        filter_expr = f'actor.id eq "{actor_user_id}" and ({type_filter})'
        # No watermark to protect here (read-only lookup, nothing persisted)
        # -- completeness only matters to sync_okta_events, see
        # get_system_log's docstring.
        events, _complete = okta_client.get_system_log(filter_expr=filter_expr, since=since, limit=1000)

        wanted = set(resource_ids)
        buckets = {rid: [] for rid in resource_ids}
        for event in events:  # already DESCENDING (most-recent-first) by default
            hit_ids = mapping["extract_ids"](event) & wanted
            for rid in hit_ids:
                if len(buckets[rid]) < limit_per_resource:
                    buckets[rid].append({
                        "published": event.get("published"),
                        "request_id": _extract_request_id(event),
                        "outcome": (event.get("outcome") or {}).get("result"),
                    })

        for rid in resource_ids:
            results[rid] = {"resource_kind": resource_kind, "supported": True, "events": buckets[rid]}

    return results


def _access_report_target(event, target_type):
    """The event's own target[] entry of the given type ('Secret' or
    'Secret Folder') -- carries that resource's id + displayName. Returns
    None if this event doesn't target that type (shouldn't happen for
    events already bucketed under the matching resource_kind, but guards
    against an unexpected payload shape rather than raising)."""
    return next((t for t in (event.get("target") or []) if t.get("type") == target_type), None)


try:
    from cryptography.fernet import Fernet, InvalidToken
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

# Env var checked BEFORE keyring for the cache-encryption key, so a headless
# server deployment (systemd LoadCredential=, a secrets manager, etc. --
# nothing that depends on a desktop secret-service/D-Bus session, which
# `keyring` itself needs and a bare Ubuntu server doesn't have) can supply
# its own key without touching the standalone/desktop path at all. Same
# precedence idea as the rest of this file's "server-friendly override,
# desktop-friendly default" split (see keyring_get/set above).
SECRETS_LOG_CACHE_KEY_ENV_VAR = "OPA_SECRETS_WIZARD_LOG_CACHE_KEY"
_SECRETS_LOG_CACHE_KEYRING_FIELD = "secrets_log_cache_key"
_SECRETS_LOG_CACHE_KEYRING_ENV = "_shared"  # not a real saved environment name; one key for the whole cache file


def _get_or_create_cache_encryption_key():
    """Returns the Fernet key used to encrypt secrets_log_cache.json, as
    bytes. Checked in order: SECRETS_LOG_CACHE_KEY_ENV_VAR (server mode --
    caller/deployment owns key lifecycle entirely), then the OS keyring
    (standalone/desktop mode -- generated once and stored there,
    transparent to the user, mirrors how credential secrets already work).
    Raises RuntimeError if neither is available, since silently falling
    back to plaintext would defeat the point of calling this at all."""
    env_key = os.environ.get(SECRETS_LOG_CACHE_KEY_ENV_VAR)
    if env_key:
        return env_key.encode("utf-8")

    _require_keyring()
    existing = keyring_get(_SECRETS_LOG_CACHE_KEYRING_ENV, _SECRETS_LOG_CACHE_KEYRING_FIELD)
    if existing:
        return existing.encode("utf-8")

    new_key = Fernet.generate_key()
    keyring_set(_SECRETS_LOG_CACHE_KEYRING_ENV, _SECRETS_LOG_CACHE_KEYRING_FIELD, new_key.decode("utf-8"))
    return new_key


def _cache_fernet():
    if not CRYPTOGRAPHY_AVAILABLE:
        raise RuntimeError(
            "The 'cryptography' package is required to store Secrets Access Dashboard "
            "history locally. Install it with: pip install cryptography"
        )
    return Fernet(_get_or_create_cache_encryption_key())


def _secrets_log_cache_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "secrets_log_cache.json")


def load_secrets_log_cache():
    """Reads and decrypts secrets_log_cache.json. A file from before
    encryption was added (plaintext JSON) is detected and transparently
    migrated: read as plaintext once, then re-saved encrypted on the next
    save_secrets_log_cache call (callers of load always go on to mutate +
    save, so this doesn't need its own write). A file that fails to
    decrypt under the CURRENT key (e.g. the keyring entry was cleared, or
    OPA_SECRETS_WIZARD_LOG_CACHE_KEY changed/is missing after being set
    before) is treated as unreadable history, not a crash -- logged as a
    warning and started fresh, same "never let a cache problem take down
    the dashboard" posture as the rest of this cache."""
    path = _secrets_log_cache_path()
    if not os.path.isfile(path):
        return {}
    with open(path, "rb") as f:
        raw = f.read()
    if not raw:
        return {}
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass  # not plaintext JSON -- fall through to decrypt
    try:
        plaintext = _cache_fernet().decrypt(raw)
    except InvalidToken:
        log("WARN", f"{path} could not be decrypted with the current key -- starting a fresh local cache. "
                     "This happens if the encryption key changed or was lost; previously-cached history is "
                     "not recoverable, but nothing else is affected.")
        return {}
    return json.loads(plaintext.decode("utf-8"))


def save_secrets_log_cache(data):
    encrypted = _cache_fernet().encrypt(json.dumps(data).encode("utf-8"))
    _atomic_write_bytes(_secrets_log_cache_path(), encrypted)


def set_preserve_logs_locally(name, enabled, owner=LOCAL_OWNER_KEY):
    """Opt an environment in/out of caching Secrets Access Dashboard System
    Log events to disk (secrets_log_cache.json) beyond Okta's 90-day
    retention. A dedicated action rather than folded into
    upsert_environment's metadata-field loop, since this is a plain
    boolean toggle, not part of the credential form. Raises KeyError if
    `name` isn't a saved environment owned by `owner`."""
    storage_name = environment_storage_name(owner, name)
    data = load_environments()
    if storage_name not in data["environments"]:
        raise KeyError(f"No saved environment named '{name}'")
    data["environments"][storage_name]["preserve_logs_locally"] = bool(enabled)
    save_environments(data)


SYNC_SCHEDULE_DEFAULTS = {
    "enabled": False,
    "run_time": "02:00",  # 24h local HH:MM
    "ingestion_scope": "curated",  # "curated" or "all" -- see audit_store.py
    "retention_days": None,  # None = no time-based prune
    "retention_max_size_mb": None,  # None = no size-based prune
}


def get_sync_schedule(name, owner=LOCAL_OWNER_KEY):
    """Returns the environment's sync_schedule dict, filled in with
    SYNC_SCHEDULE_DEFAULTS for any field never explicitly set (so callers
    never have to guess at partial/legacy shapes). Raises KeyError if
    `name` isn't a saved environment owned by `owner`."""
    storage_name = environment_storage_name(owner, name)
    data = load_environments()
    if storage_name not in data["environments"]:
        raise KeyError(f"No saved environment named '{name}'")
    stored = data["environments"][storage_name].get("sync_schedule", {})
    return {**SYNC_SCHEDULE_DEFAULTS, **stored}


def set_sync_schedule(name, config, owner=LOCAL_OWNER_KEY):
    """Saves the environment's daily-sync configuration (enabled, run
    time, ingestion scope, retention). Own dedicated setter, deliberately
    NOT folded into upsert_environment's metadata-field loop -- same
    reasoning as set_preserve_logs_locally above: this is a settings
    object, not part of the credential form. Raises KeyError if `name`
    isn't a saved environment owned by `owner`, ValueError if
    ingestion_scope isn't a real choice."""
    if config.get("ingestion_scope", "curated") not in ("curated", "all"):
        raise ValueError('ingestion_scope must be "curated" or "all"')
    storage_name = environment_storage_name(owner, name)
    data = load_environments()
    if storage_name not in data["environments"]:
        raise KeyError(f"No saved environment named '{name}'")
    merged = {**SYNC_SCHEDULE_DEFAULTS, **data["environments"][storage_name].get("sync_schedule", {}), **config}
    data["environments"][storage_name]["sync_schedule"] = merged
    save_environments(data)
    return merged


def _merge_system_log_events(env_name, project_id, events):
    """Upserts freshly-fetched System Log events (keyed by their own uuid,
    always present) into secrets_log_cache.json under
    cache[env_name][project_id], then returns the full merged list for that
    project -- cache entries the live 90-day query no longer returns (aged
    out of Okta's retention) are preserved, not dropped, which is the whole
    point of this cache. Records first_captured_at once, the first time any
    event is ever written for this project, so the UI can be honest about
    how far back local coverage actually goes (never further than the
    moment this was turned on)."""
    cache = load_secrets_log_cache()
    project_bucket = cache.setdefault(env_name, {}).setdefault(project_id, {"first_captured_at": None, "events": {}})
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    if project_bucket["first_captured_at"] is None and events:
        project_bucket["first_captured_at"] = now
    for event in events:
        uid = event.get("uuid")
        if uid:
            project_bucket["events"][uid] = event
    save_secrets_log_cache(cache)
    return list(project_bucket["events"].values())


def build_secrets_access_report(client, okta_client, resource_group_id, project_id, since_days=90, reveal_limit=5,
                                 preserve_locally=False, env_name=None):
    """For every secret and secret folder in a project -- including ones
    since deleted -- who created/updated/deleted/(for secrets) revealed it,
    and when. See SECRETS_ACCESS_REPORT_EVENT_TYPES's comment for the live
    verification behind this.

    Two sources merged into one report:
      1. The live folder/secret walk (fetch_all_folders_and_secrets) --
         "what exists right now."
      2. One System Log query, filtered by target.id eq project_id (a
         project-scoped event's target[] always includes the project as a
         co-target, confirmed live) AND the 7 known eventTypes, since the
         `since_days` cutoff -- "what happened," including to things that
         no longer exist and therefore aren't in source 1 at all.

    A resource present in the live walk is "active" even with zero log
    history (it may simply be older than the 90-day retention window --
    this is surfaced honestly via since_days in the response rather than
    guessed at). A resource with log history but absent from the live walk
    is "deleted" only if its bucket actually contains a delete event;
    otherwise it's "unknown" (e.g. a create/update inside the log window
    for something that's since aged out of *this* project's live listing
    for some other reason) -- never silently assumed deleted without direct
    evidence.

    Returns {"secrets": [...], "folders": [...], "since_days": since_days,
    "local_retention_enabled": preserve_locally, "oldest_captured_at": ...}.
    Each row: {id, name, path, status, created, updated, deleted}
    (created/deleted are {"by", "at"} or None; updated is a list of
    {"by", "at"}, most-recent-first). Secret rows additionally carry
    reveals: a list of {"by", "at", "request_id"}, most-recent-first,
    capped at reveal_limit.

    If `preserve_locally` is set (with `env_name`), every event this live
    query returns is merged into secrets_log_cache.json (see
    _merge_system_log_events) and the merged set -- not just this call's
    live 90-day window -- is what actually gets bucketed below, so history
    already captured survives Okta aging it out of its own retention.
    `oldest_captured_at` in the response is the earliest event timestamp
    actually available (from the merged set if caching is on, else just
    this query's own results) -- never further back than whenever caching
    was first turned on for this project, since events already >90 days
    old the first time can't be retroactively recovered."""
    folders, secrets = fetch_all_folders_and_secrets(client, resource_group_id, project_id)
    folders_by_id = {f["id"]: f for f in folders if f.get("id")}
    secrets_by_id = {s["id"]: s for s in secrets if s.get("id")}

    type_filter = " or ".join(
        f'eventType eq "{t}"' for types in SECRETS_ACCESS_REPORT_EVENT_TYPES.values() for t in types
    )
    since = (datetime.now(timezone.utc) - timedelta(days=since_days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    filter_expr = f'target.id eq "{project_id}" and ({type_filter})'
    # No watermark to protect here (read-only report, nothing persisted) --
    # completeness only matters to sync_okta_events, see get_system_log's
    # docstring.
    events, _complete = okta_client.get_system_log(filter_expr=filter_expr, since=since, limit=1000)

    if preserve_locally and env_name:
        events = _merge_system_log_events(env_name, project_id, events)
        # _merge_system_log_events returns cache.values(), insertion order,
        # not necessarily DESCENDING -- the bucketing loop below relies on
        # most-recent-first (first create/delete seen wins), so re-sort
        # explicitly rather than assume dict ordering happens to match.
        events = sorted(events, key=lambda e: e.get("published") or "", reverse=True)
    oldest_captured_at = min((e.get("published") for e in events if e.get("published")), default=None)

    # Per resource_kind: {resource_id: {"name":..., "path":..., "created":None,
    # "updated":[], "deleted":None, "reveals":[]}} -- path is filled from the
    # log's own "Secret Path" target (a leading "/" stripped for
    # consistency with the live walk's slash-joined convention), since a
    # deleted resource's path can't be reconstructed any other way.
    buckets = {"secret": {}, "secret_folder": {}}
    target_type_for_kind = {"secret": "Secret", "secret_folder": "Secret Folder"}
    event_type_to_kind = {
        t: kind for kind, types in SECRETS_ACCESS_REPORT_EVENT_TYPES.items() for t in types
    }

    for event in events:  # already DESCENDING (most-recent-first) per get_system_log's default
        kind = event_type_to_kind.get(event.get("eventType"))
        if kind is None:
            continue
        target = _access_report_target(event, target_type_for_kind[kind])
        if target is None or not target.get("id"):
            continue
        rid = target["id"]
        bucket = buckets[kind].setdefault(rid, {
            "name": target.get("displayName") or "",
            "path": "",
            "created": None,
            "updated": [],
            "deleted": None,
            "reveals": [],
        })
        path_target = next((t for t in (event.get("target") or []) if t.get("type") == "Secret Path"), None)
        if path_target and not bucket["path"]:
            bucket["path"] = (path_target.get("displayName") or "").lstrip("/")

        # displayName over alternateId: for a human actor these usually
        # agree (full name vs. email), but a service-account actor (e.g.
        # this dashboard's own "claudesvr") has an opaque "users/<uuid>"
        # alternateId/id with the only human-readable value in
        # displayName -- confirmed live against real delete events from
        # this project's own past service-account-driven testing.
        actor = event.get("actor") or {}
        entry = {"by": actor.get("displayName") or actor.get("alternateId"), "at": event.get("published")}
        event_type = event.get("eventType")
        if event_type.endswith(".create"):
            if bucket["created"] is None:  # events are most-recent-first; a resource has exactly one create
                bucket["created"] = entry
        elif event_type.endswith(".update"):
            bucket["updated"].append(entry)
        elif event_type.endswith(".delete"):
            if bucket["deleted"] is None:
                bucket["deleted"] = entry
        elif event_type.endswith(".reveal"):
            if len(bucket["reveals"]) < reveal_limit:
                bucket["reveals"].append({**entry, "request_id": _extract_request_id(event)})

    def _build_rows(kind, live_by_id):
        rows = []
        seen_ids = set()
        for rid, resource in live_by_id.items():
            seen_ids.add(rid)
            b = buckets[kind].get(rid, {})
            # A secret's parent_id always points at a folder (never another
            # secret), so path reconstruction walks folders_by_id regardless
            # of which kind is being built.
            rows.append({
                "id": rid,
                "name": resource.get("name", ""),
                "path": full_path(resource, folders_by_id),
                "status": "active",
                "created": b.get("created"),
                "updated": b.get("updated", []),
                "deleted": b.get("deleted"),
                **({"reveals": b.get("reveals", [])} if kind == "secret" else {}),
            })
        for rid, b in buckets[kind].items():
            if rid in seen_ids:
                continue
            # Not in the live walk: "deleted" only with direct evidence
            # (a real delete event in this bucket) -- otherwise "unknown"
            # rather than assumed, per this report's honesty requirement.
            status = "deleted" if b.get("deleted") else "unknown"
            rows.append({
                "id": rid,
                "name": b.get("name", ""),
                "path": b.get("path", ""),
                "status": status,
                "created": b.get("created"),
                "updated": b.get("updated", []),
                "deleted": b.get("deleted"),
                **({"reveals": b.get("reveals", [])} if kind == "secret" else {}),
            })
        return rows

    return {
        "secrets": _build_rows("secret", secrets_by_id),
        "folders": _build_rows("secret_folder", folders_by_id),
        "since_days": since_days,
        "local_retention_enabled": bool(preserve_locally and env_name),
        "oldest_captured_at": oldest_captured_at,
    }


def build_project_secrets_report_from_archive(client, environment, resource_group_id, project_id):
    """Phase 5 of the compliance-reporting-dashboard plan: the same report
    as build_secrets_access_report above, but sourced from the unified
    audit_store.py SQLite archive instead of a live Okta System Log call
    + the bespoke secrets_log_cache.json. Requires `audit_store` to have
    already been populated for `environment` (via a sync or CSV import) --
    this function does not itself call Okta at all, so it works even with
    no Okta API token configured, unlike the original.

    Deliberately reuses the EXACT SAME bucketing/status logic as
    build_secrets_access_report (verbatim-copied, not refactored to share
    code) -- that function's active/deleted/unknown honesty rules took
    several iterations to get right (see this project's own history), and
    the risk of a shared-code refactor introducing a subtle regression in
    the already-working live-query path outweighs the small duplication.
    Only the EVENT SOURCE differs: audit_store.query_events (all history
    ever ingested, no 90-day/1000-row cap) instead of one bounded
    okta_client.get_system_log call.

    Returns the exact same shape as build_secrets_access_report, with
    `local_retention_enabled` always True (the whole point of sourcing
    from the archive) and `oldest_captured_at` reflecting the archive's
    real earliest event for this project, not a live-query artifact."""
    import audit_store

    folders, secrets = fetch_all_folders_and_secrets(client, resource_group_id, project_id)
    folders_by_id = {f["id"]: f for f in folders if f.get("id")}
    secrets_by_id = {s["id"]: s for s in secrets if s.get("id")}

    all_event_types = [t for types in SECRETS_ACCESS_REPORT_EVENT_TYPES.values() for t in types]
    archived_rows = audit_store.query_events(environment, event_types=all_event_types, limit=100000)
    # audit_store stores the raw Okta event dict under "raw" -- filter to
    # this project client-side (confirmed live: a project-scoped event's
    # target[] always includes the project itself as a co-target, same
    # fact the original function's server-side `target.id eq` filter
    # relies on -- just applied here instead of in the query, since the
    # archive has no per-project index and doesn't need one at this
    # realistic scale, see plan for the real row-count check behind this).
    events = [
        r["raw"] for r in archived_rows
        if any(t.get("type") == "Project" and t.get("id") == project_id for t in (r["raw"].get("target") or []))
    ]
    events = sorted(events, key=lambda e: e.get("published") or "", reverse=True)
    oldest_captured_at = min((e.get("published") for e in events if e.get("published")), default=None)

    buckets = {"secret": {}, "secret_folder": {}}
    target_type_for_kind = {"secret": "Secret", "secret_folder": "Secret Folder"}
    event_type_to_kind = {
        t: kind for kind, types in SECRETS_ACCESS_REPORT_EVENT_TYPES.items() for t in types
    }

    for event in events:  # already sorted DESCENDING (most-recent-first) above
        kind = event_type_to_kind.get(event.get("eventType"))
        if kind is None:
            continue
        target = _access_report_target(event, target_type_for_kind[kind])
        if target is None or not target.get("id"):
            continue
        rid = target["id"]
        bucket = buckets[kind].setdefault(rid, {
            "name": target.get("displayName") or "",
            "path": "",
            "created": None,
            "updated": [],
            "deleted": None,
            "reveals": [],
        })
        path_target = next((t for t in (event.get("target") or []) if t.get("type") == "Secret Path"), None)
        if path_target and not bucket["path"]:
            bucket["path"] = (path_target.get("displayName") or "").lstrip("/")

        actor = event.get("actor") or {}
        entry = {"by": actor.get("displayName") or actor.get("alternateId"), "at": event.get("published")}
        event_type = event.get("eventType")
        if event_type.endswith(".create"):
            if bucket["created"] is None:
                bucket["created"] = entry
        elif event_type.endswith(".update"):
            bucket["updated"].append(entry)
        elif event_type.endswith(".delete"):
            if bucket["deleted"] is None:
                bucket["deleted"] = entry
        elif event_type.endswith(".reveal"):
            bucket["reveals"].append({**entry, "request_id": _extract_request_id(event)})

    def _build_rows(kind, live_by_id):
        rows = []
        seen_ids = set()
        for rid, resource in live_by_id.items():
            seen_ids.add(rid)
            b = buckets[kind].get(rid, {})
            rows.append({
                "id": rid,
                "name": resource.get("name", ""),
                "path": full_path(resource, folders_by_id),
                "status": "active",
                "created": b.get("created"),
                "updated": b.get("updated", []),
                "deleted": b.get("deleted"),
                **({"reveals": b.get("reveals", [])} if kind == "secret" else {}),
            })
        for rid, b in buckets[kind].items():
            if rid in seen_ids:
                continue
            status = "deleted" if b.get("deleted") else "unknown"
            rows.append({
                "id": rid,
                "name": b.get("name", ""),
                "path": b.get("path", ""),
                "status": status,
                "created": b.get("created"),
                "updated": b.get("updated", []),
                "deleted": b.get("deleted"),
                **({"reveals": b.get("reveals", [])} if kind == "secret" else {}),
            })
        return rows

    return {
        "secrets": _build_rows("secret", secrets_by_id),
        "folders": _build_rows("secret_folder", folders_by_id),
        "since_days": None,  # archive has no fixed window -- whole history ever ingested
        "local_retention_enabled": True,
        "oldest_captured_at": oldest_captured_at,
    }


# Canonical step sequence for progress reporting -- shared with the
# server's job runner so the frontend can render "step N of len(STEPS)"
# and know which label goes with which key. Steps with per-item detail
# (index_resources, user_groups) also emit "progress" events between
# their "start" and "done".
ACCESS_MODEL_STEPS = [
    ("resource_groups", "Fetching resource groups"),
    ("groups", "Fetching groups"),
    ("users", "Fetching users"),
    ("workload_roles", "Fetching workload roles"),
    ("clients", "Fetching enrolled clients"),
    ("devices", "Fetching Okta-managed devices"),
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


def build_access_model(client, okta_client=None, on_progress=None):
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

    okta_client is OPTIONAL -- an environment's Okta URL/API token are
    themselves optional (only needed for group creation, per the
    environment setup form), so this falls back to an empty devices list
    rather than failing the whole bootstrap when they're not configured.
    When present, pulls Okta's own org-wide Device inventory (confirmed
    live 2026-10-01, GET /api/v1/devices) -- a genuinely separate resource
    from OpaClient.list_clients' OPA Clients, see list_devices' docstring.

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

    # Workload roles/connections are TENANT-WIDE, not per-project
    # (confirmed live 2026-09-30 -- neither path takes a resource_group_id/
    # project_id), unlike servers/saas/okta/AD/database accounts below --
    # fetched once here rather than inside the per-project loop.
    _report(on_progress, "workload_roles", "start")
    workload_roles = client.list_workload_roles()
    workload_connections = client.list_workload_connections()
    gateways = client.list_gateways()
    database_connections = client.list_database_connections()
    saas_app_connections = client.list_saas_app_connections()
    active_directory_connections = client.list_active_directory_connections()
    # Assignments/relationships are ALSO tenant-wide (confirmed live
    # 2026-09-30 -- no resource_group_id in the real response). NOT a
    # separate access-grant mechanism from security policies -- confirmed
    # live (see ASSIGNMENTS_PATH/RELATIONSHIPS_PATH docstrings): a policy
    # with a non-empty `relationships[]` field uses this as an ALTERNATE
    # way to specify both its principal and its resource target, in place
    # of the ordinary principals/resource_selector fields every other
    # policy uses. list_assignments()'s own response omits the real
    # resource_assignments/relationship_assignments data (confirmed live
    # -- always null/absent on the list endpoint), so each assignment's
    # detail must be fetched individually; real tenants have very few of
    # these (a curated admin config, not a high-cardinality resource), so
    # this doesn't scale badly even as the feature grows.
    assignment_summaries = client.list_assignments()
    assignments = [client.get_assignment(a["id"]) for a in assignment_summaries if a.get("id")]
    # Resolved once here (reusing the SAME helper the policy-splice below
    # uses) so the Relationships tab can show real resource names/kinds
    # for an assignment directly, without re-deriving this resolution
    # itself or waiting on a policy to reference it.
    for assignment in assignments:
        assignment["resolved_resources"] = _resolve_relationship_assignment_resources(
            assignment.get("resource_assignments")
        )
    relationships = client.list_relationships()
    # relationship id -> LIST of (assignment, its matching
    # relationship_assignment) pairs -- built once here, used by the
    # policy-resolution loop below. MUST be one-to-MANY: confirmed live
    # against the dev tenant that the SAME relationship (e.g.
    # "TDI_Safe_Owners") is reused across multiple real assignments
    # (Xactly-Prod, TDI-Root-Admin, AvalaraFloQast-Prod), each with a
    # DIFFERENT principal group and a DIFFERENT granted secret/folder --
    # a real policy referencing that one relationship effectively grants
    # ALL of those groups access to ALL of those resources, not just one.
    # A one-to-one dict here would silently drop every assignment but the
    # last for a shared relationship -- caught before shipping by probing
    # the dev environment specifically for this multi-assignment case.
    assignments_by_relationship_id = {}
    for assignment in assignments:
        for ra in assignment.get("relationship_assignments") or []:
            rel_id = (ra.get("relationship") or {}).get("id")
            if rel_id:
                assignments_by_relationship_id.setdefault(rel_id, []).append((assignment, ra))
    _report(on_progress, "workload_roles", "done",
            f"{len(workload_roles)} workload role(s), {len(workload_connections)} workload connection(s), "
            f"{len(gateways)} gateway(s), {len(database_connections)} database connection(s), "
            f"{len(saas_app_connections)} SaaS app connection(s), "
            f"{len(active_directory_connections)} AD connection(s), "
            f"{len(assignments)} assignment(s), {len(relationships)} relationship(s)")

    _report(on_progress, "clients", "start")
    clients = client.list_clients()
    _report(on_progress, "clients", "done", f"{len(clients)} enrolled client(s)")

    _report(on_progress, "devices", "start")
    devices = okta_client.list_devices() if okta_client else []
    _report(on_progress, "devices", "done",
            f"{len(devices)} device(s)" if okta_client else "skipped (no Okta credentials configured)")

    _report(on_progress, "projects", "start")
    projects_by_rg = [(rg, client.list_projects(rg["id"])) for rg in resource_groups]
    total_projects = sum(len(ps) for _rg, ps in projects_by_rg)
    _report(on_progress, "projects", "done",
            f"{total_projects} project(s) across {len(resource_groups)} resource group(s)")

    indexes = {"secret_folders": {}, "secrets": {}, "servers": {}, "saas_accounts": {}, "okta_accounts": {},
               "secret_folder_children": {}}
    projects = []
    # Full resource objects, not just id-keyed lookup refs -- `indexes` above
    # exists solely to resolve security-policy rule selectors down to a
    # project (see _resolve_rule) and always discarded the actual objects
    # once that lookup was built. These four lists are what the new
    # tenant-wide Resources tab (Access Explorer) actually renders --
    # populated in the SAME per-project walk below so this doesn't cost a
    # second full pass over every resource group/project.
    all_servers = []
    all_saas_accounts = []
    all_okta_accounts = []
    all_active_directory_accounts = []
    all_database_accounts = []

    _report(on_progress, "index_resources", "start")
    indexed_count = 0
    for rg, rg_projects in projects_by_rg:
        for project in rg_projects:
            project = dict(project)
            project["resource_group_id"] = rg["id"]
            projects.append(project)
            proj_ref = {"project_id": project["id"], "project_name": project["name"], "resource_group_id": rg["id"]}
            # Adds resource_group_name too, unlike proj_ref above -- the new
            # full-object lists are rendered directly in a flat tenant-wide
            # table (ResourcesTab), which needs the human-readable name
            # without a second resource_groups lookup; proj_ref's existing
            # shape is left untouched since _resolve_rule's callers already
            # depend on its exact fields.
            proj_ref_named = {**proj_ref, "resource_group_name": rg["name"]}

            folders, secrets = fetch_all_folders_and_secrets(client, rg["id"], project["id"])
            for f in folders:
                if f.get("id"):
                    indexes["secret_folders"][f["id"]] = proj_ref
            for s in secrets:
                if s.get("id"):
                    indexes["secrets"][s["id"]] = proj_ref
            indexes["secret_folder_children"].update(_folder_descendant_secrets(folders, secrets))

            for server in client.list_project_servers(rg["id"], project["id"]):
                if server.get("id"):
                    indexes["servers"][server["id"]] = proj_ref
                all_servers.append({**server, **proj_ref_named})

            for acct in client.list_project_saas_app_accounts(rg["id"], project["id"]):
                key = acct.get("privileged_resource_id")
                if key:
                    # access_tracking_id: confirmed live 2026-08-15 -- the
                    # account's own OPA-internal id (distinct from
                    # privileged_resource_id, the Okta-side AppUser id used
                    # to key this index and shown as the resolved "id") is
                    # what actually shows up as a "Service Account" target
                    # in pam.service_account.password.reveal /
                    # pam.resource.checkout events. The Okta-side id is
                    # never logged as a System Log target at all -- see
                    # RESOURCE_ACCESS_EVENT_TYPES.
                    indexes["saas_accounts"][key] = {**proj_ref, "access_tracking_id": acct.get("id")}
                all_saas_accounts.append({**acct, **proj_ref_named})

            for acct in client.list_project_okta_ud_accounts(rg["id"], project["id"]):
                key = acct.get("okta_user_id")
                if key:
                    indexes["okta_accounts"][key] = {**proj_ref, "access_tracking_id": acct.get("id")}
                all_okta_accounts.append({**acct, **proj_ref_named})

            # These two are new as of 2026-09-30 -- confirmed live against a
            # real tenant (patlabs), not previously called anywhere in this
            # codebase. Unlike servers/saas/okta above, no security-policy
            # rule selector resolves to either of these by an OPA-internal
            # id today (AD/DB selectors resolve via name/domain condition
            # text instead -- see _resolve_rule's active_directory/database
            # branches), so there's no matching `indexes[...]` entry to
            # populate here, only the full-object list for the Resources tab.
            for acct in client.list_project_active_directory_accounts(rg["id"], project["id"]):
                all_active_directory_accounts.append({**acct, **proj_ref_named})

            for acct in client.list_project_database_accounts(rg["id"], project["id"]):
                all_database_accounts.append({**acct, **proj_ref_named})

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
        # Relationship-based policy (confirmed live 2026-09-30 -- see
        # ASSIGNMENTS_PATH's docstring): a policy with a non-empty
        # `relationships[]` uses this as an ALTERNATE way to specify both
        # its principal and its resource target, replacing the ordinary
        # principals/resource_selector fields every other policy uses.
        # Every OTHER real policy (confirmed: 15 of 16 on patlabs, 13 of
        # 15 on dev) has an EMPTY relationships field and is completely
        # unaffected -- effective_principals/relationship_resolutions stay
        # None for those, and the code below falls through to the
        # existing behavior unchanged.
        policy_relationships = policy.get("relationships") or []
        effective_principals = None
        relationship_resolutions = []
        if policy_relationships:
            # ONE-TO-MANY: confirmed live against the dev tenant that the
            # SAME relationship is reused across multiple real assignments
            # (e.g. "TDI_Safe_Owners" spans 3 assignments, each with a
            # different principal group and a different granted resource)
            # -- collect every matching (assignment, relationship_assignment)
            # pair across every relationship this policy references, not
            # just the first/last match.
            matches = []
            for rel_ref in policy_relationships:
                matches.extend(assignments_by_relationship_id.get(rel_ref.get("id"), []))
            if matches:
                seen_principal_ids = set()
                effective_principals_list = []
                for assignment, ra in matches:
                    principal = ra.get("principal") or {}
                    if principal.get("id") and principal["id"] not in seen_principal_ids:
                        seen_principal_ids.add(principal["id"])
                        effective_principals_list.append(principal)
                    relationship_resolutions.extend(
                        _resolve_relationship_assignment_resources(
                            assignment.get("resource_assignments"),
                            relationship_name=(ra.get("relationship") or {}).get("name"),
                            assignment_name=assignment.get("name"),
                        )
                    )
                # Matches this codebase's existing principals shape
                # (user_groups is a plain list of {id,name,type} refs) --
                # workload_roles stays empty since every real
                # relationship_assignment principal seen live is a
                # user_group, never a workload_role.
                effective_principals = {"user_groups": effective_principals_list, "workload_roles": []}

        rules_out = []
        for rule in policy.get("rules", []):
            resolutions = _resolve_rule(rule, indexes)
            # A relationship-based policy's rule has an EMPTY
            # resource_selector (confirmed live -- the real grant comes
            # from the assignment instead), so _resolve_rule's own
            # fallback would show a bare condition description with no
            # real resource attached. Splice in the real resolved
            # resource(s) from the matching assignment(s) instead, when
            # any were found.
            if relationship_resolutions:
                resolutions = relationship_resolutions
            rules_out.append({
                "name": rule.get("name"),
                "resource_type": rule.get("resource_type"),
                "resource_type_label": RESOURCE_TYPE_LABELS.get(rule.get("resource_type"), rule.get("resource_type")),
                "privileges": [
                    {"privilege_type": p.get("privilege_type"), "flags": _privilege_flags(p.get("privilege_value"))}
                    for p in rule.get("privileges", [])
                ],
                "conditions": rule.get("conditions", []),
                "resolutions": resolutions,
            })
        policies_out.append({
            "id": policy.get("id"),
            "name": policy.get("name"),
            "description": policy.get("description", ""),
            "active": policy.get("active", False),
            "type": policy.get("type"),
            "resource_group": policy.get("resource_group"),
            "principals": effective_principals if effective_principals is not None else policy.get("principals", {}),
            "rules": rules_out,
            # Raw policy -> relationship link (already computed above as
            # policy_relationships, just also exposed here) -- lets the
            # Relationships tab answer "which policies use this
            # relationship" without re-deriving the match itself.
            "relationship_ids": [r["id"] for r in policy_relationships if r.get("id")],
        })
    _report(on_progress, "resolve", "done", f"{len(policies_out)} polic(ies) resolved")

    return {
        "resource_groups": resource_groups,
        "projects": projects,
        "groups": groups,
        "users": users_with_groups,
        "policies": policies_out,
        "servers": all_servers,
        "saas_accounts": all_saas_accounts,
        "okta_accounts": all_okta_accounts,
        "active_directory_accounts": all_active_directory_accounts,
        "database_accounts": all_database_accounts,
        "workload_roles": workload_roles,
        "workload_connections": workload_connections,
        "gateways": gateways,
        "database_connections": database_connections,
        "saas_app_connections": saas_app_connections,
        "active_directory_connections": active_directory_connections,
        "assignments": assignments,
        "relationships": relationships,
        "clients": clients,
        "devices": devices,
    }


def get_ad_connection_discovery_config(client, ad_connection_id):
    """On-demand fetch (NOT part of build_access_model's bootstrap -- see
    module notes above for the same reasoning find_last_access_for_user
    already uses for per-user resource access: not worth fetching this for
    every AD connection up front when only one is being looked at at a
    time) of one AD connection's discovery configuration -- explains WHY
    an individual AD account got discovered/matched at all. See
    AD_CONNECTION_RULES_PATH's docstring."""
    return {
        "rules": client.get_ad_connection_rules(ad_connection_id),
        "rule_settings": client.get_ad_connection_rule_settings(ad_connection_id),
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
