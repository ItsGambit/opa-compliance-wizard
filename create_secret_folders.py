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
#                  (resolve_existing_folders) matches by FULL PATH since
#                  5.40.6 (ENG2-02): a folder with the same name somewhere
#                  else in the project is shown as "name in use" and is
#                  never adopted as a parent -- the create is attempted at
#                  the planned location and OPA's answer is reported.
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
# Version     : 5.42.0
# =============================================================================

import argparse
import contextlib
import contextvars
import csv
import email.utils
import http.client
import json
import math
import os
import re
import socket
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

SCRIPT_VERSION = "5.42.0"
NAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")
# ENG2-12: OPA's spec documents no pattern or length for a secret-folder
# name (SecretFolderCreateRequest.name is a bare string); 255 is the limit
# the same spec gives its other names, used here so an over-long name
# fails before the run instead of mid-way. "." and ".." pass the character
# rule but are path syntax, not names.
FOLDER_NAME_MAX_LEN = 255


def is_valid_folder_name(name):
    """The one folder-name rule, shared by the CLI (validate_names), the
    dashboard (serve.py's _run_pipeline) and mirrored in
    frontend/src/utils/validate.ts."""
    return (
        isinstance(name, str)
        and 0 < len(name) <= FOLDER_NAME_MAX_LEN
        and name not in (".", "..")
        and NAME_PATTERN.fullmatch(name) is not None
    )

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
# AND a real tenant -- tenant-wide, same family as the
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
# Both confirmed live 2026-09-30 against a real tenant -- neither
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
# user1.lastname@example.com) exists as a discovered resource at all:
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

# Confirmed 2026-10-07 by a read-only probe of a real compliance archive
# (two environments, ~130k rows across these families -- not inferred from
# docs): every pam.service_account.* event carries the account as a
# "Service Account" target whose `id` is the account's OPA-internal id --
# the same value build_access_model stores as access_tracking_id from
# list_project_saas_app_accounts / list_project_okta_ud_accounts -- with
# alternateId identical to id, and debugContext.debugData.serviceAccountType
# naming the account family (see SERVICE_ACCOUNT_TYPE_TO_KIND).
# pam.resource.checkout carries the same id as its "Service Account" target
# but has NO serviceAccountType; its debugData.resourceType is what tells
# the family apart there (see CHECKOUT_RESOURCE_TYPE_TO_KIND). Database and
# Active Directory accounts share the exact same "Service Account" target
# type AND the same reveal/rotation eventTypes, so NOTHING about the target
# alone says which family an event belongs to -- the report below has to
# classify every event explicitly before bucketing it.
#
# Real lifecycle events exist for service accounts (create/update/delete/
# assign -- all seen with real payloads), so a deleted account can be
# reported as "deleted" from direct evidence, the same honesty rule the
# Secrets report uses. pam.resource.checkin.start/.end are deliberately
# excluded, same reasoning as RESOURCE_ACCESS_EVENT_TYPES above.
SERVICE_ACCOUNT_REPORT_EVENT_TYPES = {
    "lifecycle": [
        "pam.service_account.create",
        "pam.service_account.update",
        "pam.service_account.delete",
        "pam.service_account.assign",
    ],
    "reveal": ["pam.service_account.password.reveal"],
    "checkout": ["pam.resource.checkout"],
    # password_rotation.start exists too (and stays in audit_store's
    # generic Credential Rotation card) but carries no outcome; .end is
    # the outcome-bearing event (SUCCESS / FAILURE / DEFERRED, all three
    # seen on real rows, FAILURE rows carry outcome.reason), so the
    # per-account rotation history is built from .end alone.
    "rotation": ["pam.service_account.password_rotation.end"],
}

# debugData.serviceAccountType -> report kind. Every key was seen on real
# events. DATABASE_ACCOUNT and PAM_AD_ACCOUNT are listed as "other" ON
# PURPOSE so they are excluded (and counted in the response's `excluded`
# block) rather than silently dropped as unrecognised -- they are real,
# high-volume families (AD rotations alone were 83k rows in the probe) that
# this report is explicitly not about. The staged-accounts API uses the
# same two strings (OKTA_USER_ACCOUNT / APP_ACCOUNT) for its account_type.
SERVICE_ACCOUNT_TYPE_TO_KIND = {
    "APP_ACCOUNT": "saas",
    "OKTA_USER_ACCOUNT": "okta",
    "DATABASE_ACCOUNT": "other",
    "PAM_AD_ACCOUNT": "other",
}

# debugData.resourceType on pam.resource.checkout -> report kind. Only
# MANAGED_SAAS_APP_SERVICE_ACCOUNT is live-confirmed for SaaS; no Okta UD
# checkout has been observed yet, so there is deliberately NO Okta entry
# here -- see build_service_accounts_report_from_archive for how an
# unlisted value is handled (it attaches to an account the report already
# knows about, but never conjures a new one from an unconfirmed string).
CHECKOUT_RESOURCE_TYPE_TO_KIND = {
    "MANAGED_SAAS_APP_SERVICE_ACCOUNT": "saas",
    "PAM_DATABASE_ACCOUNT": "other",
    "SERVER_ACCOUNT": "other",
}

SERVICE_ACCOUNT_ROTATION_LIMIT_DEFAULT = 25
SERVICE_ACCOUNT_ROTATION_LIMIT_MAX = 200
# Cap on the bulk-loaded lifecycle/reveal/checkout rows (same figure the
# Secrets archive builder uses). The report says `truncated` when hit.
SERVICE_ACCOUNT_EVENT_LOAD_LIMIT = 100000

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
    dependency -- this is intentionally a minimal parser, not python-dotenv.

    OPA_WIZARD_SKIP_DOTENV=1 disables it (TEST-07, external review
    2026-10-05): the test suite sets it so a developer's own repo-root
    .env (e.g. DEPLOYMENT_MODE=hosted for CLI use) can never leak into
    tests -- clearing os.environ alone doesn't help, since this function
    re-reads the FILE."""
    if os.environ.get("OPA_WIZARD_SKIP_DOTENV") == "1":
        return
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.isfile(env_path):
        return
    for key, value in _parse_dotenv_text(_read_dotenv_text(env_path)):
        os.environ.setdefault(key, value)


def _read_dotenv_text(env_path):
    """ENG1-12 (external review, 2026-10-05): the file used to be opened as
    plain utf-8, so a UTF-8 BOM (Notepad) silently renamed the first key
    and a UTF-16 file (PowerShell 5's `>` redirection) raised
    UnicodeDecodeError at IMPORT time, taking the CLI and the server down
    with a traceback. Now: a UTF-16 BOM is decoded as UTF-16, a UTF-8 BOM
    is dropped, and a file that still isn't text is skipped with a warning
    on stderr (log() isn't defined yet at import time) instead of
    crashing. Every key is still loaded, not only OPA_* -- users behind a
    proxy rely on HTTPS_PROXY / SSL_CERT_FILE here, which urllib reads."""
    with open(env_path, "rb") as f:
        raw = f.read()
    try:
        if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
            return raw.decode("utf-16")
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        sys.stderr.write(f"WARNING: ignoring {env_path}: it is not UTF-8 or UTF-16 text.\n")
        return ""


def _parse_dotenv_text(text):
    """Yields (key, value) for each KEY=VALUE line; blank lines and # comments
    are skipped, and a leading `export ` (shell syntax, ENG1-12) is
    dropped rather than becoming part of the key."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, raw_value = line.partition("=")
        key = key.strip()
        if key.startswith("export ") or key.startswith("export\t"):
            key = key[len("export"):].strip()
        if not key:
            continue
        yield key, _parse_dotenv_value(raw_value)


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

# ENG1-02 (external review, 2026-10-05): base_domain becomes OpaClient's
# base_url as f"https://{base_domain}" verbatim, with no validation at
# all before this fix -- a bare hostname, nothing else. No scheme (one is
# always prepended), no path/query (nothing after the host is ever
# meaningful here), no userinfo (an authority like
# "real-tenant.okta.com@attacker.example.com" is a syntactically valid
# URL whose actual host is attacker.example.com, not the tenant before
# the @). Standard DNS label shape; real values seen include dashes and
# multiple subdomain levels (e.g. "mxmco-3.pam.oktapreview.com").
_BASE_DOMAIN_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$")


def validate_base_domain(base_domain):
    """Raises ValueError on anything that isn't a bare hostname -- see
    this constant's own comment for why. Returns the validated value
    (callers that want a one-line `x = validate_base_domain(x)` can)."""
    if not _BASE_DOMAIN_RE.fullmatch(base_domain or ""):
        raise ValueError(
            f"base_domain must be a bare hostname (e.g. 'your-org.okta.com'), got {base_domain!r} -- "
            "no scheme, path, query, port or '@'."
        )
    return base_domain


def validate_okta_url(okta_url):
    """okta_url is OPTIONAL (see server/serve.py's own `if
    creds.get('okta_url')` guards) -- empty/None passes through
    unchanged. When set, becomes OktaClient's base_url via
    `org_url.rstrip('/')` verbatim; must be a real https:// origin with
    nothing after the host (no path/query/fragment) and no userinfo
    (same "...@attacker.example.com" concern as validate_base_domain)."""
    if not okta_url:
        return okta_url
    parsed = urllib.parse.urlsplit(okta_url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            f"okta_url must be a bare https:// origin (e.g. 'https://your-org.okta.com'), got {okta_url!r} -- "
            "no path, query, fragment or '@'."
        )
    return okta_url


def _environments_file_path():
    """Only still used by migrate_legacy_environments_json() -- the
    one-shot Phase 2 import of this file's data into SQLite. Nothing else
    reads/writes environments.json anymore (see list_environments_for()/
    list_all_environments() below, all SQL-backed as of v5.29.0)."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "environments.json")


LOCAL_OWNER_KEY = None  # sentinel for "no verified identity" -- local/direct runs, and every CLI call


def _owner_storage_key(owner):
    """The real storage key for `data["active"]`/`active_environments.owner_key`
    (and, pre-Phase-2, the keyring/metadata storage key too). Never emit
    the JSON token "null" as an actual key string -- use a stable literal
    instead, since both JSON object keys and SQLite TEXT primary keys are
    always strings anyway, and `None` would otherwise round-trip as the
    4-character string "null"."""
    return owner if owner else "__local__"


def _atomic_write_json(path, value, mode=0o600):
    """SECURITY FIX (external review, 2026-09-30): every mutable JSON file
    this project writes previously used a plain truncating `open(path,
    "w")` -- a reader (in this case, a SEPARATE process:
    server/auth_gate.py reading access_control.json) hitting that file
    mid-write sees a truncated/partial file, gets a JSONDecodeError, and
    falls back to the unrestricted login-bootstrap default -- confirmed
    exploitable: a crash or a login landing exactly during a write can
    transiently or permanently disable the login-restriction gate.

    Standard write-new-file-then-rename pattern: write to a temp file in
    the SAME directory (so the final os.replace is on the same filesystem,
    making it atomic -- a cross-filesystem "rename" would silently
    fall back to copy+delete, which is NOT atomic), fsync it before the
    rename so the write is durable even across a crash between the write
    and the rename, then os.replace -- POSIX guarantees a concurrent
    reader always sees either the complete old file or the complete new
    one, never a partial write, no matter when it opens the path.

    As of v5.29.0 (Phase 2 SQLite migration), the only remaining caller
    of this is access_control.json's own setter -- environments.json and
    banner_config.json moved into SQLite, which gives them a real
    transactional story this function never could (see docs/fast-follow-
    redesign.md's Phase 2 for why access_control.json deliberately did
    NOT move: server/auth_gate.py reads it directly as a separate OS
    process with zero sqlite3 dependency today, by design, and that
    process's login-gate role is exactly the one place in this app where
    adding a new dependency/failure-mode isn't worth a consistency win
    this file genuinely doesn't need -- it's a single, infrequently
    written, admin-only config blob with nothing else to be
    cross-table-consistent with)."""
    _atomic_write_text(path, json.dumps(value, indent=2), mode=mode)


def _atomic_write_text(path, text, mode=0o600):
    """The write-temp-then-os.replace mechanism behind _atomic_write_json,
    shared with every other whole-file rewrite (the audit log's MFA
    backfill, POST /api/csv) so none of them can leave a truncated file
    behind on a crash, kill or full disk. `mode` is applied explicitly
    (mkstemp's own 0600 default is not relied on)."""
    directory = os.path.dirname(path) or "."
    fd, temp_path = tempfile.mkstemp(dir=directory, prefix=".tmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(temp_path, mode)
        os.replace(temp_path, path)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


# ---------------------------------------------------------------------------
# Environment metadata, active-environment pointers, sync schedules, and
# the announcement banner -- all SQL-backed as of v5.29.0 (Phase 2 of
# docs/fast-follow-redesign.md). Every one of these functions keeps the
# EXACT SAME public signature it had when backed by environments.json/
# banner_config.json -- every caller in server/serve.py and the CLI's
# own main() goes through these functions already, so swapping the
# storage engine behind them needed zero call-site changes anywhere
# else, confirmed by a full exploration pass before this was written.
# ---------------------------------------------------------------------------
def _row_to_environment_meta(row):
    """Shapes one app_environments row (plus its sync_schedule, if any)
    into the same dict shape every caller already expects (the old
    environments.json record shape) -- so list_environments_for/
    list_all_environments/etc. don't need their own callers to change."""
    import audit_store
    conn = audit_store._get_connection()
    meta = {
        "environment_id": row["environment_id"],
        "owner": row["owner_id"],
        "name": row["display_name"],
        "base_domain": row["base_domain"],
        "team_name": row["team_name"],
        "key_id": row["key_id"],
        "okta_url": row["okta_url"] or "",
        "shared": bool(row["shared"]),
    }
    schedule_row = conn.execute(
        "SELECT * FROM sync_schedules WHERE environment_id = ?", (row["environment_id"],)
    ).fetchone()
    if schedule_row is not None:
        meta["sync_schedule"] = {
            "enabled": bool(schedule_row["enabled"]),
            "run_time": schedule_row["run_time"],
            "ingestion_scope": schedule_row["ingestion_scope"],
            "retention_days": schedule_row["retention_days"],
            "retention_max_size_mb": schedule_row["retention_max_size_mb"],
        }
    return meta


def list_environments_for(owner):
    """Returns {name: meta} visible to `owner`: their own environments plus
    anything explicitly marked shared=True. LOCAL_OWNER_KEY is treated as
    just another owner value here -- NOT a bypass that sees every other
    owner's private environments (same reasoning as the pre-Phase-2
    JSON-backed version: a bypass would let anyone with local/CLI access
    on a shared server read every logged-in user's private credentials).

    Own environments are applied AFTER shared ones so a same-named
    environment `owner` actually owns always wins over a like-named
    environment merely shared by someone else -- without this ordering,
    iteration order alone would decide which one a caller's own
    credential lookup resolves to, which could silently authenticate
    against the wrong tenant. (SQLite's own iteration order for a SELECT
    with no ORDER BY isn't guaranteed stable the way a dict literal's
    insertion order is, which is exactly why this ordering is enforced
    explicitly here via two separate queries, not left implicit.)

    Each returned `meta` carries its real `environment_id` -- see
    _row_to_environment_meta.

    PARTIAL FIX (external review, 2026-10-05, ENG1-04): when TWO
    DIFFERENT OWNERS each share an environment with the SAME display
    name, both rows match the first query below, and whichever one the
    dict comprehension assigns LAST wins -- SQLite's row order for a
    SELECT with no ORDER BY is not guaranteed, so which shared
    environment (and whose keyring credentials) a third party's lookup
    actually resolves to was effectively arbitrary. `ORDER BY created_at,
    environment_id` makes that tie-break deterministic and REPEATABLE
    (the same two rows always resolve the same way, call after call,
    rather than possibly flipping) -- it does not resolve the deeper
    ambiguity (two genuinely different shared environments still can't
    both be addressed by this flat {name: meta} shape; see
    list_all_environments's own id-keyed alternative), which needs
    environment_id-based addressing throughout the API, a larger change
    tracked separately."""
    import audit_store
    conn = audit_store._get_connection()
    visible = {}
    for row in conn.execute(
        "SELECT * FROM app_environments WHERE shared = 1 AND owner_id IS NOT ? ORDER BY created_at, environment_id",
        (owner,),
    ):
        visible[row["display_name"]] = _row_to_environment_meta(row)
    for row in conn.execute(
        "SELECT * FROM app_environments WHERE owner_id IS ? ORDER BY created_at, environment_id", (owner,)
    ):
        visible[row["display_name"]] = _row_to_environment_meta(row)
    return visible


def list_all_environments():
    """Returns {environment_id: meta} for EVERY stored environment, across
    every owner -- unlike list_environments_for(owner), which deliberately
    scopes to what one requesting identity is allowed to see. This exists
    for server-side background work with no requesting identity of its
    own (the daily sync scheduler): it needs to find and run every saved
    environment's sync schedule, including a non-shared environment
    privately owned by some other logged-in user, not just LOCAL_OWNER_KEY's
    own/shared ones. Never expose this dict directly to an HTTP response --
    it carries every owner's metadata (though still no secrets; those stay
    in the keychain either way).

    Keyed by the real environment_id (unique regardless of display name or
    owner), so a genuine owner collision (two different owners each have an
    environment named the same) never silently drops one, unlike
    list_environments_for's flat {name: meta} would if collapsed the same
    way."""
    import audit_store
    conn = audit_store._get_connection()
    return {
        row["environment_id"]: _row_to_environment_meta(row)
        for row in conn.execute("SELECT * FROM app_environments")
    }


def get_active_environment_name(owner):
    import audit_store
    conn = audit_store._get_connection()
    row = conn.execute(
        """SELECT a.display_name FROM active_environments ae
           JOIN app_environments a ON a.environment_id = ae.environment_id
           WHERE ae.owner_key = ?""",
        (_owner_storage_key(owner),),
    ).fetchone()
    return row["display_name"] if row else None


def set_active_environment(owner, name):
    """Stores the active pointer by resolving `name` to its real
    environment_id and storing THAT in active_environments -- a real
    improvement over the old environments.json design (confirmed via
    code history: the old `data["active"][owner_key] = name` stored the
    bare display name directly, so renaming an environment or a same-name
    collision could silently point `active` at the wrong thing).
    active_environments.environment_id REFERENCES
    app_environments(environment_id) ON DELETE CASCADE, so a deleted
    environment can never leave a dangling active-pointer -- SQLite
    enforces this at the schema level now, instead of delete_environment
    needing to remember to clean it up by hand (which it still does
    below, for the SEPARATE case of an admin deleting a different
    owner's environment -- CASCADE only helps the CALLING owner's own
    pointer here, see delete_environment's docstring).

    BUG FIX (external review, 2026-10-05, ENG1-03): this used to resolve
    `name` via _find_own_environment_sql -- the CALLER's own (owner,
    name) row only -- while get_environment_credentials (called first by
    server/serve.py's activate_environment, which already set up a live
    OpaClient/OktaClient and written them into the owner's session slot
    before this function ever runs) resolves via list_environments_for,
    which ALSO includes anything shared=True by a different owner.
    Activating a shared environment therefore authenticated successfully
    and populated the session, then raised KeyError here -- the request
    failed, but left the owner's session pointed at a tenant with no
    matching "active" pointer. Now resolves the same way
    get_environment_credentials does, so a successful activation can
    never fail at this specific step for an environment that's actually
    visible to the caller."""
    import audit_store
    conn = audit_store._get_connection()
    meta = list_environments_for(owner).get(name)
    if meta is None:
        raise KeyError(f"No saved environment named '{name}' owned by this user.")
    environment_id = meta["environment_id"]
    with audit_store._db_lock:
        conn.execute(
            "INSERT OR REPLACE INTO active_environments (owner_key, environment_id) VALUES (?, ?)",
            (_owner_storage_key(owner), environment_id),
        )
        conn.commit()


def set_active_environment_id(owner, environment_id):
    """Stores the active pointer as exactly this environment_id (5.40.7,
    UI-07) -- for an activation that was already resolved and checked by
    id, so a rename or share between the check and the write can't make
    the pointer name a different environment. Same visibility rule as
    get_environment_credentials_by_id: own, or shared. Raises KeyError."""
    import audit_store
    conn = audit_store._get_connection()
    row = conn.execute(
        "SELECT 1 FROM app_environments WHERE environment_id = ? AND (owner_id IS ? OR shared = 1)",
        (environment_id, owner),
    ).fetchone()
    if row is None:
        raise KeyError(f"No saved environment with id '{environment_id}' visible to this user")
    with audit_store._db_lock:
        conn.execute(
            "INSERT OR REPLACE INTO active_environments (owner_key, environment_id) VALUES (?, ?)",
            (_owner_storage_key(owner), environment_id),
        )
        conn.commit()


def _find_own_environment_sql(conn, owner, name):
    """SQL-backed sibling of _find_own_environment -- returns
    (environment_id, meta) for the CALLING owner's own environment with
    this display name, or (None, None). (owner, name) is guaranteed
    unique by the UNIQUE(owner_id, display_name) constraint on
    app_environments, so this is a direct, unambiguous lookup, never a
    cross-owner scan -- that's _resolve_admin_target's job."""
    row = conn.execute(
        "SELECT * FROM app_environments WHERE owner_id IS ? AND display_name = ?", (owner, name)
    ).fetchone()
    if row is None:
        return None, None
    return row["environment_id"], _row_to_environment_meta(row)

# ---------------------------------------------------------------------------
# Announcement banner
# ---------------------------------------------------------------------------
# A single, dashboard-wide banner (not per-environment/per-owner) shown at
# the top of every page -- mirrors Okta's own admin console banners
# ("Preview Sandbox", incident notices) which are one announcement for the
# whole org, not one per admin. SQL-backed as of v5.29.0 (a single-row
# table, same one-banner-for-the-whole-app shape as the old banner_config.json).
BANNER_VARIANTS = ("info", "warning", "danger")
_BANNER_DEFAULTS = {"enabled": False, "message": "", "variant": "warning", "dismissible": True}


def _banner_config_path():
    """Only still used by migrate_legacy_environments_json() -- the
    one-shot Phase 2 import of this file's data into SQLite."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "banner_config.json")


def get_banner_config():
    import audit_store
    conn = audit_store._get_connection()
    row = conn.execute("SELECT * FROM banner_config WHERE id = 1").fetchone()
    if row is None:
        return dict(_BANNER_DEFAULTS)
    return {
        "enabled": bool(row["enabled"]),
        "message": row["message"],
        "variant": row["variant"] if row["variant"] in BANNER_VARIANTS else "warning",
        "dismissible": bool(row["dismissible"]),
    }


def set_banner_config(enabled, message, variant, dismissible):
    if variant not in BANNER_VARIANTS:
        raise ValueError(f"variant must be one of {', '.join(BANNER_VARIANTS)}")
    message = (message or "").strip()
    if enabled and not message:
        raise ValueError("message is required when the banner is enabled")
    import audit_store
    conn = audit_store._get_connection()
    with audit_store._db_lock:
        conn.execute(
            """INSERT INTO banner_config (id, enabled, message, variant, dismissible)
               VALUES (1, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled, message=excluded.message,
                   variant=excluded.variant, dismissible=excluded.dismissible""",
            (int(bool(enabled)), message, variant, int(bool(dismissible))),
        )
        conn.commit()
    return {"enabled": bool(enabled), "message": message, "variant": variant, "dismissible": bool(dismissible)}


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


def validate_access_control_config(admin_group_id, user_group_id, restrict_login):
    """Shared validation/normalization for access_control.json's three
    fields -- extracted (Phase 3) so the new /api/access_control/prepare
    route can validate a proposed config BEFORE minting a pending admin
    action, using the exact same rule set_access_control_config already
    enforces, instead of duplicating (and risking drifting from) the
    check. Returns the normalized {admin_group_id, user_group_id,
    restrict_login} dict; raises ValueError on an invalid combination."""
    admin_group_id = (admin_group_id or "").strip() or None
    user_group_id = (user_group_id or "").strip() or None
    if restrict_login and not admin_group_id and not user_group_id:
        raise ValueError("at least one group ID is required to restrict login")
    return {
        "admin_group_id": admin_group_id,
        "user_group_id": user_group_id,
        "restrict_login": bool(restrict_login),
    }


def set_access_control_config(admin_group_id, user_group_id, restrict_login):
    config = validate_access_control_config(admin_group_id, user_group_id, restrict_login)
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


class CredentialStoreUnavailable(RuntimeError):
    """ENG1-10 (external review, 2026-10-05): the OS credential store could
    not be READ (locked keychain, Secret Service / D-Bus down, no backend).
    Distinct from "no such secret" (keyring returns None for that): every
    backend failure used to be swallowed into None, so a locked keyring
    looked like every environment had lost its secrets ("Missing required
    field: key_secret", has_okta_token false, an empty secret sent to the
    token endpoint) and invited users to re-enter credentials. Routes
    answer 503; the legacy-store migration stops instead of guessing."""


def _keyring_get_raw(service, field):
    try:
        return keyring.get_password(service, field)
    except Exception as exc:
        # The class only: a backend's message can echo the service name.
        raise CredentialStoreUnavailable(
            f"The OS credential store could not be read ({type(exc).__name__}). Unlock or start it "
            "(e.g. the login keychain or the Secret Service / gnome-keyring) and try again."
        ) from exc


def keyring_get(storage_name, field):
    """Reads a secret. `storage_name` is the environment's real
    `environment_id` (a UUID4) -- see docs/fast-follow-redesign.md's
    Phase 1. (This used to also fall back to a pre-multi-user,
    unnamespaced storage-name shape; that fallback branch was removed
    2026-10-01 once both of this project's real installs were confirmed
    migrated to a real environment_id -- see list_all_environments().)

    Still falls back to the legacy keyring SERVICE PREFIX
    (`opa-secrets-wizard`, pre-5.20.0-rename) -- a separate, still-live
    concern unrelated to the Phase 1 identity migration: confirmed via
    live inspection on 2026-10-01 that both real installs still have a
    genuine, orphaned credential sitting under that oldest prefix+bare-
    name combination, so this fallback stays until that's separately
    confirmed clean. Read-only: nothing is ever written back under the
    legacy prefix, so a value naturally migrates to the new prefix the
    next time it's saved."""
    if not KEYRING_AVAILABLE:
        return None

    for prefix in (KEYRING_SERVICE_PREFIX, _LEGACY_KEYRING_SERVICE_PREFIX):
        value = _keyring_get_raw(_keyring_service(storage_name, prefix), field)
        if value is not None:
            return value
    return None


def keyring_delete(storage_name, field):
    """Deletes a secret. Tries BOTH service prefixes keyring_get() reads
    from (current + legacy, see its own docstring) -- a value that's
    never been re-saved since before the 5.20.0 rename still lives under
    the legacy prefix, and deleting only the current prefix would
    silently no-op for it (confirmed live 2026-10-01: this previously
    deleted nothing for the secrets_log_cache.json Fernet key, which
    predated the rename). Each attempt is independently best-effort --
    a missing entry under either prefix is not an error."""
    if not KEYRING_AVAILABLE:
        return
    for prefix in (KEYRING_SERVICE_PREFIX, _LEGACY_KEYRING_SERVICE_PREFIX):
        try:
            keyring.delete_password(_keyring_service(storage_name, prefix), field)
        except Exception:
            pass



def _undo_keyring_writes(written):
    """Best-effort rollback of upsert_environment's keychain writes (see
    ENG1-07 there). `written` maps (environment_id, field) -> the value
    stored before the write, or None if there was none."""
    for (env_id, field), previous in written.items():
        try:
            if previous is None:
                keyring_delete(env_id, field)
            else:
                keyring_set(env_id, field, previous)
        except Exception as exc:
            log("ERROR", f"Could not undo a credential write for environment {env_id} ({field}): {type(exc).__name__}")


def _resolve_environment_target(conn, name, owner, is_admin, environment_id):
    """(target_id or None, target_owner, existing row or None) -- which
    environment an upsert edits: by id for an admin override (ENG1-01),
    otherwise the caller's own (owner, name)."""
    if is_admin and environment_id:
        row = conn.execute("SELECT * FROM app_environments WHERE environment_id = ?", (environment_id,)).fetchone()
        if row is not None:
            return row["environment_id"], row["owner_id"], row
        return None, owner, None
    target_id, _meta = _find_own_environment_sql(conn, owner, name)
    if target_id is None:
        return None, owner, None
    row = conn.execute("SELECT * FROM app_environments WHERE environment_id = ?", (target_id,)).fetchone()
    return target_id, owner, row


_ENVIRONMENT_ROW_COLUMNS = (
    "owner_id", "display_name", "base_domain", "team_name", "key_id", "okta_url", "shared", "updated_at",
)


def _write_environment_row(conn, name, fields, owner, is_admin, environment_id, expected_target, has_stored_secret,
                           secret_values):
    """Inside upsert_environment's BEGIN IMMEDIATE (holding _db_lock): the
    lookup, the checks and the row write -- no keychain call happens here.
    Returns (target_id, is_create, previous_row) for the caller's undo."""
    target_id, target_owner, row = _resolve_environment_target(conn, name, owner, is_admin, environment_id)
    existing_meta = _row_to_environment_meta(row) if row is not None else None
    if existing_meta is not None and existing_meta.get("owner") != owner and not is_admin:
        raise PermissionError(f"Environment '{name}' is not owned by this user.")

    # A create (no existing environment matched) mints a brand-new random
    # id -- NEVER derived from (owner, name), so it carries no information
    # about either.
    is_create = target_id is None
    if is_create:
        target_id = str(uuid.uuid4())
    meta = dict(existing_meta or {})
    for field in ENVIRONMENT_METADATA_FIELDS:
        if field in fields:
            meta[field] = (fields.get(field) or "").strip()
    meta["owner"] = target_owner
    meta["name"] = name
    meta.setdefault("shared", False)

    missing = [f for f in ("base_domain", "team_name", "key_id") if not meta.get(f)]
    if missing:
        raise ValueError(f"Missing required field(s): {', '.join(missing)}")
    if not secret_values["key_secret"]:
        # "Already stored" was read before the lock (keychain calls never
        # run under it) for the environment resolved then; if a concurrent
        # write changed which environment this resolves to, that answer
        # doesn't apply.
        if is_create or target_id != expected_target or not has_stored_secret:
            raise ValueError("Missing required field: key_secret")
    # SECURITY FIX (external review, 2026-10-05, ENG1-02): base_domain/
    # okta_url become OpaClient/OktaClient's base_url verbatim (f"https://
    # {base_domain}", org_url.rstrip("/")) -- validated here, at the one
    # place every save (CLI, API, admin override) goes through, so a value
    # with a path/query/userinfo (e.g. "real-tenant.okta.com@attacker.
    # example.com") can't steer requests elsewhere even without a redirect.
    validate_base_domain(meta["base_domain"])
    validate_okta_url(meta.get("okta_url"))

    # (owner, display_name) must stay unique -- also for owner NULL (local
    # mode), which the table's UNIQUE constraint does not cover -- whenever
    # this write would CREATE that pair: a create, or an admin renaming
    # someone's environment onto a name they already use. Editing an
    # environment under its own unchanged name is never refused, even on
    # an install where the old race already left a duplicate.
    if is_create or (row is not None and row["display_name"] != name):
        clash = conn.execute(
            "SELECT 1 FROM app_environments WHERE owner_id IS ? AND display_name = ? AND environment_id != ?",
            (target_owner, name, target_id),
        ).fetchone()
        if clash:
            raise ValueError(f"An environment named '{name}' already exists for this owner.")

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    conn.execute(
        """INSERT INTO app_environments
           (environment_id, owner_id, display_name, base_domain, team_name, key_id, okta_url,
            shared, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(environment_id) DO UPDATE SET
               owner_id=excluded.owner_id, display_name=excluded.display_name,
               base_domain=excluded.base_domain, team_name=excluded.team_name,
               key_id=excluded.key_id, okta_url=excluded.okta_url,
               shared=excluded.shared, updated_at=excluded.updated_at""",
        (target_id, meta.get("owner"), name, meta.get("base_domain", ""), meta.get("team_name", ""),
         meta.get("key_id", ""), meta.get("okta_url", ""), int(bool(meta.get("shared"))),
         now, now),
    )
    previous = {col: row[col] for col in _ENVIRONMENT_ROW_COLUMNS} if row is not None else None
    written = dict(zip(_ENVIRONMENT_ROW_COLUMNS, (
        meta.get("owner"), name, meta.get("base_domain", ""), meta.get("team_name", ""), meta.get("key_id", ""),
        meta.get("okta_url", ""), int(bool(meta.get("shared"))), now,
    )))
    return target_id, is_create, previous, written


def _undo_environment_row(conn, target_id, is_create, previous, written):
    """Puts the app_environments row back after the keychain half of an
    upsert failed: removed on a create, previous values on an update --
    only if every column is still exactly what this upsert wrote
    (`written`), so a write that committed in between (even within the
    same second) is never reverted."""
    import audit_store
    unchanged = " AND ".join(f"{col} IS ?" for col in _ENVIRONMENT_ROW_COLUMNS)
    still_ours = tuple(written[col] for col in _ENVIRONMENT_ROW_COLUMNS)
    with audit_store._db_lock:
        try:
            if is_create:
                conn.execute(f"DELETE FROM app_environments WHERE environment_id = ? AND {unchanged}",
                             (target_id, *still_ours))
            else:
                assignments = ", ".join(f"{col} = ?" for col in _ENVIRONMENT_ROW_COLUMNS)
                conn.execute(f"UPDATE app_environments SET {assignments} WHERE environment_id = ? AND {unchanged}",
                             (*(previous[col] for col in _ENVIRONMENT_ROW_COLUMNS), target_id, *still_ours))
            conn.commit()
        except Exception as exc:
            conn.rollback()
            log("ERROR", f"Could not undo the environment row for {target_id}: {type(exc).__name__}")


class EnvironmentTargetChanged(Exception):
    """upsert_environment(expected_target_id=...): the save would now write
    a different environment than the one it was checked against."""


_UNSET = object()


def upsert_environment(name, fields, owner=LOCAL_OWNER_KEY, is_admin=False, environment_id=None, dry_run=False,
                       expected_target_id=_UNSET):
    """Saves non-secret metadata to app_environments and secret fields to
    the OS keychain. Blank secret fields on an update leave the previously
    stored secret untouched (so editing metadata doesn't force re-entering
    credentials). Raises ValueError if required fields end up missing.
    Returns (name, environment_id) -- environment_id is the real, stable
    id of the environment that was just created or updated, needed by
    callers (e.g. activate_environment) that must resolve it without a
    second lookup.

    `owner` defaults to LOCAL_OWNER_KEY (no verified identity) so every
    existing call site -- the CLI, and any code that doesn't know about
    per-user scoping -- keeps working unchanged. Creating a new environment
    always sets its `owner` to this value and mints a brand-new random
    `environment_id`; updating an EXISTING environment owned by someone
    else is refused (PermissionError) unless `is_admin` is True -- an
    admin override edits the environment IN PLACE under its own existing
    owner/id, it does not transfer ownership to the admin (an admin fixing
    another user's broken credentials shouldn't silently become that
    environment's new owner).

    `environment_id`, when supplied (an admin editing an EXISTING
    environment via the UI, which always knows its real id), resolves the
    target directly via an O(1) lookup -- unambiguous even when two
    different owners share a display name.

    SECURITY FIX (external review, 2026-10-05, ENG1-01): an admin call with
    NO environment_id used to fall back to a by-name scan across EVERY
    owner -- and a *create* (the admin's own "add environment" form) never
    has an id, so that ambiguous fallback was the path every admin create
    actually took. Two colleagues both saving an environment named "dev"
    meant whichever one existed first silently absorbed the other's
    "create": the admin's keyring secrets got written under the OTHER
    owner's existing row (credential capture -- that owner could now
    activate and operate with the admin's privileged key/token), or an
    admin's real values got overwritten by a later-arriving unprivileged
    user's throwaway ones. Now: an admin call with no environment_id is
    ALWAYS a create scoped to the admin's own (owner, name) -- identical to
    the non-admin path -- never a cross-owner adoption. The by-name scan
    is gone entirely; an admin editing an existing environment belonging to
    someone else must pass that environment's real environment_id (which
    the UI already has for every row it lists).

    dry_run (5.42.0): every check -- permission, required fields, domain
    and URL validation, the duplicate-name check -- runs inside the same
    transaction as a real save, which is then rolled back; nothing is
    written anywhere. Returns (name, environment_id of the existing
    environment this would edit, or None for a create). The server's
    step-up flow runs it before asking for MFA.

    expected_target_id (5.42.0): the environment id (None = a create) the
    dry run reported. Checked inside the same transaction as the write;
    a different target raises EnvironmentTargetChanged and nothing is
    written."""
    if not name or not name.strip():
        raise ValueError("Environment name is required (e.g. dev, uat, prod).")
    name = name.strip()
    secret_values = {f: (fields.get(f) or "").strip() for f in ENVIRONMENT_SECRET_FIELDS}
    import audit_store
    conn = audit_store._get_connection()

    # ENG1-07 (external review, 2026-10-05): every check now runs BEFORE
    # anything is stored, and nothing is left half-written. Before: secrets
    # were written to the keychain first, so a request that then failed
    # validation (blank domain, missing key_id) had already replaced the
    # stored key_secret -- or, on a create, left a keychain entry under a
    # UUID no row references; the lookup ran outside the lock, so two
    # concurrent local creates (owner_id NULL, which UNIQUE(owner_id,
    # display_name) does not dedupe) made two rows; and an admin rename
    # onto an existing name raised a bare IntegrityError after the secrets
    # were written. Now, in three steps:
    #   1. outside every lock: whether a key_secret is already stored (the
    #      only keychain READ the checks need);
    #   2. BEGIN IMMEDIATE (this process's _db_lock AND SQLite's write
    #      lock, so another process can't interleave): lookup, permission,
    #      validation, duplicate-name check and the row write -- no
    #      keychain call, so a slow or prompting keychain never holds up
    #      every other database writer;
    #   3. after the commit: the keychain writes. If one fails, the
    #      keychain is put back (deleted on a create, previous value
    #      restored on an update) and so is the row, unless another write
    #      changed it meanwhile. Known narrow window: between the commit
    #      and the keychain write a reader can see the new metadata with
    #      the old (or, on a create, no) secret, and two concurrent edits
    #      of one environment's secret can undo each other's keychain
    #      value on failure -- the price of never holding the database
    #      lock across a keychain call.
    has_stored_secret = False
    expected_target = None
    if not secret_values["key_secret"]:
        with audit_store._db_lock:
            outer_transaction = conn.in_transaction
            expected_target, _owner, _row = _resolve_environment_target(conn, name, owner, is_admin, environment_id)
            if conn.in_transaction and not outer_transaction:
                conn.rollback()  # only a read this call started; nothing was written
        if expected_target is not None:
            has_stored_secret = bool(keyring_get(expected_target, "key_secret"))

    with audit_store._db_lock:
        started = not conn.in_transaction
        if started:
            conn.execute("BEGIN IMMEDIATE")
        elif dry_run:
            # Inside a caller's transaction: undo only this dry run's writes.
            conn.execute("SAVEPOINT upsert_dry_run")
        try:
            target_id, is_create, previous_row, written_row = _write_environment_row(
                conn, name, fields, owner, is_admin, environment_id, expected_target, has_stored_secret,
                secret_values,
            )
            if expected_target_id is not _UNSET and (None if is_create else target_id) != expected_target_id:
                raise EnvironmentTargetChanged(name)
            if dry_run:
                if started:
                    conn.rollback()
                else:
                    conn.execute("ROLLBACK TO upsert_dry_run")
                    conn.execute("RELEASE upsert_dry_run")
                return name, (None if is_create else target_id)
            conn.commit()
        except BaseException:
            if started or not dry_run:
                conn.rollback()
            else:
                conn.execute("ROLLBACK TO upsert_dry_run")
                conn.execute("RELEASE upsert_dry_run")
            raise

    written = {}  # (environment_id, field) -> value stored before this call (None = there was none)
    try:
        for field, value in secret_values.items():
            if value:  # blank + already exists -> leave the previously stored secret alone
                written[(target_id, field)] = None if is_create else keyring_get(target_id, field)
                keyring_set(target_id, field, value)
    except BaseException:
        _undo_keyring_writes(written)
        _undo_environment_row(conn, target_id, is_create, previous_row, written_row)
        raise
    return name, target_id


def _resolve_admin_target(environment_id):
    """Shared resolution for every CROSS-OWNER admin-override path below.
    `environment_id` (the real UUID primary key) is now REQUIRED -- an O(1)
    lookup, never a cross-owner scan.

    SECURITY FIX (external review, 2026-10-05, ENG1-01): this used to also
    accept a bare `name` and, when no id was supplied, fall back to a
    by-name scan across EVERY owner -- first-match-wins, genuinely
    ambiguous (confirmed exploitable) whenever two different owners had an
    environment with the same display name. That fallback is removed
    entirely, not just de-prioritized: callers that don't have a real
    cross-owner id (i.e. every call where the admin is acting on their OWN
    environment) now resolve through _find_own_environment_sql instead --
    see set_environment_shared/delete_environment below -- which only ever
    looks at that one owner's row, no scan at all. Raises KeyError if the
    id doesn't exist."""
    import audit_store
    conn = audit_store._get_connection()
    row = conn.execute("SELECT * FROM app_environments WHERE environment_id = ?", (environment_id,)).fetchone()
    if row is None:
        raise KeyError(f"No saved environment with id '{environment_id}'")
    return row["environment_id"], _row_to_environment_meta(row)


def set_environment_shared(name, owner, shared, is_admin=False, environment_id=None, dry_run=False):
    """Toggles an environment's `shared` flag. Only its owner may do this
    unless `is_admin` is True. An admin with a real cross-owner
    `environment_id` (editing a row that isn't theirs) resolves it
    unambiguously via _resolve_admin_target; an admin with NO id -- same as
    a non-admin -- always acts on their OWN (owner, name) row, never a
    cross-owner scan by name (see ENG1-01 in _resolve_admin_target's
    docstring). Raises PermissionError if not the owner and not an admin,
    KeyError if unknown.

    dry_run (5.42.0): every check above, nothing written -- the server's
    step-up flow runs it before asking for MFA, then calls again for real."""
    import audit_store
    conn = audit_store._get_connection()
    if is_admin and environment_id:
        target_id, meta = _resolve_admin_target(environment_id)
    else:
        target_id, meta = _find_own_environment_sql(conn, owner, name)
        if meta is None:
            raise KeyError(f"No environment named '{name}' owned by this user.")
        if meta.get("owner") != owner:
            raise PermissionError(f"Environment '{name}' is not owned by this user.")
    if dry_run:
        return target_id
    with audit_store._db_lock:
        conn.execute("UPDATE app_environments SET shared = ? WHERE environment_id = ?", (int(bool(shared)), target_id))
        conn.commit()
    return target_id  # ENG1-06: lets the caller drop other owners' live sessions on an unshare


def delete_environment(name, owner=LOCAL_OWNER_KEY, is_admin=False, environment_id=None, purge_archive=False,
                       dry_run=False):
    """Removes an environment's metadata and both keychain secrets. Returns
    {"was_active": bool, "environment_id": str, "archive": counts|None}:
    was_active is True if it was the active environment for THIS caller
    (caller should clear any live client for this owner); environment_id
    is the real id that was deleted, so the caller can also drop every
    OTHER owner's live session on it (ENG1-06 -- a shared environment's
    cached OpaClient kept working for everyone who had activated it);
    archive is the per-table purge count when purge_archive=True, else
    None. purge_archive deletes the environment's compliance archive
    (events, targets, sync state, manifests -- DATA-12, external review
    2026-10-05); the default keeps the archive as an orphan an admin can
    later export or purge via audit_store.list_orphaned_archives /
    purge_environment_archive, since keeping evidence is the safer default
    and deleting it must be an explicit, audit-logged choice. The purge
    runs after the environment row and secrets are gone; if it fails the
    environment stays deleted and the archive stays as an orphan (nothing
    is half-deleted), and the error propagates. Raises KeyError if the name
    doesn't exist (for this owner, unless `is_admin` with a real
    cross-owner id), PermissionError if it exists but is owned by someone
    else and `is_admin` is False. See _resolve_admin_target's docstring
    (ENG1-01) for why a bare admin override with no id now always resolves
    to the CALLER's own row, never a cross-owner scan by name.

    `active_environments.environment_id REFERENCES app_environments
    ON DELETE CASCADE` means the DELETE below automatically removes EVERY
    owner's active-pointer row that referenced this environment, not just
    the calling owner's -- a real improvement over the old environments.json
    design, which needed delete_environment to remember to hand-clean the
    "someone else's active pointer might dangle" case (still checked below,
    for the return value's sake, but no longer needed to prevent a dangling
    pointer -- SQLite guarantees that now).

    dry_run (5.42.0): resolves and checks only; returns
    {"environment_id": target} and deletes nothing (see
    set_environment_shared)."""
    import audit_store
    conn = audit_store._get_connection()
    if is_admin and environment_id:
        target_id, meta = _resolve_admin_target(environment_id)
    else:
        target_id, meta = _find_own_environment_sql(conn, owner, name)
        if meta is None:
            raise KeyError(f"No saved environment named '{name}'")
        if meta.get("owner") != owner:
            raise PermissionError(f"Environment '{name}' is not owned by this user.")
    if dry_run:
        return {"environment_id": target_id}
    owner_key = _owner_storage_key(owner)
    was_active = conn.execute(
        "SELECT 1 FROM active_environments WHERE owner_key = ? AND environment_id = ?", (owner_key, target_id)
    ).fetchone() is not None
    with audit_store._db_lock:
        conn.execute("DELETE FROM app_environments WHERE environment_id = ?", (target_id,))
        conn.commit()
    for field in ENVIRONMENT_SECRET_FIELDS:
        keyring_delete(target_id, field)
    archive_counts = audit_store.purge_environment_archive(target_id) if purge_archive else None
    return {"was_active": was_active, "environment_id": target_id, "archive": archive_counts}


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
    environment_id = meta["environment_id"]
    creds = dict(meta)
    for field in ENVIRONMENT_SECRET_FIELDS:
        creds[field] = keyring_get(environment_id, field) or ""
    creds["name"] = name
    return creds


def get_active_environment_id(owner):
    """The stored active pointer's environment_id for `owner` (or None) --
    the id itself, never re-resolved through a display name."""
    import audit_store
    conn = audit_store._get_connection()
    row = conn.execute(
        "SELECT environment_id FROM active_environments WHERE owner_key = ?", (_owner_storage_key(owner),)
    ).fetchone()
    return row["environment_id"] if row else None


def get_environment_credentials_by_id(environment_id, owner=LOCAL_OWNER_KEY):
    """Like get_environment_credentials, but addressed by the real
    environment_id instead of a display name: an environment `owner` owns,
    or one shared by anyone. Used to restore a saved session exactly (5.40.3
    review follow-up): re-resolving the pointer through its NAME could land
    a user in a different, same-named environment after a rename, or when
    their own environment shadows a shared one. Raises KeyError if the id
    doesn't exist or isn't visible to `owner`."""
    import audit_store
    conn = audit_store._get_connection()
    row = conn.execute(
        "SELECT * FROM app_environments WHERE environment_id = ? AND (owner_id IS ? OR shared = 1)",
        (environment_id, owner),
    ).fetchone()
    if row is None:
        raise KeyError(f"No saved environment with id '{environment_id}' visible to this user")
    creds = _row_to_environment_meta(row)
    for field in ENVIRONMENT_SECRET_FIELDS:
        creds[field] = keyring_get(environment_id, field) or ""
    creds["name"] = row["display_name"]
    return creds


def verify_environment_evidence_chain(name, owner=LOCAL_OWNER_KEY, deep=False):
    """Phase 6: resolves `name` to its real environment_id (same
    visibility rule as get_environment_credentials -- a shared
    environment resolves correctly for a non-owner caller) and walks its
    ingestion-manifest hash chain via audit_store.verify_ingestion_chain.
    deep=True also re-reads and re-hashes every sealed curated event
    (DATA-04) -- slower, proportional to the archive. Raises KeyError if
    `name` doesn't exist or isn't visible to `owner`."""
    import audit_store
    visible = list_environments_for(owner)
    meta = visible.get(name)
    if meta is None:
        raise KeyError(f"No saved environment named '{name}'")
    return audit_store.verify_ingestion_chain(meta["environment_id"], deep=deep)


def get_active_environment_credentials(owner=LOCAL_OWNER_KEY):
    """Returns credentials for the currently-active saved environment for
    `owner`, or None if none is set/active, no longer visible, or no longer
    addressable by its name (see restorable_active_environment_credentials
    -- the CLI and the server restore the same environment, by id)."""
    try:
        return restorable_active_environment_credentials(owner)
    except KeyError:
        return None


def restorable_active_environment_credentials(owner=LOCAL_OWNER_KEY):
    """The ONE rule for restoring `owner`'s saved active environment (server
    session restore and CLI alike, 5.40.3). The pointer stores an
    environment_id; restore exactly that environment if it is still the
    owner's own or still shared -- AND only if its display name still
    resolves to that same id for this owner. The second check matters
    because the rest of the app addresses environments by name: after a
    rename (or once the owner's own same-named environment shadows a shared
    one) a session restored by id would act on one tenant while every
    name-keyed route and the UI resolved to another. Returns None when
    there is no pointer; raises KeyError (with the reason) when the pointer
    can't be restored, so the caller can log it and let the user choose."""
    environment_id = get_active_environment_id(owner)
    if not environment_id:
        return None
    creds = get_environment_credentials_by_id(environment_id, owner=owner)
    by_name = list_environments_for(owner).get(creds["name"])
    if by_name is None or by_name["environment_id"] != environment_id:
        raise KeyError(
            f"Saved environment '{creds['name']}' ({environment_id}) is shadowed by another environment of "
            "the same name for this user; choose one explicitly."
        )
    return creds


def migrate_legacy_environments_json():
    """One-shot Phase 2 migration: imports environments.json's and
    banner_config.json's data into the SQLite tables audit_store.py's
    migration 1 (_migration_001_unified_schema) just created, re-keys the
    archive's existing `environment` (now `environment_id`) column values
    from bare display name to the real environment_id, then DELETES both
    JSON files once every step is verified -- read-old -> write-new ->
    verify -> delete-old, same discipline Phase 1 used for keyring
    credential migration.

    Called once from main()/server startup, AFTER audit_store.init_db()
    has already run its schema migrations -- a no-op if environments.json
    doesn't exist (either a fresh install, or an install that's already
    been migrated and had the file deleted).

    THE REAL-DATA-INFORMED DECISION this function encodes (confirmed with
    the user before writing this, against real data on the Ubuntu server):
    when more than one environment_id shares a display name (the genuine
    owner-collision case Phase 1 was built to handle -- e.g. a shared/
    no-owner "dev" AND a real-identity-owned "dev" pointing at the same
    tenant), the archive's historical rows for that bare name attach to
    whichever environment_id has a REAL stored keyring key_secret, not an
    arbitrary pick. Confirmed live: the shared/no-owner copies in this
    exact scenario had ZERO credentials and therefore could not possibly
    have produced any of the real archived history -- attaching history
    to the uncredentialed copy instead would have exposed sensitive audit
    data (PAM credential reveals, admin privilege grants) to anyone who
    can merely see a shared environment, regardless of real relationship
    to the identity that actually generated that history. If NEITHER or
    BOTH candidates have a credential (ambiguous either way), the first
    one encountered is used and a warning is logged -- this is a one-shot
    migration decision made once, not an ongoing ambiguity the app has to
    keep resolving."""
    import audit_store
    path = _environments_file_path()
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    environments = data.get("environments") or {}
    active = data.get("active") or {}

    conn = audit_store._get_connection()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    # name -> [environment_id, ...] -- built BEFORE inserting anything, so
    # the collision-resolution step below can see every candidate for a
    # given bare name up front.
    ids_by_name = defaultdict(list)
    for environment_id, meta in environments.items():
        ids_by_name[meta.get("name")].append(environment_id)

    with audit_store._db_lock:
        # BUG FIX (found live-testing this migration against this
        # machine's real audit_store.db, 2026-10-01): the archive
        # re-keying step below updates events.environment_id and
        # event_targets.environment_id in separate statements, but
        # event_targets' FOREIGN KEY (environment_id, uuid) REFERENCES
        # events(environment_id, uuid) is checked per-statement by
        # default -- re-keying events first makes every one of its
        # event_targets rows momentarily point at a (environment_id,
        # uuid) pair that no longer exists in events, failing the FK
        # check before event_targets' own UPDATE ever runs (and the
        # reverse order fails symmetrically). PRAGMA defer_foreign_keys,
        # unlike PRAGMA foreign_keys, can be toggled mid-transaction and
        # defers every FK check to COMMIT instead of per-statement --
        # exactly what this circular events<->event_targets remap needs.
        # Automatically resets to OFF at the next commit/rollback (SQLite's
        # own documented behavior), so no explicit cleanup is needed.
        conn.execute("PRAGMA defer_foreign_keys = ON")
        for environment_id, meta in environments.items():
            conn.execute(
                """INSERT OR REPLACE INTO app_environments
                   (environment_id, owner_id, display_name, base_domain, team_name, key_id, okta_url,
                    shared, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (environment_id, meta.get("owner"), meta.get("name"), meta.get("base_domain", ""),
                 meta.get("team_name", ""), meta.get("key_id", ""), meta.get("okta_url", ""),
                 int(bool(meta.get("shared"))),
                 now, now),
            )
            schedule = meta.get("sync_schedule")
            if schedule:
                conn.execute(
                    """INSERT OR REPLACE INTO sync_schedules
                       (environment_id, enabled, run_time, ingestion_scope, retention_days, retention_max_size_mb)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (environment_id, int(bool(schedule.get("enabled", False))),
                     schedule.get("run_time", "02:00"), schedule.get("ingestion_scope", "curated"),
                     schedule.get("retention_days"), schedule.get("retention_max_size_mb")),
                )

        for owner_key, name in active.items():
            candidate_ids = ids_by_name.get(name) or []
            if len(candidate_ids) == 1:
                conn.execute(
                    "INSERT OR REPLACE INTO active_environments (owner_key, environment_id) VALUES (?, ?)",
                    (owner_key, candidate_ids[0]),
                )
            elif len(candidate_ids) > 1:
                # Ambiguous by name alone -- resolve by matching the
                # owner_key's OWN environment first (the common, correct
                # case), falling back to the first candidate otherwise.
                owned = [eid for eid in candidate_ids if _owner_storage_key(environments[eid].get("owner")) == owner_key]
                conn.execute(
                    "INSERT OR REPLACE INTO active_environments (owner_key, environment_id) VALUES (?, ?)",
                    (owner_key, owned[0] if owned else candidate_ids[0]),
                )

        banner_path = _banner_config_path()
        if os.path.isfile(banner_path):
            with open(banner_path, encoding="utf-8") as f:
                banner = json.load(f)
            conn.execute(
                """INSERT OR REPLACE INTO banner_config (id, enabled, message, variant, dismissible)
                   VALUES (1, ?, ?, ?, ?)""",
                (int(bool(banner.get("enabled", False))), banner.get("message", ""),
                 banner.get("variant", "warning") if banner.get("variant") in BANNER_VARIANTS else "warning",
                 int(bool(banner.get("dismissible", True)))),
            )

        # Archive re-keying: for each bare display name with real rows in
        # events/sync_state (still keyed by that name at this point --
        # audit_store's migration 1 renamed the COLUMN to environment_id,
        # but the stored VALUES are still whatever bare name was there
        # before), resolve the correct environment_id and UPDATE in place.
        archived_names = {row[0] for row in conn.execute("SELECT DISTINCT environment_id FROM events")}
        archived_names |= {row[0] for row in conn.execute("SELECT DISTINCT environment_id FROM sync_state")}
        for bare_name in archived_names:
            candidate_ids = ids_by_name.get(bare_name) or []
            if not candidate_ids:
                continue  # archived data for an environment that no longer has a JSON record -- leave as-is, nothing to resolve to
            if bare_name in candidate_ids:
                continue  # already a real environment_id (archive was already migrated in a prior partial run) -- do not re-map
            if len(candidate_ids) == 1:
                resolved_id = candidate_ids[0]
            else:
                # THE credential-based collision resolution -- see this
                # function's own docstring for the real-data finding that
                # justifies this over any name-based heuristic.
                credentialed = [eid for eid in candidate_ids if keyring_get(eid, "key_secret")]
                if len(credentialed) == 1:
                    resolved_id = credentialed[0]
                else:
                    log("WARN", f"Archive collision for '{bare_name}': {len(candidate_ids)} candidate environment_ids, "
                                 f"{len(credentialed)} with a stored credential -- using the first candidate "
                                 f"({candidate_ids[0]}) rather than guessing further. Verify this is correct.")
                    resolved_id = candidate_ids[0]
            before_events = conn.execute("SELECT COUNT(*) FROM events WHERE environment_id = ?", (bare_name,)).fetchone()[0]
            before_sync_state = conn.execute("SELECT COUNT(*) FROM sync_state WHERE environment_id = ?", (bare_name,)).fetchone()[0]
            before_targets = conn.execute("SELECT COUNT(*) FROM event_targets WHERE environment_id = ?", (bare_name,)).fetchone()[0]
            conn.execute("UPDATE events SET environment_id = ? WHERE environment_id = ?", (resolved_id, bare_name))
            conn.execute("UPDATE sync_state SET environment_id = ? WHERE environment_id = ?", (resolved_id, bare_name))
            conn.execute("UPDATE event_targets SET environment_id = ? WHERE environment_id = ?", (resolved_id, bare_name))
            after_events = conn.execute("SELECT COUNT(*) FROM events WHERE environment_id = ?", (resolved_id,)).fetchone()[0]
            if after_events < before_events:
                raise RuntimeError(
                    f"Archive migration row-count mismatch for '{bare_name}' -> '{resolved_id}': "
                    f"expected at least {before_events} events, found {after_events}. Aborting without committing."
                )
            log("INFO", f"Archive migration: '{bare_name}' -> environment_id '{resolved_id}' "
                        f"({before_events} events, {before_sync_state} sync_state row(s), {before_targets} targets).")

        conn.commit()

    # Delete the JSON files only AFTER every insert/update above has
    # committed successfully -- not transactional with the SQLite commit
    # (separate files can't be), so delete-after-verified-commit is the
    # correct order, same read-old -> write-new -> verify -> delete-old
    # shape Phase 1 used for keyring credentials.
    os.remove(path)
    if os.path.isfile(_banner_config_path()):
        os.remove(_banner_config_path())
    log("INFO", f"Migrated {len(environments)} environment(s) from environments.json into SQLite; file deleted.")


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------
# Append-only, one JSON object per line -- audit_log.jsonl next to this
# script. Written for every write/mutating
# action (see server/serve.py's callers), local/CLI-triggered actions
# included (with actor_email/actor_sub left None) so local usage is
# auditable too, not just logged-in dashboard usage.
_audit_log_lock = threading.Lock()


def _audit_log_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "audit_log.jsonl")


def _audit_log_lock_path(path):
    return os.path.join(os.path.dirname(path) or ".", "." + os.path.basename(path) + ".lock")


_audit_os_lock_down_until = 0.0  # monotonic; see _audit_log_exclusive
AUDIT_LOG_LOCK_RETRY_AFTER_SECS = 60


@contextlib.contextmanager
def _audit_log_exclusive(path, require_os_lock=False):
    """ENG1-11 (external review, 2026-10-05): _audit_log_lock is per
    process, but the log is shared by every process that runs this code
    (a second server instance, the CLI, a test run against a real
    checkout). Appends are O_APPEND and small, but the MFA backfill
    REWRITES the file (write-temp-then-replace), so another process
    appending during that rewrite would lose its line. This takes the
    thread lock and an exclusive OS lock on a SIDECAR file (the log itself
    is replaced by the rewrite, so a lock on its inode would not exclude
    anyone who opened the new one). If the OS lock can't be taken (e.g. a
    read-only directory) it continues with the thread lock alone and says
    so -- an audit write must not fail because of its own lock. The OS lock
    is waited for at most AUDIT_LOG_LOCK_WAIT_SECS: a stopped or hung
    process holding it must not freeze every audited request here. After
    a failure the OS lock is not tried again for
    AUDIT_LOG_LOCK_RETRY_AFTER_SECS (one WARN, not one 5 s wait per
    request). require_os_lock=True (the MFA backfill's whole-file REWRITE,
    the one operation the OS lock really protects) raises
    MfaBackfillBusy instead of falling back."""
    global _audit_os_lock_down_until
    with _audit_log_lock:
        fd = None
        if not require_os_lock and time.monotonic() < _audit_os_lock_down_until:
            pass  # known unavailable right now: in-process lock only
        else:
            try:
                fd = os.open(_audit_log_lock_path(path), os.O_RDWR | os.O_CREAT, 0o600)
                if not _lock_fd(fd, AUDIT_LOG_LOCK_WAIT_SECS):
                    raise TimeoutError("held by another process")
                _audit_os_lock_down_until = 0.0
            except OSError as exc:
                if fd is not None:
                    os.close(fd)
                fd = None
                if require_os_lock:
                    if isinstance(exc, TimeoutError):
                        raise MfaBackfillBusy("The audit log is locked by another process. Try again in a moment.") from exc
                    # Not "busy": retrying won't help (e.g. a lock file owned
                    # by another user, or a read-only directory).
                    raise MfaBackfillBusy(
                        f"The audit log's lock file {os.path.basename(_audit_log_lock_path(path))} can't be used "
                        f"({type(exc).__name__}); check its owner and permissions."
                    ) from exc
                _audit_os_lock_down_until = time.monotonic() + AUDIT_LOG_LOCK_RETRY_AFTER_SECS
                log("WARN", f"Audit log: cross-process lock unavailable ({type(exc).__name__}); using the "
                            f"in-process lock only for the next {AUDIT_LOG_LOCK_RETRY_AFTER_SECS} s.")
        try:
            yield
        finally:
            if fd is not None:
                try:
                    _unlock_fd(fd)
                except OSError:
                    pass  # closing the descriptor releases it anyway
                os.close(fd)


AUDIT_LOG_LOCK_WAIT_SECS = 5


def _lock_fd(fd, wait_secs):
    """Exclusive, non-blocking attempts until wait_secs pass. True if taken."""
    try:
        import fcntl
    except ImportError:  # Windows
        import msvcrt

        def attempt():
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
    else:
        def attempt():
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    deadline = time.monotonic() + wait_secs
    while True:
        try:
            attempt()
            return True
        except OSError as exc:
            if not isinstance(exc, (BlockingIOError, PermissionError)) and getattr(exc, "errno", None) not in (11, 13, 35, 36):
                raise
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.05)


def _unlock_fd(fd):
    try:
        import fcntl
    except ImportError:  # Windows
        import msvcrt
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        return
    fcntl.flock(fd, fcntl.LOCK_UN)


def log_audit_event(actor_email, actor_sub, action, details=None, client_ip=None, user_agent=None):
    """client_ip/user_agent are new as of 2026-09-30 (Okta's own System
    Log always captures both; this log never did) -- optional so every
    existing call site keeps working unchanged until updated to pass
    them. Older entries in audit_log.jsonl predate these fields entirely
    (not backfilled -- there's no real data to backfill, since neither
    was ever captured) and simply won't have the keys; read_audit_log's
    callers should treat a missing key the same as an explicit None.

    ENG1-11 (external review, 2026-10-05): the file is created 0600 (it
    holds e-mails, IPs and user agents; local mode used to get the
    process umask, usually 0644), appends hold the cross-process lock
    (_audit_log_exclusive), and an append that fails (disk full,
    read-only file) no longer raises: every caller logs AFTER its action
    has already happened, so raising turned a completed action into a 500
    with no record anywhere. The failure is logged to stderr/the journal
    with the action, actor sub and time (not the e-mail/IP/agent), and
    the entry is still returned."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "actor_email": actor_email,
        "actor_sub": actor_sub,
        "action": action,
        "details": details or {},
        "client_ip": client_ip,
        "user_agent": user_agent,
    }
    data = (json.dumps(entry, separators=(",", ":")) + "\n").encode("utf-8")
    path = _audit_log_path()
    try:
        with _audit_log_exclusive(path):
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0), 0o600)
            try:
                _tighten_to_owner_only(fd)
                view = memoryview(data)
                while view:
                    view = view[os.write(fd, view):]
            finally:
                os.close(fd)
    except OSError as exc:
        log("ERROR", f"Audit log append FAILED ({type(exc).__name__}: {exc.strerror}); the action itself completed. "
                     f"Unrecorded entry: action={action} actor_sub={actor_sub} at={entry['timestamp']}")
    return entry


def _tighten_to_owner_only(fd):
    """An audit log created by an older version (local mode: the process
    umask, usually 0644) is narrowed to 0600 on its next write. POSIX only;
    best effort (a file owned by someone else is left as it is)."""
    if not hasattr(os, "fchmod"):
        return
    try:
        mode = os.fstat(fd).st_mode & 0o777
        if mode & 0o077:
            os.fchmod(fd, mode & 0o700)
    except OSError:
        pass


def _audit_log_lines_newest_first(path, block_size=64 * 1024):
    """Yields the file's lines (bytes, without the newline) from the END,
    reading backwards in blocks -- so a page near the top of the log costs
    O(offset + limit) lines, not a parse of the whole file (ENG1-11)."""
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        position = f.tell()
        pending = b""
        while position > 0:
            step = min(block_size, position)
            position -= step
            f.seek(position)
            pending = f.read(step) + pending
            lines = pending.split(b"\n")
            pending = lines[0]  # may be the tail of a line that started in an earlier block
            for line in reversed(lines[1:]):
                yield line
        if pending:
            yield pending


def read_audit_log(limit=200, offset=0):
    """Returns the most recent `limit` entries (most-recent-first), skipping
    `offset` from the top. Reads the file from the end and stops once the
    page is full (ENG1-11) -- same entries, same order and the same
    skipping of blank, unparseable and non-object lines as the old
    whole-file read."""
    path = _audit_log_path()
    if not os.path.isfile(path) or limit <= 0:
        return []
    entries = []
    skipped = 0
    for raw in _audit_log_lines_newest_first(path):
        line = raw.decode("utf-8", errors="replace").strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(entry, dict):  # ENG1-05: a valid-JSON non-object line is not an entry
            continue
        if skipped < offset:
            skipped += 1
            continue
        entries.append(entry)
        if len(entries) >= limit:
            break
    return entries


# ENG1-05: an access_control.update entry gets at most this many
# corroboration lookups (one per Refresh click) before it stops consuming
# the per-click budget, and none at all once it is older than Okta's
# System Log retention -- the event can no longer be found either way.
MFA_BACKFILL_MAX_ATTEMPTS = 5
MFA_BACKFILL_RETENTION_DAYS = 90
# A miss within this long of the save is Okta's System Log indexing lag
# (the very case this backfill exists for) -- it is retried but never
# counted against MFA_BACKFILL_MAX_ATTEMPTS.
MFA_BACKFILL_UNCOUNTED_GRACE = timedelta(hours=1)
# One backfill at a time: a second concurrent Refresh would repeat the same
# lookups and have its results discarded (the lines already changed).
_mfa_backfill_running = threading.Lock()


class MfaBackfillBusy(Exception):
    """Another backfill is already running in this process."""


class MfaLookupEntryRejected(Exception):
    """lookup_fn asked, and the lookup service refused THIS entry's
    parameters (e.g. HTTP 400). Deterministic for that entry, so it counts
    as an attempt (it ages out) and the run moves on to the next entry
    instead of stopping -- otherwise one bad entry, always first in line,
    would starve every older one."""


class MfaLookupUnavailable(Exception):
    """Raised by a backfill lookup_fn when it could not ASK at all (lookup
    secret unset, auth gate unreachable, timeout) -- as opposed to asking
    and getting "no such event" (None). An unavailable lookup never counts
    as an attempt; it ends the run, keeping whatever was already found."""


def _read_audit_log_lines(path):
    with open(path, encoding="utf-8") as f:
        return [line.rstrip("\n") for line in f if line.rstrip("\n")]


def backfill_mfa_log_events(lookup_fn, max_lookups=20, now=None):
    """Closes the Okta System-Log-indexing-lag gap confirmed live 2026-09-30
    (see server/auth_gate.py's _query_mfa_log_event docstring):
    access_control.update entries whose okta_mfa_log_event is still None
    (the corroborating event hadn't been indexed by Okta yet at save time)
    get a fresh lookup attempt every time an admin clicks Refresh on the
    Audit Log page, not just once at save time.

    `lookup_fn(actor_sub, near_iso_timestamp) -> dict | None` is injected
    (see server/serve.py's caller) rather than this module calling
    auth_gate.py directly -- this module has no Okta org URL/token of its
    own for this purpose (that lives in auth_gate.py's separate process/
    keyring entry), so the actual Okta call is always made by whichever
    caller HAS that access; this function only finds/rewrites rows.

    `max_lookups` bounds how many entries get a fresh Okta call in one
    Refresh click, so repeated clicks can't trigger unbounded Okta calls.

    ENG1-05 (external review, 2026-10-05) -- three defects fixed:
    1. The lookups (up to max_lookups x a 15 s network timeout) used to run
       while holding _audit_log_lock, so every audited write in the app
       blocked behind one Refresh. Now: candidates are read, the lock is
       released for the lookups, then re-taken to re-read the file and
       apply the results.
    2. The rewrite truncated the log in place (a crash or full disk lost
       the whole audit trail). Now written via _atomic_write_text, and
       results are applied by EXACT original line text to the freshly
       re-read file, so anything appended during the lookups is kept.
    3. Iteration was oldest-first with no memory of failures, so 20
       never-resolvable entries starved every newer one forever. Now
       newest-first; each failed lookup increments
       details.okta_mfa_log_lookup_attempts, and an entry is skipped once it
       reaches MFA_BACKFILL_MAX_ATTEMPTS or is older than
       MFA_BACKFILL_RETENTION_DAYS. Valid-JSON non-object lines are skipped
       (they used to raise AttributeError -> 500 on every Refresh).

    5.40.3 review follow-up: only a definite "not found" (lookup_fn returns
    None) for an entry older than MFA_BACKFILL_UNCOUNTED_GRACE counts as an
    attempt. lookup_fn raises MfaLookupUnavailable (or anything else) when
    it could not ask; the run then stops, applying the results it already
    has, without charging anyone an attempt. A second concurrent call
    raises MfaBackfillBusy at once instead of repeating the same lookups.
    MfaLookupEntryRejected from lookup_fn counts an attempt for that entry
    and moves on.

    Returns the number of entries that gained corroboration."""
    if not _mfa_backfill_running.acquire(blocking=False):
        raise MfaBackfillBusy("An MFA log refresh is already running. Try again in a moment.")
    try:
        return _backfill_mfa_log_events_locked(lookup_fn, max_lookups, now)
    finally:
        _mfa_backfill_running.release()


def _backfill_mfa_log_events_locked(lookup_fn, max_lookups, now):
    path = _audit_log_path()
    if not os.path.isfile(path):
        return 0
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=MFA_BACKFILL_RETENTION_DAYS)

    with _audit_log_exclusive(path):
        lines = _read_audit_log_lines(path)

    candidates = []  # (original_line, entry)
    for line in reversed(lines):  # newest first
        if len(candidates) >= max_lookups:
            break
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(entry, dict) or entry.get("action") != "access_control.update":
            continue
        details = entry.get("details")
        if not isinstance(details, dict) or details.get("okta_mfa_log_event") is not None:
            continue
        actor_sub = entry.get("actor_sub")
        timestamp = entry.get("timestamp")
        if not actor_sub or not isinstance(timestamp, str):
            continue
        attempts = details.get("okta_mfa_log_lookup_attempts")
        if isinstance(attempts, int) and attempts >= MFA_BACKFILL_MAX_ATTEMPTS:
            continue
        try:
            entry_dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            if entry_dt.tzinfo is None:
                entry_dt = entry_dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if entry_dt < cutoff:
            continue
        candidates.append((line, entry, entry_dt))

    if not candidates:
        return 0

    # Network lookups run WITHOUT the lock.
    replacements = {}
    updated_count = 0
    for line, entry, entry_dt in candidates:
        rejected = False
        try:
            found = lookup_fn(entry["actor_sub"], entry["timestamp"])
        except MfaLookupEntryRejected as exc:
            log("WARN", f"MFA log backfill: lookup refused for the entry at {entry['timestamp']}: {exc}")
            found, rejected = None, True
        except Exception as exc:  # MfaLookupUnavailable, or a transport error the caller didn't map
            log("WARN", f"MFA log backfill stopped: lookup unavailable ({type(exc).__name__}: {exc})")
            break
        details = dict(entry["details"])
        if found is not None:
            details["okta_mfa_log_event"] = found
            updated_count += 1
        elif rejected or now - entry_dt >= MFA_BACKFILL_UNCOUNTED_GRACE:
            attempts = details.get("okta_mfa_log_lookup_attempts")
            details["okta_mfa_log_lookup_attempts"] = (attempts if isinstance(attempts, int) else 0) + 1
        else:
            continue  # indexing lag: retry next time, nothing to write
        replacements[line] = json.dumps({**entry, "details": details}, separators=(",", ":"))

    if not replacements:
        return 0
    with _audit_log_exclusive(path, require_os_lock=True):
        current = _read_audit_log_lines(path)
        changed = False
        for i, line in enumerate(current):
            new_line = replacements.get(line)
            if new_line is not None:
                current[i] = new_line
                changed = True
        if changed:
            try:
                mode = os.stat(path).st_mode & 0o777
            except OSError:
                mode = 0o600
            _atomic_write_text(path, "\n".join(current) + "\n", mode=mode)
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
USER_GROUP_WORKERS = 4  # ENG2-08: parallel list_user_groups calls; must stay <= RATE_LIMIT_MIN_REMAINING
RATE_LIMIT_WAIT_BUFFER_SECS = 1
_rate_limit_lock = threading.Lock()
_rate_limit_state = {}  # host -> {"remaining": int, "reset": int}

# Phase 8 of docs/fast-follow-redesign.md: set once per inbound request
# (server/serve.py's do_GET/do_POST/do_DELETE) or background job
# (server/serve.py's _run_sync_job/_run_access_job, each given the
# triggering request's own id) so every log line produced while
# handling that one request/job carries the same id -- the thing a
# structured-logging phase is actually for ("what happened during this
# one click", not just "what happened at this timestamp"). A
# ContextVar, not a plain module global, specifically because
# ThreadingHTTPServer gives each request its own OS thread, and a
# background sync/access-model job runs in yet another thread it starts
# itself -- a plain global would leak one request's id into whichever
# other thread happened to read it next. None (the default) when
# there's no request to correlate with at all (CLI usage, this script's
# own module-level warnings, a scheduler tick before it's generated its
# own id -- see server/serve.py's _scheduler_loop).
CORRELATION_ID = contextvars.ContextVar("correlation_id", default=None)


def log(level, message):
    """Writes one JSON-line log record to stdout (WARN/ERROR to stderr,
    matching this function's pre-Phase-8 stream split) -- machine-
    parseable (one `json.loads` per line) instead of the previous
    colorized `[timestamp] [LEVEL] message` plaintext, so a real log
    aggregator (or just `jq`) can filter/group by level or
    correlation_id without regex. Signature is UNCHANGED from before
    this phase (still just `log(level, message)`) -- every existing
    call site across this file/audit_store.py needed zero changes; only
    this function's own body did."""
    record = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "level": level,
        "msg": message,
    }
    correlation_id = CORRELATION_ID.get()
    if correlation_id:
        record["correlation_id"] = correlation_id
    stream = sys.stderr if level in ("WARN", "ERROR") else sys.stdout
    print(json.dumps(record), file=stream)


def die(message):
    log("ERROR", message)
    sys.exit(1)


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------
# Non-HTTP statuses an API error can carry (ENG1-09 / ENG2-06): the call
# never got a usable HTTP answer. Every `except OpaApiError` /
# `except OktaApiError` handles these like any other API failure, instead
# of a raw URLError / TimeoutError / JSONDecodeError escaping as a 400/500.
API_STATUS_NETWORK = "network"
API_STATUS_INVALID_RESPONSE = "invalid_response"


def _api_error_message(status, url, body):
    if status == API_STATUS_NETWORK:
        return f"Network error calling {url}: {body}"
    if status == API_STATUS_INVALID_RESPONSE:
        return f"Unusable response from {url}: {body}"
    return f"HTTP {status} calling {url}: {body}"


class OpaApiError(Exception):
    def __init__(self, status, url, body):
        self.status = status
        self.url = url
        self.body = body
        super().__init__(_api_error_message(status, url, body))


class OktaApiError(Exception):
    def __init__(self, status, url, body):
        self.status = status
        self.url = url
        self.body = body
        super().__init__(_api_error_message(status, url, body))


def _is_network_error(exc):
    return isinstance(exc, (OpaApiError, OktaApiError)) and exc.status == API_STATUS_NETWORK


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
    # ENG1-08: a reset far in the future (a broken proxy, a bogus header)
    # used to park every later request to this host for that long.
    reset_in_secs = _clamp_wait(reset - server_now)
    with _rate_limit_lock:
        _rate_limit_state[_rate_limit_host(url)] = {
            "remaining": remaining,
            "reset_monotonic": time.monotonic() + reset_in_secs,
        }


def _note_rate_limited_until(url, seconds):
    """Records "no requests to this host for `seconds`" (clamped) -- the
    next _wait_if_rate_limited for it sleeps that long. Never shortens a
    later deadline already recorded."""
    deadline = time.monotonic() + _clamp_wait(seconds)
    host = _rate_limit_host(url)
    with _rate_limit_lock:
        state = _rate_limit_state.get(host)
        if state and state["remaining"] <= RATE_LIMIT_MIN_REMAINING and state["reset_monotonic"] > deadline:
            return
        _rate_limit_state[host] = {"remaining": 0, "reset_monotonic": deadline}


def _wait_if_rate_limited(url):
    """Proactively sleep until the rate-limit window resets if the last
    response we saw for this host reported few requests left -- this is
    what keeps the recursive folder-tree walk (one API call per folder)
    from ever tripping a 429 in the first place."""
    with _rate_limit_lock:
        state = _rate_limit_state.get(_rate_limit_host(url))
    if not state or state["remaining"] > RATE_LIMIT_MIN_REMAINING:
        return
    wait_secs = _clamp_wait(state["reset_monotonic"] - time.monotonic()) + RATE_LIMIT_WAIT_BUFFER_SECS
    if wait_secs > RATE_LIMIT_WAIT_BUFFER_SECS:
        log("WARN", f"Rate limit nearly exhausted for {_rate_limit_host(url)} "
                     f"({state['remaining']} request(s) left) -- waiting {wait_secs:.0f}s for the window to reset...")
        time.sleep(wait_secs)
        return wait_secs
    return 0.0


# ENG1-08 (external review, 2026-10-05): every rate-limit wait used to be
# whatever the server (or a proxy, or -- before ENG1-02 -- any host a user
# typed in) said: Retry-After 1e9 meant sleeping ~31 years, a negative or
# NaN value made time.sleep raise ValueError (-> HTTP 400), and an
# HTTP-date Retry-After was ignored. Okta's rate-limit windows are 60 s, so
# no single wait needs to exceed RATE_LIMIT_MAX_WAIT_SECS, and one call
# gives up (as a 429) once its waits add up to RATE_LIMIT_TOTAL_BUDGET_SECS
# instead of holding a request thread or sync job for hours.
RATE_LIMIT_MAX_WAIT_SECS = 120
RATE_LIMIT_TOTAL_BUDGET_SECS = 600


def _clamp_wait(seconds):
    """A usable wait in [0, RATE_LIMIT_MAX_WAIT_SECS]; non-finite -> 0."""
    if seconds is None or not math.isfinite(seconds):
        return 0.0
    return min(max(float(seconds), 0.0), float(RATE_LIMIT_MAX_WAIT_SECS))


def _retry_after_secs(headers):
    """On an actual 429, prefer an authoritative wait time over blind
    backoff: Retry-After (seconds, a relative delta -- immune to clock skew
    by construction) if present, else derive from x-ratelimit-reset (an
    absolute unix timestamp), anchored to the response's own 'Date' header
    rather than local wall time for the same clock-skew reasons as
    _record_rate_limit. Falls back to the fixed backoff only if none of
    Retry-After, x-ratelimit-reset, or Date are present."""
    server_now = _server_time_from_headers(headers)
    if server_now is None:
        server_now = time.time()
    retry_after = (headers.get("Retry-After") or "").strip()
    if retry_after:
        seconds = None
        try:
            seconds = float(retry_after)
        except ValueError:
            # RFC 9110 10.2.3: Retry-After may also be an HTTP-date.
            try:
                seconds = email.utils.parsedate_to_datetime(retry_after).timestamp() - server_now
            except (TypeError, ValueError, IndexError, OverflowError):
                seconds = None
        if seconds is not None and math.isfinite(seconds) and seconds >= 0:
            return _clamp_wait(seconds) + RATE_LIMIT_WAIT_BUFFER_SECS
    reset = headers.get("x-ratelimit-reset")
    if reset is not None:
        try:
            return _clamp_wait(int(reset) - server_now) + RATE_LIMIT_WAIT_BUFFER_SECS
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


def _origin(parts):
    scheme = (parts.scheme or "").lower()
    return scheme, (parts.hostname or "").lower(), parts.port or {"https": 443, "http": 80}.get(scheme)


def _same_origin_path(base_url, link):
    """ENG1-09 (external review, 2026-10-05): the path+query to request for
    a pagination `next` link, or None if the link points anywhere other
    than base_url's own origin. Shared by OpaClient._list,
    OktaClient.list_devices and OktaClient.get_system_log. Before: the OPA
    client sent its bearer token to whatever absolute URL a Link header
    named (any host), and the Okta client stripped its base only on an
    exact, case-sensitive prefix match -- so an org URL saved as
    https://Your-Org.okta.com, or a link with an explicit :443, turned page 2
    into base_url + "https://..." and every multi-page call failed.
    Scheme and host compare case-insensitively, default ports normalised."""
    if not link:
        return None
    if link.startswith("/") and not link.startswith("//"):
        return link
    try:
        target = urllib.parse.urlsplit(link)
        base = urllib.parse.urlsplit(base_url)
        if target.scheme.lower() not in ("http", "https") or _origin(target) != _origin(base):
            return None
    except ValueError:  # e.g. a non-numeric port
        return None
    return (target.path or "/") + (f"?{target.query}" if target.query else "")


_CROSS_ORIGIN_WARNED = "\0cross-origin-warned"  # marker kept in a walk's `seen` set (never a real path)
MAX_LIST_PAGES = 10000  # runaway backstop for _list/list_devices; a real tenant is nowhere near this


def _next_page_path(base_url, headers, seen, error_cls, what):
    """The next page's path (always requested on base_url's own origin) for
    a Link-paginated list, or None when there is none. Raises error_cls
    (never silently truncates) when the link repeats a page already
    fetched or the walk passes MAX_LIST_PAGES."""
    link = _parse_next_link(headers)
    if not link:
        return None
    path = _same_origin_path(base_url, link)
    if path is None:
        # A link naming another origin: the credential never goes there.
        # Its path+query is requested on THIS client's own origin instead
        # -- the OPA spec doesn't say which host its Link URLs carry (an
        # alias of the same API would otherwise break every multi-page
        # list), and the upstream that sent it is the one we already
        # trust with our data. Logged, host only.
        try:
            target = urllib.parse.urlsplit(link)
        except ValueError:
            raise error_cls(API_STATUS_INVALID_RESPONSE, what, "unparseable pagination link") from None
        path = (target.path or "/") + (f"?{target.query}" if target.query else "")
        if not path.startswith("/") or path.startswith("//"):
            raise error_cls(API_STATUS_INVALID_RESPONSE, what, "unusable pagination link")
        # ...and only for the same collection the walk started on, so a
        # hostile link can't steer page 2 to an unrelated endpoint.
        if (target.path or "/").rstrip("/") != what.rstrip("/"):
            raise error_cls(API_STATUS_INVALID_RESPONSE, what,
                            "a pagination link to another origin points at a different collection")
        if _CROSS_ORIGIN_WARNED not in seen:
            seen.add(_CROSS_ORIGIN_WARNED)
            log("WARN", f"{what}: pagination link names another origin ({target.netloc or '?'}); "
                         "following its path on the configured origin only.")
    if path in seen:
        raise error_cls(API_STATUS_INVALID_RESPONSE, what, "pagination loop: the next-page link repeats a page")
    if len(seen) > MAX_LIST_PAGES:
        raise error_cls(API_STATUS_INVALID_RESPONSE, what, f"more than {MAX_LIST_PAGES} pages; stopping")
    seen.add(path)
    return path


class _NoCrossHostRedirectHandler(urllib.request.HTTPRedirectHandler):
    """SECURITY FIX (external review, 2026-10-05, ENG1-02): urllib's
    default redirect handling follows a 30x to ANY Location, on ANY host,
    on ANY scheme, and -- critically -- carries forward headers set on the
    original Request (confirmed live: a request with an Authorization
    header, redirected cross-host, delivers that exact header to the new
    host). Since `base_domain` (OpaClient) and `okta_url` (OktaClient) are
    user-supplied environment fields with no validation at save time (see
    upsert_environment's own validate_base_domain/validate_okta_url calls
    below), a malicious or compromised value naming a redirecting host
    would exfiltrate this project's real OPA key_secret/Okta API token to
    whatever host the redirect points at. Confirmed via a two-local-server
    PoC: an unmodified urlopen() call delivered the Authorization header
    to a second server after one 302.

    This handler refuses (raises HTTPError, same as the server having
    returned the redirect's status directly) any redirect that changes
    scheme (https -> http) or host:port -- same-host, same-scheme
    redirects (the overwhelmingly common legitimate case, e.g. a trailing
    slash) still work exactly as before."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old = urllib.parse.urlsplit(req.full_url)
        new = urllib.parse.urlsplit(newurl)
        if (new.scheme, new.hostname, new.port) != (old.scheme, old.hostname, old.port):
            raise urllib.error.HTTPError(
                newurl, code,
                f"Refusing to follow a redirect from {old.scheme}://{old.netloc} to "
                f"{new.scheme}://{new.netloc} -- would leak this request's credentials "
                f"to a different host.",
                headers, fp,
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_SAFE_OPENER = urllib.request.build_opener(_NoCrossHostRedirectHandler)


_IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "PUT", "DELETE"})


def _is_connect_phase_error(reason):
    """True for a network failure that certainly happened BEFORE the
    request reached the server (name resolution, connection refused), so
    even a POST can be retried without risking a duplicate."""
    return isinstance(reason, (ConnectionRefusedError, socket.gaierror))


def http_json_request(method, url, headers=None, body=None, error_cls=OpaApiError, return_headers=False,
                      idempotent=None, rate_limit_wait=True):
    """Shared retrying HTTP-JSON helper used by both OpaClient and
    OktaClient, so the retry/backoff logic lives in exactly one place.
    Tracks x-ratelimit-* response headers per host and proactively waits
    out the window when few requests remain, so callers doing many
    sequential requests (e.g. the recursive folder-tree walk) shouldn't
    ever see a 429 in normal operation.

    With return_headers=True, returns (parsed_body, response_headers)
    instead of just parsed_body -- used for Link-header pagination.

    Uses _SAFE_OPENER (ENG1-02 above), not the module-level
    urllib.request.urlopen, so a redirect to a different host/scheme is
    refused instead of silently carrying this request's credentials
    there.

    ENG1-09 / ENG2-06 (external review, 2026-10-05):
    - A 5xx, or a network failure that may have happened after the server
      received the request (a timeout, a reset), is retried only for an
      idempotent request (GET/HEAD/OPTIONS/PUT/DELETE, or a caller passing
      idempotent=True, e.g. the token exchange). A POST used to be retried
      too: a 502/504 from an intermediary after the upstream committed
      created a duplicate (Okta group names are not unique). A
      connect-phase failure (DNS, connection refused) is still retried for
      every method -- nothing reached the server.
    - Every failure now surfaces as error_cls: status "network" for a
      transport failure (URLError after the retries, a timeout or reset
      while reading, an HTTP protocol error) and "invalid_response" for a
      2xx body that isn't JSON. They used to escape as URLError /
      TimeoutError / JSONDecodeError -- a traceback in the CLI, an aborted
      execute_plan, or (JSONDecodeError being a ValueError) a misleading
      HTTP 400 from the dashboard.
    - Rate-limit waits are clamped (see RATE_LIMIT_MAX_WAIT_SECS) and one
      call gives up with a 429 once its waits pass
      RATE_LIMIT_TOTAL_BUDGET_SECS.
    - rate_limit_wait=False sends at once and raises a 429 instead of
      waiting (no proactive wait, no 429 retry): for a write that must go
      out right after the read it was checked against (ENG2-05); the
      caller waits, re-reads and retries itself."""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = dict(headers or {})
    headers.setdefault("Accept", "application/json")
    if data is not None:
        headers["Content-Type"] = "application/json"
    if idempotent is None:
        idempotent = method.upper() in _IDEMPOTENT_METHODS

    # Two independent retry budgets: `error_attempt` for genuine failures
    # (5xx/network, capped low by MAX_RETRIES since repeated failure likely
    # means something's actually wrong) and `rate_limit_attempt` for 429s
    # (capped much higher by MAX_RATE_LIMIT_RETRIES since each wait is
    # authoritative, not a guess) -- see the constants above for why these
    # are no longer the same counter.
    error_attempt = 0
    rate_limit_attempt = 0
    waited = 0.0
    while True:
        if rate_limit_wait:
            waited += _wait_if_rate_limited(url) or 0.0
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with _SAFE_OPENER.open(req, timeout=REQUEST_TIMEOUT_SECS) as resp:
                _record_rate_limit(url, resp.headers)
                resp_headers = resp.headers
                raw = resp.read()
        except urllib.error.HTTPError as e:
            _record_rate_limit(url, e.headers)
            try:
                raw_body = e.read().decode("utf-8", errors="replace")
            except (OSError, http.client.HTTPException):
                raw_body = ""
            if e.code == 429:
                rate_limit_attempt += 1
                wait_secs = _retry_after_secs(e.headers)
                if (rate_limit_wait and rate_limit_attempt <= MAX_RATE_LIMIT_RETRIES
                        and waited + wait_secs <= RATE_LIMIT_TOTAL_BUDGET_SECS):
                    log("WARN", f"{method} {url} -> HTTP 429 (rate limited); "
                                f"waiting {wait_secs:.0f}s before retry "
                                f"({rate_limit_attempt}/{MAX_RATE_LIMIT_RETRIES})...")
                    time.sleep(wait_secs)
                    waited += wait_secs
                    continue
                if not rate_limit_wait:
                    # The caller waits itself (OpaClient.wait_for_rate_limit),
                    # which only sees recorded state -- record this 429's own
                    # wait, so a bare Retry-After is honoured too.
                    _note_rate_limited_until(url, wait_secs - RATE_LIMIT_WAIT_BUFFER_SECS)
                raise error_cls(e.code, url, raw_body) from None
            if e.code in RETRYABLE_STATUS_CODES and idempotent:
                error_attempt += 1
                if error_attempt <= MAX_RETRIES:
                    log("WARN", f"{method} {url} -> HTTP {e.code}, retrying ({error_attempt}/{MAX_RETRIES})...")
                    time.sleep(RETRY_BACKOFF_SECS * error_attempt)
                    continue
            raise error_cls(e.code, url, raw_body) from None
        except urllib.error.URLError as e:
            if idempotent or _is_connect_phase_error(e.reason):
                error_attempt += 1
                if error_attempt <= MAX_RETRIES:
                    log("WARN", f"{method} {url} -> network error ({e.reason!r}), retrying ({error_attempt}/{MAX_RETRIES})...")
                    time.sleep(RETRY_BACKOFF_SECS * error_attempt)
                    continue
            raise error_cls(API_STATUS_NETWORK, url, f"{type(e.reason).__name__}: {e.reason}") from e
        except (OSError, http.client.HTTPException) as e:
            # Raised while READING the response (timeout, reset, truncated
            # body) -- the request certainly reached the server.
            if idempotent:
                error_attempt += 1
                if error_attempt <= MAX_RETRIES:
                    log("WARN", f"{method} {url} -> {type(e).__name__} reading the response, retrying "
                                f"({error_attempt}/{MAX_RETRIES})...")
                    time.sleep(RETRY_BACKOFF_SECS * error_attempt)
                    continue
            raise error_cls(API_STATUS_NETWORK, url, f"{type(e).__name__} while reading the response") from e
        try:
            parsed = json.loads(raw.decode("utf-8")) if raw else None
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise error_cls(API_STATUS_INVALID_RESPONSE, url, "the response body is not JSON") from None
        return (parsed, resp_headers) if return_headers else parsed


# ENG2-16 (external review, 2026-10-05): resource identifiers reach the
# OPA client from request paths and payloads. They are opaque UUID-shaped
# ids, so a conservative charset check at the route layer
# (validate_resource_id) plus percent-quoting every id interpolated into a
# URL path (_path_id) means an id containing "/", "?", "#", "%" or ".."
# can never make the service key call a different collection than the
# route intends, nor alter an Okta System Log filter expression.
_RESOURCE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


def validate_resource_id(value, label="id"):
    """Returns `value` if it is a plausible opaque OPA/Okta id
    ([A-Za-z0-9_-], 1-128 chars); raises ValueError otherwise (-> 400 at
    the route layer)."""
    if not isinstance(value, str) or not _RESOURCE_ID_RE.match(value):
        raise ValueError(f"{label} is not a valid identifier")
    return value


def _path_id(value):
    """Percent-quotes one id for use as a single URL path segment."""
    return urllib.parse.quote(str(value), safe="")


class OpaClient:
    def __init__(self, base_domain, team_name, key_id, key_secret):
        self.base_url = f"https://{base_domain}"
        self.team_name = team_name
        self.key_id = key_id
        self.key_secret = key_secret
        self.bearer_token = None
        self._current_user = None  # see get_current_user()
        # One token refresh at a time (ENG2-08 runs some reads on worker
        # threads): a thread whose request was rejected refreshes only if
        # nobody replaced the token it used in the meantime.
        self._token_lock = threading.Lock()
        self._fetch_token()

    def _fetch_token(self):
        path = TOKEN_PATH.format(team=self.team_name)
        body = {"key_id": self.key_id, "key_secret": self.key_secret}
        # A token exchange creates nothing, so retrying it is always safe.
        resp = self._raw_request("POST", path, body=body, authed=False, idempotent=True)
        token = (resp or {}).get("bearer_token")
        if not token:
            raise OpaApiError(API_STATUS_INVALID_RESPONSE, path, "no 'bearer_token' in the token response")
        self.bearer_token = token

    def request(self, method, path, body=None, return_headers=False, _retried_auth=False, rate_limit_wait=True):
        token_used = self.bearer_token
        try:
            return self._raw_request(method, path, body=body, authed=True, return_headers=return_headers,
                                     rate_limit_wait=rate_limit_wait)
        except OpaApiError as e:
            # ENG1-09: OPA also answers 401 for "Missing capability: ..."
            # (a permission the service user lacks, confirmed live) -- a new
            # token can't fix that, so don't spend a token exchange and a
            # second request on it.
            if e.status == 401 and not _retried_auth and "missing capability" not in str(e.body).lower():
                log("WARN", "Bearer token rejected (401); refreshing and retrying once...")
                with self._token_lock:
                    if self.bearer_token == token_used:
                        self._fetch_token()
                return self.request(method, path, body=body, return_headers=return_headers, _retried_auth=True,
                                    rate_limit_wait=rate_limit_wait)
            raise

    def _raw_request(self, method, path, body=None, authed=True, return_headers=False, idempotent=None,
                     rate_limit_wait=True):
        # Always relative to base_url: absolute URLs (pagination links) are
        # reduced to a same-origin path first -- see _next_page_path.
        url = self.base_url + path
        headers = {"Authorization": f"Bearer {self.bearer_token}"} if authed else {}
        return http_json_request(method, url, headers=headers, body=body, error_cls=OpaApiError,
                                  return_headers=return_headers, idempotent=idempotent, rate_limit_wait=rate_limit_wait)

    def _list(self, path):
        """Fetches every page of a "list" envelope response, following the
        Link: rel="next" response header until exhausted -- no endpoint in
        this codebase ever wants only page 1, so pagination lives here
        once rather than being opted into per call site. A next link is
        only followed on this client's own origin, and a repeating link
        or a runaway walk is an error, never a silent truncation (ENG1-09,
        see _next_page_path)."""
        items = []
        next_path = path
        seen = {path}
        while next_path:
            resp, headers = self.request("GET", next_path, return_headers=True)
            if isinstance(resp, dict) and isinstance(resp.get(LIST_ENVELOPE_KEY), list):
                items.extend(resp[LIST_ENVELOPE_KEY])
            else:
                # The shape only: the body can carry tenant data (ENG1-09).
                log("WARN", f"Unexpected list response shape from {path.split('?')[0]} "
                             f"({type(resp).__name__}), treating the page as empty.")
            next_path = _next_page_path(self.base_url, headers, seen, OpaApiError, path.split("?")[0])
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
        path = PROJECTS_PATH.format(team=self.team_name, resource_group_id=_path_id(resource_group_id))
        return self._list(path)

    def create_project(self, resource_group_id, name):
        path = PROJECTS_PATH.format(team=self.team_name, resource_group_id=_path_id(resource_group_id))
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
        path = SECURITY_POLICY_ITEM_PATH.format(team=self.team_name, security_policy_id=_path_id(security_policy_id))
        return self.request("GET", path)

    def create_security_policy(self, policy_body):
        path = SECURITY_POLICY_PATH.format(team=self.team_name)
        return self.request("POST", path, body=policy_body)

    def update_security_policy(self, security_policy_id, policy_body, rate_limit_wait=True):
        """PUT is a full replace, not a patch -- confirmed live 2026-08-14
        (returns 204, no body). Callers must GET the current policy first
        and submit the complete modified object; see
        upsert_folder_rule_in_policy for the one place that matters here.
        rate_limit_wait=False: sent at once, a 429 is raised rather than
        waited out (see http_json_request; ENG2-05)."""
        path = SECURITY_POLICY_ITEM_PATH.format(team=self.team_name, security_policy_id=_path_id(security_policy_id))
        return self.request("PUT", path, body=policy_body, rate_limit_wait=rate_limit_wait)

    def wait_for_rate_limit(self):
        """Waits out this host's rate-limit window now, if it is nearly
        used up -- so a read and the write checked against it can then go
        out back to back (ENG2-05). Returns the seconds slept."""
        return _wait_if_rate_limited(self.base_url + "/")

    def delete_security_policy(self, security_policy_id):
        path = SECURITY_POLICY_ITEM_PATH.format(team=self.team_name, security_policy_id=_path_id(security_policy_id))
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
        """Confirmed live 2026-09-30 against a real tenant (10 real
        enrolled clients returned) -- every end-user OPA client (laptop/
        workstation) enrolled for this team, not just the caller's own
        (requires ?all=true, per the spec's own ListClients description:
        'By default, this only returns clients associated with the
        requesting user')."""
        path = CLIENTS_PATH.format(team=self.team_name) + "?all=true"
        return self._list(path)

    def list_project_servers(self, resource_group_id, project_id):
        path = PROJECT_SERVERS_PATH.format(
            team=self.team_name, resource_group_id=_path_id(resource_group_id), project_id=_path_id(project_id)
        )
        return self._list(path)

    def list_project_saas_app_accounts(self, resource_group_id, project_id):
        path = PROJECT_SAAS_APP_ACCOUNTS_PATH.format(
            team=self.team_name, resource_group_id=_path_id(resource_group_id), project_id=_path_id(project_id)
        )
        return self._list(path)

    def list_project_okta_ud_accounts(self, resource_group_id, project_id):
        path = PROJECT_OKTA_UD_ACCOUNTS_PATH.format(
            team=self.team_name, resource_group_id=_path_id(resource_group_id), project_id=_path_id(project_id)
        )
        return self._list(path)

    def list_project_active_directory_accounts(self, resource_group_id, project_id):
        """Confirmed live 2026-09-30 against a real tenant (project
        Test_User_A_Project) -- real shape includes account_name,
        sam_account_name, distinguished_name, sid, domain.name, email,
        account_status_detail."""
        path = PROJECT_ACTIVE_DIRECTORY_ACCOUNTS_PATH.format(
            team=self.team_name, resource_group_id=_path_id(resource_group_id), project_id=_path_id(project_id)
        )
        return self._list(path)

    def list_project_database_accounts(self, resource_group_id, project_id):
        """Confirmed live 2026-09-30 against a real tenant (projects
        Postgresql-DB-Accounts/SQL-DB-Accounts) -- real shape includes
        account_name, database_connection.name,
        database_connection_auth_type, account_status_detail."""
        path = PROJECT_DATABASE_ACCOUNTS_PATH.format(
            team=self.team_name, resource_group_id=_path_id(resource_group_id), project_id=_path_id(project_id)
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
        path = f"{ASSIGNMENTS_PATH.format(team=self.team_name)}/{_path_id(assignment_id)}"
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
        path = AD_CONNECTION_RULES_PATH.format(team=self.team_name, ad_connection_id=_path_id(ad_connection_id))
        return self._list(path)

    def get_ad_connection_rule_settings(self, ad_connection_id):
        """Confirmed live 2026-09-30 -- a single object (is_configured/
        matching_criteria/partial_matching_criteria/allow_partial_matches),
        not a collection -- plain GET, not _list."""
        path = AD_CONNECTION_RULE_SETTINGS_PATH.format(team=self.team_name, ad_connection_id=_path_id(ad_connection_id))
        return self.request("GET", path)

    def list_folders(self, resource_group_id, project_id):
        """TOP-LEVEL (root) folders only -- despite its name, this endpoint
        (ListTopLevelSecretFoldersForProject) does not include nested
        folders. Confirmed live 2026-08-14: a folder with 5 real
        sub-folders showed only itself here; the sub-folders were entirely
        absent. Use fetch_all_folders() for the full tree -- see module
        docstring fact #2."""
        path = FOLDERS_COLLECTION_PATH.format(
            team=self.team_name, resource_group_id=_path_id(resource_group_id), project_id=_path_id(project_id)
        )
        return self._list(path)

    def list_folder_items(self, resource_group_id, project_id, folder_id):
        """Direct children of one folder -- both sub-folders and secrets,
        distinguished by their "type" field (TYPE_FOLDER vs
        "key_value_secret"). This is the only way to discover nesting;
        there's no parent_id on any read response (see fetch_all_folders)."""
        path = FOLDER_ITEMS_PATH.format(
            team=self.team_name, resource_group_id=_path_id(resource_group_id),
            project_id=_path_id(project_id), folder_id=_path_id(folder_id),
        )
        return self._list(path)

    def create_folder(self, resource_group_id, project_id, name, description, parent_id=None):
        path = FOLDERS_COLLECTION_PATH.format(
            team=self.team_name, resource_group_id=_path_id(resource_group_id), project_id=_path_id(project_id)
        )
        body = {FIELD_NAME: name}
        if description:
            body[FIELD_DESCRIPTION] = description
        if parent_id:
            body[FIELD_PARENT_ID] = parent_id
        return self.request("POST", path, body=body)

    def get_folder(self, resource_group_id, project_id, folder_id):
        """GET .../secret_folders/{id} (RetrieveSecretFolder in the OPA spec;
        SecretFolderResponse carries id and name, never a parent). Used by
        the policy route (ENG2-05) to confirm a folder really is in the
        project named in the URL and to take its name from OPA instead of
        from the request."""
        path = FOLDER_ITEM_PATH.format(
            team=self.team_name, resource_group_id=_path_id(resource_group_id), project_id=_path_id(project_id), folder_id=_path_id(folder_id)
        )
        return self.request("GET", path)

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
            team=self.team_name, resource_group_id=_path_id(resource_group_id), project_id=_path_id(project_id), folder_id=_path_id(folder_id)
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

    def get_device_users(self, device_id):
        """GET /api/v1/devices/{id}/users ("List Users for Device") --
        confirmed live 2026-10-02 against a real tenant: returns a JSON
        LIST (never a single object -- Okta genuinely supports multiple
        users per device, e.g. a shared/kiosk-style device; confirmed via
        2 real devices in this tenant each with 2 associated users), one
        entry per association: {created, managementStatus, screenLockType,
        user: {id, status, profile: {firstName, lastName, email, login,
        ...}, ...}}. Distinct from list_clients' user_name (that's OPA's
        own PAM-client enrollment, a different system -- see list_devices'
        own docstring on why the two only partially overlap)."""
        return self.request("GET", f"/api/v1/devices/{urllib.parse.quote(device_id, safe='')}/users")

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
        in the same bootstrap pass.

        Also gets an added `users` key -- a flat list of email strings
        (via get_device_users, same per-device enrichment pattern as
        authenticator_enrollments above, same graceful-empty-list-on-
        failure handling). Extracted to a simple List[str] rather than
        passing through the full nested user object, since no caller
        needs more than a display-ready name for a read-only table
        column -- email preferred, falling back to login, then
        "firstName lastName", matching how actor display names are
        resolved elsewhere in this file."""
        devices = []
        next_path = "/api/v1/devices?limit=200"
        seen = {next_path}
        while next_path:
            resp, headers = self.request("GET", next_path, return_headers=True)
            devices.extend(d for d in (resp or []) if isinstance(d, dict))
            next_path = _next_page_path(self.base_url, headers, seen, OktaApiError, "/api/v1/devices")
        for d in devices:
            device_id = d.get("id")
            if not device_id:  # ENG2-11: no id -> nothing to enrich, not a KeyError for the whole bootstrap
                d["authenticator_enrollments"], d["users"] = [], []
                continue
            try:
                d["authenticator_enrollments"] = self.get_device_authenticator_enrollments(device_id)
            except OktaApiError:
                d["authenticator_enrollments"] = []
            try:
                associations = self.get_device_users(device_id)
            except OktaApiError:
                associations = []
            users = []
            for assoc in associations or []:
                if not isinstance(assoc, dict):
                    continue
                profile = (assoc.get("user") or {}).get("profile") or {}
                name = (
                    profile.get("email")
                    or profile.get("login")
                    or " ".join(part for part in (profile.get("firstName"), profile.get("lastName")) if part)
                )
                if name:
                    users.append(name)
            d["users"] = users
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
        seen = {next_path}
        pages = 0
        while next_path and pages < max_pages:
            resp, headers = self.request("GET", next_path, return_headers=True)
            events.extend(resp or [])
            # Link URLs from Okta are absolute (https://org...); only this
            # org's own origin is followed, compared case-insensitively
            # with default ports normalised (ENG1-09, _same_origin_path).
            # A repeating link is an error here too, never a silent stop.
            next_path = _next_page_path(self.base_url, headers, seen, OktaApiError, SYSTEM_LOG_PATH)
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
        # ENG2-12: a JSON row whose path isn't a string used to raise
        # AttributeError (-> 500); it's the caller's input, so a 400.
        if not isinstance(row, dict):
            raise ValueError(f"Row {row_num}: each row must be an object with a 'path'.")
        if row.get("path") is not None and not isinstance(row.get("path"), str):
            raise ValueError(f"Row {row_num}: 'path' must be a string.")
        if row.get("description") is not None and not isinstance(row.get("description"), str):
            raise ValueError(f"Row {row_num}: 'description' must be a string.")
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
    parse_rows for the actual tree-building logic.

    ENG2-12 / ENG2-13: header names are matched trimmed and
    case-insensitively (a spreadsheet's "Path " used to pass the header
    check and then be ignored on every row, ending in a misleading "No
    usable paths found"), and a file that isn't UTF-8 ends with a clear
    message instead of a traceback."""
    try:
        with open(csv_path, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            if reader.fieldnames:
                reader.fieldnames = [(c or "").strip().lower() for c in reader.fieldnames]
            if not reader.fieldnames or "path" not in reader.fieldnames:
                die(f"CSV must have a 'path' column header. Found: {reader.fieldnames}")
            rows = list(reader)
    except UnicodeDecodeError:
        die(f"{csv_path} is not UTF-8 text. Save it as 'CSV UTF-8' and try again.")
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
    invalid = [path for path in ordered_paths if not is_valid_folder_name(path[-1])]
    if invalid:
        log("ERROR", "These folder names will be rejected (only A-Z a-z 0-9 . _ - are allowed, "
                     f"at most {FOLDER_NAME_MAX_LEN} characters, and not '.' or '..'):")
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


def detect_case_variant_names(ordered_paths):
    """ENG2-12: names that differ only by letter case (DB vs db). Whether
    OPA treats them as the same name is not documented, so this is a
    warning, not a block: {casefolded name: [paths]} for every name that
    appears in more than one spelling."""
    groups = {}
    for path in ordered_paths:
        groups.setdefault(path[-1].casefold(), []).append(path)
    return {key: paths for key, paths in groups.items() if len({p[-1] for p in paths}) > 1}


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
    visited = set()
    while current is not None:
        # ENG2-11: a folder stored with name None (the walk keeps
        # folder.get(name)) used to raise TypeError in the join below.
        names.append(current.get("name") or "?")
        parent_id = current.get("parent_id")
        if not parent_id or parent_id in visited:  # a parent cycle can't loop forever
            break
        visited.add(parent_id)
        current = by_id.get(parent_id)
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


class MultiTargetRuleError(Exception):
    """Raised by upsert_folder_rule_in_policy when the matched rule's
    selector names more than just this one folder -- see that function's
    docstring (UI-01) for why replacing it outright would be destructive."""


def upsert_folder_rule_in_policy(policy, folder_id, folder_name, rule_name, privilege_flags, mfa=None):
    """Mutates and returns policy["rules"]: replaces the rule that already
    targets this exact folder (by secret_folder id), or appends a new one.
    `policy` must be the full object from get_security_policy -- PUT is a
    full replace (see OpaClient.update_security_policy), never a patch.

    SECURITY/CORRECTNESS FIX (external review, 2026-10-05, UI-01): this
    used to replace the matched rule WHOLESALE with a brand-new one built
    from only what the current form submitted -- silently dropping any
    non-MFA condition the form has no UI for at all (e.g. a gateway or
    access-request condition), and -- worse -- every OTHER folder the old
    rule's selector also named, since the new rule's selector only ever
    lists this one folder. Two independent guards now:
    1. Raises MultiTargetRuleError, refusing the replace outright, if the
       matched rule's selector names MORE than this one folder -- there
       is no safe way to "replace" a shared rule from a single-folder
       form without silently dropping the other folders' access. The
       caller (serve.py) turns this into a 409 telling the admin to edit
       the rule in OPA directly.
    2. Any condition on the matched rule whose condition_type ISN'T "mfa"
       is always carried over into the new rule, since this form has no
       field for those at all -- there's nothing the caller could have
       meant to replace it WITH. The mfa condition itself is exactly what
       `mfa` says (a dict to set/replace it, falsy to clear it) -- a real
       user choice via the dialog's "Require MFA" checkbox, which the
       frontend now prefills from the existing rule (see
       AssignAccessDialog.tsx) rather than always defaulting to off, so
       leaving it unchecked when the rule already had MFA is a genuine
       "turn it off" action, not an accidental drop."""
    other_conditions = []
    for rule in policy.get("rules") or []:
        if _rule_targets_folder(rule, folder_id):
            selectors = (rule.get("resource_selector") or {}).get("selectors") or []
            if len(selectors) > 1:
                raise MultiTargetRuleError(
                    f"The matched rule '{rule.get('name')}' targets {len(selectors)} resources, not just "
                    f"'{folder_name}'. Edit this rule directly in OPA to avoid dropping access to the others."
                )
            other_conditions = [c for c in (rule.get("conditions") or []) if c.get("condition_type") != "mfa"]
            break

    conditions = other_conditions + ([build_mfa_condition(**mfa)] if mfa else [])

    new_rule = {
        "name": rule_name,
        "resource_type": "secret_based_resource",
        "resource_selector": build_secret_folder_selector(folder_id, folder_name),
        "privileges": [{"privilege_type": "secret", "privilege_value": build_secret_privilege(privilege_flags)}],
        "conditions": conditions,
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
    a group here grants it every other rule already in the policy too.

    ENG2-05 (external review, 2026-10-05): returns a copy of `principals`
    with only those two lists changed -- any other key the API returns
    there is kept rather than dropped on the PUT (the spec documents only
    user_groups and workload_roles today). Existing entries without an id
    (ENG2-11) no longer raise KeyError."""
    merged = dict(principals) if isinstance(principals, dict) else {}
    for key, refs in (("user_groups", group_refs), ("workload_roles", workload_role_refs)):
        current = list(merged.get(key) or [])
        seen = {e.get("id") for e in current if isinstance(e, dict)}
        for ref in refs or []:
            if ref["id"] not in seen:
                current.append(ref)
                seen.add(ref["id"])
        merged[key] = current
    return merged


def validate_principal_refs(refs, label):
    """ENG2-05: group/workload-role refs arrive from the browser and go to
    OPA as sent. Each must be an object with a valid id; only id, name and
    type are passed on. Raises ValueError (-> 400)."""
    if refs is None:
        return []
    if not isinstance(refs, list):
        raise ValueError(f"{label} must be a list")
    out = []
    for ref in refs:
        if not isinstance(ref, dict):
            raise ValueError(f"every entry of {label} must be an object with an id")
        clean = {"id": validate_resource_id(ref.get("id"), f"{label} id")}
        for key in ("name", "type"):
            if ref.get(key) is not None:
                if not isinstance(ref[key], str):
                    raise ValueError(f"{label} {key} must be a string")
                clean[key] = ref[key]
        out.append(clean)
    return out


def validate_secret_privilege_flags(flags):
    """ENG2-05: build_secret_privilege used bool(value), so a non-UI client
    sending "false" (a non-empty string) GRANTED the privilege. Every known
    field present must now be a real boolean. Unknown keys are ignored, as
    before (they never reach OPA: only the 8 known fields are emitted)."""
    if flags is None:
        return {}
    if not isinstance(flags, dict):
        raise ValueError("privileges must be an object of {field: true|false}")
    for field in SECRET_PRIVILEGE_FIELDS:
        if field in flags and not isinstance(flags[field], bool):
            raise ValueError(f"privileges.{field} must be true or false")
    return flags


def validate_mfa_condition(mfa):
    """ENG2-05: build_mfa_condition(**mfa) raised TypeError (-> 500) on any
    unexpected key. Returns None (no MFA) or a clean
    {"reauth_seconds": int >= 0, "acr_values": non-empty str}."""
    if not mfa:
        return None
    if not isinstance(mfa, dict) or set(mfa) != {"reauth_seconds", "acr_values"}:
        raise ValueError("mfa must be null or {reauth_seconds, acr_values}")
    seconds, acr = mfa["reauth_seconds"], mfa["acr_values"]
    if isinstance(seconds, bool) or not isinstance(seconds, int) or seconds < 0:
        raise ValueError("mfa.reauth_seconds must be a whole number of seconds, 0 or more")
    if not isinstance(acr, str) or not acr.strip():
        raise ValueError("mfa.acr_values must be a non-empty string")
    return {"reauth_seconds": seconds, "acr_values": acr.strip()}


def policy_fingerprint(policy):
    """A stable digest of a policy object as returned by GET, for the
    ENG2-05 compare-before-PUT check. List order is ignored (every list,
    at any depth, is compared as a sorted multiset): nothing documents
    that two GETs of an unchanged policy return principals or rules in the
    same order, and a false "changed" would block every assignment, while
    a pure re-ordering changes nothing a PUT of the first copy would lose."""
    def canonical(value):
        if isinstance(value, dict):
            return {k: canonical(v) for k, v in value.items()}
        if isinstance(value, list):
            return sorted((canonical(v) for v in value), key=lambda v: json.dumps(v, sort_keys=True, default=str))
        return value
    return json.dumps(canonical(policy), sort_keys=True, separators=(",", ":"), default=str)


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
        "principals": policy.get("principals") or {"user_groups": [], "workload_roles": []},
        # ENG2-11: a present-but-null "rules"/"privileges"/"conditions"
        # (a relationship-only policy) used to raise TypeError -> 500.
        "rules": [
            {
                "name": rule.get("name"),
                "resource_type": rule.get("resource_type"),
                "resource_type_label": RESOURCE_TYPE_LABELS.get(rule.get("resource_type"), rule.get("resource_type")),
                "privileges": [
                    {"privilege_type": p.get("privilege_type"), "flags": _privilege_flags(p.get("privilege_value"))}
                    for p in rule.get("privileges") or [] if isinstance(p, dict)
                ],
                "conditions": rule.get("conditions") or [],
                "targets": _summarize_rule_targets(rule),
            }
            for rule in policy.get("rules") or [] if isinstance(rule, dict)
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
# against BOTH a real tenant (saas_app_account_assignments) and dev
# (secret_or_folder_assignments) that this "this is a new feature, we'll
# see more of this" -- new kinds are expected to keep appearing. An
# unrecognized future key still resolves generically (see
# _resolve_relationship_assignment_resources below) rather than being
# silently dropped.
_RELATIONSHIP_ASSIGNMENT_ID_NAME_FIELDS = {
    # Confirmed live 2026-09-30 (a real tenant) -- privileged_resource_id is the
    # SaaS account's real System Log-tracking id (same field this
    # codebase already relies on elsewhere for SaaS accounts -- see
    # RESOURCE_ACCESS_EVENT_TYPES' access_tracking_id precedent).
    "saas_app_account_assignments": ("privileged_resource_id", "account_name"),
    # Confirmed live 2026-09-30 (dev) -- a secret OR secret_folder grant,
    # distinguished by the item's own "type" field, not this dict key.
    "secret_or_folder_assignments": ("id", "name"),
}


def _resolve_relationship_assignment_resources(resource_assignments, relationship_name=None, assignment_name=None,
                                                principal=None):
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
    if not isinstance(resource_assignments, dict) or not resource_assignments:
        return []
    out = []
    for key, items in resource_assignments.items():
        id_field, name_field = _RELATIONSHIP_ASSIGNMENT_ID_NAME_FIELDS.get(key, ("id", "name"))
        # secret_or_folder_assignments distinguishes secret vs. secret_folder
        # via the item's own "type" field (confirmed live) -- fall back to
        # the dict key itself for any kind with no such field.
        for item in items if isinstance(items, list) else []:
            if not isinstance(item, dict):
                continue
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
            if principal:
                # ENG2-10 (additive, 5.40.6): the principal of the assignment
                # that granted THIS resource, so a view can pair them instead
                # of reading the policy's merged principal list as a
                # cross-product. Whether OPA grants per assignment or across
                # the shared relationship is still to be confirmed live.
                resolved["principal_id"] = principal.get("id")
                resolved["principal_name"] = principal.get("name")
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
    Supported entries also carry "complete" (False when the System Log
    walk hit its page cap, ENG2-09).
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
        filter_expr = f'actor.id eq "{validate_resource_id(actor_user_id, "actor id")}" and ({type_filter})'
        # ENG2-09 (external review, 2026-10-05): nothing is persisted here,
        # but the reader still needs to know when the walk hit the page cap
        # -- the newest events are kept (DESCENDING), so a resource whose
        # only events are past the cap shows "no access" when it wasn't.
        events, complete = okta_client.get_system_log(filter_expr=filter_expr, since=since, limit=1000)

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
            results[rid] = {"resource_kind": resource_kind, "supported": True, "events": buckets[rid],
                            "complete": bool(complete)}

    return results


def _access_report_target(event, target_type):
    """The event's own target[] entry of the given type ('Secret' or
    'Secret Folder') -- carries that resource's id + displayName. Returns
    None if this event doesn't target that type (shouldn't happen for
    events already bucketed under the matching resource_kind, but guards
    against an unexpected payload shape rather than raising)."""
    return next((t for t in (event.get("target") or []) if t.get("type") == target_type), None)


SYNC_SCHEDULE_DEFAULTS = {
    "enabled": False,
    "run_time": "02:00",  # 24h HH:MM in UTC (the scheduler and the UI both treat it as UTC)
    "ingestion_scope": "curated",  # "curated" or "all" -- see audit_store.py
    "retention_days": None,  # None = no time-based prune
    "retention_max_size_mb": None,  # None = no size-based prune
}


def get_sync_schedule(name, owner=LOCAL_OWNER_KEY):
    """Returns the environment's sync_schedule dict, filled in with
    SYNC_SCHEDULE_DEFAULTS for any field never explicitly set (so callers
    never have to guess at partial/legacy shapes). Raises KeyError if
    `name` isn't a saved environment owned by `owner`."""
    import audit_store
    conn = audit_store._get_connection()
    _, meta = _find_own_environment_sql(conn, owner, name)
    if meta is None:
        raise KeyError(f"No saved environment named '{name}'")
    return _merged_sync_schedule(meta)


def get_sync_schedule_by_id(environment_id):
    """get_sync_schedule addressed by the real environment_id (5.42.0).
    Display names are only unique per owner -- and not even that for
    owner-less rows (UNIQUE(owner_id, display_name) never matches NULLs) --
    so the scheduler, a sync worker and a shared user's "Sync now" read the
    schedule of exactly the environment they act on. No visibility rule:
    callers resolve visibility first. Raises KeyError if the id is unknown."""
    import audit_store
    conn = audit_store._get_connection()
    row = conn.execute("SELECT * FROM app_environments WHERE environment_id = ?", (environment_id,)).fetchone()
    if row is None:
        raise KeyError(f"No saved environment with id '{environment_id}'")
    return _merged_sync_schedule(_row_to_environment_meta(row))


def _merged_sync_schedule(meta):
    stored = meta.get("sync_schedule") or {}
    merged = {**SYNC_SCHEDULE_DEFAULTS, **stored}
    # ENG2-04: a retention value saved before validation existed (0, a
    # negative number, a string) used to reach prune_events, where 0
    # means "cutoff = now" -- every non-curated event deleted on each
    # sync. Read tolerantly as "no limit" and say so; the write path
    # rejects such values outright now.
    for field in ("retention_days", "retention_max_size_mb"):
        value = merged.get(field)
        if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float)) or value < 1):
            log("WARN", f"sync schedule for '{meta.get('name')}' has an invalid stored {field}={value!r}; treating it as no limit")
            merged[field] = None
    return merged


_RUN_TIME_PATTERN = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


def validate_sync_schedule_config(config):
    """ENG2-04 / UI-09 (external review, 2026-10-05): only
    `ingestion_scope` used to be checked. A `run_time` like "25:00" made
    an enabled schedule never fire with nothing reporting it; a
    `retention_days` of 0 or a negative number made the next sync's prune
    delete EVERY non-curated event (a cutoff at or after "now"), which
    Okta's 90-day retention makes unrecoverable; `enabled: "false"`
    truthed to True; and arbitrary request keys rode through `**config`
    into the audit event. Returns a dict holding ONLY the known keys that
    were supplied, each validated; raises ValueError (-> HTTP 400) with a
    message naming the field. Validation is on write only -- stored rows
    with odd values are still read tolerantly by the scheduler."""
    if not isinstance(config, dict):
        raise ValueError("sync schedule must be a JSON object")
    unknown = set(config) - set(SYNC_SCHEDULE_DEFAULTS)
    if unknown:
        raise ValueError(f"unknown sync schedule field(s): {', '.join(sorted(unknown))}")
    clean = {}
    if "enabled" in config:
        if not isinstance(config["enabled"], bool):
            raise ValueError("enabled must be true or false")
        clean["enabled"] = config["enabled"]
    if "run_time" in config:
        run_time = config["run_time"]
        if not isinstance(run_time, str) or not _RUN_TIME_PATTERN.match(run_time):
            raise ValueError('run_time must be "HH:MM" (24-hour, UTC)')
        clean["run_time"] = run_time
    if "ingestion_scope" in config:
        if config["ingestion_scope"] not in ("curated", "all"):
            raise ValueError('ingestion_scope must be "curated" or "all"')
        clean["ingestion_scope"] = config["ingestion_scope"]
    for field in ("retention_days", "retention_max_size_mb"):
        if field in config:
            value = config[field]
            # bool is an int subclass -- True would silently mean "1 day".
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 1):
                raise ValueError(f"{field} must be a whole number of at least 1, or null for no limit")
            clean[field] = value
    return clean


def set_sync_schedule(name, config, owner=LOCAL_OWNER_KEY):
    """Saves the environment's daily-sync configuration (enabled, run
    time, ingestion scope, retention). Own dedicated setter, deliberately
    NOT folded into upsert_environment's metadata-field loop -- this is a
    settings object, not part of the credential form. Raises KeyError if `name`
    isn't a saved environment owned by `owner`, ValueError if
    ingestion_scope isn't a real choice."""
    config = validate_sync_schedule_config(config)
    import audit_store
    conn = audit_store._get_connection()
    target_id, meta = _find_own_environment_sql(conn, owner, name)
    if meta is None:
        raise KeyError(f"No saved environment named '{name}'")
    return _write_sync_schedule(conn, target_id, meta, config)


def set_sync_schedule_by_id(environment_id, config):
    """set_sync_schedule addressed by the real environment_id (5.42.0) --
    used once the caller has resolved visibility and the shared-environment
    permission (see shared_capability_allowed). Raises KeyError if the id is
    unknown, ValueError for an invalid config."""
    config = validate_sync_schedule_config(config)
    import audit_store
    conn = audit_store._get_connection()
    row = conn.execute("SELECT * FROM app_environments WHERE environment_id = ?", (environment_id,)).fetchone()
    if row is None:
        raise KeyError(f"No saved environment with id '{environment_id}'")
    return _write_sync_schedule(conn, environment_id, _row_to_environment_meta(row), config)


def _write_sync_schedule(conn, target_id, meta, config):
    import audit_store
    merged = {**SYNC_SCHEDULE_DEFAULTS, **(meta.get("sync_schedule") or {}), **config}
    with audit_store._db_lock:
        conn.execute(
            """INSERT INTO sync_schedules
               (environment_id, enabled, run_time, ingestion_scope, retention_days, retention_max_size_mb)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(environment_id) DO UPDATE SET
                   enabled=excluded.enabled, run_time=excluded.run_time,
                   ingestion_scope=excluded.ingestion_scope, retention_days=excluded.retention_days,
                   retention_max_size_mb=excluded.retention_max_size_mb""",
            (target_id, int(bool(merged["enabled"])), merged["run_time"], merged["ingestion_scope"],
             merged["retention_days"], merged["retention_max_size_mb"]),
        )
        conn.commit()
    return merged


# ---------------------------------------------------------------------------
# Shared-environment permissions (5.42.0)
# ---------------------------------------------------------------------------
# What a user may do with an environment ANOTHER user owns and has shared.
# Sharing itself stays the owner's decision (set_environment_shared); what a
# shared user may then do with it is an admin's. An owner is never limited
# by any of this. Each capability resolves per environment: an override for
# that environment (allow/deny), else the global default (allow/deny), else
# the built-in default below. The built-in defaults are exactly what a
# shared user could do before 5.42.0, so an upgrade changes nothing until an
# admin changes a setting. "inherit" is never stored: it is the absence of a
# row (migration 008's two tables).
SHARED_CAPABILITIES = (
    {"key": "view_archive", "label": "View archived reports", "builtin": "allow",
     "description": "Compliance reports, resource history, sync status and the basic evidence-chain check, read from this app's archive."},
    {"key": "live_read", "label": "Live read queries", "builtin": "allow",
     "description": "Reads from the owner's OPA team and Okta org with the owner's credentials: Access Explorer, Folder Builder lists and preview, the Secrets and Service Accounts dashboards."},
    {"key": "tenant_write", "label": "Write to the OPA tenant / Okta org", "builtin": "allow",
     "description": "Creates and changes things with the owner's credentials: resource groups, projects, folders, security policies, group membership, and new Okta groups with Group Push."},
    {"key": "import_csv", "label": "Import a CSV into the archive", "builtin": "allow",
     "description": "Adds System Log events from a CSV file in the project folder to this environment's compliance archive."},
    {"key": "reset_watermark", "label": "Reset the sync watermark", "builtin": "allow",
     "description": "Makes the next sync backfill the full 90-day window."},
    {"key": "sync_now", "label": "Run Sync now", "builtin": "deny",
     "description": "Starts a compliance sync with the owner's Okta API token and the owner's saved sync settings."},
    {"key": "sync_settings", "label": "Change sync settings", "builtin": "deny",
     "description": "Turns the daily sync on or off and changes its time and ingestion scope. Retention stays the owner's (it deletes archived events)."},
)
SHARED_CAPABILITY_KEYS = tuple(c["key"] for c in SHARED_CAPABILITIES)
SHARED_PERMISSION_VALUES = ("allow", "deny")


def _validate_shared_capability(capability):
    if capability not in SHARED_CAPABILITY_KEYS:
        raise ValueError(f"unknown shared-environment capability {capability!r}")


def get_shared_permission_defaults():
    """{capability: {"value": allow|deny, "source": "default"|"built_in",
    "updated_at", "updated_by"}} -- the effective global default for every
    capability and where it comes from."""
    import audit_store
    conn = audit_store._get_connection()
    stored = {row["capability"]: row for row in conn.execute("SELECT * FROM shared_permission_defaults")}
    out = {}
    for cap in SHARED_CAPABILITIES:
        row = stored.get(cap["key"])
        if row is not None and row["value"] in SHARED_PERMISSION_VALUES:
            out[cap["key"]] = {"value": row["value"], "source": "default",
                               "updated_at": row["updated_at"], "updated_by": row["updated_by"]}
        else:
            out[cap["key"]] = {"value": cap["builtin"], "source": "built_in", "updated_at": None, "updated_by": None}
    return out


def get_shared_permission_overrides(environment_id):
    """{capability: allow|deny} -- only the capabilities this environment
    overrides (the rest inherit)."""
    import audit_store
    conn = audit_store._get_connection()
    return {
        row["capability"]: row["value"]
        for row in conn.execute(
            "SELECT capability, value FROM shared_permission_overrides WHERE environment_id = ?", (environment_id,)
        )
        if row["capability"] in SHARED_CAPABILITY_KEYS and row["value"] in SHARED_PERMISSION_VALUES
    }


def effective_shared_permissions(environment_id, defaults=None):
    """{capability: {"value": allow|deny, "source": "override"|"default"|"built_in"}}
    for a shared (non-owner) user of this environment. `defaults` lets a
    caller listing many environments read the global defaults once."""
    defaults = defaults if defaults is not None else get_shared_permission_defaults()
    overrides = get_shared_permission_overrides(environment_id)
    out = {}
    for key in SHARED_CAPABILITY_KEYS:
        if key in overrides:
            out[key] = {"value": overrides[key], "source": "override"}
        else:
            out[key] = {"value": defaults[key]["value"], "source": defaults[key]["source"]}
    return out


def environment_owner(environment_id):
    """(exists, owner_id) for one environment id."""
    import audit_store
    conn = audit_store._get_connection()
    row = conn.execute("SELECT owner_id FROM app_environments WHERE environment_id = ?", (environment_id,)).fetchone()
    return (False, None) if row is None else (True, row["owner_id"])


def shared_capability_allowed(environment_id, caller_owner, capability):
    """THE shared-environment permission check (5.42.0). True when
    `caller_owner` (engine-layer owner: an Okta sub, or LOCAL_OWNER_KEY)
    owns the environment -- owners are never limited -- or when the
    capability resolves to "allow" for it (override, else global default,
    else built-in). An unknown environment id is False (callers resolve
    visibility before asking; this never grants anything on a row that
    isn't there). An unknown capability is a programming error (ValueError)."""
    _validate_shared_capability(capability)
    exists, owner = environment_owner(environment_id)
    if not exists:
        return False
    if owner == caller_owner:
        return True
    return effective_shared_permissions(environment_id)[capability]["value"] == "allow"


def validate_shared_permission_changes(changes, allow_inherit=True):
    """`changes` = {capability: "allow"|"deny"|"inherit"}; returns it
    validated (ValueError names the problem). Empty is refused."""
    if not isinstance(changes, dict) or not changes:
        raise ValueError("changes must be a non-empty object of capability -> allow / deny / inherit")
    allowed = SHARED_PERMISSION_VALUES + (("inherit",) if allow_inherit else ())
    clean = {}
    for capability, value in changes.items():
        _validate_shared_capability(capability)
        if value not in allowed:
            raise ValueError(f"{capability} must be one of {', '.join(allowed)}")
        clean[capability] = value
    return clean


def set_shared_permissions(changes, environment_id=None, updated_by=None):
    """Applies `changes` ({capability: allow|deny|inherit}) to the global
    defaults (environment_id None) or to one environment's overrides, in
    one transaction. "inherit" deletes the row. Returns
    [{"capability", "before", "after"}] for every capability whose stored
    value actually changed (before/after are "allow"/"deny"/"inherit" --
    the STORED setting, not the effective one), for the audit entry.
    Raises KeyError for an unknown environment, ValueError for bad input."""
    changes = validate_shared_permission_changes(changes)
    import audit_store
    conn = audit_store._get_connection()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    diff = []
    with audit_store._db_lock:
        if not conn.in_transaction:
            conn.execute("BEGIN IMMEDIATE")
        try:
            if environment_id is not None:
                if conn.execute("SELECT 1 FROM app_environments WHERE environment_id = ?", (environment_id,)).fetchone() is None:
                    raise KeyError(f"No saved environment with id '{environment_id}'")
                rows = conn.execute(
                    "SELECT capability, value FROM shared_permission_overrides WHERE environment_id = ?", (environment_id,)
                ).fetchall()
            else:
                rows = conn.execute("SELECT capability, value FROM shared_permission_defaults").fetchall()
            current = {r["capability"]: r["value"] for r in rows}
            for capability, value in changes.items():
                before = current.get(capability, "inherit")
                if before == value:
                    continue
                if environment_id is not None:
                    if value == "inherit":
                        conn.execute("DELETE FROM shared_permission_overrides WHERE environment_id = ? AND capability = ?",
                                     (environment_id, capability))
                    else:
                        conn.execute(
                            """INSERT INTO shared_permission_overrides (environment_id, capability, value, updated_at, updated_by)
                               VALUES (?, ?, ?, ?, ?)
                               ON CONFLICT(environment_id, capability) DO UPDATE SET
                                   value=excluded.value, updated_at=excluded.updated_at, updated_by=excluded.updated_by""",
                            (environment_id, capability, value, now, updated_by),
                        )
                else:
                    if value == "inherit":
                        conn.execute("DELETE FROM shared_permission_defaults WHERE capability = ?", (capability,))
                    else:
                        conn.execute(
                            """INSERT INTO shared_permission_defaults (capability, value, updated_at, updated_by)
                               VALUES (?, ?, ?, ?)
                               ON CONFLICT(capability) DO UPDATE SET
                                   value=excluded.value, updated_at=excluded.updated_at, updated_by=excluded.updated_by""",
                            (capability, value, now, updated_by),
                        )
                diff.append({"capability": capability, "before": before, "after": value})
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
    return diff


def build_secrets_access_report(client, okta_client, resource_group_id, project_id, since_days=90, reveal_limit=5):
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
    "local_retention_enabled": False, "oldest_captured_at": ...,
    "complete": bool} -- complete is False when the System Log walk was
    cut short by its page cap (ENG2-09).
    Each row: {id, name, path, status, created, updated, deleted}
    (created/deleted are _audit_entry dicts -- {"by", "at", "request_id",
    "outcome", "outcome_reason"} -- or None; updated is a list of them,
    most-recent-first). Secret rows additionally carry reveals: the same
    entries, most-recent-first, capped at reveal_limit. Since v5.40.0 a
    delete only counts with a SUCCESS outcome and `created` prefers the
    successful attempt (see _record_create / _record_delete) -- the same
    rules the Service Accounts report uses, so a FAILED delete can no
    longer mark a live secret "deleted".

    `local_retention_enabled` is always False here -- Phase 5 (2026-10-01)
    retired this function's own local caching (secrets_log_cache.json);
    this is now a pure live-Okta-query function, bounded strictly to
    `since_days`. Only called for an environment that hasn't synced yet
    (see server/serve.py's route) -- once ANY sync completes,
    build_project_secrets_report_from_archive takes over permanently and
    this function is never called again for that environment; its archive
    already captures a strict superset of what this cache ever did, with
    no retention limit at all. `local_retention_enabled`/
    `oldest_captured_at` are kept in the response shape (not removed) --
    the frontend's own caveat text ("based on the last N days..." vs.
    "supplemented with locally-preserved history...") depends on both
    fields regardless of which function produced them."""
    folders, secrets = fetch_all_folders_and_secrets(client, resource_group_id, project_id)
    folders_by_id = {f["id"]: f for f in folders if f.get("id")}
    secrets_by_id = {s["id"]: s for s in secrets if s.get("id")}

    type_filter = " or ".join(
        f'eventType eq "{t}"' for types in SECRETS_ACCESS_REPORT_EVENT_TYPES.values() for t in types
    )
    since = (datetime.now(timezone.utc) - timedelta(days=since_days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    filter_expr = f'target.id eq "{validate_resource_id(project_id, "project_id")}" and ({type_filter})'
    # ENG2-09 (external review, 2026-10-05): `complete` is False when the
    # walk hit get_system_log's page cap. DESCENDING order means it is the
    # OLDEST events (the creates) that are missing, so the report says so
    # instead of presenting a truncated result as the whole window.
    events, complete = okta_client.get_system_log(filter_expr=filter_expr, since=since, limit=1000)
    oldest_captured_at = min((e.get("published") for e in events if e.get("published")), default=None)
    buckets = _bucket_secret_events(events, reveal_limit=reveal_limit)  # already DESCENDING
    return {
        "secrets": _secret_report_rows("secret", secrets_by_id, buckets, folders_by_id),
        "folders": _secret_report_rows("secret_folder", folders_by_id, buckets, folders_by_id),
        "since_days": since_days,
        "local_retention_enabled": False,
        "oldest_captured_at": oldest_captured_at,
        "complete": bool(complete),
    }


def _bucket_secret_events(events, reveal_limit=None):
    """Shared by both secrets reports (live and archive -- ENG2-14: the two
    hand-copied loops had already diverged). `events` must be newest
    first. Returns {"secret": {id: bucket}, "secret_folder": {id: bucket}};
    a bucket is {"name", "path", "created", "updated", "deleted",
    "reveals"}, entries shaped by _audit_entry, the create/delete rules
    shared with the Service Accounts report (_record_create /
    _record_delete: a delete only counts with a SUCCESS outcome, a create
    prefers the successful attempt). Path comes from the log's own
    "Secret Path" target (leading "/" stripped, matching the live walk's
    convention), since a deleted resource's path can't be reconstructed
    any other way. reveal_limit caps reveals per secret (None = no cap)."""
    buckets = {"secret": {}, "secret_folder": {}}
    target_type_for_kind = {"secret": "Secret", "secret_folder": "Secret Folder"}
    event_type_to_kind = {
        t: kind for kind, types in SECRETS_ACCESS_REPORT_EVENT_TYPES.items() for t in types
    }
    for event in events:
        if not isinstance(event, dict):
            continue
        event_type = event.get("eventType")
        kind = event_type_to_kind.get(event_type)
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
        path_target = next(
            (t for t in (event.get("target") or []) if isinstance(t, dict) and t.get("type") == "Secret Path"), None
        )
        if path_target and not bucket["path"]:
            bucket["path"] = (path_target.get("displayName") or "").lstrip("/")

        entry = _audit_entry(event)
        if event_type.endswith(".create"):
            _record_create(bucket, entry)
        elif event_type.endswith(".update"):
            bucket["updated"].append(entry)
        elif event_type.endswith(".delete"):
            _record_delete(bucket, entry)
        elif event_type.endswith(".reveal"):
            if reveal_limit is None or len(bucket["reveals"]) < reveal_limit:
                bucket["reveals"].append(entry)
    return buckets


def _secret_report_rows(kind, live_by_id, buckets, folders_by_id):
    """One report row per resource of `kind`: every resource in the live
    walk ("active", even with no log history -- it may predate the
    window), then every resource seen only in the log -- "deleted" only
    with a real delete event in its bucket, otherwise "unknown", never
    assumed. A secret's parent_id always points at a folder, so paths are
    rebuilt from folders_by_id for both kinds."""
    rows = []
    seen_ids = set()
    for rid, resource in live_by_id.items():
        seen_ids.add(rid)
        b = buckets[kind].get(rid, {})
        rows.append({
            "id": rid,
            "name": resource.get("name") or "",
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
        rows.append({
            "id": rid,
            "name": b.get("name", ""),
            "path": b.get("path", ""),
            "status": "deleted" if b.get("deleted") else "unknown",
            "created": b.get("created"),
            "updated": b.get("updated", []),
            "deleted": b.get("deleted"),
            **({"reveals": b.get("reveals", [])} if kind == "secret" else {}),
        })
    return rows


def build_project_secrets_report_from_archive(client, environment_id, resource_group_id, project_id):
    """Phase 5 of the compliance-reporting-dashboard plan: the same report
    as build_secrets_access_report above, but sourced from the unified
    audit_store.py SQLite archive instead of a live Okta System Log call.
    Requires `audit_store` to have
    already been populated for `environment` (via a sync or CSV import) --
    this function does not itself call Okta at all, so it works even with
    no Okta API token configured, unlike the original.

    Uses the SAME bucketing and row/status logic as
    build_secrets_access_report -- since 5.40.6 literally the same code
    (_bucket_secret_events / _secret_report_rows; the two hand-copied
    loops had already diverged, ENG2-14), pinned by a golden test that
    feeds both paths the same events. Only the EVENT SOURCE differs:
    audit_store.iter_events_targeting (all history ever ingested for this
    project, no 90-day window and no row cap) instead of one bounded
    okta_client.get_system_log call; and reveals are not capped here.

    Returns the exact same shape as build_secrets_access_report, with
    `local_retention_enabled` always True (the whole point of sourcing
    from the archive) and `oldest_captured_at` reflecting the archive's
    real earliest event for this project, not a live-query artifact."""
    import audit_store

    folders, secrets = fetch_all_folders_and_secrets(client, resource_group_id, project_id)
    folders_by_id = {f["id"]: f for f in folders if f.get("id")}
    secrets_by_id = {s["id"]: s for s in secrets if s.get("id")}

    all_event_types = [t for types in SECRETS_ACCESS_REPORT_EVENT_TYPES.values() for t in types]
    # ENG2-03 (external review, 2026-10-05): filtered to this project IN
    # SQL (audit_store.iter_events_targeting, via the indexed event_targets
    # table) and streamed, with no row cap -- the old environment-wide
    # query_events(limit=100000) applied its cap BEFORE the project filter,
    # silently dropping the oldest events (the creates) once the
    # environment held more than 100k of these events. The Project-type
    # check is the same one as before (a project-scoped event's target[]
    # always includes the project itself, confirmed live), so exactly the
    # same events qualify.
    events = (
        r["raw"] for r in audit_store.iter_events_targeting(environment_id, project_id, all_event_types)
        if any(isinstance(t, dict) and t.get("type") == "Project" and t.get("id") == project_id
               for t in (r["raw"].get("target") or []))
    )
    oldest = {"at": None}

    def _track_oldest(stream):
        for event in stream:
            published = event.get("published")
            if published and (oldest["at"] is None or published < oldest["at"]):
                oldest["at"] = published
            yield event

    # Newest first (the query's ORDER BY). Reveals are not capped here --
    # the archive shows every reveal it holds (a cap is an open decision).
    buckets = _bucket_secret_events(_track_oldest(events), reveal_limit=None)
    return {
        "secrets": _secret_report_rows("secret", secrets_by_id, buckets, folders_by_id),
        "folders": _secret_report_rows("secret_folder", folders_by_id, buckets, folders_by_id),
        "since_days": None,  # archive has no fixed window -- whole history ever ingested
        "local_retention_enabled": True,
        "oldest_captured_at": oldest["at"],
        "complete": True,  # nothing is capped; the archive holds what was ingested
    }


def walk_service_account_rosters(client):
    """Every SaaS app account ("saas") and Okta Universal Directory account
    ("okta") across every resource group and project the client can see,
    as a list of (kind, account, project_ref) tuples, plus a count of what
    was walked. These are the same two per-project list calls
    build_access_model's index_resources step makes (and the same
    project_ref shape ResourcesTab renders), pulled out so the
    service-accounts report can refresh rosters without the rest of that
    much heavier bootstrap. build_access_model keeps its own loop because
    it walks folders/servers/AD/DB accounts in the same pass.

    Tenant-wide on purpose: service-account events carry no project
    co-target (confirmed, see SERVICE_ACCOUNT_REPORT_EVENT_TYPES), so a
    per-project walk could never say which project a since-deleted
    account belonged to -- "deleted" is only honest against the whole
    tenant's live roster. Cost is 1 + R + 2P calls; the caller surfaces
    the walked counts so a large tenant can see what it paid for."""
    accounts = []
    walked = {"resource_groups": 0, "projects": 0}
    for rg in client.list_resource_groups():
        walked["resource_groups"] += 1
        for project in client.list_projects(rg["id"]):
            walked["projects"] += 1
            ref = {
                "project_id": project.get("id"),
                "project_name": project.get("name"),
                "resource_group_id": rg.get("id"),
                "resource_group_name": rg.get("name"),
            }
            for acct in client.list_project_saas_app_accounts(rg["id"], project["id"]):
                accounts.append(("saas", acct, ref))
            for acct in client.list_project_okta_ud_accounts(rg["id"], project["id"]):
                accounts.append(("okta", acct, ref))
    return accounts, walked


def _audit_entry(event):
    """One history entry for the per-resource reports (Secrets Access and
    Service Accounts): who, when, Okta request id, and the event's own
    outcome. Outcome is not decoration: a real service-account create can
    end DEFERRED or FAILURE and be retried (seen live), a rotation ends
    SUCCESS / FAILURE / DEFERRED, and a secret delete can fail too -- an
    entry without its outcome reads as "it happened" when it may not
    have. displayName over alternateId for the actor: for a human the two
    usually agree (full name vs. email), but a service-account actor has
    an opaque "users/<uuid>" alternateId with the only human-readable
    value in displayName -- confirmed live against real delete events."""
    actor = event.get("actor") or {}
    outcome = event.get("outcome") or {}
    return {
        "by": actor.get("displayName") or actor.get("alternateId"),
        "at": event.get("published"),
        "request_id": _extract_request_id(event),
        "outcome": outcome.get("result"),
        "outcome_reason": outcome.get("reason"),
    }


def _entry_succeeded(entry):
    """True unless the entry's event explicitly reported a non-SUCCESS
    outcome. A missing outcome counts as success on purpose: every real
    Okta System Log event carries outcome.result, so "absent" only
    happens for a hand-built or reconstructed payload, and treating that
    as a failure would hide real history. An explicit DEFERRED / FAILURE
    is never treated as "it happened" -- a failed delete must not mark a
    resource deleted, and a deferred create is not when it was created."""
    return entry.get("outcome") in (None, "SUCCESS")


def _record_create(bucket, entry):
    """Events are newest-first. Keeps the newest SUCCESSFUL create; until
    one is seen, keeps the newest attempt (with its outcome) so the row
    still says what happened rather than nothing."""
    if bucket["created"] is None or (_entry_succeeded(entry) and not _entry_succeeded(bucket["created"])):
        bucket["created"] = entry


def _record_delete(bucket, entry):
    """Only a successful delete is evidence of deletion -- this is what
    the active/deleted/unknown status is computed from, so a FAILURE
    here would mark a live resource deleted."""
    if bucket["deleted"] is None and _entry_succeeded(entry):
        bucket["deleted"] = entry


def _service_account_event_kind(event):
    """'saas' / 'okta' / 'other' / None for one raw event, from the
    live-confirmed debugData field for its eventType (serviceAccountType
    for pam.service_account.*, resourceType for pam.resource.checkout --
    see the two *_TO_KIND tables). None means the event carries no
    recognised family marker at all (seen live: an update event with an
    empty serviceAccountType), NOT "not a service account" -- the caller
    resolves those from the account's other evidence."""
    debug_data = (event.get("debugContext") or {}).get("debugData") or {}
    if event.get("eventType") == "pam.resource.checkout":
        return CHECKOUT_RESOURCE_TYPE_TO_KIND.get(debug_data.get("resourceType"))
    return SERVICE_ACCOUNT_TYPE_TO_KIND.get(debug_data.get("serviceAccountType"))


def _empty_rotation_summary():
    return {"total": 0, "by_outcome": {}, "first_at": None, "last_at": None, "recent": []}


def build_service_accounts_report_from_archive(client, environment_id, rotation_limit=SERVICE_ACCOUNT_ROTATION_LIMIT_DEFAULT):
    """The SaaS / Okta service-account counterpart of
    build_project_secrets_report_from_archive: every SaaS app account and
    Okta Universal Directory account in the tenant -- including ones since
    deleted -- with who created / updated / assigned / deleted it, who
    revealed its password or checked it out, and its rotation history,
    sourced from the audit_store archive (never a live System Log call).

    Two sources merged, same as the Secrets report:
      1. The live roster walk (walk_service_account_rosters) -- "what
         exists right now", keyed by the account's own OPA-internal id.
      2. The archive -- "what happened", keyed by the SAME id (confirmed,
         see SERVICE_ACCOUNT_REPORT_EVENT_TYPES), including accounts that
         no longer exist and so aren't in source 1 at all.

    Status honesty rules are the Secrets report's, verbatim in spirit:
    present in the live walk => "active" (even with zero history);
    absent live => "deleted" ONLY when a SUCCESS delete event exists,
    otherwise "unknown". Never inferred.

    Two things the Secrets builder never had to do:
      * Classify before bucketing. Database and AD accounts share the
        same target type AND the same reveal/rotation eventTypes, so
        every event votes for a family via its live-confirmed debugData
        marker; the roster is authoritative when it knows the id, a
        saas/okta vote wins over an "other" vote, and an id with no vote
        at all is excluded and COUNTED (response["excluded"]) rather than
        guessed. A pam.resource.checkout with an unrecognised
        resourceType can attach to an account the report already knows
        but never creates one -- the Okta UD checkout marker is not yet
        live-confirmed (see CHECKOUT_RESOURCE_TYPE_TO_KIND).
      * Scale rotations differently. password_rotation.end is by far the
        highest-volume PAM event in a real archive (115k rows, 83k of them
        AD), so it is never bulk-loaded as raw JSON: totals come from one
        GROUP BY over the indexed resource_id column
        (audit_store.count_events_by_resource), only the newest
        `rotation_limit` rows per account are fetched as entries, and an
        account that only ever appears in rotation events (its lifecycle
        predates the archive) is still discovered -- one raw row is read
        to classify it.

    Returns {"accounts": [row...], "summary": {...}, "walked": {...},
    "excluded": {...}, "since_days": None, "local_retention_enabled":
    True, "oldest_captured_at": ...}. Each row: id, kind ("saas"|"okta"),
    name, username, app_name, okta_user_id, privileged_resource_id,
    resource_group_id/_name, project_id/_name (all None for an account no
    longer in the live walk -- its project is not knowable, see
    walk_service_account_rosters), status, sync_status and
    last_password_change_at (live-only, INFORMATIONAL: a freshly
    registered SaaS account can legitimately sit NOT_SYNCED, see
    docs/api-notes.md), created, updated[], assigned[], deleted,
    reveals[], checkouts[] (most-recent-first; checkouts carry expires_at)
    and rotations {total, by_outcome, first_at, last_at, recent[]}.
    `created` prefers the most recent SUCCESS create over a DEFERRED/
    FAILURE attempt (the attempt is kept, with its outcome, when no
    success exists); `deleted` is only ever a SUCCESS delete."""
    import audit_store

    if not isinstance(rotation_limit, int) or not (1 <= rotation_limit <= SERVICE_ACCOUNT_ROTATION_LIMIT_MAX):
        raise ValueError(
            f"rotation_limit must be an integer between 1 and {SERVICE_ACCOUNT_ROTATION_LIMIT_MAX}, got {rotation_limit!r}"
        )

    roster, walked = walk_service_account_rosters(client)
    live = {}  # account id -> (kind, account, project_ref), walk order preserved
    for kind, acct, ref in roster:
        aid = acct.get("id")
        if aid and aid not in live:
            live[aid] = (kind, acct, ref)

    # --- Source 2a: the low-volume families, bulk-loaded like the Secrets
    # builder does (a real archive had ~110 rows across these). ---
    low_volume_types = [
        t for key in ("lifecycle", "reveal", "checkout") for t in SERVICE_ACCOUNT_REPORT_EVENT_TYPES[key]
    ]
    rotation_types = SERVICE_ACCOUNT_REPORT_EVENT_TYPES["rotation"]
    archived = audit_store.query_events(
        environment_id, event_types=low_volume_types, limit=SERVICE_ACCOUNT_EVENT_LOAD_LIMIT
    )
    # Honest about a cut-off, the same way run_report/resource_history are
    # (UI-03/DATA-07): these families are small on every real archive seen
    # so far (~110 rows), but the cap exists and a report that silently
    # dropped the OLDEST rows would be missing exactly the creates and
    # deletes the status column depends on.
    event_total = audit_store.count_events(environment_id, event_types=low_volume_types)
    truncated = event_total > len(archived)
    events = sorted((r["raw"] for r in archived), key=lambda e: e.get("published") or "", reverse=True)

    # Pass 1: one family vote per event, keyed by the account id. Nothing
    # is bucketed yet -- an id's family is decided from ALL its evidence
    # first (an update with an empty marker must not hide behind an older
    # create that does carry one).
    votes = {}  # id -> set of kinds voted ('saas'/'okta'/'other'); None votes are not recorded
    names_from_events = {}  # id -> newest NON-EMPTY displayName seen (events are newest-first)

    def _note_name(aid, name):
        if name and aid not in names_from_events:
            names_from_events[aid] = name

    def _note_vote(aid, kind):
        if kind is not None:
            votes.setdefault(aid, set()).add(kind)

    seen_event_ids = set()
    for event in events:
        target = _access_report_target(event, "Service Account")
        if target is None or not target.get("id"):
            continue
        aid = target["id"]
        seen_event_ids.add(aid)
        _note_name(aid, target.get("displayName"))
        _note_vote(aid, _service_account_event_kind(event))

    # --- Source 2b: rotation totals for EVERY id that has any, via the
    # indexed columns (never raw JSON) -- also how an account that only
    # ever rotated gets discovered at all. Its family comes from the
    # stored resource_type_detail values (serviceAccountType, written at
    # ingest by audit_store._resource_type_detail_fallback), so even an
    # id whose newest row carries an empty marker is classified from the
    # rows that do. Only an id with NO stored marker on any row (every
    # row predates that fallback) falls back to reading a few raw rows. ---
    rotation_totals = audit_store.count_events_by_resource(environment_id, event_types=rotation_types)
    for aid, totals in rotation_totals.items():
        if aid in live or aid in seen_event_ids:
            continue
        for detail in totals.get("type_details") or {}:
            _note_vote(aid, SERVICE_ACCOUNT_TYPE_TO_KIND.get(detail))
        if aid in votes:
            continue
        for row in audit_store.query_events(
            environment_id, event_types=rotation_types, resource_id=aid, limit=5, match_alternate_id=False
        ):
            raw = row["raw"]
            _note_name(aid, (_access_report_target(raw, "Service Account") or {}).get("displayName"))
            _note_vote(aid, _service_account_event_kind(raw))

    warnings = {"conflicting_family_markers": 0}

    def _decide_kind(aid):
        voted = votes.get(aid, set())
        roster_kind = live[aid][0] if aid in live else None
        conflicting = (voted - {roster_kind}) if roster_kind else (voted if len(voted) > 1 else set())
        if conflicting:
            # Real evidence disagreeing with itself (a roster SaaS id whose
            # events say DATABASE_ACCOUNT, or an event-only id voting both
            # saas and okta) -- surfaced as a count and logged, never
            # silently resolved. The roster stays authoritative.
            warnings["conflicting_family_markers"] += 1
            log("WARN", f"service_accounts_report: conflicting family markers {sorted(voted)} "
                        f"(roster says {roster_kind!r}) for one account id")
        if roster_kind:
            return roster_kind
        for kind in ("saas", "okta"):
            if kind in voted:
                return kind
        if "other" in voted:
            return "other"
        return None

    candidate_ids = set(live) | seen_event_ids | set(rotation_totals)
    excluded = {"other_account_types": 0, "unclassified": 0}
    kind_by_id = {}
    for aid in candidate_ids:
        kind = _decide_kind(aid)
        if kind in ("saas", "okta"):
            kind_by_id[aid] = kind
        elif kind == "other":
            excluded["other_account_types"] += 1
        else:
            excluded["unclassified"] += 1

    # Pass 2: bucket the low-volume events for the ids that made the cut.
    def _new_bucket():
        return {
            "created": None,  # newest SUCCESS create, else newest attempt -- see _record_create
            "updated": [],
            "assigned": [],
            "deleted": None,  # SUCCESS delete only -- see _record_delete
            "reveals": [],
            "checkouts": [],
        }

    buckets = {aid: _new_bucket() for aid in kind_by_id}
    for event in events:  # newest-first
        target = _access_report_target(event, "Service Account")
        if target is None or target.get("id") not in buckets:
            continue
        bucket = buckets[target["id"]]
        entry = _audit_entry(event)
        event_type = event.get("eventType") or ""
        if event_type.endswith(".create"):
            _record_create(bucket, entry)
        elif event_type.endswith(".update"):
            bucket["updated"].append(entry)
        elif event_type.endswith(".assign"):
            bucket["assigned"].append(entry)
        elif event_type.endswith(".delete"):
            _record_delete(bucket, entry)
        elif event_type.endswith(".reveal"):
            bucket["reveals"].append(entry)
        elif event_type == "pam.resource.checkout":
            debug_data = (event.get("debugContext") or {}).get("debugData") or {}
            bucket["checkouts"].append({**entry, "expires_at": debug_data.get("checkoutExpiry")})

    # --- Rotation history: newest `rotation_limit` rows per account that
    # has any, each an index-ordered read on resource_id alone
    # (alternateId == id for every service-account event, confirmed). ---
    rotations_by_id = {}
    for aid in kind_by_id:
        totals = rotation_totals.get(aid)
        if not totals:
            rotations_by_id[aid] = _empty_rotation_summary()
            continue
        recent = []
        for row in audit_store.query_events(
            environment_id, event_types=rotation_types, resource_id=aid, limit=rotation_limit, match_alternate_id=False
        ):
            raw = row["raw"]
            # A rotation-only account classified from stored markers never
            # had a raw row read until now -- its display name comes from
            # the same rows this history needs anyway (newest non-empty).
            _note_name(aid, (_access_report_target(raw, "Service Account") or {}).get("displayName"))
            debug_data = (raw.get("debugContext") or {}).get("debugData") or {}
            initiated = debug_data.get("system Initiated")  # literal key with a space, confirmed live
            recent.append({
                **_audit_entry(raw),
                "system_initiated": None if initiated is None else str(initiated).strip().lower() == "yes",
            })
        rotations_by_id[aid] = {
            "total": totals["total"],
            "by_outcome": totals["by_outcome"],
            "first_at": totals["first_at"],
            "last_at": totals["last_at"],
            "recent": recent,
        }

    def _row(aid):
        kind = kind_by_id[aid]
        b = buckets[aid]
        acct, ref = (live[aid][1], live[aid][2]) if aid in live else ({}, {})
        if aid in live:
            status = "active"
        else:
            status = "deleted" if b["deleted"] else "unknown"
        return {
            "id": aid,
            "kind": kind,
            "name": acct.get("name") or names_from_events.get(aid) or "",
            "username": acct.get("username"),
            "app_name": acct.get("application_instance_name") if kind == "saas" else None,
            "okta_user_id": acct.get("okta_user_id") if kind == "okta" else None,
            "privileged_resource_id": acct.get("privileged_resource_id") if kind == "saas" else None,
            "resource_group_id": ref.get("resource_group_id"),
            "resource_group_name": ref.get("resource_group_name"),
            "project_id": ref.get("project_id"),
            "project_name": ref.get("project_name"),
            "status": status,
            "sync_status": acct.get("sync_status"),
            "last_password_change_at": acct.get("last_password_change_system_timestamp"),
            "created": b["created"],
            "updated": b["updated"],
            "assigned": b["assigned"],
            "deleted": b["deleted"],
            "reveals": b["reveals"],
            "checkouts": b["checkouts"],
            "rotations": rotations_by_id[aid],
        }

    # Live roster first (walk order: resource group, project), then every
    # event-only account sorted by name so the report reads the same way
    # on every refresh.
    live_rows = [_row(aid) for aid in live if aid in kind_by_id]
    event_only_rows = sorted(
        (_row(aid) for aid in kind_by_id if aid not in live),
        key=lambda r: ((r["name"] or "").lower(), r["id"]),
    )
    rows = live_rows + event_only_rows

    oldest_candidates = [e.get("published") for e in events if e.get("published")]
    oldest_candidates += [t["first_at"] for t in rotation_totals.values() if t.get("first_at")]
    summary = {
        "total": len(rows),
        "saas": sum(1 for r in rows if r["kind"] == "saas"),
        "okta": sum(1 for r in rows if r["kind"] == "okta"),
        "active": sum(1 for r in rows if r["status"] == "active"),
        "deleted": sum(1 for r in rows if r["status"] == "deleted"),
        "unknown": sum(1 for r in rows if r["status"] == "unknown"),
    }
    return {
        "accounts": rows,
        "summary": summary,
        "walked": walked,
        "excluded": excluded,
        "warnings": warnings,
        "event_total": event_total,
        "truncated": truncated,
        "since_days": None,  # archive has no fixed window -- whole history ever ingested
        "local_retention_enabled": True,
        "oldest_captured_at": min(oldest_candidates, default=None),
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
    # ENG2-07 (external review, 2026-10-05): one list call the service key
    # isn't allowed to make (401 "Missing capability", 403) or that doesn't
    # exist on this tenant (404) used to abort the whole bootstrap after
    # minutes of work. The tenant inventory lists below and the
    # per-project account lists are optional: on those statuses they come
    # back empty and a warning names the section, returned in the model so
    # the UI says which parts are incomplete. Resource groups, projects,
    # users, groups, folders and policies stay hard failures -- without
    # them the model would be wrong, not just incomplete.
    warnings = []

    def _optional(label, fn, *args):
        try:
            return fn(*args)
        except OpaApiError as exc:
            if exc.status in (401, 403, 404):
                warnings.append({"section": label, "status": exc.status,
                                 "message": f"{label}: not available to this service key (HTTP {exc.status}); shown as empty."})
                log("WARN", f"Access model: {label} unavailable (HTTP {exc.status}); continuing without it.")
                return []
            raise

    _report(on_progress, "workload_roles", "start")
    workload_roles = _optional("workload roles", client.list_workload_roles)
    workload_connections = _optional("workload connections", client.list_workload_connections)
    gateways = _optional("gateways", client.list_gateways)
    database_connections = _optional("database connections", client.list_database_connections)
    saas_app_connections = _optional("SaaS app connections", client.list_saas_app_connections)
    active_directory_connections = _optional("Active Directory connections", client.list_active_directory_connections)
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
    assignment_summaries = _optional("assignments", client.list_assignments)
    assignments = []
    for summary in assignment_summaries:
        if isinstance(summary, dict) and summary.get("id"):
            label = f"assignment {summary.get('name') or summary['id']}"
            detail = _optional(label, lambda assignment_id=summary["id"]: [client.get_assignment(assignment_id)])
            assignments.extend(a for a in detail if isinstance(a, dict))
    # Resolved once here (reusing the SAME helper the policy-splice below
    # uses) so the Relationships tab can show real resource names/kinds
    # for an assignment directly, without re-deriving this resolution
    # itself or waiting on a policy to reference it.
    for assignment in assignments:
        assignment["resolved_resources"] = _resolve_relationship_assignment_resources(
            assignment.get("resource_assignments")
        )
    relationships = _optional("relationships", client.list_relationships)
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
    clients = _optional("enrolled clients", client.list_clients)
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

            for server in _optional(f"servers in project {project.get('name')}", client.list_project_servers, rg["id"], project["id"]):
                if server.get("id"):
                    indexes["servers"][server["id"]] = proj_ref
                all_servers.append({**server, **proj_ref_named})

            for acct in _optional(f"SaaS app accounts in project {project.get('name')}", client.list_project_saas_app_accounts, rg["id"], project["id"]):
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

            for acct in _optional(f"Okta Universal Directory accounts in project {project.get('name')}", client.list_project_okta_ud_accounts, rg["id"], project["id"]):
                key = acct.get("okta_user_id")
                if key:
                    indexes["okta_accounts"][key] = {**proj_ref, "access_tracking_id": acct.get("id")}
                all_okta_accounts.append({**acct, **proj_ref_named})

            # These two are new as of 2026-09-30 -- confirmed live against a
            # real tenant, not previously called anywhere in this
            # codebase. Unlike servers/saas/okta above, no security-policy
            # rule selector resolves to either of these by an OPA-internal
            # id today (AD/DB selectors resolve via name/domain condition
            # text instead -- see _resolve_rule's active_directory/database
            # branches), so there's no matching `indexes[...]` entry to
            # populate here, only the full-object list for the Resources tab.
            for acct in _optional(f"Active Directory accounts in project {project.get('name')}", client.list_project_active_directory_accounts, rg["id"], project["id"]):
                all_active_directory_accounts.append({**acct, **proj_ref_named})

            for acct in _optional(f"database accounts in project {project.get('name')}", client.list_project_database_accounts, rg["id"], project["id"]):
                all_database_accounts.append({**acct, **proj_ref_named})

            indexed_count += 1
            _report(on_progress, "index_resources", "progress",
                    f"{indexed_count}/{total_projects} projects ({project['name']})")
    _report(on_progress, "index_resources", "done", f"{indexed_count} project(s) indexed")

    _report(on_progress, "user_groups", "start")
    users_with_groups = []

    def _user_groups(user):
        try:
            return client.list_user_groups(user.get("name"))
        except OpaApiError as exc:
            log("WARN", f"Could not fetch groups for user '{user.get('name')}': {exc}")
            return []

    # ENG2-08 (external review, 2026-10-05): one call per user, independent
    # of each other and already failure-tolerant -- the one part of the
    # bootstrap that's safe to overlap. USER_GROUP_WORKERS stays at or under
    # RATE_LIMIT_MIN_REMAINING, so the workers together can't overrun the
    # headroom http_json_request keeps before its proactive wait; token
    # refreshes are serialised in OpaClient.request. Results keep the users'
    # order (and each worker runs in a copy of this thread's context, so log
    # lines keep the job's correlation id). The rest of the walk stays
    # sequential.
    user_dicts = [dict(u) for u in users if isinstance(u, dict)]
    with ThreadPoolExecutor(max_workers=USER_GROUP_WORKERS, thread_name_prefix="user-groups") as pool:
        futures = [pool.submit(contextvars.copy_context().run, _user_groups, u) for u in user_dicts]
        for i, (user, future) in enumerate(zip(user_dicts, futures)):
            user["groups"] = future.result() or []
            users_with_groups.append(user)
            _report(on_progress, "user_groups", "progress", f"{i + 1}/{len(user_dicts)} users ({user.get('name')})")
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
        # Every OTHER real policy (confirmed: 15 of 16 on a real tenant, 13 of
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
                if isinstance(rel_ref, dict):
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
                            principal=principal,
                        )
                    )
                # Matches this codebase's existing principals shape
                # (user_groups is a plain list of {id,name,type} refs) --
                # workload_roles stays empty since every real
                # relationship_assignment principal seen live is a
                # user_group, never a workload_role.
                effective_principals = {"user_groups": effective_principals_list, "workload_roles": []}

        rules_out = []
        for rule in policy.get("rules") or []:  # ENG2-11: "rules": null (a relationship-only policy) is not a crash
            if not isinstance(rule, dict):
                continue
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
                    for p in rule.get("privileges") or [] if isinstance(p, dict)
                ],
                "conditions": rule.get("conditions") or [],
                "resolutions": resolutions,
            })
        policies_out.append({
            "id": policy.get("id"),
            "name": policy.get("name"),
            "description": policy.get("description", ""),
            "active": policy.get("active", False),
            "type": policy.get("type"),
            "resource_group": policy.get("resource_group"),
            "principals": effective_principals if effective_principals is not None else (policy.get("principals") or {}),
            "rules": rules_out,
            # Raw policy -> relationship link (already computed above as
            # policy_relationships, just also exposed here) -- lets the
            # Relationships tab answer "which policies use this
            # relationship" without re-deriving the match itself.
            "relationship_ids": [r["id"] for r in policy_relationships if isinstance(r, dict) and r.get("id")],
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
        # ENG2-07: sections that came back empty because the service key
        # may not read them -- the UI shows these instead of implying "none".
        "warnings": warnings,
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
def _folder_path_tuple(folder, by_id):
    """The folder's full path as a tuple of names, from its parent chain
    (a name may in principle contain "/", so this never splits a joined
    string). None if any name on the chain is missing or the chain loops."""
    names = []
    current = folder
    visited = set()
    while current is not None:
        name = current.get(FIELD_NAME)
        if not name:
            return None
        names.append(name)
        parent_id = current.get("parent_id")
        if not parent_id:
            break
        if parent_id in visited:
            return None
        visited.add(parent_id)
        current = by_id.get(parent_id)
        if current is None:
            return None
    return tuple(reversed(names))


def resolve_existing_folders(client, resource_group_id, project_id, ordered_paths):
    """Returns (existing, name_in_use): existing maps a planned path tuple
    to the id of the folder that already exists AT THAT EXACT PATH;
    name_in_use maps a planned path that doesn't exist yet to the path of
    an existing folder elsewhere in the project with the same name
    (compared case-insensitively), for the plan to show.

    ENG2-02 (external review, 2026-10-05): this used to match by leaf name
    only, project-wide. With Dev/DB in the project, a plan for
    Prod/DB/creds marked Prod/DB as "[exists]" with Dev/DB's id, and
    creds was created under Dev/DB -- inheriting Dev's policy grants --
    while the results CSV recorded Prod/DB/creds as created. Now only an
    exact path match is adopted. A same-named folder elsewhere is never
    used as a parent: the create is attempted at the planned location and
    OPA decides (fact #1 in the header says it refuses a name already used
    anywhere in the project; if it doesn't, the folder lands where the CSV
    says). Either way nothing is created under the wrong parent."""
    folders = fetch_all_folders(client, resource_group_id, project_id)
    log("INFO", f"Scanned {len(folders)} existing folder(s) in project (recursive, all depths).")
    by_id = {f.get(FIELD_ID): f for f in folders if f.get(FIELD_ID)}
    path_to_id = {}
    paths_by_name = {}
    for f in folders:
        fid = f.get(FIELD_ID)
        if not fid:
            continue
        path = _folder_path_tuple(f, by_id)
        if path is None:
            continue
        if path in path_to_id:
            log("WARN", f"Tenant already has more than one folder at '{'/'.join(path)}'; using the first one found.")
            continue
        path_to_id[path] = fid
        paths_by_name.setdefault(path[-1].casefold(), []).append(path)

    existing = {path: path_to_id[path] for path in ordered_paths if path in path_to_id}
    name_in_use = {}
    for path in ordered_paths:
        if path in existing:
            continue
        elsewhere = sorted(p for p in paths_by_name.get(path[-1].casefold(), []) if p != path)
        if elsewhere:
            name_in_use[path] = "/".join(elsewhere[0])
    return existing, name_in_use


# ---------------------------------------------------------------------------
# Plan / execute
# ---------------------------------------------------------------------------
def print_plan(ordered_paths, existing, collisions, name_in_use=None, case_variants=None):
    name_in_use = name_in_use or {}
    if collisions:
        log("WARN", "Name collisions detected -- OPA requires folder names to be unique per project:")
        for name, paths in collisions.items():
            where = ", ".join("/".join(p) for p in paths)
            log("WARN", f"  '{name}' is used at multiple positions: {where}")
        log("WARN", "Only the first folder created with each name will succeed; the rest will error with 409.")
    if case_variants:
        log("WARN", "Names that differ only by letter case (OPA may treat them as the same name):")
        for _key, paths in case_variants.items():
            log("WARN", f"  {', '.join('/'.join(p) for p in paths)}")

    log("INFO", "Planned folder tree:")
    for path in ordered_paths:
        indent = "  " * (len(path) - 1)
        if path in existing:
            marker = "[exists]     "
        elif path in name_in_use:
            marker = "[name in use]"
        else:
            marker = "[will create]"
        suffix = f"  -- a folder with this name already exists at '{name_in_use[path]}'" if path in name_in_use else ""
        log("INFO", f"  {indent}{marker} {path[-1]}  (full path: {'/'.join(path)}){suffix}")


NOT_ATTEMPTED_AFTER_NETWORK_FAILURE = "Not attempted: an earlier network failure stopped the run (re-run to continue)."


def execute_plan(client, resource_group_id, project_id, ordered_paths, descriptions, existing):
    """Creates every planned folder that doesn't exist yet, parents first.
    Always returns one result row per planned path.

    ENG2-06 (external review, 2026-10-05): a network failure (now an
    OpaApiError with status "network", see http_json_request) used to
    escape as URLError/TimeoutError, losing every result already
    recorded: no results CSV, no folders.execute audit entry, a traceback
    in the CLI -- although folders had been created. Now that row is an
    error, and every later row is reported as not attempted (a dead
    network would only fail them one by one); a re-run picks up where it
    stopped, since existing folders are detected."""
    results = []
    folder_ids = dict(existing)
    network_failed = False

    for path in ordered_paths:
        if network_failed and path not in folder_ids:
            results.append((path, "", "error", NOT_ATTEMPTED_AFTER_NETWORK_FAILURE))
            continue
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
                raise OpaApiError(API_STATUS_INVALID_RESPONSE, "create_folder", f"no '{FIELD_ID}' in the create response")
            folder_ids[path] = new_id
            results.append((path, new_id, "created", ""))
            log("SUCCESS", f"Created '{'/'.join(path)}' (id={new_id})")
        except OpaApiError as e:
            log("ERROR", f"Failed to create '{'/'.join(path)}': {e}")
            results.append((path, "", "error", str(e)))
            if _is_network_error(e):
                network_failed = True

    return results


_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe_cell(value):
    """ENG2-15 (external review, 2026-10-05): a cell a spreadsheet would
    evaluate as a formula (a folder named "-A1" is a valid OPA name) gets
    a leading single quote. Only for output-only files -- never applied to
    a CSV this tool reads back."""
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(_FORMULA_PREFIXES) else text


def _write_results_rows(f, results):
    writer = csv.writer(f)
    writer.writerow(["path", "folder_id", "status", "error_message"])
    for path, folder_id, status, error_message in results:
        writer.writerow([_csv_safe_cell(v) for v in ("/".join(path), folder_id, status, error_message)])


def write_results_csv(output_path, results):
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        _write_results_rows(f, results)
    log("INFO", f"Results written to {output_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
_CLI_CREDENTIAL_VARS = (ENV_BASE_DOMAIN, ENV_TEAM_NAME, ENV_KEY_ID, ENV_KEY_SECRET)


def _resolve_cli_credentials():
    """ENG2-13 (external review, 2026-10-05): ONE source, all four values --
    all from the environment (shell or .env), else all from the
    dashboard's active environment. Mixing field by field let a leftover
    OPA_TEAM_NAME (or a preview-org OPA_BASE_DOMAIN) combine with
    production's key while the log said the dashboard environment was in
    use. A partial set in the environment now stops with the names that
    are missing."""
    from_env = {name: os.environ.get(name, "").strip() for name in _CLI_CREDENTIAL_VARS}
    supplied = [name for name, value in from_env.items() if value]
    if supplied and len(supplied) < len(_CLI_CREDENTIAL_VARS):
        missing = [name for name in _CLI_CREDENTIAL_VARS if not from_env[name]]
        die(
            f"Only some credentials are set in the environment/.env ({', '.join(supplied)}); missing: "
            f"{', '.join(missing)}. Set all four, or unset them all to use the dashboard's active environment."
        )
    if supplied:
        return tuple(from_env[name] for name in _CLI_CREDENTIAL_VARS)
    try:
        active = get_active_environment_credentials()
    except CredentialStoreUnavailable as exc:
        die(str(exc))
    if not active:
        die(
            f"No credentials found. Set {', '.join(_CLI_CREDENTIAL_VARS)} as environment variables or in a "
            "local .env file, or activate an environment in the dashboard."
        )
    values = tuple((active.get(field) or "").strip() for field in ("base_domain", "team_name", "key_id", "key_secret"))
    missing = [name for name, value in zip(_CLI_CREDENTIAL_VARS, values) if not value]
    if missing:
        die(f"The dashboard's active environment ('{active.get('name')}') is missing: {', '.join(missing)}.")
    log("INFO", f"Using credentials from the dashboard's active environment ('{active.get('name')}').")
    return values


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
        help="Output results CSV path (default: folders_result_<timestamp>.csv). Must not exist unless --force.",
    )
    parser.add_argument("--force", action="store_true", help="Allow --output to overwrite an existing file.")
    args = parser.parse_args()

    if not os.path.isfile(args.csv):
        die(f"CSV file not found: {args.csv}")

    base_domain, team_name, key_id, key_secret = _resolve_cli_credentials()

    log("INFO", f"OPA Secret Folder Bulk Creator v{SCRIPT_VERSION}")
    log("INFO", f"Mode: {'EXECUTE' if args.execute else 'DRY-RUN (no changes will be made)'}")

    ordered_paths, descriptions = parse_csv(args.csv)
    if not ordered_paths:
        die("No usable paths found in CSV.")

    validate_names(ordered_paths)
    collisions = detect_name_collisions(ordered_paths)
    case_variants = detect_case_variant_names(ordered_paths)

    try:
        client = OpaClient(base_domain, team_name, key_id, key_secret)
        existing, name_in_use = resolve_existing_folders(client, args.resource_group_id, args.project_id, ordered_paths)
    except OpaApiError as e:  # network failures are OpaApiError too since 5.40.6 (ENG2-06)
        die(f"Failed during setup/lookup: {e}")

    print_plan(ordered_paths, existing, collisions, name_in_use, case_variants)

    if not args.execute:
        log("INFO", "Dry-run complete. Re-run with --execute to actually create the folders above.")
        return

    # ENG2-13: the results file is opened BEFORE anything is created -- a
    # bad directory used to fail only after every folder existed, losing
    # the record -- and an existing file is never overwritten silently.
    output_path = args.output or f"folders_result_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    try:
        results_file = open(output_path, "w" if args.force else "x", newline="", encoding="utf-8")
    except FileExistsError:
        die(f"{output_path} already exists. Choose another --output, or add --force to overwrite it.")
    except OSError as e:
        die(f"Cannot write the results file {output_path}: {e.strerror}")
    with results_file:
        results = execute_plan(client, args.resource_group_id, args.project_id, ordered_paths, descriptions, existing)
        _write_results_rows(results_file, results)
    log("INFO", f"Results written to {output_path}")

    created = sum(1 for r in results if r[2] == "created")
    skipped = sum(1 for r in results if r[2] == "skipped_exists")
    errors = sum(1 for r in results if r[2] == "error")
    log("SUCCESS", f"Done. Created={created} Skipped(existing)={skipped} Errors={errors}")
    if errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
