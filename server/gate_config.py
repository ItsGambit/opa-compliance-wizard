"""Pure configuration helpers for server/auth_gate.py.

Kept in their own module, with no side effects, so tests can import them
(auth_gate.py itself reads the keyring and creates the session key at import
time). Added in 5.38.0 to run a SECOND auth gate instance against a second
Okta org on the same server, alongside the existing one:

- OKTA_AUTH_SERVER picks the Okta authorization server that issues the login
  tokens. "default" (unset) keeps the long-standing behaviour:
  {OKTA_ORG_URL}/oauth2/default. "org" uses Okta's org authorization server,
  whose issuer is the org URL itself -- needed with a custom domain such as
  https://login.example.com, where the default server's issuer can be the
  *.okta.com URL instead. Any other value names a custom authorization server
  by its ID.
- OPA_SESSION_KEY_PATH gives each gate instance its own session-signing key.
  Two gates sharing one key would accept each other's session cookies, so a
  session from one org would be valid on the other org's address.
- OPA_ACCESS_CONTROL_PATH (5.38.3) gives each gate its own access-control file
  (admin group, user group, restrict_login). The default access_control.json
  holds the MAIN org's group IDs; another org's gate checking those IDs would
  refuse everyone (or, worse with a coincidental ID, admit the wrong people).
  The dashboard's Access control page (serve.py) only edits the default file.
"""
import re
from pathlib import Path

DEFAULT_SESSION_KEY_PATH = "/etc/opa-secrets-wizard-session.key"
_AUTH_SERVER_ID = re.compile(r"[A-Za-z0-9]{1,64}")


def okta_endpoints(org_url, auth_server="default"):
    """Issuer and OAuth endpoint URLs for the chosen Okta authorization server."""
    if auth_server == "org":
        issuer = org_url
        base = f"{org_url}/oauth2"
    elif auth_server and _AUTH_SERVER_ID.fullmatch(auth_server):
        issuer = f"{org_url}/oauth2/{auth_server}"
        base = issuer
    else:
        raise RuntimeError(
            f"OKTA_AUTH_SERVER must be 'default', 'org' or a custom authorization server ID, got {auth_server!r}"
        )
    return {
        "issuer": issuer,
        "authorize": f"{base}/v1/authorize",
        "token": f"{base}/v1/token",
        "jwks": f"{base}/v1/keys",
        "logout": f"{base}/v1/logout",
    }


def session_key_path(env):
    """Where this gate instance keeps its session-signing key (absolute path)."""
    path = Path(env.get("OPA_SESSION_KEY_PATH") or DEFAULT_SESSION_KEY_PATH)
    if not path.is_absolute():
        raise RuntimeError(f"OPA_SESSION_KEY_PATH must be an absolute path, got {str(path)!r}")
    return path


def access_control_path(env, default):
    """Where this gate instance reads its access control (absolute path); default = access_control.json."""
    path = Path(env.get("OPA_ACCESS_CONTROL_PATH") or default)
    if not path.is_absolute():
        raise RuntimeError(f"OPA_ACCESS_CONTROL_PATH must be an absolute path, got {str(path)!r}")
    return path
