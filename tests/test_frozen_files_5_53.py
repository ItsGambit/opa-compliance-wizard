"""5.53.0 must not change the nginx site template, any systemd unit, or the
second-site deny list.

Why: a changed template makes the updater rebuild every install's nginx site
on upgrade, and that rebuild does not yet carry a custom backend port or hand
edits through (planned for 5.54.0 with a health check through nginx). The
approved Settings-unlock design for 5.53.0 also relies on the template staying
as it is. Remove or update this test only in the release that ships that work.
"""
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# sha256 of each file as released in 5.52.0.
FROZEN = {
    "server/nginx-opa-secrets-wizard.conf": "3d6ded683d969f64034b8eb9a68c42bf7584b59e22abd5bb32cf6f03f850ac58",
    "server/ocw-stage@.service": "22b2868abe12e61947ec71420d74bee390815f320c4d47a0991c2ca7f61d604f",
    "server/ocw-upgrade-due.service": "73e2494ed968d451c9650e021ed456b5e29b063ca4dfdb1de62838fb26c5c198",
    "server/ocw-upgrade.service": "99e1d8b5cd7b251c44ba918367552dcb5a9d679b3f79ee302955dff036b76c23",
    "server/opa-auth-gate.service": "e4cc2741a10f66539bf9033b4a38b2d32d26952d5141caf110108d1d5251ceca",
    "server/opa-compliance-wizard.service": "ef3be76ca8ec7fb5b96cda7785fbe3dbd39f39d4e2c5e900502650c6ac2a8922",
}

FROZEN_DENIED_PREFIXES = (
    "/api/access_control", "/api/shared_permissions", "/api/archives", "/api/upgrade", "/api/overview",
)


def test_template_and_units_unchanged():
    changed = [
        path for path, digest in FROZEN.items()
        if hashlib.sha256((ROOT / path).read_bytes()).hexdigest() != digest
    ]
    assert changed == [], f"frozen in 5.53.0, changed: {changed}"


def test_second_site_deny_list_unchanged():
    import sys
    sys.path.insert(0, str(ROOT / "server"))
    try:
        import nginx_second_site
    finally:
        sys.path.pop(0)
    assert nginx_second_site.SECOND_SITE_DENIED_PREFIXES == FROZEN_DENIED_PREFIXES
