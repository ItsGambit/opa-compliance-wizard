"""tests/integration/make_test_release.py (used by the VM script) must produce releases that the real verifiers accept,
signed only by throwaway keys, and the deliberately broken variants must really be broken."""

import json
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

import updater_fakes  # noqa: F401  (sys.path for the root modules)
import ocw_trust
from server.updater import keys as keylib
from server.updater import verify as verifylib

REPO = Path(__file__).resolve().parent.parent
TOOL = REPO / "tests" / "integration" / "make_test_release.py"


def run(*args):
    return subprocess.run([sys.executable, str(TOOL), *args], capture_output=True, text=True, timeout=300, check=True).stdout


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    d = tmp_path_factory.mktemp("vmhelper")
    run("keygen", str(d / "keys"))
    run("build", str(REPO), str(d / "keys"), str(d / "out"), "98.0.2")
    run("build", str(REPO), str(d / "keys"), str(d / "out"), "98.0.3", "--break", "crash")
    run("build", str(REPO), str(d / "keys"), str(d / "out"), "98.0.4", "--sign-with", "other")
    run("build", str(REPO), str(d / "keys"), str(d / "out"), "98.0.5", "--break", "unhealthy")
    return d


def test_the_test_keys_are_throwaway_and_not_the_projects(built):
    mine = json.loads((built / "keys" / "release_keys.json").read_text())
    real = json.loads((REPO / "server" / "release_keys.json").read_text())
    assert {k["key_id"] for k in mine["keys"]}.isdisjoint({k["key_id"] for k in real["keys"]})
    assert oct((built / "keys" / "primary.key").stat().st_mode & 0o777) == "0o600"


def test_good_releases_verify_in_both_implementations_and_a_stranger_does_not(built):
    kl = (built / "keys" / "release_keys.json").read_bytes()
    trust = {"schema": 1, "serial": 0, "keys": ocw_trust.parse_key_list(kl), "revoked": []}
    eff = keylib.effective_from(keylib.load_key_list(built / "keys" / "release_keys.json"))
    for v in ("98.0.2", "98.0.3"):
        tar, sig = built / "out" / f"ocw-{v}.tar.gz", built / "out" / f"ocw-{v}.tar.gz.minisig"
        assert ocw_trust.verify_release(str(tar), str(sig), trust, "98.0.1")["version"] == v
        assert verifylib.verify_release(str(tar), str(sig), eff, "98.0.1").version == v
    with pytest.raises(ocw_trust.TrustError) as e:
        ocw_trust.verify_release(str(built / "out/ocw-98.0.4.tar.gz"), str(built / "out/ocw-98.0.4.tar.gz.minisig"), trust, "98.0.1")
    assert e.value.code == "key_unknown"


def test_the_broken_variants_are_broken_and_the_good_one_is_not(built):
    def text(v):
        with tarfile.open(built / "out" / f"ocw-{v}.tar.gz") as t:
            return t.extractfile("server/serve.py").read().decode()
    assert "deliberately refuses to start" in text("98.0.3") and "deliberately refuses to start" not in text("98.0.2")
    assert 'status = "degraded"  # test release' in text("98.0.5")
    with tarfile.open(built / "out" / "ocw-98.0.2.tar.gz") as t:
        names = t.getnames()
        assert "manifest.json" in names and "server/updater/root/ocw_activate.py" in names and "frontend/dist/index.html" in names
        assert not [n for n in names if n.endswith((".db", ".pyc")) or ".git/" in n or n.startswith(".venv")]


def test_the_crash_release_exits_instead_of_starting_the_server(built):
    with tarfile.open(built / "out" / "ocw-98.0.3.tar.gz") as t:
        text = t.extractfile("server/serve.py").read().decode()
    block = text[text.rindex('if __name__ == "__main__":'):]
    assert "deliberately refuses to start" in block and "main()" not in block


def test_the_template_comment_release_bakes_and_the_test_revocation_applies(built, tmp_path):
    import sys
    sys.path.insert(0, str(REPO / "server"))
    import nginx_bake
    run("build", str(REPO), str(built / "keys"), str(tmp_path / "out"), "98.0.8", "--template-comment")
    with tarfile.open(tmp_path / "out" / "ocw-98.0.8.tar.gz") as t:
        tpl = t.extractfile("server/nginx-opa-secrets-wizard.conf").read().decode()
    assert tpl.rstrip().endswith("# vm test: template changed")
    live_tpl = (REPO / "server" / "nginx-opa-secrets-wizard.conf").read_text()
    live = live_tpl.replace("REPLACE_WITH_SERVER_NAME", "vm.example.com").replace("REPLACE_WITH_NGINX_PROXY_SECRET_VALUE", "s3cret")
    baked, problems = nginx_bake.bake(live, tpl)
    assert not problems and baked != live and "template changed" in baked
    run("revoke", str(built / "keys"), str(tmp_path / "revocation.json"))
    trust = {"schema": 1, "serial": 0, "keys": ocw_trust.parse_key_list((built / "keys" / "release_keys.json").read_bytes()), "revoked": []}
    new, details = ocw_trust.apply_revocation(trust, (tmp_path / "revocation.json").read_bytes())
    assert details["to_serial"] == 1 and len(details["revoked"]) == 1
