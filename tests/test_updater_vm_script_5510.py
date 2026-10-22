"""5.51.0 F7: tests/integration/updater-vm.sh (run by hand on a VM) had a stale assertion and a failure handler that aborted under set -e
before the updater was installed. The handler must report, and the assertion must match what install.sh prints."""
import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = (REPO / "tests" / "integration" / "updater-vm.sh").read_text(encoding="utf-8")


def test_the_dry_run_assertion_matches_the_message_install_sh_prints():
    installer = (REPO / "server" / "install.sh").read_text(encoding="utf-8")
    needle = re.search(r"grep -q 'does NOT deny ([^']+)' \$WORK/dryrun\.txt", SCRIPT).group(1)
    assert needle in installer and "does NOT deny /api/upgrade" not in SCRIPT


def test_the_failure_handler_reports_instead_of_aborting_before_the_updater_exists(tmp_path):
    body = SCRIPT[SCRIPT.index("diag() {"):]
    body = body[:body.index("\n}\n") + 3]
    script = f'set -euo pipefail\nWORK={tmp_path}\nDATA={tmp_path}/none\nOPT={tmp_path}/none\nDIAG_N=0\nPATH=/usr/bin:/bin\n{body}\ndiag\necho still-running\n'
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0 and "still-running" in out.stdout and "ocw-updater is not installed yet" in out.stdout
    assert (tmp_path / "diag-1.txt").exists()
