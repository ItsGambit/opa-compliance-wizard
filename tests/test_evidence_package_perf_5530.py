"""Performance of one whole evidence package build (acceptance criterion 4): a 12-month period over a 1,000,000-event
synthetic archive, end to end (coverage, every report file, events, chain, seals, completeness, the zip), then the offline
verifier on the result. Reuses the evidence core's archive generator (tests/test_evidence_core_perf_5530.py).

Skipped unless OPA_PERF=1.

    OPA_PERF=1 .venv/bin/python -m pytest -q -s tests/test_evidence_package_perf_5530.py
    OPA_PERF_EVENTS=200000 ...      a smaller archive (the limits are only asserted at 1,000,000)
    OPA_PERF_DB=/path/archive.db    reuse (or create, if absent) an archive instead of a temporary one

Also runnable by hand:  python tests/test_evidence_package_perf_5530.py build DB OUT.zip
The build and the verifier each run in a fresh subprocess so the peak RSS is theirs alone."""
import json
import os
import subprocess
import sys
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests"))
from test_evidence_core_perf_5530 import DAYS, ENV, generate  # noqa: E402

MAX_SECONDS = 600
MAX_RSS_MB = 512

pytestmark = [
    pytest.mark.perf,
    pytest.mark.skipif(os.environ.get("OPA_PERF") != "1", reason="performance test: set OPA_PERF=1 to run"),
]


def _rss_mb(ru_maxrss):
    return ru_maxrss / (1024 * 1024) if sys.platform == "darwin" else ru_maxrss / 1024


def build(db, out):
    import resource
    from datetime import datetime, timedelta, timezone
    os.environ["OPA_AUDIT_DB_PATH"] = db
    sys.path.insert(0, ROOT)
    import evidence_core as core
    import evidence_package
    today = datetime.now(timezone.utc).date()
    period = core.parse_period((today - timedelta(days=DAYS)).isoformat(), (today - timedelta(days=1)).isoformat())
    stages = []
    t0 = time.time()
    result = evidence_package.build_package(
        out, ENV, "Synthetic environment", period, builder="perf run", app_version="5.53.0", gaps_acknowledged=True,
        progress=lambda stage, fraction: stages.append((round(time.time() - t0, 1), stage)))
    wall = time.time() - t0
    return {"wall_seconds": round(wall, 1), "peak_rss_mb": round(_rss_mb(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss), 1),
            "zip_mb": round(result["bytes"] / 1048576, 1), "events": result["events"], "report_rows": result["report_rows"],
            "coverage_pct": result["coverage_pct"],
            "stages": [list(x) for i, x in enumerate(stages) if i == 0 or x[1] != stages[i - 1][1]]}


def _run(*args):
    proc = subprocess.run([sys.executable, os.path.abspath(__file__), *args], capture_output=True, text=True, timeout=3000)
    assert proc.returncode == 0, proc.stderr[-2000:]
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_a_twelve_month_package_of_a_large_archive_builds_within_the_limits(tmp_path):
    n = int(os.environ.get("OPA_PERF_EVENTS", "1000000"))
    db = os.environ.get("OPA_PERF_DB") or str(tmp_path / "perf_archive.db")
    if not os.path.exists(db):
        t = time.time()
        made = _run("gen", db, str(n))
        print("\nperf archive generated:", made, "in %.0fs" % (time.time() - t))
    out = str(tmp_path / "package.zip")
    result = _run("build", db, out)
    print("\nperf build:", json.dumps(result))
    import resource
    before = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    t = time.time()
    proc = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "tools", "verify_evidence_package.py"), out], capture_output=True, text=True, cwd=str(tmp_path))
    verify = {"seconds": round(time.time() - t, 1), "exit": proc.returncode, "last_line": proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else "",
              "peak_rss_mb_children": round(_rss_mb(max(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss, before)), 1)}
    print("perf verify:", json.dumps(verify))
    assert result["events"] > 0 and proc.returncode == 0 and verify["last_line"].startswith("RESULT: PASS"), (result, verify, proc.stdout[-1500:])
    if n >= 1_000_000:
        assert result["wall_seconds"] <= MAX_SECONDS, result
        assert result["peak_rss_mb"] <= MAX_RSS_MB, result


if __name__ == "__main__":
    if sys.argv[1] == "gen":
        print(json.dumps(generate(sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 1_000_000, DAYS)))
    else:
        print(json.dumps(build(sys.argv[2], sys.argv[3])))
