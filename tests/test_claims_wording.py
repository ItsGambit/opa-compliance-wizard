"""Acceptance criterion 10 (5.53.0): documents, templates and app text make none of the forbidden claims."""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FORBIDDEN = re.compile(r"tamper[- ]?proof|tamper[- ]?evident|audit[- ]?ready|certified|auditor[- ]accepted|\bcompliant\b", re.IGNORECASE)

# Paths (relative to the repository root) that are scanned: files, or directories walked recursively.
SCANNED = ["README.md", "SECURITY.md", "docs", ".github", "tools", "server", "frontend/src", "evidence_package.py", "evidence_core.py", "CHANGELOG.md"]
TEXT_SUFFIXES = {".md", ".txt", ".yml", ".yaml", ".py", ".sh", ".ts", ".tsx", ".css", ".html", ".json", ".conf", ".template", ".service", ".in", ""}
SKIP_DIRS = {"node_modules", "__pycache__", ".venv", "dist", "test"}

# (relative path, lowercase fragment) -> reason. Use only for a legitimate non-claim sense, e.g. Okta's own term.
ALLOWLIST = {}

# CHANGELOG.md keeps the history of the project, including lines that QUOTE a phrase a later release removed. A hit is allowed only when
# its line contains one of these markers (a new line with a forbidden claim has none), each with the reason.
CHANGELOG_HISTORIC = {
    'no longer calls the hash chain "tamper-evident"': "5.53.0 entry quoting the phrase it removed from the Okta Admins note",
    'a wording test scans the README': "5.53.0 entry listing the phrases the wording test refuses",
    "5.50.0 — **Foundation and first Okta insight": "the released 5.50.0 summary line, as published",
    'not a certified report in itself': "an old entry that quotes the claim it reworded away",
    "generates 14 audit-ready reports": "an old entry quoting the original README sentence it replaced",
}


def _is_test_file(name):
    return bool(re.search(r"\.(test|spec)\.[jt]sx?$", name))


def _files():
    for entry in SCANNED:
        full = os.path.join(ROOT, entry)
        if os.path.isfile(full):
            yield entry
            continue
        for dirpath, dirnames, filenames in os.walk(full):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                if _is_test_file(name) or os.path.splitext(name)[1] not in TEXT_SUFFIXES:
                    continue
                yield os.path.relpath(os.path.join(dirpath, name), ROOT)


def test_no_forbidden_claims_in_docs_templates_or_app_text():
    hits = []
    scanned = 0
    for rel in _files():
        scanned += 1
        with open(os.path.join(ROOT, rel), encoding="utf-8", errors="replace") as fh:
            for n, line in enumerate(fh, 1):
                for m in FORBIDDEN.finditer(line):
                    if (rel, m.group(0).lower()) in ALLOWLIST:
                        continue
                    if rel == "CHANGELOG.md" and any(marker in line for marker in CHANGELOG_HISTORIC):
                        continue
                    hits.append(f"{rel}:{n}: {m.group(0)}")
    assert scanned > 20, "the scan found almost no files; the path list is wrong"
    assert not hits, "forbidden claim wording:\n" + "\n".join(hits)


def test_scan_actually_detects_the_words():
    for word in ("tamper-proof", "Tamper-Evident", "audit-ready", "Certified", "auditor-accepted", "A compliant setup"):
        assert FORBIDDEN.search(word), word
    assert not FORBIDDEN.search("compliance report")
    assert not FORBIDDEN.search("noncompliantly")


def test_allowlist_entries_have_reasons():
    assert all(reason.strip() for reason in ALLOWLIST.values())
    assert all(reason.strip() for reason in CHANGELOG_HISTORIC.values())


def test_a_new_changelog_line_with_a_forbidden_claim_is_caught():
    assert FORBIDDEN.search("- **Added.** A tamper-proof export.") and not any(m in "- **Added.** A tamper-proof export." for m in CHANGELOG_HISTORIC)
    assert "CHANGELOG.md" in set(_files())


def test_the_evidence_package_templates_and_texts_are_in_the_scan():
    """5.53.0: the static texts of an evidence package (auditors' README, cover sheet, what-this-tool-reads) and its builder are
    scanned, so a forbidden claim cannot ship inside a package. (The built package is scanned in test_evidence_package_5530.py.)"""
    scanned = set(_files())
    for rel in ("server/evidence_templates/README-FOR-AUDITORS.txt", "server/evidence_templates/cover-sheet.html",
                "server/evidence_templates/what-this-tool-reads.txt", "docs/evidence-package.md", "docs/evidence-package-format.md",
                "server/evidence_jobs.py", "evidence_package.py", "tools/verify_evidence_package.py", "SECURITY.md"):
        assert rel in scanned, rel
