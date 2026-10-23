"""Acceptance criterion 10 (5.53.0): documents, templates and app text make none of the forbidden claims."""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FORBIDDEN = re.compile(r"tamper[- ]?proof|tamper[- ]?evident|audit[- ]?ready|certified|auditor[- ]accepted|\bcompliant\b", re.IGNORECASE)

# Paths (relative to the repository root) that are scanned: files, or directories walked recursively.
SCANNED = ["README.md", "SECURITY.md", "docs", ".github", "tools", "server", "frontend/src"]
TEXT_SUFFIXES = {".md", ".txt", ".yml", ".yaml", ".py", ".sh", ".ts", ".tsx", ".css", ".html", ".json", ".conf", ".template", ".service", ".in", ""}
SKIP_DIRS = {"node_modules", "__pycache__", ".venv", "dist", "test"}

# (relative path, lowercase fragment) -> reason. Use only for a legitimate non-claim sense, e.g. Okta's own term.
ALLOWLIST = {}


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
