#!/usr/bin/env python3
"""Pinned sources checkout as LF. Standard library only.

Inventory is ca.TOOL_SOURCE_PATHS plus the adapter and the CHECKS wrapper.
git check-attr eol must report lf for each. A global *.py rule is not this pin.
"""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
import corpus_adequacy as ca  # noqa: E402

GITATTRIBUTES = REPO_ROOT / ".gitattributes"
EXTRA = (
    "adapters/tersign_evidence_record.py",
    "measurements/tersign_checks.py",
)


def _inventory():
    return list(ca.TOOL_SOURCE_PATHS) + list(EXTRA)


def _eol(path):
    out = subprocess.check_output(
        ["git", "check-attr", "eol", "--", path],
        cwd=REPO_ROOT,
        text=True,
    )
    line = out.strip().splitlines()[-1]
    name, attr, value = line.split(": ")
    if attr != "eol":
        raise AssertionError("unexpected check-attr line: %r" % line)
    if name != path:
        raise AssertionError("check-attr path %r != %r" % (name, path))
    return value


class PinnedSourceEol(unittest.TestCase):
    def test_runtime_adapter_and_wrapper_eol_is_lf(self):
        for path in _inventory():
            self.assertEqual(_eol(path), "lf", path)

    def test_gitattributes_has_no_global_py_rule(self):
        lines = GITATTRIBUTES.read_text(encoding="utf-8").splitlines()
        for line in lines:
            self.assertFalse(line.split("#", 1)[0].strip().startswith("*.py"))


if __name__ == "__main__":
    unittest.main(verbosity=1)
