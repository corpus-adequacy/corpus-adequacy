#!/usr/bin/env python3
"""Pinned sources checkout as LF. Standard library only.

Inventory is ca.TOOL_SOURCE_PATHS plus the adapter and the CHECKS wrapper.
git check-attr eol must report lf for each. A global *.py rule is not this pin.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
import corpus_adequacy as ca  # noqa: E402

GITATTRIBUTES = REPO_ROOT / ".gitattributes"
ADAPTER = "adapters/tersign_evidence_record.py"
WRAPPER = "measurements/tersign_checks.py"
EXTRA = (ADAPTER, WRAPPER)


def _inventory():
    return list(ca.TOOL_SOURCE_PATHS) + list(EXTRA)


def _rule(path):
    return "%s text eol=lf" % path


def _eol(path, cwd=REPO_ROOT):
    out = subprocess.check_output(
        ["git", "check-attr", "eol", "--", path],
        cwd=cwd,
        text=True,
    )
    line = out.strip().splitlines()[-1]
    name, attr, value = line.split(": ")
    if attr != "eol":
        raise AssertionError("unexpected check-attr line: %r" % line)
    if name != path:
        raise AssertionError("check-attr path %r != %r" % (name, path))
    return value


def _eol_with_attributes(attributes_text, path):
    with tempfile.TemporaryDirectory() as d:
        repo = Path(d)
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("placeholder\n", encoding="utf-8")
        (repo / ".gitattributes").write_text(attributes_text, encoding="utf-8")
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
        return _eol(path, cwd=repo)


class PinnedSourceEol(unittest.TestCase):
    def test_runtime_adapter_and_wrapper_eol_is_lf(self):
        for path in _inventory():
            self.assertEqual(_eol(path), "lf", path)

    def test_inventory_reads_tool_source_paths(self):
        inv = _inventory()
        self.assertEqual(inv[: len(ca.TOOL_SOURCE_PATHS)], list(ca.TOOL_SOURCE_PATHS))
        self.assertEqual(inv[len(ca.TOOL_SOURCE_PATHS) :], list(EXTRA))

    def test_dropping_a_runtime_path_from_the_inventory_is_incomplete(self):
        dropped = ca.TOOL_SOURCE_PATHS[0]
        mutant = [p for p in _inventory() if p != dropped]
        self.assertNotIn(dropped, mutant)
        self.assertIn(dropped, _inventory())
        self.assertIn(dropped, ca.TOOL_SOURCE_PATHS)

    def test_removing_a_runtime_path_rule_is_not_lf(self):
        dropped = ca.TOOL_SOURCE_PATHS[0]
        text = "".join(_rule(p) + "\n" for p in _inventory() if p != dropped)
        self.assertNotEqual(_eol_with_attributes(text, dropped), "lf")

    def test_removing_the_adapter_rule_is_not_lf(self):
        text = "".join(_rule(p) + "\n" for p in _inventory() if p != ADAPTER)
        self.assertNotEqual(_eol_with_attributes(text, ADAPTER), "lf")

    def test_removing_the_wrapper_rule_is_not_lf(self):
        text = "".join(_rule(p) + "\n" for p in _inventory() if p != WRAPPER)
        self.assertNotEqual(_eol_with_attributes(text, WRAPPER), "lf")

    def test_gitattributes_has_no_global_py_rule(self):
        lines = GITATTRIBUTES.read_text(encoding="utf-8").splitlines()
        for line in lines:
            self.assertFalse(line.split("#", 1)[0].strip().startswith("*.py"))


if __name__ == "__main__":
    unittest.main(verbosity=1)
