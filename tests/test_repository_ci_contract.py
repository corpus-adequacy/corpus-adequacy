#!/usr/bin/env python3
"""Contract tests for the repository CI workflow. Standard library only.

Parses `.github/workflows/ci.yml` with a regex subset: this repository has no
YAML dependency, and a second parser would be a second answer to the same
contract.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

CLAIMED_OSES = ("ubuntu-latest", "macos-latest", "windows-latest")
ACTION_RE = re.compile(
    r"uses:\s*(actions/(?:checkout|setup-python))@([^\s#]+)"
)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
TIMEOUT_RE = re.compile(r"(?m)^[ \t]*timeout-minutes:\s*[1-9]\d*\s*$")
PIP_INSTALL_RE = re.compile(
    r"(?i)(?:\bpip(?:3)?\s+install\b|\bpython(?:3)?\s+-m\s+pip\s+install\b)"
)
COMPILE_RE = re.compile(r"\bpython(?:3)?\s+-m\s+(?:py_compile|compileall)\b")
UNITTEST_RE = re.compile(
    r"\bpython(?:3)?\s+-W\s+error::ResourceWarning\s+-m\s+unittest\s+discover\s+-s\s+tests\b"
)


class RepositoryCiContract(unittest.TestCase):
    def setUp(self):
        self.assertTrue(WORKFLOW.is_file(), f"missing CI workflow: {WORKFLOW}")
        self.text = WORKFLOW.read_text(encoding="utf-8")

    def test_job_declares_timeout(self):
        self.assertRegex(self.text, TIMEOUT_RE)

    def test_checkout_and_setup_python_use_full_sha(self):
        uses = ACTION_RE.findall(self.text)
        names = {name for name, _ref in uses}
        self.assertIn("actions/checkout", names)
        self.assertIn("actions/setup-python", names)
        for name, ref in uses:
            with self.subTest(action=name, ref=ref):
                self.assertRegex(
                    ref,
                    SHA_RE,
                    f"{name} must be pinned to a 40-hex SHA, not {ref!r}",
                )

    def test_unittest_invocation_treats_resourcewarning_as_error(self):
        self.assertRegex(self.text, UNITTEST_RE)

    def test_syntax_compile_step_present(self):
        self.assertRegex(self.text, COMPILE_RE)

    def test_workflow_does_not_install_dependencies(self):
        match = PIP_INSTALL_RE.search(self.text)
        self.assertFalse(
            match,
            "dependency install is forbidden"
            + (f": {match.group(0)!r}" if match else ""),
        )

    def test_matrix_includes_ubuntu_macos_and_windows(self):
        for os_name in CLAIMED_OSES:
            with self.subTest(os=os_name):
                self.assertIn(os_name, self.text)


if __name__ == "__main__":
    unittest.main()
