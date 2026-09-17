#!/usr/bin/env python3
"""The threat model names only mechanisms the code has (#102)."""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "measurements"))

import corpus_adequacy as ca  # noqa: E402
import effective_envelope  # noqa: E402
from tests.test_contained_hosted_workflow_contract import (  # noqa: E402
    ALLOWED_HOSTED_WORKFLOW,
    parse_workflow_yaml,
)
from tests.test_owned_contained_v1_hosted import OWNED_PUBLICATION_WORKFLOW  # noqa: E402

DOC = ROOT / "docs" / "threat-model.md"


class ThreatModelMatchesTheCode(unittest.TestCase):
    def setUp(self):
        self.text = DOC.read_text(encoding="utf-8")

    def test_every_named_unproved_reason_is_closed(self):
        named = set(re.findall(r"`(timeout|output-cap|oom-killed-reported|setup|inner-exit)`",
                               self.text))
        self.assertEqual(named, {"timeout", "output-cap", "oom-killed-reported", "setup",
                                 "inner-exit"})
        self.assertTrue(named <= set(ca.CLOSED_UNPROVED_REASONS))

    def test_named_profiles_are_the_closed_set(self):
        for profile in ("trusted-local", "contained-oci-v0", "contained-oci-v1"):
            self.assertIn("`%s`" % profile, self.text)
        self.assertEqual(effective_envelope.CONTAINED_PROFILE, "contained-oci-v0")
        self.assertEqual(effective_envelope.CONTAINED_PROFILE_V1, "contained-oci-v1")

    def test_the_stated_token_permissions_are_the_workflows(self):
        self.assertIn("`contents: read`", self.text)
        self.assertIn("`id-token` and\n  `attestations` write", self.text)
        expected = {"contents": "read", "id-token": "write", "attestations": "write"}
        self.assertEqual(ALLOWED_HOSTED_WORKFLOW["permissions"], expected)
        self.assertEqual(OWNED_PUBLICATION_WORKFLOW["permissions"], expected)
        for path in (".github/workflows/contained-hosted-publication.yml",
                     ".github/workflows/owned-contained-v1-publication.yml"):
            tree = parse_workflow_yaml((ROOT / path).read_text(encoding="utf-8"))
            self.assertEqual(tree["permissions"], expected, path)

    def test_the_offline_environment_name_is_the_one_passed(self):
        self.assertIn("`CARGO_NET_OFFLINE`", self.text)
        self.assertEqual(effective_envelope.OFFLINE_ENV_NAME, "CARGO_NET_OFFLINE")

    def test_the_applied_limit_definition_and_the_split_issue_are_stated(self):
        self.assertIn('"Limit applied" in this project means', self.text)
        self.assertIn("public #197", self.text)
        for claim in ("escape-proof sandbox", "CPU or file-descriptor bound"):
            self.assertIn(claim, self.text)

    def test_readme_and_security_policy_point_here(self):
        self.assertIn("docs/threat-model.md", (ROOT / "README.md").read_text(encoding="utf-8"))
        self.assertIn("docs/threat-model.md", (ROOT / "SECURITY.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
