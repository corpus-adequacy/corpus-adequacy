#!/usr/bin/env python3
"""Public conduct-route contract for issue #166."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COC = ROOT / "CODE_OF_CONDUCT.md"
COVENANT = "https://www.contributor-covenant.org/version/3/0/code_of_conduct/"
CONDUCT_ADDRESS = "roelschuurkes@gmail.com"
VULNERABILITY_ROUTE = "security/advisories"


def _text(name: str) -> str:
    """Read a document with line wrapping collapsed."""
    return re.sub(r"\s+", " ", (ROOT / name).read_text(encoding="utf-8"))


def _section(name: str) -> str:
    text = COC.read_text(encoding="utf-8")
    start = text.index(f"## {name}")
    end = text.find("\n## ", start + 1)
    return re.sub(r"\s+", " ", text[start:] if end == -1 else text[start:end])


class ConductRouteContract(unittest.TestCase):
    def test_reporting_section_names_the_selected_private_route(self):
        reporting = _section("Reporting")
        self.assertIn(CONDUCT_ADDRESS, reporting)
        self.assertNotIn(VULNERABILITY_ROUTE, reporting)
        self.assertNotRegex(reporting, r"PENDING|PLACEHOLDER|TODO")

    def test_policy_names_the_standard_and_its_attribution(self):
        policy = _text("CODE_OF_CONDUCT.md")
        self.assertIn(COVENANT, policy)
        self.assertIn("Contributor Covenant version 3.0", policy)
        self.assertIn("CC BY-SA 4.0", policy)

    def test_policy_discloses_the_single_reader_and_continuity_limit(self):
        policy = _text("CODE_OF_CONDUCT.md")
        self.assertIn("Roel Schuurkes is the only person who reads this address", policy)
        self.assertIn("There is no deputy or alternate recipient", policy)
        self.assertIn("A report about Roel still reaches Roel", policy)
        self.assertIn("handling may be delayed", policy)

    def test_policy_promises_neither_timing_nor_confidentiality(self):
        policy = _text("CODE_OF_CONDUCT.md")
        self.assertIn("No response or resolution time is promised", policy)
        self.assertIn("cannot guarantee confidentiality", policy)
        self.assertIsNone(re.search(r"within \d+|\d+ (hours|days|business days)", policy))

    def test_conduct_and_vulnerability_routes_cross_link(self):
        self.assertIn("SECURITY.md", _text("CODE_OF_CONDUCT.md"))
        self.assertIn("CODE_OF_CONDUCT.md", _text("SECURITY.md"))

    def test_contributor_and_support_guidance_link_the_policy(self):
        for name in ("CONTRIBUTING.md", "SUPPORT.md"):
            with self.subTest(file=name):
                self.assertIn("(CODE_OF_CONDUCT.md)", _text(name))


if __name__ == "__main__":
    unittest.main()
