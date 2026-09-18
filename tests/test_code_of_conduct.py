#!/usr/bin/env python3
"""The conduct-reporting route and the Code of Conduct that names it (#166).

One test here fails on purpose until the maintainer chooses a private route: the Code of Conduct
must not be merged pointing at nothing. Everything else pins the policy's shape.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COC = ROOT / "CODE_OF_CONDUCT.md"
PLACEHOLDER = "CONDUCT_ROUTE_PENDING"
COVENANT = "https://www.contributor-covenant.org/version/3/0/code_of_conduct/"
VULNERABILITY_ROUTE = "security/advisories"


def _text(name: str) -> str:
    """File text with line wrapping collapsed, so a phrase split across lines still matches."""
    return re.sub(r"\s+", " ", (ROOT / name).read_text(encoding="utf-8"))


def _reporting_section() -> str:
    text = COC.read_text(encoding="utf-8")
    start = text.index("## Reporting")
    end = text.index("\n## ", start + 1)
    return re.sub(r"\s+", " ", text[start:end])


class TheRoute(unittest.TestCase):
    def test_a_private_route_has_been_chosen(self):
        """Fails until the maintainer picks the route. This is what keeps the draft unmergeable."""
        self.assertNotIn(PLACEHOLDER, _reporting_section(),
                         "choose a private conduct route before merging (#166)")

    def test_the_route_is_not_the_vulnerability_route(self):
        self.assertNotIn(VULNERABILITY_ROUTE, _reporting_section())

    def test_the_route_names_something(self):
        self.assertRegex(_reporting_section(), r"privately to: \*\*\S+.*\*\*")


class ThePolicy(unittest.TestCase):
    def test_it_adopts_the_covenant_by_its_canonical_address(self):
        self.assertIn(COVENANT, _text("CODE_OF_CONDUCT.md"))

    def test_it_says_who_reads_a_report_and_what_happens_if_that_is_the_maintainer(self):
        text = _text("CODE_OF_CONDUCT.md")
        self.assertIn("the maintainer is the only reader of this route", text)
        self.assertIn("A report about the maintainer has no independent reader", text)
        self.assertIn("handed to a successor maintainer", text)

    def test_it_promises_no_response_time(self):
        text = _text("CODE_OF_CONDUCT.md")
        self.assertIn("No response time is promised", text)
        self.assertIsNone(re.search(r"within \d+|\d+ (hours|days|business days)", text))

    def test_the_two_routes_point_at_each_other_and_not_at_themselves(self):
        self.assertIn("SECURITY.md", _text("CODE_OF_CONDUCT.md"))
        self.assertIn("CODE_OF_CONDUCT.md", _text("SECURITY.md"))

    def test_contributor_guidance_links_the_policy(self):
        for name in ("CONTRIBUTING.md", "SUPPORT.md"):
            with self.subTest(file=name):
                self.assertIn("(CODE_OF_CONDUCT.md)", _text(name))


if __name__ == "__main__":
    unittest.main()
