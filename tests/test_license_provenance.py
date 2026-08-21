#!/usr/bin/env python3
"""License and extraction-provenance contract. Standard library only.

Pins the upstream MIT text, the Assay extraction SHA, and the trust-boundary
sentences. A missing or substituted LICENSE, a stripped copyright notice, or a
README that drops the source SHA or the trusted-manifest warning must fail.
"""

from __future__ import annotations

import hashlib
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LICENSE = REPO_ROOT / "LICENSE"
README = REPO_ROOT / "README.md"
GITATTRIBUTES = REPO_ROOT / ".gitattributes"
LICENSE_EOL_LF = "LICENSE text eol=lf"

# Exact upstream MIT at Rul1an/assay@78c792f574e882aad683b690bfbff5445774056e
UPSTREAM_LICENSE_SHA256 = (
    "fa103e85c81b02db33f34ea4c59b1a4a7f18e0052042879906ce82f9597b1b7c"
)
COPYRIGHT_NOTICE = "Copyright (c) 2025-2026 Assay Contributors"
EXTRACTION_SHA = "78c792f574e882aad683b690bfbff5445774056e"
EXTRACTION_REPO = "Rul1an/assay"
TRUSTED_MANIFEST_WARNING = (
    "A manifest is executable trusted input: an author declaration, not "
    "independent evidence."
)
NETWORK_BOUNDARY = (
    "That the tool itself uses no network does not mean a child or a "
    "manifest cannot."
)
ISOLATION_BOUNDARY = (
    "Isolation and least privilege are the caller's job; this is not a sandbox."
)
DO_NOT_RUN_UNTRUSTED = "Do not run a manifest you do not trust."
THIRD_PARTY_NOT_EVIDENCE = (
    "A third-party manifest is not independent evidence merely because it "
    "was written elsewhere."
)


class LicenseProvenance(unittest.TestCase):
    def test_license_file_is_present(self):
        self.assertTrue(LICENSE.is_file(), "root LICENSE is missing")

    def test_gitattributes_pins_license_to_lf(self):
        self.assertTrue(GITATTRIBUTES.is_file(), "root .gitattributes is missing")
        lines = GITATTRIBUTES.read_text(encoding="utf-8").splitlines()
        self.assertIn(LICENSE_EOL_LF, lines)
        self.assertNotIn("LICENSE text eol=crlf", lines)

    def test_license_is_the_exact_upstream_mit_text(self):
        digest = hashlib.sha256(LICENSE.read_bytes()).hexdigest()
        self.assertEqual(digest, UPSTREAM_LICENSE_SHA256)

    def test_copyright_notice_is_retained(self):
        self.assertIn(COPYRIGHT_NOTICE, LICENSE.read_text(encoding="utf-8"))

    def test_readme_names_the_extraction_source_sha(self):
        text = README.read_text(encoding="utf-8")
        self.assertIn(EXTRACTION_REPO, text)
        self.assertIn(EXTRACTION_SHA, text)

    def test_readme_states_the_trusted_manifest_warning(self):
        text = README.read_text(encoding="utf-8")
        self.assertIn(TRUSTED_MANIFEST_WARNING, text)
        self.assertIn(NETWORK_BOUNDARY, text)
        self.assertIn(ISOLATION_BOUNDARY, text)

    def test_readme_forbids_running_an_untrusted_manifest(self):
        self.assertIn(DO_NOT_RUN_UNTRUSTED, README.read_text(encoding="utf-8"))

    def test_readme_says_a_third_party_manifest_is_not_independent_evidence(self):
        self.assertIn(THIRD_PARTY_NOT_EVIDENCE, README.read_text(encoding="utf-8"))



class VendoredTersignVerifierLicense(unittest.TestCase):
    """Apache-2.0 text at tersignhq/evidence-record-conformance@1cc5ea32."""

    FIXTURE = REPO_ROOT / "fixtures" / "tersign-verify-1cc5ea32"
    LICENSE = FIXTURE / "LICENSE"
    SOURCE = FIXTURE / "SOURCE.txt"
    PIN_SHA256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
    PIN_SPDX = "SPDX-License-Identifier: Apache-2.0"
    EOL = "fixtures/tersign-verify-1cc5ea32/** text eol=lf"

    def test_vendored_license_is_present(self):
        self.assertTrue(self.LICENSE.is_file(), "vendored Tersign LICENSE is missing")

    def test_vendored_license_is_the_pinned_apache_text(self):
        digest = hashlib.sha256(self.LICENSE.read_bytes()).hexdigest()
        self.assertEqual(digest, self.PIN_SHA256)
        self.assertNotEqual(digest, UPSTREAM_LICENSE_SHA256)

    def test_source_txt_names_spdx_and_license_digest(self):
        text = self.SOURCE.read_text(encoding="utf-8")
        self.assertIn(self.PIN_SPDX, text)
        self.assertIn(self.PIN_SHA256, text)

    def test_gitattributes_pins_the_verify_fixture_to_lf(self):
        lines = GITATTRIBUTES.read_text(encoding="utf-8").splitlines()
        self.assertIn(self.EOL, lines)

    def test_upstream_pin_has_no_notice(self):
        self.assertFalse((self.FIXTURE / "NOTICE").exists())


if __name__ == "__main__":
    unittest.main(verbosity=1)
