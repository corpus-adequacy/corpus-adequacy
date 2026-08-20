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


class LicenseProvenance(unittest.TestCase):
    def test_license_file_is_present(self):
        self.assertTrue(LICENSE.is_file(), "root LICENSE is missing")

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


if __name__ == "__main__":
    unittest.main(verbosity=1)
