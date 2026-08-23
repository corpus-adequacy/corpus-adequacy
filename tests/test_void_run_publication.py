#!/usr/bin/env python3
"""RED-first void-run-attempt publication: not a measurement or score card."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import render_publication_page as rpp  # noqa: E402
from test_publication_page import VALID, _write_tree  # noqa: E402

FIXTURES = REPO_ROOT / "tests" / "fixtures" / "publication"
VOID_DIR = FIXTURES / "void-run-attempt"
VOID_REPORT = VOID_DIR / "report.v0.json"
VOID_SOURCE = VOID_DIR / "source.json"
VOID_ID = "void-run-attempt"
BUILD = "a" * 40
EXECUTION_COMMIT = "a95d2344b5a242774cc03edf599359d2aaabedf2"
PREPARE_SHA256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
FAILURE = (
    "aee-checker: the UNMUTATED implementation could not be measured (unproved)"
)
HOST_LEAK = "/private/tmp/ca-fixture-void-run/manifest.json"
COMPLETED_PAGES = (
    "runs/tersign-1cc5ea32/index.html",
    "runs/tersign-1cc5ea32/rules/0000.html",
    "runs/tersign-1cc5ea32/rules/0013.html",
)


def _hex(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _text(files: dict[str, bytes], rel: str) -> str:
    return files[rel].decode("utf-8")


def _void_tree(tmpdir: Path) -> Path:
    return _write_tree(tmpdir, [VOID_REPORT], dummy_manifest=False)


class VoidRunAttemptPublication(unittest.TestCase):
    def test_fixture_is_the_typed_void_shape_not_the_consumed_run(self):
        doc = json.loads(VOID_REPORT.read_text(encoding="utf-8"))
        self.assertEqual(doc["schema"], "corpus-adequacy.report.v0")
        self.assertIsNone(doc["score_percent"])
        self.assertEqual(doc["mutants"], [])
        self.assertEqual(doc["control_status"], "absent-or-invalid")
        self.assertTrue(any("UNMUTATED" in item for item in doc["failures"]))
        self.assertTrue(any("unproved" in item for item in doc["failures"]))
        self.assertIn(HOST_LEAK, doc["manifest"])
        self.assertNotEqual(
            _hex(VOID_REPORT),
            "88cc1b7e0e37ef9c4a6da17ecc1d62168b9f0f17b199203ca03c55471e587600",
        )
        self.assertEqual(rpp.classify_report(doc), rpp.KIND_VOID_RUN_ATTEMPT)
        valid = json.loads((VALID / "report.v0.json").read_text(encoding="utf-8"))
        self.assertEqual(
            rpp.classify_report(valid), rpp.KIND_COMPLETED_MEASUREMENT
        )

    def test_standard_measurement_path_rejects_void_report(self):
        with self.assertRaises(rpp.PublicationError) as cm:
            rpp.load_record(VOID_REPORT)
        message = str(cm.exception).lower()
        self.assertIn("void", message)
        self.assertIn("measurement", message)

    def _assert_void_publication(self, page: str, report_digest: str) -> None:
        lower = page.lower()
        self.assertIn("void run attempt", lower)
        self.assertIn("baseline unproved", lower)
        self.assertIn("control not run", lower)
        self.assertIn("no scored mutants", lower)
        self.assertIn("no score", lower)
        self.assertIn("not a measurement", lower)
        self.assertIn(FAILURE, page)
        self.assertIn(report_digest, page)
        self.assertIn(EXECUTION_COMMIT, page)
        self.assertIn(PREPARE_SHA256, page)
        self.assertIn("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210", page)
        self.assertNotIn(HOST_LEAK, page)
        self.assertNotIn("/private/tmp/", page)
        self.assertNotIn("/Users/", page)
        self.assertNotIn('class="counts"', page)
        self.assertNotIn("Copyable command", page)
        self.assertNotIn(
            "python3 corpus_adequacy.py measurements/%s/manifest.json --json"
            % VOID_ID,
            page,
        )
        self.assertNotIn('aria-label="killed 0"', page)
        self.assertNotIn('aria-label="unproved 0"', page)
        self.assertNotIn(">0</span></li>", page)

    def test_void_projection_is_digest_bound_and_not_a_score_card(self):
        report_digest = _hex(VOID_REPORT)
        with tempfile.TemporaryDirectory() as d:
            root = _void_tree(Path(d))
            files = rpp.render_site(root, BUILD)
            self.assertIn("index.html", files)
            self.assertIn("runs/%s/index.html" % VOID_ID, files)
            self.assertFalse(
                any(
                    rel.startswith("runs/%s/rules/" % VOID_ID)
                    for rel in files
                )
            )
            overview = _text(files, "index.html")
            run_page = _text(files, "runs/%s/index.html" % VOID_ID)
            self._assert_void_publication(overview, report_digest)
            self._assert_void_publication(run_page, report_digest)
            self.assertNotIn("Published measurements", overview)
            record = rpp.load_void_run_attempt(
                root / "measurements" / VOID_ID / "report.v0.json"
            )
            self.assertEqual(record["kind"], rpp.KIND_VOID_RUN_ATTEMPT)
            self.assertEqual(record["digest"], report_digest)
            with self.assertRaises(rpp.PublicationError):
                rpp._card_html(record, BUILD)
            with self.assertRaises(rpp.PublicationError):
                rpp._run_page(record, [], BUILD)

    def test_existing_completed_measurement_pages_stay_byte_identical(self):
        recorded = rpp.source_commit_from_html(
            (REPO_ROOT / "site" / "index.html").read_text(encoding="utf-8")
        )
        live = rpp.render_site(REPO_ROOT, recorded)
        for rel in COMPLETED_PAGES:
            self.assertEqual(
                live[rel],
                (REPO_ROOT / "site" / rel).read_bytes(),
                rel,
            )

    def test_measurement_only_overview_keeps_measurement_copy(self):
        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [VALID / "report.v0.json"])
            page = rpp.render_html(root, BUILD)
        self.assertIn("Published measurements", page)
        self.assertIn('class="counts"', page)
        self.assertNotIn("void run attempt", page.lower())

    def test_mutation_routing_void_through_standard_renderer_is_red(self):
        report_digest = _hex(VOID_REPORT)
        with tempfile.TemporaryDirectory() as d:
            root = _void_tree(Path(d))
            files = rpp.render_site(root, BUILD)
            self._assert_void_publication(_text(files, "index.html"), report_digest)
            with mock.patch.object(
                rpp, "classify_report", return_value=rpp.KIND_COMPLETED_MEASUREMENT
            ), mock.patch.object(rpp, "is_void_run_attempt", return_value=False):
                mutated = rpp.render_site(root, BUILD)
            with self.assertRaises(AssertionError):
                self._assert_void_publication(
                    _text(mutated, "index.html"), report_digest
                )

    def test_mutation_presenting_null_score_as_zero_is_red(self):
        report_digest = _hex(VOID_REPORT)
        with tempfile.TemporaryDirectory() as d:
            page = _text(rpp.render_site(_void_tree(Path(d)), BUILD), "index.html")
        self._assert_void_publication(page, report_digest)
        mutated = page.replace("No score", "0", 1)
        mutated = mutated.replace(
            "No scored mutants",
            '<ul class="counts"><li class="count" aria-label="killed 0">'
            '<span class="count-label">killed</span> '
            '<span class="count-value">0</span></li></ul>',
            1,
        )
        with self.assertRaises(AssertionError):
            self._assert_void_publication(mutated, report_digest)

    def test_mutation_omitting_the_failure_is_red(self):
        report_digest = _hex(VOID_REPORT)
        with tempfile.TemporaryDirectory() as d:
            page = _text(rpp.render_site(_void_tree(Path(d)), BUILD), "index.html")
        self._assert_void_publication(page, report_digest)
        mutated = page.replace(FAILURE, "", 1)
        with self.assertRaises(AssertionError):
            self._assert_void_publication(mutated, report_digest)


if __name__ == "__main__":
    unittest.main(verbosity=1)
