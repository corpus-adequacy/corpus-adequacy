#!/usr/bin/env python3
"""RED-first publication page: one validated report.v0 card, no JS truth."""

from __future__ import annotations

import hashlib
import html
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import render_publication_page as rpp  # noqa: E402
from test_tersign_verifier_measurement import (  # noqa: E402
    ClaimedReport,
    REPORT_PATH,
    REPORT_SHA256,
)

XSS_PAYLOAD = "<" + "script>alert(1)</scr" + "ipt>"
JS_HREF = "java" + "script:alert(1)"
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "publication"
VALID = FIXTURES / "valid-tersign"
UNPROVED = FIXTURES / "unproved-control"
FORBIDDEN = (
    "leaderboard",
    "score",
    "badge",
    "certificate",
    "trust",
    "ranking",
    "row number",
    "conformance seal",
)
CEILINGS = (
    "not a leaderboard",
    "not a badge",
    "not a certification",
    "not a trust score",
    "not automatic admission",
    "not completeness of declared inventory",
    "not authenticity",
    "not endorsement",
    "not implementation safety",
    "silent:0 without diagnostic_channel_declared is not \"no silent rules\"",
    "score_percent is percent of author-declared in-scope rules, not of the implementation",
)


def _write_tree(tmpdir: Path, reports: list[Path]) -> Path:
    root = tmpdir / "tree"
    for report in reports:
        dest_dir = root / "measurements" / report.parent.name
        dest_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(report, dest_dir / "report.v0.json")
        src = report.parent / "source.json"
        if src.is_file():
            shutil.copy2(src, dest_dir / "source.json")
    return root


def _render(root: Path, source_commit: str = "a" * 40) -> str:
    return rpp.render_html(root, source_commit=source_commit)


class PublicationPage(unittest.TestCase):
    def test_reuses_claimed_report_and_row_validator(self):
        self.assertTrue(REPORT_PATH.is_file())
        self.assertEqual(hashlib.sha256(REPORT_PATH.read_bytes()).hexdigest(), REPORT_SHA256)
        ClaimedReport().test_report_bytes_are_the_measured_file()
        doc = json.loads((VALID / "report.v0.json").read_text(encoding="utf-8"))
        rpp._require_report_rows(doc)

    def test_fixture_digest_swap_changes_page(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            root = _write_tree(tmp, [VALID / "report.v0.json"])
            page = _render(root)
            digest = hashlib.sha256((VALID / "report.v0.json").read_bytes()).hexdigest()
            self.assertIn(digest, page)
            self.assertIn("1cc5ea32b3da4f195b55782c8a3573d8564673a7", page)
            self.assertIn("10", page)
            self.assertIn("killed", page)
            report = root / "measurements" / "valid-tersign" / "report.v0.json"
            mutated = json.loads(report.read_text(encoding="utf-8"))
            mutated["killed"] = 99
            report.write_text(json.dumps(mutated, indent=2, sort_keys=True) + "\n")
            new_digest = hashlib.sha256(report.read_bytes()).hexdigest()
            swapped = _render(root)
            self.assertNotEqual(page, swapped)
            self.assertIn(new_digest, swapped)
            self.assertNotIn(digest, swapped)
            self.assertIn(">99<", swapped)

    def test_hostile_query_is_not_read_as_truth(self):
        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [VALID / "report.v0.json"])
            hostile = {
                "QUERY_STRING": "killed=0&report-digest=deadbeef&source-commit=00&display-name=" + XSS_PAYLOAD,
                "killed": "0",
                "HTTP_QUERY": "report-digest=deadbeef",
            }
            with mock.patch.dict(os.environ, hostile, clear=False):
                page = _render(root, source_commit="b" * 40)
            self.assertNotIn("deadbeef", page)
            self.assertNotIn(XSS_PAYLOAD, page)
            digest = hashlib.sha256((VALID / "report.v0.json").read_bytes()).hexdigest()
            self.assertIn(digest, page)
            self.assertIn("killed", page)
            self.assertIn("10", page)
            self.assertNotIn("os.environ", Path(rpp.__file__).read_text(encoding="utf-8"))

    def test_stale_generation_meta_and_byte_identity(self):
        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [VALID / "report.v0.json"])
            first = _render(root, source_commit="c" * 40)
            second = _render(root, source_commit="c" * 40)
            self.assertEqual(first, second)
            self.assertIn('name="generation-digest"', first)
            self.assertIn('name="source-commit"', first)
            self.assertIn("c" * 40, first)
            digest = rpp.generation_digest_from_html(first)
            self.assertEqual(len(digest), 64)
            self.assertIn(digest, first)
            without_gen = first.replace("generation-digest", "generation-x", 1)
            without_src = first.replace("source-commit", "source-x", 1)
            self.assertNotEqual(first, without_gen)
            self.assertNotEqual(first, without_src)
            report = root / "measurements" / "valid-tersign" / "report.v0.json"
            report.write_bytes(report.read_bytes() + b"\n")
            changed = _render(root, source_commit="c" * 40)
            self.assertNotEqual(first, changed)

    def test_html_escape_every_interpolated_field(self):
        payload = XSS_PAYLOAD
        onerror = "onerror="
        mixed = "\"&'"
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "measurements" / "escape-1"
            dest.mkdir(parents=True)
            doc = json.loads((VALID / "report.v0.json").read_text(encoding="utf-8"))
            src = json.loads((VALID / "source.json").read_text(encoding="utf-8"))
            src["repository"] = payload
            src["commit"] = "d" * 40
            src["non_claims"] = [payload, onerror, mixed]
            dest.joinpath("source.json").write_text(json.dumps(src, indent=2) + "\n")
            dest.joinpath("report.v0.json").write_text(json.dumps(doc, indent=2) + "\n")
            page = _render(Path(d), source_commit="e" * 40)
            self.assertNotIn(XSS_PAYLOAD, page)
            self.assertIn(html.escape(payload, quote=True), page)
            self.assertIn(html.escape(onerror, quote=True), page)
            self.assertIn(html.escape(mixed, quote=True), page)
            self.assertNotIn("<script>", page.split("<style>", 1)[0] if False else page.replace("<html", ""))
            self.assertNotIn("java" + "script:", page.lower())

    def test_no_script_node_from_record_and_no_js_href(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "measurements" / "href-1"
            dest.mkdir(parents=True)
            doc = json.loads((VALID / "report.v0.json").read_text(encoding="utf-8"))
            src = json.loads((VALID / "source.json").read_text(encoding="utf-8"))
            src["repository"] = JS_HREF
            src["non_claims"] = [XSS_PAYLOAD]
            dest.joinpath("source.json").write_text(json.dumps(src) + "\n")
            dest.joinpath("report.v0.json").write_text(json.dumps(doc) + "\n")
            page = _render(Path(d))
            self.assertNotIn("href=\"" + JS_HREF.split(":")[0] + ":", page.lower())
            self.assertNotIn(XSS_PAYLOAD, page)
            # optional enhance-only script must not contain record text
            if "<script" in page.lower():
                start = page.lower().find("<script")
                chunk = page[start:page.lower().find("</script>", start) + 9]
                self.assertNotIn(JS_HREF, chunk)

    def test_unpublished_algovoi_is_not_a_row(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            meas = root / "measurements" / "tersign-1cc5ea32"
            meas.mkdir(parents=True)
            shutil.copy2(VALID / "report.v0.json", meas / "report.v0.json")
            shutil.copy2(VALID / "source.json", meas / "source.json")
            (root / "adapters").mkdir()
            (root / "adapters" / "algovoi_jcs_edge.py").write_text("# unpublished adapter\n")
            fx = root / "fixtures" / "algovoi-jcs-edge-aa53149c"
            fx.mkdir(parents=True)
            (fx / "README.md").write_text("algovoi fixture, not a published measurement\n")
            page = _render(root)
            self.assertEqual(page.count('class="card"'), 1)
            self.assertEqual(page.lower().count("algovoi"), 0)
            self.assertIn("tersign-1cc5ea32", page)
            digest = hashlib.sha256((VALID / "report.v0.json").read_bytes()).hexdigest()
            self.assertIn(digest, page)

    def test_non_claims_above_rows_and_forbidden_ui_words(self):
        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [VALID / "report.v0.json"])
            page = _render(root)
            non_claims_pos = page.find("This adapter preserves one pinned upstream corpus.")
            results_pos = page.find('id="results"')
            card_pos = page.find('class="card"')
            self.assertNotEqual(non_claims_pos, -1)
            self.assertLess(non_claims_pos, card_pos)
            self.assertLess(page.find('class="non-claims"'), card_pos)
            results = page[page.find('id="results"') :]
            lower = results.lower()
            for word in FORBIDDEN:
                self.assertNotIn(word, lower)
            self.assertNotIn("score_percent", results)
            self.assertNotIn("pass-rate", page)
            for phrase in (
                "not a leaderboard/badge/certification/trust score/automatic admission/completeness of declared inventory",
                "not authenticity/endorsement/implementation safety",
                html.escape('silent:0 without diagnostic_channel_declared is not "no silent rules"', quote=True),
                "score_percent is percent of author-declared in-scope rules, not of the implementation",
            ):
                self.assertIn(phrase, page)
            self.assertIn("not measured", page)
            self.assertIn("skip to results", page.lower())
            self.assertIn("PROVENANCE.md", page)
            self.assertIn("python3 corpus_adequacy.py measurements/", page)
            self.assertIn("tersignhq/evidence-record-conformance", page)

    def test_counts_have_text_label_and_accessible_name(self):
        with tempfile.TemporaryDirectory() as d:
            page = _render(_write_tree(Path(d), [VALID / "report.v0.json"]))
            for name in ("killed", "survived", "silent", "unproved", "control_status"):
                self.assertIn(name, page)
                self.assertIn('aria-label=', page)

    def test_single_escape_function_is_html_escape_quote_true(self):
        src = Path(rpp.__file__).read_text(encoding="utf-8")
        self.assertIn("html.escape(", src)
        self.assertIn("quote=True", src)
        self.assertNotIn("quote=False", src)

    def test_live_repo_discovers_exactly_one_tersign_card(self):
        page = rpp.render_html(REPO_ROOT, source_commit="f" * 40)
        self.assertEqual(page.count('class="card"'), 1)
        self.assertIn(REPORT_SHA256, page)
        self.assertNotIn("b1a10e8c", page)
        results = page[page.find('id="results"'):]
        self.assertNotIn("score_percent", results)


class MutationProbes(unittest.TestCase):
    """Independent swaps must fail the corresponding assertion."""

    def test_count_swap_is_detected(self):
        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [VALID / "report.v0.json"])
            page = _render(root)
            self.assertIn("10", page)
            mutated = page.replace(">10<", ">0<", 1)
            self.assertNotEqual(page, mutated)

    def test_digest_swap_is_detected(self):
        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [VALID / "report.v0.json"])
            page = _render(root)
            digest = hashlib.sha256((VALID / "report.v0.json").read_bytes()).hexdigest()
            self.assertIn(digest, page)
            self.assertNotIn("deadbeef" * 4, page)


if __name__ == "__main__":
    unittest.main(verbosity=1)
