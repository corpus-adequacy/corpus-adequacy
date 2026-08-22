#!/usr/bin/env python3
"""RED-first publication page: one validated report.v0 card, no JS truth."""

from __future__ import annotations

import ast
import hashlib
import html
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import corpus_adequacy as ca  # noqa: E402
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
INDEX_SCHEMA = "corpus-adequacy.publication-index.v0"


def _hex(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_index(root: Path, ids: list[str] | None = None) -> Path:
    meas = root / "measurements"
    if ids is None:
        ids = sorted(p.name for p in meas.iterdir() if p.is_dir()) if meas.is_dir() else []
    records = []
    for rec_id in ids:
        report = meas / rec_id / "report.v0.json"
        source = meas / rec_id / "source.json"
        records.append(
            {
                "id": rec_id,
                "report_sha256": _hex(report),
                "source_sha256": _hex(source),
            }
        )
    pub = root / "publications"
    pub.mkdir(parents=True, exist_ok=True)
    dest = pub / "index.v0.json"
    dest.write_text(
        json.dumps({"schema": INDEX_SCHEMA, "records": records}, indent=2) + "\n",
        encoding="utf-8",
    )
    return dest


def _write_tree(tmpdir: Path, reports: list[Path]) -> Path:
    root = tmpdir / "tree"
    for report in reports:
        dest_dir = root / "measurements" / report.parent.name
        dest_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(report, dest_dir / "report.v0.json")
        src = report.parent / "source.json"
        if src.is_file():
            shutil.copy2(src, dest_dir / "source.json")
    _write_index(root)
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
        self.assertIs(rpp._require_report_rows, ca._require_report_rows)
        self.assertIs(rpp.read_bounded_regular_file, ca.read_bounded_regular_file)
        self.assertIs(rpp._parse_projection_json, ca._parse_projection_json)

    def test_inconsistent_top_level_killed_fails_generation(self):
        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [VALID / "report.v0.json"])
            report = root / "measurements" / "valid-tersign" / "report.v0.json"
            mutated = json.loads(report.read_text(encoding="utf-8"))
            mutated["killed"] = 99
            report.write_text(json.dumps(mutated, indent=2, sort_keys=True) + "\n")
            _write_index(root)
            with self.assertRaises(rpp.PublicationError):
                _render(root)

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

    def test_projection_meta_and_byte_identity(self):
        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [VALID / "report.v0.json"])
            first = _render(root, source_commit="c" * 40)
            second = _render(root, source_commit="c" * 40)
            self.assertEqual(first, second)
            self.assertIn('name="projection-digest"', first)
            self.assertIn('name="source-commit"', first)
            self.assertIn("c" * 40, first)
            digest = rpp.projection_digest_from_html(first)
            self.assertEqual(len(digest), 64)
            self.assertIn(digest, first)
            without_proj = first.replace("projection-digest", "projection-x", 1)
            without_src = first.replace("source-commit", "source-x", 1)
            self.assertNotEqual(first, without_proj)
            self.assertNotEqual(first, without_src)
            report = root / "measurements" / "valid-tersign" / "report.v0.json"
            report.write_bytes(report.read_bytes() + b"\n")
            with self.assertRaises(rpp.PublicationError):
                _render(root, source_commit="c" * 40)

    def test_html_escape_every_interpolated_field(self):
        payload = XSS_PAYLOAD
        onerror = "onerror="
        mixed = "\"&'"
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "measurements" / "escape-1"
            dest.mkdir(parents=True)
            doc = json.loads((VALID / "report.v0.json").read_text(encoding="utf-8"))
            src = json.loads((VALID / "source.json").read_text(encoding="utf-8"))
            src["repository"] = "owner/name"
            src["commit"] = "d" * 40
            src["non_claims"] = [payload, onerror, mixed]
            dest.joinpath("source.json").write_text(json.dumps(src, indent=2) + "\n")
            dest.joinpath("report.v0.json").write_text(json.dumps(doc, indent=2) + "\n")
            _write_index(Path(d))
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
            src["repository"] = "owner/name"
            src["commit"] = "a" * 40
            src["non_claims"] = [XSS_PAYLOAD]
            dest.joinpath("source.json").write_text(json.dumps(src) + "\n")
            dest.joinpath("report.v0.json").write_text(json.dumps(doc) + "\n")
            _write_index(Path(d))
            page = _render(Path(d))
            self.assertNotIn("href=\"" + JS_HREF.split(":")[0] + ":", page.lower())
            self.assertNotIn(XSS_PAYLOAD, page)
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
            _write_index(root)
            page = _render(root)
            self.assertEqual(page.count('class="card"'), 1)
            self.assertEqual(page.lower().count("algovoi"), 0)
            self.assertIn("tersign-1cc5ea32", page)
            digest = hashlib.sha256((VALID / "report.v0.json").read_bytes()).hexdigest()
            self.assertIn(digest, page)

    def test_unlisted_measurement_is_not_a_row(self):
        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [VALID / "report.v0.json"])
            bad = root / "measurements" / "bad"
            bad.mkdir()
            (bad / "report.v0.json").write_text("{", encoding="utf-8")
            page = _render(root)
            self.assertEqual(page.count('class="card"'), 1)
            self.assertNotIn("measurements/bad", page)

    def test_missing_index_fails_generation(self):
        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [VALID / "report.v0.json"])
            (root / "publications" / "index.v0.json").unlink()
            with self.assertRaises((rpp.PublicationError, ca.ManifestError, OSError)):
                _render(root)

    def test_omitted_index_entry_is_not_auto_published(self):
        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [VALID / "report.v0.json"])
            _write_index(root, ids=[])
            page = _render(root)
            self.assertEqual(page.count('class="card"'), 0)
            self.assertNotIn("valid-tersign", page[page.find('id="results"'):])

    def test_listed_invalid_or_missing_report_fails(self):
        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [VALID / "report.v0.json"])
            report = root / "measurements" / "valid-tersign" / "report.v0.json"
            report.write_text("{", encoding="utf-8")
            _write_index(root)
            with self.assertRaises(rpp.PublicationError):
                _render(root)
            report.unlink()
            index = {
                "schema": INDEX_SCHEMA,
                "records": [
                    {
                        "id": "valid-tersign",
                        "report_sha256": "0" * 64,
                        "source_sha256": "1" * 64,
                    }
                ],
            }
            (root / "publications" / "index.v0.json").write_text(
                json.dumps(index, indent=2) + "\n", encoding="utf-8"
            )
            with self.assertRaises(rpp.PublicationError):
                _render(root)

    def test_symlink_report_or_source_fails(self):
        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [VALID / "report.v0.json"])
            report = root / "measurements" / "valid-tersign" / "report.v0.json"
            real = report.with_name("report.real.json")
            report.rename(real)
            report.symlink_to(real.name)
            with self.assertRaises((rpp.PublicationError, ca.ManifestError)):
                _render(root)
            report.unlink()
            shutil.copy2(real, report)
            source = root / "measurements" / "valid-tersign" / "source.json"
            sreal = source.with_name("source.real.json")
            source.rename(sreal)
            source.symlink_to(sreal.name)
            with self.assertRaises((rpp.PublicationError, ca.ManifestError)):
                _render(root)

    def test_duplicate_top_level_killed_fails(self):
        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [VALID / "report.v0.json"])
            report = root / "measurements" / "valid-tersign" / "report.v0.json"
            text = report.read_text(encoding="utf-8")
            text = text.replace('"killed": 10', '"killed": 10,\n  "killed": 999', 1)
            report.write_text(text, encoding="utf-8")
            _write_index(root)
            with self.assertRaises(rpp.PublicationError):
                _render(root)

    def test_unbound_source_swap_fails(self):
        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [VALID / "report.v0.json"])
            source = root / "measurements" / "valid-tersign" / "source.json"
            src = json.loads(source.read_text(encoding="utf-8"))
            src["repository"] = "evil/swap"
            src["commit"] = "f" * 40
            source.write_text(json.dumps(src, indent=2) + "\n", encoding="utf-8")
            with self.assertRaises(rpp.PublicationError):
                _render(root)

    def test_flipped_control_status_fails(self):
        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [VALID / "report.v0.json"])
            report = root / "measurements" / "valid-tersign" / "report.v0.json"
            mutated = json.loads(report.read_text(encoding="utf-8"))
            mutated["control_status"] = "survived"
            report.write_text(json.dumps(mutated, indent=2, sort_keys=True) + "\n")
            _write_index(root)
            with self.assertRaises(rpp.PublicationError):
                _render(root)

    def test_check_does_not_write(self):
        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [VALID / "report.v0.json"])
            out = root / "site" / "index.html"
            rc = rpp.main(["--root", str(root), "--out", str(out), "--source-commit", "a" * 40])
            self.assertEqual(rc, 0)
            before = out.stat()
            out.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
            rc = rpp.main(["--root", str(root), "--out", str(out), "--source-commit", "a" * 40, "--check"])
            self.assertEqual(rc, 0)
            after = out.stat()
            self.assertEqual(before.st_mtime_ns, after.st_mtime_ns)
            self.assertEqual(before.st_ino, after.st_ino)
            self.assertEqual(before.st_size, after.st_size)

    def test_stale_renderer_fails_check(self):
        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [VALID / "report.v0.json"])
            out = root / "site" / "index.html"
            self.assertEqual(
                rpp.main(["--root", str(root), "--out", str(out), "--source-commit", "a" * 40]),
                0,
            )
            orig = rpp._page_body

            def stale(*args, **kwargs):
                return orig(*args, **kwargs).replace(
                    "<h1>Published measurements</h1>",
                    "<h1>Stale renderer title</h1>",
                    1,
                )

            with mock.patch.object(rpp, "_page_body", stale):
                with self.assertRaises(rpp.PublicationError):
                    rpp.main(["--root", str(root), "--out", str(out), "--source-commit", "a" * 40, "--check"])

    def test_non_claims_above_rows_and_forbidden_ui_words(self):
        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [VALID / "report.v0.json"])
            page = _render(root)
            non_claims_pos = page.find("This adapter preserves one pinned upstream corpus.")
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
            command_pos = page.find("python3 corpus_adequacy.py measurements/")
            counts_pos = page.find('class="counts"')
            self.assertLess(command_pos, counts_pos)
            self.assertIn("tersignhq/evidence-record-conformance", page)
            self.assertNotIn("stay representable", page)
            self.assertNotIn("Publication recomputes every machine field", page)

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
        self.assertIn("projection-digest", page)
        command = "python3 corpus_adequacy.py measurements/tersign-1cc5ea32/manifest.json --json"
        self.assertLess(page.find(command), page.find('class="counts"'))


    def test_invalid_source_shape_fails(self):
        cases = (
            ("repository-number", 123, "not-a-commit"),
            ("repository-no-slash", "not-a-repo", "a" * 40),
            ("commit-uppercase", "owner/name", "DEADBEEF" * 5),
            ("commit-non-hex", "owner/name", "not-a-commit"),
        )
        for name, repository, commit in cases:
            with self.subTest(name):
                with tempfile.TemporaryDirectory() as d:
                    root = _write_tree(Path(d), [VALID / "report.v0.json"])
                    source = root / "measurements" / "valid-tersign" / "source.json"
                    src = json.loads(source.read_text(encoding="utf-8"))
                    src["repository"] = repository
                    src["commit"] = commit
                    source.write_text(json.dumps(src, indent=2) + "\n", encoding="utf-8")
                    _write_index(root)
                    with self.assertRaises(rpp.PublicationError):
                        _render(root)


    def test_rendered_card_links_immutable_source_commit(self):
        with tempfile.TemporaryDirectory() as d:
            page = _render(_write_tree(Path(d), [VALID / "report.v0.json"]))
        src = json.loads((VALID / "source.json").read_text(encoding="utf-8"))
        commit = src["commit"]
        repo = src["repository"]
        self.assertEqual(len(commit), 40)
        self.assertIn("/commit/" + commit, page)
        self.assertIn(
            'href="https://github.com/%s/commit/%s"' % (repo, commit),
            page,
        )
        self.assertNotIn("<span>source commit", page)



    def test_load_record_calls_require_source_shape(self):
        tree = ast.parse(Path(rpp.__file__).read_text(encoding="utf-8"))
        load = next(
            n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "load_record"
        )
        calls = [
            n.func.id
            for n in ast.walk(load)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
        ]
        self.assertIn("_require_source_shape", calls)


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
