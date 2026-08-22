#!/usr/bin/env python3
"""RED-first publication page: one validated report.v0 card, no JS truth."""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
import shutil
import subprocess
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

    def test_bool_and_integral_float_counts_refuse_render(self):
        fixture = FIXTURES / "survived-silent" / "report.v0.json"
        base = json.loads(fixture.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [fixture])
            report = root / "measurements" / "survived-silent" / "report.v0.json"
            for name in rpp.DISPLAY_VERDICTS:
                for value in (True, float(base[name])):
                    with self.subTest(name=name, value=value):
                        mutated = dict(base)
                        mutated[name] = value
                        report.write_text(
                            json.dumps(mutated, indent=2, sort_keys=True) + "\n"
                        )
                        _write_index(root)
                        with self.assertRaises(rpp.PublicationError):
                            _render(root)

    def test_diagnostic_channel_is_exact_bool_or_absent(self):
        fixture = FIXTURES / "survived-silent" / "report.v0.json"
        base = json.loads(fixture.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [fixture])
            report = root / "measurements" / "survived-silent" / "report.v0.json"
            for value in (True, False):
                with self.subTest(accepted=value):
                    mutated = dict(base)
                    mutated["diagnostic_channel_declared"] = value
                    report.write_text(
                        json.dumps(mutated, indent=2, sort_keys=True) + "\n"
                    )
                    _write_index(root)
                    page = _render(root)
                    label = "declared" if value else "not declared"
                    self.assertIn(
                        'aria-label="diagnostic_channel_declared %s"' % label, page
                    )
            mutated = dict(base)
            del mutated["diagnostic_channel_declared"]
            report.write_text(json.dumps(mutated, indent=2, sort_keys=True) + "\n")
            _write_index(root)
            page = _render(root)
            self.assertIn('aria-label="diagnostic_channel_declared not declared"', page)
            for value in ("false", 1, None):
                with self.subTest(refused=value):
                    mutated = dict(base)
                    mutated["diagnostic_channel_declared"] = value
                    report.write_text(
                        json.dumps(mutated, indent=2, sort_keys=True) + "\n"
                    )
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
        repo_msg = "source repository is not owner/name"
        commit_msg = "source commit is not a 40-hex digest"
        cases = (
            ("repository-number", 123, "not-a-commit", repo_msg),
            ("repository-no-slash", "not-a-repo", "a" * 40, repo_msg),
            ("commit-uppercase", "owner/name", "DEADBEEF" * 5, commit_msg),
            ("commit-non-hex", "owner/name", "not-a-commit", commit_msg),
            ("owner-dot-dot", "../x", "a" * 40, repo_msg),
            ("repo-dot-dot", "x/..", "a" * 40, repo_msg),
            ("owner-dot", "./x", "a" * 40, repo_msg),
            ("repo-dot", "x/.", "a" * 40, repo_msg),
            ("owner-underscore", "_/repo", "a" * 40, repo_msg),
            ("owner-leading-hyphen", "-ab/name", "a" * 40, repo_msg),
            ("owner-trailing-hyphen", "ab-/name", "a" * 40, repo_msg),
            ("owner-too-long", ("a" * 40) + "/name", "a" * 40, repo_msg),
            ("empty-repo", "a/", "a" * 40, repo_msg),
        )
        for name, repository, commit, expected_message in cases:
            with self.subTest(name):
                with tempfile.TemporaryDirectory() as d:
                    root = _write_tree(Path(d), [VALID / "report.v0.json"])
                    source = root / "measurements" / "valid-tersign" / "source.json"
                    src = json.loads(source.read_text(encoding="utf-8"))
                    src["repository"] = repository
                    src["commit"] = commit
                    source.write_text(json.dumps(src, indent=2) + chr(10), encoding="utf-8")
                    _write_index(root)
                    with self.assertRaisesRegex(rpp.PublicationError, expected_message):
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



    def test_implicit_check_rejects_nonexistent_recorded_commit(self):
        zeros = "0" * 40
        with tempfile.TemporaryDirectory() as d:
            clone = Path(d) / "clone"
            subprocess.run(
                [
                    "git", "clone", "--quiet", "--no-hardlinks", "--no-tags",
                    str(REPO_ROOT), str(clone),
                ],
                check=True,
            )
            site = clone / "site" / "index.html"
            original = site.read_text(encoding="utf-8")
            recorded = rpp.source_commit_from_html(original)
            mutated = original.replace(recorded, zeros)
            self.assertIn(zeros, mutated)
            self.assertNotIn(recorded, mutated)
            site.write_text(mutated, encoding="utf-8")
            with self.assertRaisesRegex(
                rpp.PublicationError,
                "recorded source-commit is not a git commit",
            ):
                rpp.main(["--root", str(clone), "--out", str(site), "--check"])


    def test_implicit_check_rejects_crlf_provenance_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            clone = Path(d) / "clone"
            subprocess.run(
                [
                    "git", "clone", "--quiet", "--no-hardlinks", "--no-tags",
                    str(REPO_ROOT), str(clone),
                ],
                check=True,
            )
            proven = clone / "measurements" / "tersign-1cc5ea32" / "PROVENANCE.md"
            raw = proven.read_bytes()
            self.assertTrue(b"\n" in raw and b"\r\n" not in raw)
            proven.write_bytes(raw.replace(b"\n", b"\r\n"))
            site = clone / "site" / "index.html"
            with self.assertRaisesRegex(
                rpp.PublicationError,
                r"recorded source-commit bytes differ for .*PROVENANCE.md",
            ):
                rpp.main(["--root", str(clone), "--out", str(site), "--check"])


WHAT_THIS_MEASURES = (
    "This page identifies which author-declared rule-removal mutants "
    "the corpus distinguished."
)
SAFE_INSPECT_LABEL = "reads existing report bytes and does not measure"
EXIT_1_VISIBLE = (
    "exit 1 with --json is a completed inadequate measurement with "
    "declared survivors, not a crash"
)
EXIT_2_VISIBLE = "exit 2 is refusal"
EQUAL_COUNTS = "Equal counts do not imply identical report bytes."
REPORT_TOOL_COMMIT_LABEL = "report tool_commit"
PROJECTION_COMMIT_LABEL = "Pages projection source-commit"


def _visible_body(page: str) -> str:
    text = re.sub(r"<!--.*?-->", "", page, flags=re.S)
    text = re.sub(r"<style\b[^>]*>.*?</style>", "", text, flags=re.S)
    text = re.sub(r"<title\b[^>]*>.*?</title>", "", text, flags=re.S)
    return text


def _inspect_command(directory: str) -> str:
    return (
        "python3 corpus_adequacy.py --survivors measurements/%s/report.v0.json --json"
        % directory
    )


def _measure_command(directory: str) -> str:
    return "python3 corpus_adequacy.py measurements/%s/manifest.json --json" % directory


def _release_href() -> str:
    return (
        "https://github.com/corpus-adequacy/corpus-adequacy/releases/tag/v%s"
        % ca.VERSION
    )


def _first_run_script(page: str) -> str:
    start = page.find('id="first-run"')
    end = page.find('id="results"')
    self_section = page[start:end]
    for raw in re.findall(r"<pre><code>(.*?)</code></pre>", self_section, flags=re.S):
        text = html.unescape(raw)
        if "git clone" in text and "--survivors" in text and "\ncd " in text:
            return text
    raise AssertionError("first-run HTML has no obtain-then-inspect copy-paste block")


def _run_extracted_script(script: str) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory() as d:
        return subprocess.run(
            ["bash", "-c", script],
            cwd=d,
            capture_output=True,
            text=True,
            timeout=180,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )


def _assert_survivors_v0(proc: subprocess.CompletedProcess) -> None:
    if proc.returncode != 0:
        raise AssertionError(
            "first-run route rc=%s stderr=%r stdout=%r"
            % (proc.returncode, proc.stderr, proc.stdout[:500])
        )
    try:
        doc = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(
            "first-run route stdout is not JSON: %r" % proc.stdout[:500]
        ) from exc
    if not isinstance(doc, dict) or doc.get("schema") != "corpus-adequacy.survivors.v0":
        raise AssertionError("first-run route did not emit survivors.v0: %r" % proc.stdout[:500])


class FirstRunOrientation(unittest.TestCase):
    def _assert_orientation(self, page: str, directory: str, source_commit: str,
                            tool_commit: str, tool_content: str, tool_version: str):
        fold = page[: page.find('id="results"')]
        visible = _visible_body(page)
        inspect = _inspect_command(directory)
        measure = _measure_command(directory)
        self.assertIn(WHAT_THIS_MEASURES, fold)
        self.assertLess(page.find(WHAT_THIS_MEASURES), page.find('class="card"'))
        self.assertIn(SAFE_INSPECT_LABEL, fold)
        self.assertIn(inspect, fold)
        self.assertNotIn(measure, fold)
        route = _first_run_script(page)
        self.assertIn(inspect, route)
        self.assertLess(route.find("git clone"), route.find("\ncd "))
        self.assertLess(route.find("\ncd "), route.find(inspect))
        self.assertIn("cd corpus-adequacy", route)
        self.assertIn(measure, page[page.find('id="results"') :])
        self.assertIn(EXIT_1_VISIBLE, visible)
        self.assertIn(EXIT_2_VISIBLE, visible)
        self.assertIn(EQUAL_COUNTS, visible)
        self.assertIn(REPORT_TOOL_COMMIT_LABEL, fold)
        self.assertIn(PROJECTION_COMMIT_LABEL, fold)
        self.assertIn(tool_commit, fold)
        self.assertIn(source_commit, fold)
        self.assertIn(tool_content, fold)
        self.assertIn(tool_version, fold)
        self.assertNotEqual(tool_commit, source_commit)
        commit_block = fold[fold.find(REPORT_TOOL_COMMIT_LABEL):]
        self.assertLess(
            commit_block.find(tool_commit),
            commit_block.find(PROJECTION_COMMIT_LABEL),
        )
        self.assertIn(_release_href(), page)
        for href in re.findall(r'releases/tag/([^"\s]+)', page):
            self.assertEqual(href, "v%s" % ca.VERSION)
            self.assertIsNone(re.fullmatch(r"[0-9a-f]{40}", href))
        self.assertIn("--branch v%s" % ca.VERSION, page)
        self.assertIn('class="skip"', page)
        self.assertIn("<h1>", page)
        self.assertIn("<h2 id=\"first-run-heading\">", page)
        self.assertIn("overflow-x: hidden", page)
        self.assertIn("width: min(100%, 390px)", page)
        self.assertIn("a:focus", page)

    def test_live_overview_has_first_run_orientation(self):
        source_commit = "f" * 40
        page = rpp.render_html(REPO_ROOT, source_commit=source_commit)
        doc = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        self._assert_orientation(
            page,
            "tersign-1cc5ea32",
            source_commit,
            doc["tool_commit"],
            doc["tool_content_sha256"],
            doc["tool_version"],
        )

    def test_extracted_first_run_route_runs_from_empty_tempdir(self):
        page = rpp.render_html(REPO_ROOT, source_commit="f" * 40)
        _assert_survivors_v0(_run_extracted_script(_first_run_script(page)))

    def test_fixture_overview_binds_listed_report_inspect_path(self):
        source_commit = "a" * 40
        with tempfile.TemporaryDirectory() as d:
            page = _render(_write_tree(Path(d), [VALID / "report.v0.json"]),
                           source_commit=source_commit)
        doc = json.loads((VALID / "report.v0.json").read_text(encoding="utf-8"))
        self._assert_orientation(
            page,
            "valid-tersign",
            source_commit,
            doc["tool_commit"],
            doc["tool_content_sha256"],
            doc["tool_version"],
        )

    def _fixture_page(self):
        source_commit = "a" * 40
        with tempfile.TemporaryDirectory() as d:
            page = _render(_write_tree(Path(d), [VALID / "report.v0.json"]),
                           source_commit=source_commit)
        doc = json.loads((VALID / "report.v0.json").read_text(encoding="utf-8"))
        return page, source_commit, doc

    def _assert_mutant_is_red(self, page: str, source_commit: str, doc: dict):
        with self.assertRaises(AssertionError):
            self._assert_orientation(
                page,
                "valid-tersign",
                source_commit,
                doc["tool_commit"],
                doc["tool_content_sha256"],
                doc["tool_version"],
            )

    def test_mutation_inspect_pre_replaced_by_measure_is_red(self):
        page, source_commit, doc = self._fixture_page()
        inspect = _inspect_command("valid-tersign")
        measure = _measure_command("valid-tersign")
        mutated = page.replace(inspect, measure, 1)
        self._assert_mutant_is_red(mutated, source_commit, doc)

    def test_mutation_drop_cd_or_inspect_before_clone_runtime_is_red(self):
        page = rpp.render_html(REPO_ROOT, source_commit="f" * 40)
        script = _first_run_script(page)
        dropped = "\n".join(
            line for line in script.splitlines() if not line.startswith("cd ")
        )
        reordered = "\n".join(
            [line for line in script.splitlines() if "--survivors" in line]
            + [line for line in script.splitlines() if "--survivors" not in line]
        )
        for mutant in (dropped, reordered):
            with self.subTest(mutant=mutant.splitlines()[0][:40]):
                with self.assertRaises(AssertionError):
                    _assert_survivors_v0(_run_extracted_script(mutant))

    def test_mutation_survivors_points_at_manifest_is_red(self):
        page, source_commit, doc = self._fixture_page()
        mutated = page.replace(
            "--survivors measurements/valid-tersign/report.v0.json",
            "--survivors measurements/valid-tersign/manifest.json",
            1,
        )
        self._assert_mutant_is_red(mutated, source_commit, doc)

    def test_mutation_collapsed_commit_fields_is_red(self):
        page, source_commit, doc = self._fixture_page()
        mutated = page.replace(REPORT_TOOL_COMMIT_LABEL, "commit", 1)
        mutated = mutated.replace(PROJECTION_COMMIT_LABEL, "commit", 1)
        self._assert_mutant_is_red(mutated, source_commit, doc)

    def test_mutation_exit_1_only_in_comment_title_or_css_is_red(self):
        page, source_commit, doc = self._fixture_page()
        hidden = (
            page.replace(EXIT_1_VISIBLE, "<!-- %s -->" % EXIT_1_VISIBLE, 1)
            .replace("<title>", "<title>%s " % EXIT_1_VISIBLE, 1)
        )
        hidden = hidden.replace(
            "overflow-x: hidden",
            "overflow-x: hidden; /* %s */" % EXIT_1_VISIBLE,
            1,
        )
        self.assertIn(EXIT_1_VISIBLE, hidden)
        self.assertNotIn(EXIT_1_VISIBLE, _visible_body(hidden))
        self._assert_mutant_is_red(hidden, source_commit, doc)

    def test_mutation_release_href_hardcodes_sha_is_red(self):
        page, source_commit, doc = self._fixture_page()
        mutated = page.replace(_release_href(), _release_href().rsplit("/v", 1)[0] + "/" + "b" * 40, 1)
        self._assert_mutant_is_red(mutated, source_commit, doc)


if __name__ == "__main__":
    unittest.main(verbosity=1)
