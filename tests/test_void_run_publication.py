#!/usr/bin/env python3
"""RED-first void-run-attempt publication: typed attempt artifact, never raw report."""

from __future__ import annotations

import hashlib
import json
import shutil
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
from test_publication_page import (  # noqa: E402
    INDEX_SCHEMA,
    VALID,
    _hex,
    _write_index,
    _write_tree,
)

FIXTURES = REPO_ROOT / "tests" / "fixtures" / "publication"
VOID_REPORT = FIXTURES / "void-run-attempt" / "report.v0.json"
ATTEMPT_ID = "a95d-void-run-attempt"
LIVE_ATTEMPT = (
    REPO_ROOT / "publications" / "run-attempts" / ATTEMPT_ID / "run-attempt.v0.json"
)
BUILD = "a" * 40
RAW_REPORT_SHA256 = (
    "88cc1b7e0e37ef9c4a6da17ecc1d62168b9f0f17b199203ca03c55471e587600"
)
EXECUTION_COMMIT = "a95d2344b5a242774cc03edf599359d2aaabedf2"
PREPARE_SHA256 = (
    "6b533b30ed1ba83a234826800a9e4d5d58574ac8201c17e6b996e249556197ce"
)
AUTHORIZE_SHA256 = (
    "4b06114a5dc194734b9fe1cbba3f8e6ab6dfe40215857194ccce684d2d5c7599"
)
FAILURE = "sealed: the UNMUTATED binary failed (unproved) on ['<batch>']"
INVENTED_FAILURE = "UNMUTATED baseline unproved; control and mutants were not run"
HOST_LEAK = "/private/tmp/ca-fixture-void-run/manifest.json"
COMPLETED_PAGES = (
    "runs/tersign-1cc5ea32/index.html",
    "runs/tersign-1cc5ea32/rules/0000.html",
    "runs/tersign-1cc5ea32/rules/0013.html",
)


def _text(files: dict[str, bytes], rel: str) -> str:
    return files[rel].decode("utf-8")


ATTEMPT_INDEX_SCHEMA = "corpus-adequacy.run-attempt-index.v0"
PINNED_DIGESTS = (
    RAW_REPORT_SHA256,
    EXECUTION_COMMIT,
    PREPARE_SHA256,
    AUTHORIZE_SHA256,
)
OTHER_HEX64 = "11" * 32
OTHER_COMMIT = "b" * 40


def _write_attempt_index(root: Path, *, measurement_ids: list[str] | None = None) -> None:
    _write_index(root, ids=measurement_ids if measurement_ids is not None else [])
    attempt = root / "publications" / "run-attempts" / ATTEMPT_ID / "run-attempt.v0.json"
    dest = root / "publications" / "run-attempts" / "index.v0.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(
        json.dumps(
            {
                "schema": ATTEMPT_INDEX_SCHEMA,
                "attempts": [
                    {"id": ATTEMPT_ID, "attempt_sha256": _hex(attempt)},
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def _attempt_tree(tmpdir: Path, attempt_doc: dict | None = None) -> Path:
    root = tmpdir / "tree"
    dest = root / "publications" / "run-attempts" / ATTEMPT_ID
    dest.mkdir(parents=True)
    if attempt_doc is None:
        shutil.copy2(LIVE_ATTEMPT, dest / "run-attempt.v0.json")
    else:
        (dest / "run-attempt.v0.json").write_text(
            json.dumps(attempt_doc, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    _write_attempt_index(root, measurement_ids=[])
    return root


def _canonical_attempt() -> dict:
    return json.loads(LIVE_ATTEMPT.read_text(encoding="utf-8"))


def _void_measurement_tree(tmpdir: Path) -> Path:
    staged = tmpdir / "staged" / "void-run-attempt"
    staged.mkdir(parents=True)
    shutil.copy2(VOID_REPORT, staged / "report.v0.json")
    shutil.copy2(VALID / "source.json", staged / "source.json")
    return _write_tree(tmpdir, [staged / "report.v0.json"], dummy_manifest=False)


class VoidRunAttemptPublication(unittest.TestCase):
    def test_void_shaped_report_cannot_enter_measurement_renderer(self):
        doc = json.loads(VOID_REPORT.read_text(encoding="utf-8"))
        self.assertTrue(rpp.is_void_run_attempt(doc))
        self.assertIn(HOST_LEAK, doc["manifest"])
        self.assertNotEqual(hashlib.sha256(VOID_REPORT.read_bytes()).hexdigest(), RAW_REPORT_SHA256)
        with self.assertRaises(rpp.PublicationError) as cm:
            rpp.load_record(VOID_REPORT)
        message = str(cm.exception).lower()
        self.assertIn("void", message)
        self.assertIn("measurement", message)
        with tempfile.TemporaryDirectory() as d:
            root = _void_measurement_tree(Path(d))
            with self.assertRaises(rpp.PublicationError):
                rpp.render_site(root, BUILD)

    def test_published_attempt_binds_retained_digests(self):
        doc = _canonical_attempt()
        self.assertEqual(doc["schema"], "corpus-adequacy.run-attempt.v0")
        self.assertEqual(doc["kind"], rpp.KIND_VOID_RUN_ATTEMPT)
        self.assertEqual(doc["raw_report_sha256"], RAW_REPORT_SHA256)
        self.assertEqual(doc["execution_commit"], EXECUTION_COMMIT)
        self.assertEqual(doc["prepare_sha256"], PREPARE_SHA256)
        self.assertEqual(doc["authorize_sha256"], AUTHORIZE_SHA256)
        self.assertEqual(doc["baseline_status"], "unproved")
        self.assertEqual(doc["control_status"], "not-run")
        self.assertEqual(doc["mutant_status"], "not-scored")
        self.assertEqual(doc["score_status"], "none")
        self.assertIn(FAILURE, doc["failures"])
        self.assertNotIn("commit", doc)
        self.assertNotIn("source", doc)
        live_text = LIVE_ATTEMPT.read_text(encoding="utf-8")
        for marker in rpp.HOST_MARKERS:
            self.assertNotIn(marker, live_text)
        record = rpp.load_run_attempt(LIVE_ATTEMPT)
        self.assertEqual(record["kind"], rpp.KIND_VOID_RUN_ATTEMPT)
        self.assertEqual(record["raw_report_sha256"], RAW_REPORT_SHA256)
        self.assertEqual(record["execution_commit"], EXECUTION_COMMIT)
        self.assertEqual(record["prepare_sha256"], PREPARE_SHA256)
        self.assertEqual(record["authorize_sha256"], AUTHORIZE_SHA256)

    def test_generic_loader_accepts_any_well_formed_attempt(self):
        src = Path(rpp.__file__).read_text(encoding="utf-8")
        for name in (
            "VOID_RAW_REPORT_SHA256",
            "VOID_EXECUTION_COMMIT",
            "VOID_PREPARE_SHA256",
            "VOID_AUTHORIZE_SHA256",
        ):
            self.assertNotIn(name, src)
        for digest in PINNED_DIGESTS:
            self.assertNotIn(digest, src)
        doc = dict(_canonical_attempt())
        doc["raw_report_sha256"] = OTHER_HEX64
        doc["execution_commit"] = OTHER_COMMIT
        doc["prepare_sha256"] = "22" * 32
        doc["authorize_sha256"] = "33" * 32
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "run-attempt.v0.json"
            path.write_text(
                json.dumps(doc, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            record = rpp.load_run_attempt(path)
        self.assertEqual(record["raw_report_sha256"], OTHER_HEX64)
        self.assertEqual(record["execution_commit"], OTHER_COMMIT)
        self.assertEqual(record["prepare_sha256"], "22" * 32)
        self.assertEqual(record["authorize_sha256"], "33" * 32)

    def _assert_void_publication(self, page: str) -> None:
        lower = page.lower()
        self.assertIn("void run attempt", lower)
        self.assertIn("baseline unproved", lower)
        self.assertIn("control not run", lower)
        self.assertIn("no scored mutants", lower)
        self.assertIn("no score", lower)
        self.assertIn("not a measurement", lower)
        self.assertIn(rpp._esc(FAILURE), page)
        self.assertIn(RAW_REPORT_SHA256, page)
        self.assertIn(EXECUTION_COMMIT, page)
        self.assertIn(PREPARE_SHA256, page)
        self.assertIn(AUTHORIZE_SHA256, page)
        self.assertNotIn("raw report.v0.json", lower)
        self.assertNotIn("/report.v0.json", page)
        self.assertNotIn(rpp.RAW_PREFIX, page)
        self.assertNotIn(HOST_LEAK, page)
        self.assertNotIn("/private/tmp/", page)
        self.assertNotIn("/Users/", page)
        self.assertNotIn('class="counts"', page)
        self.assertNotIn("Copyable command", page)
        self.assertNotIn(
            "python3 corpus_adequacy.py measurements/%s/manifest.json --json"
            % ATTEMPT_ID,
            page,
        )
        self.assertNotIn('aria-label="killed 0"', page)
        self.assertNotIn('aria-label="unproved 0"', page)

    def test_void_projection_has_no_raw_report_link(self):
        with tempfile.TemporaryDirectory() as d:
            files = rpp.render_site(_attempt_tree(Path(d)), BUILD)
        overview = _text(files, "index.html")
        run_page = _text(files, "runs/%s/index.html" % ATTEMPT_ID)
        self._assert_void_publication(overview)
        self._assert_void_publication(run_page)
        self.assertFalse(
            any(rel.startswith("runs/%s/rules/" % ATTEMPT_ID) for rel in files)
        )
        record = rpp.load_run_attempt(LIVE_ATTEMPT)
        with self.assertRaises(rpp.PublicationError):
            rpp._card_html(record, BUILD)
        with self.assertRaises(rpp.PublicationError):
            rpp._run_page(record, [], BUILD)

    def test_missing_or_wrong_authorize_is_red(self):
        base = _canonical_attempt()
        for mutated in (
            {key: value for key, value in base.items() if key != "authorize_sha256"},
            {key: value for key, value in base.items() if key != "prepare_sha256"},
            dict(base, authorize_sha256="ab"),
            dict(base, prepare_sha256="ab"),
        ):
            with self.subTest(mutated=sorted(set(base) ^ set(mutated))):
                with tempfile.TemporaryDirectory() as d:
                    path = Path(d) / "run-attempt.v0.json"
                    path.write_text(
                        json.dumps(mutated, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                    with self.assertRaises(rpp.PublicationError):
                        rpp.load_run_attempt(path)

    def test_source_commit_cannot_substitute_for_execution_commit(self):
        base = _canonical_attempt()
        swapped = dict(base)
        del swapped["execution_commit"]
        swapped["commit"] = EXECUTION_COMMIT
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "run-attempt.v0.json"
            path.write_text(
                json.dumps(swapped, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                rpp.PublicationError, "execution_commit"
            ):
                rpp.load_run_attempt(path)

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
        self.assertNotIn('id="void-attempts"', page)
        self.assertNotIn("Void run attempt", page)

    def test_mutation_routing_void_report_through_standard_renderer_is_red(self):
        with tempfile.TemporaryDirectory() as d:
            root = _void_measurement_tree(Path(d))
            with self.assertRaises(rpp.PublicationError):
                rpp.render_site(root, BUILD)
            with mock.patch.object(rpp, "is_void_run_attempt", return_value=False):
                mutated = rpp.render_site(root, BUILD)
            with self.assertRaises(AssertionError):
                self._assert_void_publication(_text(mutated, "index.html"))

    def test_mutation_presenting_null_score_as_zero_is_red(self):
        with tempfile.TemporaryDirectory() as d:
            page = _text(rpp.render_site(_attempt_tree(Path(d)), BUILD), "index.html")
        self._assert_void_publication(page)
        mutated = page.replace("No score", "0", 1)
        mutated = mutated.replace(
            "No scored mutants",
            '<ul class="counts"><li class="count" aria-label="killed 0">'
            '<span class="count-label">killed</span> '
            '<span class="count-value">0</span></li></ul>',
            1,
        )
        with self.assertRaises(AssertionError):
            self._assert_void_publication(mutated)

    def test_mutation_omitting_the_failure_is_red(self):
        with tempfile.TemporaryDirectory() as d:
            page = _text(rpp.render_site(_attempt_tree(Path(d)), BUILD), "index.html")
        self._assert_void_publication(page)
        mutated = page.replace(rpp._esc(FAILURE), "", 1)
        with self.assertRaises(AssertionError):
            self._assert_void_publication(mutated)

    def test_load_run_attempt_refuses_host_leak(self):
        base = _canonical_attempt()
        leaked = (
            dict(base, failures=[HOST_LEAK]),
            dict(base, non_claims=[HOST_LEAK]),
        )
        for doc in leaked:
            with self.subTest(fields=sorted(k for k in ("failures", "non_claims") if HOST_LEAK in str(doc.get(k)))):
                with tempfile.TemporaryDirectory() as d:
                    path = Path(d) / "run-attempt.v0.json"
                    path.write_text(
                        json.dumps(doc, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                    with self.assertRaisesRegex(rpp.PublicationError, "host"):
                        rpp.load_run_attempt(path)

    def test_committed_attempt_keeps_exact_retained_failure(self):
        src = (REPO_ROOT / "corpus_adequacy.py").read_text(encoding="utf-8")
        self.assertIn(
            '"%s: the UNMUTATED binary failed (%s) on %s"',
            src,
        )
        doc = _canonical_attempt()
        self.assertEqual(doc["raw_report_sha256"], RAW_REPORT_SHA256)
        self.assertEqual(doc["failures"][0], FAILURE)
        self.assertNotEqual(doc["failures"][0], INVENTED_FAILURE)
        live = LIVE_ATTEMPT.read_text(encoding="utf-8")
        self.assertIn(FAILURE, live)
        self.assertNotIn(INVENTED_FAILURE, live)
        self.assertNotIn(HOST_LEAK, live)
        self.assertNotIn("/private/tmp/", live)

    def test_load_run_attempt_refuses_other_windows_drive_roots(self):
        base = _canonical_attempt()
        for leak in (
            "D:/Users/leak/manifest.json",
            "D:\\Users\\leak\\manifest.json",
            "D:/leak/manifest.json",
        ):
            with self.subTest(leak=leak):
                doc = dict(base, failures=[leak])
                with tempfile.TemporaryDirectory() as d:
                    path = Path(d) / "run-attempt.v0.json"
                    path.write_text(
                        json.dumps(doc, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                    with self.assertRaisesRegex(rpp.PublicationError, "host|absolute"):
                        rpp.load_run_attempt(path)

    def test_publication_index_v0_is_closed_to_schema_and_records(self):
        live = json.loads(
            (REPO_ROOT / "publications" / "index.v0.json").read_text(encoding="utf-8")
        )
        self.assertEqual(set(live), {"schema", "records"})
        self.assertEqual(live["schema"], INDEX_SCHEMA)
        self.assertNotIn("attempts", live)
        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [VALID / "report.v0.json"])
            raw, entries = rpp.load_publication_index(root)
            doc = json.loads(raw.decode("utf-8"))
            self.assertEqual(set(doc), {"schema", "records"})
            self.assertEqual([item["id"] for item in entries], ["valid-tersign"])
            widened = dict(doc, attempts=[{"id": ATTEMPT_ID, "attempt_sha256": "0" * 64}])
            (root / "publications" / "index.v0.json").write_text(
                json.dumps(widened, indent=2) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(rpp.PublicationError, "unknown"):
                rpp.load_publication_index(root)

    def test_legacy_index_without_attempts_stays_identical(self):
        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [VALID / "report.v0.json"])
            index_path = root / "publications" / "index.v0.json"
            before = index_path.read_bytes()
            _index_bytes, records = rpp.load_listed_records(root)
            page = rpp.render_html(root, BUILD)
            self.assertEqual(index_path.read_bytes(), before)
            self.assertEqual(set(json.loads(before.decode("utf-8"))), {"schema", "records"})
            self.assertEqual(
                [rec["kind"] for rec in records],
                [rpp.KIND_COMPLETED_MEASUREMENT],
            )
            self.assertNotIn('id="void-attempts"', page)
            self.assertNotIn("Void run attempt", page)
            self.assertFalse(
                (root / "publications" / "run-attempts" / "index.v0.json").exists()
            )

    def test_separate_attempts_index_lists_the_committed_record(self):
        dest = REPO_ROOT / "publications" / "run-attempts" / "index.v0.json"
        doc = json.loads(dest.read_text(encoding="utf-8"))
        self.assertEqual(doc["schema"], ATTEMPT_INDEX_SCHEMA)
        self.assertEqual(set(doc), {"schema", "attempts"})
        self.assertEqual(doc["attempts"][0]["id"], ATTEMPT_ID)
        self.assertEqual(doc["attempts"][0]["attempt_sha256"], _hex(LIVE_ATTEMPT))
        _raw, attempts = rpp.load_attempt_index(REPO_ROOT)
        self.assertEqual(attempts[0]["id"], ATTEMPT_ID)

    def test_crlf_working_tree_bytes_miss_the_pinned_attempt_digest(self):
        attrs = (REPO_ROOT / ".gitattributes").read_text(encoding="utf-8")
        self.assertIn("publications/run-attempts/** text eol=lf", attrs)
        lf = LIVE_ATTEMPT.read_bytes()
        self.assertNotIn(b"\r\n", lf)
        digest = hashlib.sha256(lf).hexdigest()
        self.assertEqual(digest, _hex(LIVE_ATTEMPT))
        with tempfile.TemporaryDirectory() as d:
            crlf_path = Path(d) / "run-attempt.v0.json"
            crlf_path.write_bytes(lf.replace(b"\n", b"\r\n"))
            self.assertNotEqual(hashlib.sha256(crlf_path.read_bytes()).hexdigest(), digest)
            with self.assertRaisesRegex(rpp.PublicationError, "attempt digest mismatch"):
                rpp.load_run_attempt(crlf_path, expected_attempt_sha256=digest)

    def test_load_run_attempt_refuses_non_string_non_claims(self):
        base = _canonical_attempt()
        for hostile in (1, {"claim": "x"}, ["nested"]):
            with self.subTest(hostile=hostile):
                doc = dict(base, non_claims=[hostile])
                with tempfile.TemporaryDirectory() as d:
                    path = Path(d) / "run-attempt.v0.json"
                    path.write_text(
                        json.dumps(doc, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                    with self.assertRaisesRegex(rpp.PublicationError, "non_claims"):
                        rpp.load_run_attempt(path)

    def _title_and_h1(self, page: str) -> tuple[str, str]:
        title_start = page.find("<title>")
        title_end = page.find("</title>")
        h1_start = page.find("<h1>")
        h1_end = page.find("</h1>")
        self.assertNotEqual(title_start, -1)
        self.assertNotEqual(h1_start, -1)
        return (
            page[title_start + len("<title>") : title_end],
            page[h1_start + len("<h1>") : h1_end],
        )

    def _skip_target(self, page: str) -> str:
        marker = '<a class="skip" href="#'
        start = page.find(marker)
        self.assertNotEqual(start, -1)
        href_end = page.find('"', start + len(marker))
        target_id = page[start + len(marker) : href_end]
        target = page.find('id="%s"' % target_id)
        self.assertNotEqual(target, -1, target_id)
        return page[target:]

    def test_attempts_only_heading_avoids_measurements(self):
        with tempfile.TemporaryDirectory() as d:
            page = rpp.render_html(_attempt_tree(Path(d)), BUILD)
        title, heading = self._title_and_h1(page)
        self.assertNotIn("measurements", title.lower())
        self.assertNotIn("measurements", heading.lower())
        self.assertNotIn("Committed records", page)

    def test_skip_target_contains_void_section(self):
        mixed = rpp.render_html(REPO_ROOT, BUILD)
        with tempfile.TemporaryDirectory() as d:
            attempts_only = rpp.render_html(_attempt_tree(Path(d)), BUILD)
        for page in (mixed, attempts_only):
            with self.subTest(page=page[page.find("<h1>") : page.find("</h1>")]):
                self.assertIn('id="void-attempts"', self._skip_target(page))

    def test_measurement_only_copy_names_only_its_index(self):
        with tempfile.TemporaryDirectory() as d:
            page = rpp.render_html(
                _write_tree(Path(d), [VALID / "report.v0.json"]), BUILD
            )
        title, heading = self._title_and_h1(page)
        self.assertIn("Published measurements", heading)
        self.assertIn("publications/index.v0.json", page)
        self.assertNotIn("publications/run-attempts/index.v0.json", page)
        self.assertNotIn("void run attempts listed", page.lower())
        self.assertIn("measurements", title.lower())

    def test_mixed_copy_names_both_typed_indexes(self):
        page = rpp.render_html(REPO_ROOT, BUILD)
        title, heading = self._title_and_h1(page)
        self.assertNotIn("Published measurements", heading)
        self.assertNotIn("measurements", title.lower())
        self.assertIn("publications/index.v0.json", page)
        self.assertIn("publications/run-attempts/index.v0.json", page)
        self.assertIn("completed measurements", page)
        self.assertIn("void run attempts", page)

    def test_attempts_only_overview_omits_handoff_cta(self):
        with tempfile.TemporaryDirectory() as d:
            page = rpp.render_html(_attempt_tree(Path(d)), BUILD)
        self.assertNotIn("#publication-handoff", page)
        self.assertNotIn("Hand off a completed measurement", page)
        self.assertNotIn('id="publication-handoff"', page)
        self.assertIn("Request source intake", page)
        with tempfile.TemporaryDirectory() as d:
            measured = rpp.render_html(
                _write_tree(Path(d), [VALID / "report.v0.json"]), BUILD
            )
        self.assertIn("#publication-handoff", measured)
        self.assertIn('id="publication-handoff"', measured)


if __name__ == "__main__":
    unittest.main(verbosity=1)
