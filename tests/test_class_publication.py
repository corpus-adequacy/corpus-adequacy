#!/usr/bin/env python3
"""Separate evidence classes on the publication site (#103).

One candidate and one corpus, measured with two separately authored mutant sets, shown side by
side with two denominators and nothing added together. These tests read retained bytes only:
no candidate, no Docker, no PREPARE.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import sys
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
for entry in (str(ROOT), str(ROOT / "measurements"), str(ROOT / "scripts")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import corpus_adequacy as ca  # noqa: E402
import render_publication_page as rpp  # noqa: E402

EVIDENCE = "owned-slice-b-20f6d8b"
FIRST_EVIDENCE = "owned-slice-b-5918ec4"
MANIFESTS = ("measurements/owned-contained-v1/manifest.json",
             "measurements/owned-independent-v0/manifest.json")
BUILD = "c" * 40


def _entry(root: Path, evidence: str = EVIDENCE, comparison_id: str = "owned-slice-b") -> dict:
    entry = {"id": comparison_id, "evidence": evidence}
    for key, rel in rpp.CLASS_ENTRY_FILES.items():
        raw = (root / "measurements" / evidence / rel).read_bytes()
        entry[key] = hashlib.sha256(raw).hexdigest()
    return entry


def _write_index(root: Path, entries: list, **extra) -> None:
    doc = dict({"comparisons": entries, "schema": rpp.CLASS_INDEX_SCHEMA}, **extra)
    path = root / rpp.CLASS_INDEX_REL
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _tree(tmp: Path, *, evidence: str = EVIDENCE) -> Path:
    """The files a comparison loader reads, copied from this checkout."""
    root = tmp / "tree"
    shutil.copytree(ROOT / "measurements" / evidence, root / "measurements" / evidence)
    for rel in MANIFESTS:
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / rel, root / rel)
    return root


def _rewrite_json(path: Path, change) -> None:
    doc = json.loads(path.read_text(encoding="utf-8"))
    change(doc)
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class _Text(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts, self._skip = [], False

    def handle_starttag(self, tag, attrs):
        if tag == "style":
            self._skip = True

    def handle_endtag(self, tag):
        if tag == "style":
            self._skip = False

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


def _visible_text(page: str) -> str:
    parser = _Text()
    parser.feed(page)
    return re.sub(r"\s+", " ", " ".join(parser.parts))


def _live():
    _raw, comparisons = rpp.load_class_comparisons(ROOT)
    return comparisons


class TheLiveComparison(unittest.TestCase):
    def test_one_comparison_is_published_from_the_clean_measurement(self):
        comparisons = _live()
        self.assertEqual([c["id"] for c in comparisons], ["owned-slice-b"])
        self.assertEqual(comparisons[0]["evidence"], EVIDENCE)

    def test_each_side_keeps_its_own_denominator(self):
        rec = _live()[0]
        self.assertEqual((rec["declared"]["counts"]["killed"], rec["declared"]["scored"]),
                         (2, 2))
        self.assertEqual((rec["independent"]["counts"]["killed"],
                          rec["independent"]["scored"]), (0, 1))

    def test_the_page_shows_counts_and_never_a_percentage_or_a_total(self):
        page = _visible_text(rpp._class_page(_live()[0], BUILD))
        self.assertIn("2 of 2", page)
        self.assertIn("0 of 1", page)
        self.assertNotIn("%", page)
        # Two plus one is the number a pooled score would use. It must not appear anywhere.
        # Bare digits would match inside the hex digests the page shows, so probe fractions.
        for pooled in ("of 3", "3 mutants", "2/3", "0.66", "0.67"):
            self.assertNotIn(pooled, page, pooled)

    def test_the_survivor_comes_before_the_comparison_table(self):
        page = rpp._class_page(_live()[0], BUILD)
        survivor = page.index("truncate owned-fixture upper guard to the first value above maximum")
        self.assertLess(page.index('id="findings-heading"'), page.index("<table>"))
        self.assertLess(survivor, page.index("<table>"))

    def test_the_table_is_accessible_and_has_exactly_two_data_columns(self):
        page = rpp._class_page(_live()[0], BUILD)
        table = page[page.index("<table>"):page.index("</table>")]
        self.assertIn("<caption>", table)
        self.assertEqual(re.findall(r'<th scope="col">([^<]*)</th>', table),
                         ["Declared", "Independent"])
        rows = re.findall(r"<tr>(.*?)</tr>", table, flags=re.S)[1:]
        self.assertTrue(rows)
        for row in rows:
            self.assertEqual(row.count('<th scope="row">'), 1)
            self.assertEqual(row.count("<td>"), 2)

    def test_the_independent_column_says_what_its_author_could_see(self):
        page = _visible_text(rpp._class_page(_live()[0], BUILD))
        self.assertIn("Codex delegated selection writer, as recorded and not authenticated", page)
        self.assertIn("committed openly before the run; not held out", page)

    def test_the_overview_links_the_comparison_without_a_combined_number(self):
        files = rpp.render_site(ROOT, BUILD)
        self.assertIn("classes/owned-slice-b/index.html", files)
        overview = files["index.html"].decode("utf-8")
        self.assertIn('id="evidence-classes"', overview)
        self.assertIn('href="classes/owned-slice-b/index.html"', overview)
        section = overview[overview.index('id="evidence-classes"'):]
        self.assertNotIn("%", _visible_text(section[:section.index("</section>")]))

    def test_evidence_links_name_every_bound_file_at_the_build_commit(self):
        page = rpp._class_page(_live()[0], BUILD)
        for rel in rpp.CLASS_ENTRY_FILES.values():
            self.assertIn("%s/%s/measurements/%s/%s" % (rpp.RAW_PREFIX, BUILD, EVIDENCE, rel),
                          page)


class Termination(unittest.TestCase):
    def test_only_a_list_of_termination_kinds_counts_as_termination(self):
        for how, expected in (("timeout", True), ("output-cap, timeout", True),
                              ("signal", True), ("1 vector(s) moved", False),
                              ("parse-error", False), ("", False), (None, False)):
            with self.subTest(how=how):
                self.assertIs(rpp._is_termination_how(how), expected)

    def test_a_kill_by_termination_is_named_on_the_page(self):
        rec = _live()[0]
        rec["declared"] = dict(rec["declared"], by_termination=1, ordinary=[
            ("killed", "a mutant the candidate only crashed under", True)])
        page = _visible_text(rpp._class_page(rec, BUILD))
        self.assertIn("killed, but only by the candidate ending abnormally", page)


class Refusals(unittest.TestCase):
    def _load(self, root: Path):
        return rpp.load_class_comparisons(root)

    def test_the_clean_tree_loads(self):
        with tempfile.TemporaryDirectory() as d:
            root = _tree(Path(d))
            _write_index(root, [_entry(root)])
            self.assertEqual(self._load(root)[1][0]["id"], "owned-slice-b")

    def test_a_changed_byte_in_any_bound_file_is_refused(self):
        for rel in rpp.CLASS_ENTRY_FILES.values():
            with self.subTest(rel=rel), tempfile.TemporaryDirectory() as d:
                root = _tree(Path(d))
                _write_index(root, [_entry(root)])
                path = root / "measurements" / EVIDENCE / rel
                path.write_bytes(path.read_bytes() + b" ")
                with self.assertRaisesRegex(rpp.PublicationError, "digest mismatch"):
                    self._load(root)

    def test_the_first_measurement_cannot_be_published(self):
        """Its reports carry a host path (#204); the clean re-measurement exists for this."""
        with tempfile.TemporaryDirectory() as d:
            root = _tree(Path(d), evidence=FIRST_EVIDENCE)
            _write_index(root, [_entry(root, evidence=FIRST_EVIDENCE)])
            with self.assertRaisesRegex(rpp.PublicationError, "manifest contains"):
                self._load(root)

    def test_the_index_is_closed(self):
        with tempfile.TemporaryDirectory() as d:
            root = _tree(Path(d))
            entry = _entry(root)
            _write_index(root, [entry], extra="x")
            with self.assertRaisesRegex(rpp.PublicationError, "unknown fields"):
                self._load(root)
            _write_index(root, [dict(entry, score="0 of 3")])
            with self.assertRaisesRegex(rpp.PublicationError, "unknown"):
                self._load(root)
            partial = dict(entry)
            del partial["declared_prepare_sha256"]
            _write_index(root, [partial])
            with self.assertRaisesRegex(rpp.PublicationError, "missing"):
                self._load(root)
            _write_index(root, [entry, dict(entry)])
            with self.assertRaisesRegex(rpp.PublicationError, "more than once"):
                self._load(root)

    def test_a_class_attempt_that_binds_another_report_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root = _tree(Path(d))
            path = root / "measurements" / EVIDENCE / "independent" / "class-attempt.v0.json"
            doc = json.loads(path.read_text(encoding="utf-8"))
            doc["report_sha256"] = "sha256:" + "0" * 64
            path.write_bytes(ca.encode_class_attempt_v0(doc))
            _write_index(root, [_entry(root)])
            with self.assertRaisesRegex(rpp.PublicationError, "does not bind the listed report"):
                self._load(root)

    def test_non_canonical_class_artifact_bytes_are_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root = _tree(Path(d))
            path = root / "measurements" / EVIDENCE / "independent" / "class-attempt.v0.json"
            doc = json.loads(path.read_text(encoding="utf-8"))
            path.write_text(json.dumps(doc, separators=(",", ":")), encoding="utf-8")
            self.assertNotEqual(path.read_bytes(), ca.encode_class_attempt_v0(doc))
            _write_index(root, [_entry(root)])
            with self.assertRaisesRegex(rpp.PublicationError, "not canonical"):
                self._load(root)

    def test_an_unproved_class_has_nothing_to_set_beside_another(self):
        with tempfile.TemporaryDirectory() as d:
            root = _tree(Path(d))
            path = root / "measurements" / EVIDENCE / "independent" / "class-attempt.v0.json"
            doc = json.loads(path.read_text(encoding="utf-8"))
            doc["status"] = "unproved"
            path.write_bytes(ca._encode_class_artifact_v0(doc))
            _write_index(root, [_entry(root)])
            # Isolate the status check from the codec, which would also refuse this document.
            with mock.patch.object(rpp.ca, "encode_class_attempt_v0",
                                   side_effect=ca._encode_class_artifact_v0):
                with self.assertRaisesRegex(rpp.PublicationError, "unproved class"):
                    self._load(root)

    def test_sides_that_did_not_share_one_environment_are_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root = _tree(Path(d))
            _rewrite_json(root / "measurements" / EVIDENCE / "declared" / "prepare.v2.json",
                          lambda doc: doc["toolchain"].update(image_id="sha256:" + "1" * 64))
            _write_index(root, [_entry(root)])
            with self.assertRaisesRegex(rpp.PublicationError, "did not share toolchain"):
                self._load(root)

    def test_a_report_whose_manifest_bytes_changed_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root = _tree(Path(d))
            manifest = root / MANIFESTS[0]
            manifest.write_bytes(manifest.read_bytes() + b"\n")
            _write_index(root, [_entry(root)])
            with self.assertRaisesRegex(rpp.PublicationError, "did not measure"):
                self._load(root)

    def test_a_side_whose_positive_control_survived_has_no_result(self):
        with tempfile.TemporaryDirectory() as d:
            root = _tree(Path(d))
            _write_index(root, [_entry(root)])
            original = rpp._require_displayed_parity

            def survived_control(doc, mutants):
                original(doc, mutants)
                doc["control_status"] = "survived"

            with mock.patch.object(rpp, "_require_displayed_parity",
                                   side_effect=survived_control):
                with self.assertRaisesRegex(rpp.PublicationError, "positive control is survived"):
                    self._load(root)

    def test_no_index_publishes_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            root = _tree(Path(d))
            self.assertEqual(self._load(root), (b"", []))


class TheProjectionDigestBindsTheComparison(unittest.TestCase):
    def test_changing_a_bound_byte_changes_the_digest(self):
        index_bytes, comparisons = rpp.load_class_comparisons(ROOT)
        args = (b"index", [], b"renderer", BUILD)
        before = rpp.compute_projection_digest(
            *args, class_index_bytes=index_bytes, comparisons=comparisons)
        moved = [dict(comparisons[0], files=dict(comparisons[0]["files"]))]
        rel = "independent/report.v0.json"
        moved[0]["files"][rel] = moved[0]["files"][rel] + b" "
        after = rpp.compute_projection_digest(
            *args, class_index_bytes=index_bytes, comparisons=moved)
        self.assertNotEqual(before, after)

    def test_without_an_index_the_digest_is_what_it_was(self):
        args = (b"index", [], b"renderer", BUILD)
        self.assertEqual(rpp.compute_projection_digest(*args),
                         rpp.compute_projection_digest(*args, class_index_bytes=b"",
                                                       comparisons=[]))


class TheEvidenceLinkCommit(unittest.TestCase):
    def test_a_commit_before_the_evidence_existed_cannot_carry_its_links(self):
        """The site was pinned to aa2ef19, which predates the Slice B evidence."""
        with self.assertRaisesRegex(rpp.PublicationError, "missing measurements/%s" % EVIDENCE):
            rpp._require_recorded_link_commit(
                ROOT, "aa2ef19efaa8f6140f7a1766553768984b60e5aa", [], _live())

    def test_the_recorded_commit_carries_every_linked_byte(self):
        recorded = rpp.source_commit_from_html(
            (ROOT / "site" / "index.html").read_text(encoding="utf-8"))
        rpp._require_recorded_link_commit(ROOT, recorded, [], _live())


if __name__ == "__main__":
    unittest.main()
