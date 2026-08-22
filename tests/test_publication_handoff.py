#!/usr/bin/env python3
"""RED-first publication handoff URL from validated report bytes only."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlparse

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import corpus_adequacy as ca  # noqa: E402
import publication_handoff as handoff  # noqa: E402
import render_publication_page as rpp  # noqa: E402
from test_publication_page import _render, _write_index, _write_tree  # noqa: E402

XSS_PAYLOAD = "<" + "script>alert(1)</scr" + "ipt>"
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "publication"
VALID = FIXTURES / "valid-tersign"
UNPROVED = FIXTURES / "unproved-control"
TEMPLATE = REPO_ROOT / ".github" / "ISSUE_TEMPLATE" / "publish-measurement.yml"
INTAKE = REPO_ROOT / ".github" / "ISSUE_TEMPLATE" / "add-corpus.yml"
INTAKE_IDS = (
    "repository-url",
    "source-commit",
    "manifest-path",
    "adapter",
    "runner",
    "license-context",
    "relationship",
    "public-context",
    "scoped-request",
    "consent",
)


def _ids_from_text(text: str) -> tuple[str, ...]:
    ids = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("id:"):
            ids.append(stripped.split(":", 1)[1].strip())
    return tuple(ids)


def _ids_in_yaml(path: Path) -> tuple[str, ...]:
    return _ids_from_text(path.read_text(encoding="utf-8"))


def _handoff_command(report_rel: str) -> str:
    return "python3 scripts/publication_handoff.py %s" % report_rel


class PublicationHandoff(unittest.TestCase):
    def test_publication_form_ids_are_exact_closed_set(self):
        expected = handoff.MACHINE_FIELD_IDS + handoff.USER_FIELD_IDS
        self.assertEqual(_ids_in_yaml(TEMPLATE), expected)
        self.assertEqual(len(set(expected)), len(expected))
        self.assertIn("source-sha256", handoff.MACHINE_FIELD_IDS)
        self.assertIn("public-evidence-url", handoff.USER_FIELD_IDS)
        self.assertNotIn("public-evidence-url", handoff.MACHINE_FIELD_IDS)
        intake_ids = _ids_in_yaml(INTAKE)
        for fid in INTAKE_IDS:
            self.assertIn(fid, intake_ids)
        renamed = TEMPLATE.read_text(encoding="utf-8").replace(
            "id: killed", "id: killed-count", 1
        )
        self.assertNotEqual(_ids_from_text(renamed), expected)
        self.assertIn("killed-count", _ids_from_text(renamed))
        added = expected + ("extra-field",)
        self.assertNotEqual(added, expected)
        without_source_sha = tuple(
            fid for fid in expected if fid != "source-sha256"
        )
        self.assertNotEqual(without_source_sha, expected)
        form = TEMPLATE.read_text(encoding="utf-8")
        start = form.find("id: source-sha256")
        self.assertNotEqual(start, -1)
        block = form[start : start + 500]
        self.assertIn("source.json metadata SHA-256", block)
        self.assertIn("validated source.json metadata bytes", block)
        self.assertNotIn("source corpus", block.lower())
        self.assertNotIn("upstream content", block.lower())

    def test_fixture_digest_swap_changes_url(self):
        url = handoff.handoff_url(VALID / "report.v0.json")
        digest = hashlib.sha256((VALID / "report.v0.json").read_bytes()).hexdigest()
        source_digest = hashlib.sha256((VALID / "source.json").read_bytes()).hexdigest()
        qs = parse_qs(urlparse(url).query)
        self.assertEqual(qs["template"], ["publish-measurement.yml"])
        self.assertEqual(qs["report-digest"], [digest])
        self.assertEqual(qs["source-sha256"], [source_digest])
        self.assertEqual(qs["killed"], ["10"])
        self.assertEqual(qs["survived"], ["2"])
        self.assertEqual(qs["silent"], ["0"])
        self.assertEqual(qs["unproved"], ["0"])
        self.assertEqual(qs["control-status"], ["killed"])
        self.assertEqual(qs["source-commit"], ["1cc5ea32b3da4f195b55782c8a3573d8564673a7"])
        self.assertEqual(qs["runner"], ["process"])
        self.assertEqual(qs["tool-commit"], ["a2f723fe5ae5036e97090b9691316e483c3f1acc"])
        self.assertNotIn("public-evidence-url", qs)
        for fid in handoff.MACHINE_FIELD_IDS:
            self.assertIn(fid, qs)
        for fid in handoff.USER_FIELD_IDS:
            self.assertNotIn(fid, qs)
        with tempfile.TemporaryDirectory() as d:
            clone = Path(d) / "report.v0.json"
            src = Path(d) / "source.json"
            doc = json.loads((VALID / "report.v0.json").read_text(encoding="utf-8"))
            doc["killed"] = 1
            clone.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
            src.write_text((VALID / "source.json").read_text(encoding="utf-8"))
            with self.assertRaises(rpp.PublicationError):
                handoff.handoff_url(clone)

    def test_hostile_query_does_not_prefab_machine_fields(self):
        source_digest = hashlib.sha256((VALID / "source.json").read_bytes()).hexdigest()
        hostile = {
            "QUERY_STRING": (
                "killed=0&report-digest=deadbeef&source-commit=ff&source-sha256=aa"
                "&public-evidence-url=https://evil.example&display-name=" + XSS_PAYLOAD
            ),
            "killed": "0",
            "report-digest": "deadbeef",
            "source-sha256": "aa" * 32,
            "public-evidence-url": "https://evil.example",
        }
        with mock.patch.dict(os.environ, hostile, clear=False):
            url = handoff.handoff_url(VALID / "report.v0.json")
        qs = parse_qs(urlparse(url).query)
        self.assertNotEqual(qs["killed"], ["0"])
        self.assertEqual(qs["killed"], ["10"])
        self.assertNotEqual(qs["report-digest"], ["deadbeef"])
        self.assertNotEqual(qs["source-commit"], ["ff"])
        self.assertEqual(qs["source-sha256"], [source_digest])
        self.assertNotEqual(qs["source-sha256"], ["aa" * 32])
        self.assertNotIn("public-evidence-url", qs)
        self.assertNotIn("evil.example", url)
        src = Path(handoff.__file__).read_text(encoding="utf-8")
        self.assertNotIn("os.environ", src)
        self.assertNotIn("QUERY_STRING", src)

    def test_adequate_false_and_unproved_emit_url(self):
        tersign = handoff.handoff_url(VALID / "report.v0.json")
        self.assertTrue(tersign.startswith(
            "https://github.com/corpus-adequacy/corpus-adequacy/issues/new?template=publish-measurement.yml&"
        ))
        qs = parse_qs(urlparse(tersign).query)
        self.assertEqual(qs["unproved"], ["0"])
        self.assertEqual(qs["control-status"], ["killed"])
        doc = json.loads((VALID / "report.v0.json").read_text(encoding="utf-8"))
        self.assertFalse(doc["adequate"])

        unp = handoff.handoff_url(UNPROVED / "report.v0.json")
        uqs = parse_qs(urlparse(unp).query)
        self.assertEqual(uqs["unproved"], ["3"])
        self.assertNotEqual(uqs["control-status"], ["killed"])
        self.assertEqual(uqs["control-status"], ["survived"])

    def test_recomputes_from_bytes_not_caller_kwargs(self):
        url = handoff.handoff_url(
            VALID / "report.v0.json",
            killed="0",
            report_digest="deadbeef",
        )
        qs = parse_qs(urlparse(url).query)
        self.assertEqual(qs["killed"], ["10"])
        digest = hashlib.sha256((VALID / "report.v0.json").read_bytes()).hexdigest()
        self.assertEqual(qs["report-digest"], [digest])

    def test_row_validator_rejects_empty_mutant_fields(self):
        bad = json.loads((VALID / "report.v0.json").read_text(encoding="utf-8"))
        bad["mutants"][0]["label"] = ""
        with self.assertRaises(ca.ManifestError):
            rpp._require_report_rows(bad)

    def _assert_primary_handoff_cta(self, page: str):
        match = re.search(
            r'<a href="([^"]+)">Hand off a completed measurement</a>',
            page,
        )
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "#publication-handoff")
        self.assertNotEqual(match.group(1), rpp.ISSUES_PUBLISH)
        self.assertIn('id="publication-handoff"', page)
        self.assertIn("Manual empty publication form", page)
        self.assertIn(rpp.ISSUES_PUBLISH, page)

    def test_page_and_prefill_use_the_same_fixture_bytes(self):
        report = VALID / "report.v0.json"
        source = VALID / "source.json"
        record = rpp.load_record(report)
        report_digest = hashlib.sha256(report.read_bytes()).hexdigest()
        source_digest = hashlib.sha256(source.read_bytes()).hexdigest()
        self.assertEqual(record["digest"], report_digest)
        self.assertEqual(record["source_digest"], source_digest)
        url = handoff.handoff_url(report)
        qs = parse_qs(urlparse(url).query)
        self.assertEqual(qs["source-sha256"], [source_digest])
        self.assertEqual(qs["report-digest"], [report_digest])
        self.assertEqual(qs["source-commit"], [record["source_commit"]])
        self.assertEqual(qs["adapter"], [record["adapter"]])
        self.assertEqual(qs["runner"], [record["runner"]])
        self.assertEqual(qs["killed"], [str(record["killed"])])
        self.assertEqual(qs["survived"], [str(record["survived"])])
        self.assertEqual(qs["silent"], [str(record["silent"])])
        self.assertEqual(qs["unproved"], [str(record["unproved"])])
        self.assertEqual(qs["control-status"], [str(record["control_status"])])
        command = _handoff_command(record["report_rel"])
        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [report])
            page = _render(root)
            self.assertIn(report_digest, page)
            self.assertIn(source_digest, page)
            self.assertIn("source.json metadata SHA-256", page)
            self.assertNotIn("source corpus", page.lower())
            self.assertNotIn("upstream content", page.lower())
            self.assertIn(record["source_commit"], page)
            self.assertIn(command, page)
            self._assert_primary_handoff_cta(page)
            report_path = root / "measurements" / "valid-tersign" / "report.v0.json"
            source_path = root / "measurements" / "valid-tersign" / "source.json"
            source_path.write_bytes(source_path.read_bytes() + b"\n")
            _write_index(root)
            page_b = _render(root)
            url_b = handoff.handoff_url(report_path)
            new_source = hashlib.sha256(source_path.read_bytes()).hexdigest()
            self.assertNotEqual(source_digest, new_source)
            self.assertNotEqual(page, page_b)
            self.assertNotEqual(url, url_b)
            self.assertIn(new_source, page_b)
            self.assertNotIn(new_source, page)
            self.assertEqual(
                parse_qs(urlparse(url_b).query)["source-sha256"],
                [new_source],
            )
            self.assertNotEqual(
                parse_qs(urlparse(url).query)["source-sha256"],
                [new_source],
            )

    def test_mutation_primary_cta_empty_form_is_red(self):
        with tempfile.TemporaryDirectory() as d:
            page = _render(_write_tree(Path(d), [VALID / "report.v0.json"]))
        mutated = page.replace(
            'href="#publication-handoff">Hand off a completed measurement',
            'href="%s">Hand off a completed measurement' % rpp.ISSUES_PUBLISH,
            1,
        )
        with self.assertRaises(AssertionError):
            self._assert_primary_handoff_cta(mutated)

    def test_mutation_handoff_command_uses_manifest_is_red(self):
        record = rpp.load_record(VALID / "report.v0.json")
        command = _handoff_command(record["report_rel"])
        swapped = command.replace("report.v0.json", "manifest.json", 1)
        with tempfile.TemporaryDirectory() as d:
            page = _render(_write_tree(Path(d), [VALID / "report.v0.json"]))
        self.assertIn(command, page)
        self.assertNotIn(swapped, page)
        mutated = page.replace(command, swapped, 1)
        with self.assertRaises(AssertionError):
            self.assertIn(command, mutated)
            self.assertNotIn(swapped, mutated)


if __name__ == "__main__":
    unittest.main(verbosity=1)
