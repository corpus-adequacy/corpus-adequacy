#!/usr/bin/env python3
"""RED-first publication handoff URL from validated report bytes only."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlparse

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import corpus_adequacy as ca  # noqa: E402
import publication_handoff as handoff  # noqa: E402
import render_publication_page as rpp  # noqa: E402

XSS_PAYLOAD = "<" + "script>alert(1)</scr" + "ipt>"
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "publication"
VALID = FIXTURES / "valid-tersign"
UNPROVED = FIXTURES / "unproved-control"
TEMPLATE = REPO_ROOT / ".github" / "ISSUE_TEMPLATE" / "publish-measurement.yml"
INTAKE = REPO_ROOT / ".github" / "ISSUE_TEMPLATE" / "add-corpus.yml"
MACHINE_IDS = (
    "source-url",
    "source-commit",
    "adapter",
    "runner",
    "report-path",
    "report-digest",
    "manifest-sha256",
    "tool-commit",
    "tool-content-sha256",
    "tool-version",
    "killed",
    "survived",
    "silent",
    "unproved",
    "control-status",
)
USER_IDS = ("display-name", "relationship", "public-context", "scoping", "consent")
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


def _ids_in_yaml(path: Path) -> list[str]:
    ids = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("id:"):
            ids.append(stripped.split(":", 1)[1].strip())
    return ids


class PublicationHandoff(unittest.TestCase):
    def test_yaml_field_ids_match_generator(self):
        pub_ids = _ids_in_yaml(TEMPLATE)
        intake_ids = _ids_in_yaml(INTAKE)
        for fid in MACHINE_IDS + USER_IDS:
            self.assertIn(fid, pub_ids)
        for fid in INTAKE_IDS:
            self.assertIn(fid, intake_ids)
        self.assertEqual(tuple(handoff.MACHINE_FIELD_IDS), MACHINE_IDS)
        renamed = TEMPLATE.read_text(encoding="utf-8").replace("id: killed", "id: killed-count", 1)
        extracted = []
        for line in renamed.splitlines():
            s = line.strip()
            if s.startswith("id:"):
                extracted.append(s.split(":", 1)[1].strip())
        self.assertNotEqual(tuple(x for x in extracted if x in MACHINE_IDS or x == "killed-count"), MACHINE_IDS)
        self.assertIn("killed-count", extracted)
        self.assertNotIn("killed-count", handoff.MACHINE_FIELD_IDS)

    def test_fixture_digest_swap_changes_url(self):
        url = handoff.handoff_url(VALID / "report.v0.json")
        digest = hashlib.sha256((VALID / "report.v0.json").read_bytes()).hexdigest()
        qs = parse_qs(urlparse(url).query)
        self.assertEqual(qs["template"], ["publish-measurement.yml"])
        self.assertEqual(qs["report-digest"], [digest])
        self.assertEqual(qs["killed"], ["10"])
        self.assertEqual(qs["survived"], ["2"])
        self.assertEqual(qs["silent"], ["0"])
        self.assertEqual(qs["unproved"], ["0"])
        self.assertEqual(qs["control-status"], ["killed"])
        self.assertEqual(qs["source-commit"], ["1cc5ea32b3da4f195b55782c8a3573d8564673a7"])
        self.assertEqual(qs["runner"], ["process"])
        self.assertEqual(qs["tool-commit"], ["a2f723fe5ae5036e97090b9691316e483c3f1acc"])
        for fid in MACHINE_IDS:
            self.assertIn(fid, qs)
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
        hostile = {
            "QUERY_STRING": "killed=0&report-digest=deadbeef&source-commit=ff&display-name=" + XSS_PAYLOAD,
            "killed": "0",
            "report-digest": "deadbeef",
        }
        with mock.patch.dict(os.environ, hostile, clear=False):
            url = handoff.handoff_url(VALID / "report.v0.json")
        qs = parse_qs(urlparse(url).query)
        self.assertNotEqual(qs["killed"], ["0"])
        self.assertEqual(qs["killed"], ["10"])
        self.assertNotEqual(qs["report-digest"], ["deadbeef"])
        self.assertNotEqual(qs["source-commit"], ["ff"])
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


if __name__ == "__main__":
    unittest.main(verbosity=1)
