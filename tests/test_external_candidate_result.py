#!/usr/bin/env python3
"""The external rail's reduced candidate result (#184).

The external corpus owner's consent covers no score and no per-mutant result. The external rail
therefore publishes `report_sha256`, `control_status`, `unproved` and per-ordinal completion,
and nothing score-shaped, and it never publishes without a report bound to the collection.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tests.test_contained_hosted_publication import (  # noqa: F401  (module env fixtures)
    BINDINGS,
    CANDIDATE,
    IMAGE,
    RUNNER,
    _permitted_envelope,
    _report,
    _report_sha256,
    _run_ok,
    _write_collection,
    _write_packet,
    setUpModule,
    tearDownModule,
    hosted,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
R4_CANDIDATE = REPO_ROOT / "tests" / "fixtures" / "hosted-r4-terminal" / "candidate-result.json"
R4_CANDIDATE_SHA256 = "0ac4b193e23cfff205f68bcb51c065d5a4223c05089c5aa222c3cee6a77acb38"
EXTERNAL_SCHEMA = "corpus-adequacy.aee-contained-v0.candidate-result.v1"
RUN_ID, RUN_ATTEMPT = "1001", "1"


def _read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class ExternalReducedProjection(unittest.TestCase):
    def _gate(self, base: Path, *, execute, envelope_over=None):
        (base / "packet").mkdir()
        rels = _write_packet(base / "packet")
        over = dict(envelope_over or {})

        def run(**kwargs):
            return execute(kwargs, rels, over)

        return _run_ok(base, "packet", rels, execute=run), base / "artifacts"

    def test_publish_writes_the_reduced_v1_shape_and_never_the_legacy_one(self):
        with tempfile.TemporaryDirectory() as raw:
            decision, out = self._gate(Path(raw), execute=lambda kw, rels, over: (
                _write_collection(kw["envelope_dest"],
                                  _permitted_envelope(prepare_sha256=rels["prepare_sha256"]))))
            self.assertEqual(decision["decision"], "publish")
            doc = _read(out / hosted.CANDIDATE_RESULT_FILENAME)
            self.assertEqual(doc["schema"], EXTERNAL_SCHEMA)
            self.assertEqual(tuple(sorted(doc)), tuple(sorted(hosted.EXTERNAL_CANDIDATE_KEYS)))
            self.assertNotIn("adequate", doc)
            for key in ("killed", "survived", "silent", "failures", "declared_total"):
                self.assertNotIn(key, doc)
            self.assertEqual(doc["decision"], "publish")
            self.assertEqual(doc["score_status"], "none")
            self.assertEqual(doc["report_sha256"], _report_sha256(_report()))
            self.assertEqual(doc["control_status"], "killed")
            self.assertEqual(doc["unproved"], 0)
            self.assertEqual(doc["outcomes"], [{"ordinal": 0, "candidate_outcome": "completed"}])
            index = _read(out / hosted.COLLECTION_DIRNAME / "collection-index.v0.json")
            self.assertEqual(index["report_sha256"], doc["report_sha256"])
            self.assertNotIn(hosted.HOSTED_SCHEMA, (out / hosted.CANDIDATE_RESULT_FILENAME)
                             .read_text(encoding="utf-8"))

    def test_decision_stays_envelope_driven_when_the_report_is_not_adequate(self):
        failing = _report(killed=0, survived=1, failures=["survivor"], adequate=False)
        with tempfile.TemporaryDirectory() as raw:
            decision, out = self._gate(Path(raw), execute=lambda kw, rels, over: (
                _write_collection(kw["envelope_dest"],
                                  _permitted_envelope(prepare_sha256=rels["prepare_sha256"]),
                                  report=failing)))
            self.assertEqual(decision["decision"], "publish")
            doc = _read(out / hosted.CANDIDATE_RESULT_FILENAME)
            self.assertEqual(doc["decision"], "publish")
            self.assertEqual(doc["report_sha256"], _report_sha256(failing))
            self.assertNotIn("adequate", doc)

    def test_withheld_run_with_a_report_carries_the_same_reduced_keys(self):
        with tempfile.TemporaryDirectory() as raw:
            decision, out = self._gate(Path(raw), execute=lambda kw, rels, over: (
                _write_collection(kw["envelope_dest"], _permitted_envelope(
                    prepare_sha256=rels["prepare_sha256"], envelope_status="unverified",
                    unverified_field="runtime_version"))))
            self.assertEqual(decision["decision"], "withhold")
            doc = _read(out / hosted.CANDIDATE_RESULT_FILENAME)
            self.assertEqual(doc["schema"], EXTERNAL_SCHEMA)
            self.assertEqual(doc["decision"], "withhold")
            self.assertEqual(tuple(sorted(doc)), tuple(sorted(hosted.EXTERNAL_CANDIDATE_KEYS)))
            manifest = _read(out / hosted.DIAGNOSTIC_DIRNAME / hosted.DIAGNOSTIC_MANIFEST_FILENAME)
            self.assertEqual(manifest["report_sha256"], doc["report_sha256"])

    def test_withheld_run_without_a_report_keeps_the_void_result(self):
        with tempfile.TemporaryDirectory() as raw:
            def execute(kw, rels, over):
                _write_collection(kw["envelope_dest"], _permitted_envelope(
                    prepare_sha256=rels["prepare_sha256"], envelope_status="unverified",
                    unverified_field="runtime_version"), report_sha256=None)
                return None
            decision, out = self._gate(Path(raw), execute=execute)
            self.assertEqual(decision["decision"], "withhold")
            doc = _read(out / hosted.CANDIDATE_RESULT_FILENAME)
            self.assertEqual(doc["kind"], "void-hosted-result")

    def _refused(self, execute, reason):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            with self.assertRaises(hosted.HostedPublicationError) as ctx:
                self._gate(base, execute=execute)
            self.assertEqual(str(ctx.exception), reason)
            out = base / "artifacts"
            setup = _read(out / hosted.SETUP_STATUS_FILENAME)
            self.assertEqual(setup["setup_status"], "refused")
            self.assertEqual(setup["reason"], reason)
            self.assertEqual(_read(out / hosted.CANDIDATE_RESULT_FILENAME)["kind"],
                             "void-hosted-result")
            self.assertFalse((out / hosted.COLLECTION_DIRNAME).exists(),
                             "a refused run must not leave a publishable collection")
            kinds = [json.loads(line)["kind"] for line in
                     (out / hosted.RERUN_EVIDENCE_FILENAME).read_text().splitlines()]
            self.assertIn(hosted.RERUN_KIND_POST_EXECUTE, kinds)
            self.assertEqual(kinds[-1], hosted.RERUN_KIND_TERMINAL)

    def test_publish_without_a_report_is_a_named_refusal(self):
        def execute(kw, rels, over):
            _write_collection(kw["envelope_dest"],
                              _permitted_envelope(prepare_sha256=rels["prepare_sha256"]),
                              report_sha256=None)
            return None
        self._refused(execute, "candidate_report_absent")

    def test_a_report_the_collection_does_not_bind_is_a_named_refusal(self):
        def execute(kw, rels, over):
            _write_collection(kw["envelope_dest"],
                              _permitted_envelope(prepare_sha256=rels["prepare_sha256"]))
            return _report(killed=2, declared_total=2)
        self._refused(execute, "candidate_report_binding")

    def test_an_inconsistent_report_is_a_named_refusal(self):
        def execute(kw, rels, over):
            broken = _report(declared_total=5)
            return _write_collection(
                kw["envelope_dest"],
                _permitted_envelope(prepare_sha256=rels["prepare_sha256"]), report=broken)
        self._refused(execute, "candidate_report_total")


class ExternalCandidateLoader(unittest.TestCase):
    def _doc(self, **over):
        doc = {
            "schema": EXTERNAL_SCHEMA, "kind": "hosted-candidate-result",
            "decision": "publish", "score_status": "none",
            "bindings": dict(BINDINGS), "dispatch_bindings": dict(BINDINGS),
            "report_sha256": "ab" * 32, "control_status": "killed", "unproved": 0,
            "outcomes": [{"ordinal": 0, "candidate_outcome": "completed"}],
            "non_claims": list(hosted.NON_CLAIMS),
        }
        doc.update(over)
        return doc

    def _load(self, doc):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "candidate-result.json"
            path.write_bytes(hosted._encode_json(doc))
            return hosted.load_candidate_result(path)

    def test_valid_reduced_document_loads(self):
        self.assertEqual(self._load(self._doc())["schema"], EXTERNAL_SCHEMA)

    def test_score_shaped_or_per_site_keys_are_refused(self):
        for extra in ({"adequate": True}, {"killed": 1}, {"survived": 0},
                      {"failures": []}, {"sites": {"sealed-1": "killed"}}):
            with self.subTest(extra=extra):
                with self.assertRaises(hosted.HostedPublicationError) as ctx:
                    self._load(self._doc(**extra))
                self.assertEqual(str(ctx.exception), "candidate_result")

    def test_owned_keys_under_the_external_schema_are_refused(self):
        with self.assertRaises(hosted.HostedPublicationError):
            self._load(self._doc(adequate=True))

    def test_closed_values(self):
        for over, reason in (
            ({"report_sha256": None}, "report_sha256"),
            ({"decision": "unavailable"}, "candidate_result"),
            ({"score_status": "scored"}, "candidate_result"),
            ({"control_status": "passed"}, "candidate_result"),
            ({"unproved": -1}, "candidate_result"),
            ({"unproved": True}, "candidate_result"),
            ({"outcomes": [{"ordinal": 0, "candidate_outcome": "killed"}]}, "candidate_outcome"),
            ({"outcomes": [{"ordinal": 0, "candidate_outcome": "completed", "site": "x"}]},
             "candidate_outcome"),
            ({"outcomes": [{"ordinal": 1, "candidate_outcome": "completed"},
                           {"ordinal": 1, "candidate_outcome": "completed"}]},
             "candidate_outcome"),
        ):
            with self.subTest(over=over):
                with self.assertRaises(hosted.HostedPublicationError) as ctx:
                    self._load(self._doc(**over))
                self.assertEqual(str(ctx.exception), reason)

    def test_unknown_schema_is_refused(self):
        with self.assertRaises(hosted.HostedPublicationError) as ctx:
            self._load(self._doc(schema="corpus-adequacy.other.candidate-result.v1"))
        self.assertEqual(str(ctx.exception), "candidate_result")

    def test_retained_r4_bytes_still_load_as_the_historical_shape(self):
        raw = R4_CANDIDATE.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), R4_CANDIDATE_SHA256)
        doc = hosted.load_candidate_result(R4_CANDIDATE)
        self.assertEqual(doc["schema"], hosted.HOSTED_SCHEMA)
        self.assertNotIn("report_sha256", doc)
        self.assertEqual(doc["decision"], "publish")


class ExternalReadbackCrossChecks(unittest.TestCase):
    """The publish readback now has something to compare on the external rail."""

    def _published(self, base: Path):
        (base / "packet").mkdir()
        rels = _write_packet(base / "packet")
        decision = _run_ok(base, "packet", rels, execute=lambda **kw: _write_collection(
            kw["envelope_dest"], _permitted_envelope(prepare_sha256=rels["prepare_sha256"])))
        self.assertEqual(decision["decision"], "publish")
        return base / "artifacts"

    def _readback(self, out: Path):
        return hosted.load_hosted_attempt_artifacts(
            setup_path=out / hosted.SETUP_STATUS_FILENAME,
            candidate_path=out / hosted.CANDIDATE_RESULT_FILENAME,
            rerun_path=out / hosted.RERUN_EVIDENCE_FILENAME,
            collection_dir=out / hosted.COLLECTION_DIRNAME,
            expected_bindings=BINDINGS,
            expected_run_id=RUN_ID, expected_run_attempt=RUN_ATTEMPT)

    def _rewrite_candidate(self, out: Path, **over):
        path = out / hosted.CANDIDATE_RESULT_FILENAME
        doc = _read(path)
        doc.update(over)
        path.write_bytes(hosted._encode_json(doc))

    def test_published_set_reads_back(self):
        with tempfile.TemporaryDirectory() as raw:
            out = self._published(Path(raw))
            loaded = self._readback(out)
            self.assertEqual(loaded["candidate"]["schema"], EXTERNAL_SCHEMA)
            self.assertEqual(loaded["projection"]["report_sha256"],
                             loaded["candidate"]["report_sha256"])

    def test_carried_digest_differing_from_the_index_is_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            out = self._published(Path(raw))
            self._rewrite_candidate(out, report_sha256="cd" * 32)
            with self.assertRaises(hosted.HostedPublicationError) as ctx:
                self._readback(out)
            self.assertEqual(str(ctx.exception), "report_sha256")

    def test_outcomes_differing_from_the_members_are_refused(self):
        for outcomes in ([], [{"ordinal": 0, "candidate_outcome": "timeout"}],
                         [{"ordinal": 0, "candidate_outcome": "completed"},
                          {"ordinal": 1, "candidate_outcome": "completed"}]):
            with self.subTest(outcomes=outcomes), tempfile.TemporaryDirectory() as raw:
                out = self._published(Path(raw))
                self._rewrite_candidate(out, outcomes=outcomes)
                with self.assertRaises(hosted.HostedPublicationError) as ctx:
                    self._readback(out)
                self.assertEqual(str(ctx.exception), "candidate_outcome")

    def test_cli_readback_names_the_candidate_result_schema(self):
        import subprocess
        import sys
        with tempfile.TemporaryDirectory() as raw:
            out = self._published(Path(raw))
            proc = subprocess.run([
                sys.executable, str(Path(hosted.__file__)), "readback",
                "--setup", str(out / hosted.SETUP_STATUS_FILENAME),
                "--candidate", str(out / hosted.CANDIDATE_RESULT_FILENAME),
                "--rerun", str(out / hosted.RERUN_EVIDENCE_FILENAME),
                "--collection", str(out / hosted.COLLECTION_DIRNAME),
                "--candidate-revision", CANDIDATE, "--runner-revision", RUNNER,
                "--image-digest", IMAGE, "--run-id", RUN_ID, "--run-attempt", RUN_ATTEMPT,
            ], capture_output=True, text=True, check=False)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            summary = json.loads(proc.stdout)
            self.assertEqual(summary["candidate_result_schema"], EXTERNAL_SCHEMA)
            self.assertEqual(summary["decision"], "publish")


if __name__ == "__main__":
    unittest.main()
