#!/usr/bin/env python3
"""The owned rail's fifth artifact: canonical report.v0 bytes of a published run (#186)."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests import test_owned_contained_v1_hosted as owned_tests  # noqa: E402

# Module attributes, not imported TestCase classes: an imported class would run twice.
OWNED_PUBLICATION_WORKFLOW = owned_tests.OWNED_PUBLICATION_WORKFLOW
OWNED_V1_RAIL = owned_tests.OWNED_V1_RAIL
owned = owned_tests.owned
parse_workflow_yaml = owned_tests.parse_workflow_yaml
publication = owned_tests.publication

ROOT = Path(__file__).resolve().parents[1]
BINDINGS_RUNNER = "b" * 40
RUN_ID, RUN_ATTEMPT = "1001", "1"
OWNED_WORKFLOW = ROOT / ".github" / "workflows" / "owned-contained-v1-publication.yml"
REPORT_UPLOAD_IF = "steps.gate.outcome == 'success' && !cancelled()"


def _owned_run(workspace: Path, *, report, collection_sha=None, execute_report=None):
    """One real owned gate run over a one-member collection; returns (decision, out, bindings)."""
    from tests.test_effective_envelope import _requested_v2, _v2_effective

    requested = _requested_v2()
    bindings = {"candidate_revision": "a" * 40, "runner_revision": BINDINGS_RUNNER,
                "image_digest": requested["image_id"]}
    report_sha = (collection_sha if collection_sha is not None else
                  hashlib.sha256(publication.ca.encode_report_v0(report)).hexdigest())
    prepare_raw = json.dumps({"schema": owned.sealed_run.PREPARE_V2_SCHEMA}).encode()
    authorize_raw = b"authorize"
    prepare_sha = hashlib.sha256(prepare_raw).hexdigest()
    member = publication.effective_envelope.build_envelope_record(
        requested=requested, setup_status="ready", envelope_status="verified",
        unverified_field=None, effective=_v2_effective(), candidate_outcome="completed",
        cleanup="removed-and-absent", prepare_sha256=prepare_sha,
        execution_commit=bindings["runner_revision"], report_sha256=None,
        schema=publication.effective_envelope.ENVELOPE_SCHEMA_V1)
    packet = workspace / OWNED_V1_RAIL.packet_dirname
    packet.mkdir()
    (packet / OWNED_V1_RAIL.prepare_filename).write_bytes(prepare_raw)
    (packet / OWNED_V1_RAIL.authorize_filename).write_bytes(authorize_raw)
    (packet / "pins").mkdir()
    out = workspace / "out"

    def execute(**kwargs):
        ledger = publication.collection.Ledger()
        ledger.recorded(ledger.register(), member)
        publication.collection.write_collection(
            ledger, Path(kwargs["envelope_dest"]), report_sha256=report_sha)
        return report if execute_report is None else execute_report

    packet_files = {
        OWNED_V1_RAIL.prepare_filename: prepare_sha,
        OWNED_V1_RAIL.authorize_filename: hashlib.sha256(authorize_raw).hexdigest(),
    }
    with mock.patch.object(publication, "check_packet_manifest", return_value=packet_files), \
            mock.patch.object(publication, "load_dispatch_bindings"), \
            mock.patch.object(publication, "check_prepare_bindings"), \
            mock.patch.object(owned.sealed_run, "load_prepare_for_profile", return_value={}):
        decision = publication.run_gate(
            **bindings, operator_profile=OWNED_V1_RAIL.execution_profile,
            out_dir=out, workspace_root=workspace,
            packet_root=OWNED_V1_RAIL.packet_dirname,
            authorize_path=OWNED_V1_RAIL.authorize_filename,
            prepare_path=OWNED_V1_RAIL.prepare_filename, pins_dir="pins",
            packet_manifest_sha256="d" * 64, docker_ready=lambda: "ready",
            sealed_execute=execute,
            environ={"GITHUB_SHA": BINDINGS_RUNNER, "GITHUB_WORKFLOW_SHA": BINDINGS_RUNNER,
                     "GITHUB_RUN_ID": RUN_ID, "GITHUB_RUN_ATTEMPT": RUN_ATTEMPT},
            rail=OWNED_V1_RAIL)
    return decision, out, bindings


class OwnedReportArtifact(unittest.TestCase):
    report = staticmethod(owned_tests.OwnedHostedRailContract.report)

    def test_publish_writes_canonical_report_bytes_bound_to_index_and_candidate(self):
        report = self.report()
        with tempfile.TemporaryDirectory() as raw:
            decision, out, _ = _owned_run(Path(raw), report=report)
            self.assertEqual(decision["decision"], "publish")
            data = (out / publication.REPORT_FILENAME).read_bytes()
            self.assertEqual(data, publication.ca.encode_report_v0(report))
            digest = hashlib.sha256(data).hexdigest()
            index = json.loads((out / publication.COLLECTION_DIRNAME /
                                "collection-index.v0.json").read_text())
            candidate = json.loads((out / publication.CANDIDATE_RESULT_FILENAME).read_text())
            self.assertEqual(index["report_sha256"], digest)
            self.assertEqual(candidate["report_sha256"], digest)

    def test_withhold_writes_no_report_and_removes_a_stale_one(self):
        report = self.report(control_status="survived", killed=1, survived=1,
                             failures=["control survived"], adequate=False)
        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            (workspace / "out").mkdir()
            (workspace / "out" / publication.REPORT_FILENAME).write_bytes(b"stale\n")
            decision, out, _ = _owned_run(workspace, report=report)
            self.assertEqual(decision["decision"], "withhold")
            self.assertFalse((out / publication.REPORT_FILENAME).exists())

    def test_not_adequate_owned_run_withholds_and_writes_no_report(self):
        report = self.report(killed=1, survived=1, failures=["survivor"], adequate=False)
        with tempfile.TemporaryDirectory() as raw:
            decision, out, _ = _owned_run(Path(raw), report=report)
            self.assertEqual(decision["decision"], "withhold")
            self.assertFalse((out / publication.REPORT_FILENAME).exists())

    def test_report_that_does_not_round_trip_is_refused_before_upload(self):
        report = self.report()
        sha = _canonical_sha(report)
        with tempfile.TemporaryDirectory() as raw, \
                mock.patch.object(publication.ca, "encode_report_v0",
                                  side_effect=_non_canonical_encoder()):
            with self.assertRaises(publication.HostedPublicationError) as ctx:
                _owned_run(Path(raw), report=report, collection_sha=sha)
            self.assertEqual(str(ctx.exception), "report_round_trip")
            out = Path(raw) / "out"
            self.assertFalse((out / publication.REPORT_FILENAME).exists())
            self.assertFalse((out / publication.COLLECTION_DIRNAME).exists())
            setup = json.loads((out / publication.SETUP_STATUS_FILENAME).read_text())
            self.assertEqual(setup["setup_status"], "refused")

    def test_owned_report_bytes_refusals(self):
        report = self.report()
        good = _canonical_sha(report)
        with self.assertRaises(publication.HostedPublicationError) as ctx:
            publication.owned_report_bytes(report, report_sha256="0" * 64)
        self.assertEqual(str(ctx.exception), "report_sha256")
        with self.assertRaises(publication.HostedPublicationError) as ctx:
            publication.owned_report_bytes(report, report_sha256=good, max_bytes=10)
        self.assertEqual(str(ctx.exception), "max_artifact_bytes")
        with self.assertRaises(publication.HostedPublicationError) as ctx:
            publication.owned_report_bytes({"schema": "other"}, report_sha256=good)
        self.assertEqual(str(ctx.exception), "report_bytes")
        mixed = dict(report, extra={1: "a", "b": 2})
        with self.assertRaises(publication.HostedPublicationError) as ctx:
            publication.owned_report_bytes(mixed, report_sha256=_canonical_sha(report))
        self.assertIn(str(ctx.exception), ("report_round_trip", "report_bytes"))


def _canonical_sha(report):
    return hashlib.sha256(publication.ca.encode_report_v0(report)).hexdigest()


def _non_canonical_encoder():
    real = publication.ca.encode_report_v0
    calls = {"n": 0}

    def encode(doc):
        calls["n"] += 1
        raw = real(doc)
        # Call 1 is the projection's digest (canonical); call 2 is owned_report_bytes'
        # first encode, which returns bytes its own re-encode (call 3) cannot reproduce.
        if calls["n"] == 2:
            return raw.replace(b"\n", b"\n ", 1)
        return raw

    return encode


class OwnedReportReadback(unittest.TestCase):
    report = staticmethod(owned_tests.OwnedHostedRailContract.report)

    def _published(self, raw: str, report=None):
        report = report or self.report()
        decision, out, bindings = _owned_run(Path(raw), report=report)
        self.assertEqual(decision["decision"], "publish")
        return out, bindings

    def _cmd(self, out: Path, bindings, *extra):
        return [
            sys.executable, str(Path(publication.__file__)), "readback",
            "--setup", str(out / publication.SETUP_STATUS_FILENAME),
            "--candidate", str(out / publication.CANDIDATE_RESULT_FILENAME),
            "--rerun", str(out / publication.RERUN_EVIDENCE_FILENAME),
            "--collection", str(out / publication.COLLECTION_DIRNAME),
            "--candidate-revision", bindings["candidate_revision"],
            "--runner-revision", bindings["runner_revision"],
            "--image-digest", bindings["image_digest"],
            "--run-id", RUN_ID, "--run-attempt", RUN_ATTEMPT, *extra,
        ]

    def _run(self, cmd):
        return subprocess.run(cmd, capture_output=True, text=True, check=False)

    def test_readback_verifies_the_report_and_says_so(self):
        with tempfile.TemporaryDirectory() as raw:
            out, bindings = self._published(raw)
            proc = self._run(self._cmd(out, bindings, "--report",
                                       str(out / publication.REPORT_FILENAME)))
            self.assertEqual(proc.returncode, 0, proc.stderr)
            summary = json.loads(proc.stdout)
            self.assertEqual(summary["report"], "verified")
            candidate = json.loads((out / publication.CANDIDATE_RESULT_FILENAME).read_text())
            self.assertEqual(summary["report_sha256"], candidate["report_sha256"])
            proc = self._run(self._cmd(out, bindings))
            self.assertEqual(json.loads(proc.stdout)["report"], "not-provided")

    def test_readback_refuses_wrong_or_non_canonical_report_bytes(self):
        with tempfile.TemporaryDirectory() as raw:
            out, bindings = self._published(raw)
            path = out / publication.REPORT_FILENAME
            original = path.read_bytes()
            doc = json.loads(original)
            for data, reason in (
                (original + b"\n", "report_round_trip"),
                (original.replace(b"  ", b"   ", 1), "report_round_trip"),
                (json.dumps(doc, sort_keys=True).encode() + b"\n", "report_round_trip"),
                (publication.ca.encode_report_v0(dict(doc, killed=3, declared_total=3)),
                 "report_sha256"),
                (b"not json", "report_bytes"),
                (json.dumps({"schema": "x"}).encode(), "report_bytes"),
            ):
                with self.subTest(reason=reason, data=data[:30]):
                    path.write_bytes(data)
                    proc = self._run(self._cmd(out, bindings, "--report", str(path)))
                    self.assertEqual(proc.returncode, 2, proc.stdout)
                    self.assertIn("hosted publication refused: %s" % reason, proc.stderr)
            path.write_bytes(original)

    def test_readback_refuses_a_report_whose_facts_disagree_with_the_candidate(self):
        with tempfile.TemporaryDirectory() as raw:
            out, bindings = self._published(raw)
            report_path = out / publication.REPORT_FILENAME
            candidate_path = out / publication.CANDIDATE_RESULT_FILENAME
            candidate = json.loads(candidate_path.read_text())
            candidate["unproved"] = 1
            candidate_path.write_bytes(publication._encode_json(candidate))
            proc = self._run(self._cmd(out, bindings, "--report", str(report_path)))
            self.assertEqual(proc.returncode, 2, proc.stdout)
            self.assertIn("report_fact:unproved", proc.stderr)

    def test_readback_refuses_a_report_for_an_unbound_candidate_result(self):
        with self.assertRaises(publication.HostedPublicationError) as ctx:
            publication.load_published_report(
                ROOT / "tests" / "fixtures" / "hosted-r4-terminal" / "candidate-result.json",
                candidate=json.loads((ROOT / "tests" / "fixtures" / "hosted-r4-terminal" /
                                      "candidate-result.json").read_text()),
                report_sha256="0" * 64)
        self.assertEqual(str(ctx.exception), "report_unbound")


class OwnedReportWorkflow(unittest.TestCase):
    def setUp(self):
        self.text = OWNED_WORKFLOW.read_text(encoding="utf-8")

    def test_report_upload_is_bound_to_gate_success(self):
        tree = parse_workflow_yaml(self.text)
        self.assertEqual(tree, OWNED_PUBLICATION_WORKFLOW)
        steps = [s for s in tree["jobs"]["owned-contained"]["steps"]
                 if (s.get("with") or {}).get("name") == "owned-contained-v1-report"]
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0]["if"], REPORT_UPLOAD_IF)
        self.assertEqual(steps[0]["with"]["path"],
                         "owned-contained-v1-artifacts/" + publication.REPORT_FILENAME)

    def test_report_upload_mutations_are_red(self):
        block_start = self.text.index("      - name: Upload report\n")
        block_end = self.text.index("      - name: Upload candidate result\n")
        block = self.text[block_start:block_end]
        for mutated in (
            self.text.replace(block, "", 1),
            self.text.replace(block, block.replace(REPORT_UPLOAD_IF, "always() && !cancelled()"), 1),
            self.text.replace(block, block.replace("if-no-files-found: error",
                                                   "if-no-files-found: warn"), 1),
            self.text.replace(block, block.replace("report.v0.json", "report.v0.json*"), 1),
        ):
            self.assertNotEqual(parse_workflow_yaml(mutated), OWNED_PUBLICATION_WORKFLOW)


if __name__ == "__main__":
    unittest.main()
