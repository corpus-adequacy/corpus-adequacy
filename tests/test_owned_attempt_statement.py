#!/usr/bin/env python3
"""The owned rail seals and attests its attempts too, report included (#187 remainder)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests import test_owned_contained_v1_hosted as owned_tests  # noqa: E402
from tests.test_owned_report_artifact import (  # noqa: E402
    BINDINGS_RUNNER,
    RUN_ATTEMPT,
    RUN_ID,
    _owned_run,
)

publication = owned_tests.publication
owned = owned_tests.owned
statement = owned_tests.attempt_statement
parse_workflow_yaml = owned_tests.parse_workflow_yaml
OWNED_PUBLICATION_WORKFLOW = owned_tests.OWNED_PUBLICATION_WORKFLOW
ROOT = Path(__file__).resolve().parents[1]
OWNED_WORKFLOW = ROOT / ".github" / "workflows" / "owned-contained-v1-publication.yml"
ENVIRON = {"GITHUB_SHA": BINDINGS_RUNNER, "GITHUB_WORKFLOW_SHA": BINDINGS_RUNNER,
           "ImageOS": "ubuntu24", "ImageVersion": "1",
           "GITHUB_RUN_ID": RUN_ID, "GITHUB_RUN_ATTEMPT": RUN_ATTEMPT}


def _published(raw: str):
    report = owned_tests.OwnedHostedRailContract.report()
    decision, out, bindings = _owned_run(Path(raw), report=report)
    assert decision["decision"] == "publish", decision
    return out, bindings


def _seal(out: Path, bindings: dict, gate_outcome="success"):
    with mock.patch.dict(os.environ, ENVIRON):
        return owned.seal_owned(
            candidate_revision=bindings["candidate_revision"],
            runner_revision=bindings["runner_revision"],
            image_digest=bindings["image_digest"],
            packet_release_tag="owned-contained-v1-packet-r8",
            packet_manifest_sha256="e" * 64, gate_outcome=gate_outcome, out_dir=out)


def _readback_cmd(out: Path, bindings: dict, *extra):
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


class OwnedSeal(unittest.TestCase):
    def test_owned_seal_names_the_report_and_the_owned_rail(self):
        with tempfile.TemporaryDirectory() as raw:
            out, bindings = _published(raw)
            sealed = _seal(out, bindings)
            root = out / statement.STATEMENT_DIRNAME
            sums = (root / statement.SUMS_FILENAME).read_text()
            names = [line.split("  ", 1)[1] for line in sums.splitlines()]
            self.assertIn(publication.REPORT_FILENAME, names)
            self.assertIn("effective-envelope-collection.v0/collection-index.v0.json", names)
            self.assertEqual(sealed["subjects"], len(names))
            predicate = json.loads((root / statement.PREDICATE_FILENAME).read_text())
            self.assertEqual(predicate["rail"], owned_tests.OWNED_V1_RAIL.name)
            self.assertEqual(predicate["gate_outcome"], "success")

    def test_the_report_name_is_one_spelling(self):
        self.assertEqual(publication.REPORT_FILENAME, statement.REPORT_SUBJECT)
        self.assertEqual(publication.statement_subject_files(owned_tests.OWNED_V1_RAIL),
                         statement.OWNED_SUBJECT_FILES)
        self.assertEqual(publication.statement_subject_files(owned_tests.LEGACY_RAIL),
                         statement.SUBJECT_FILES)

    def test_the_external_rail_never_seals_a_report_file(self):
        with tempfile.TemporaryDirectory() as raw:
            out = Path(raw)
            for name in statement.SUBJECT_FILES:
                (out / name).write_bytes(b"{}\n")
            (out / publication.REPORT_FILENAME).write_bytes(b"stray\n")
            subjects = statement.enumerate_subjects(
                out, subject_files=publication.statement_subject_files(
                    owned_tests.LEGACY_RAIL))
            self.assertNotIn(publication.REPORT_FILENAME, [name for name, _ in subjects])

    def test_an_unknown_subject_set_is_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            with self.assertRaises(statement.StatementError) as ctx:
                statement.enumerate_subjects(Path(raw), subject_files=("setup-status.json",))
            self.assertEqual(str(ctx.exception), "subject_files")

    def test_facade_seal_cli(self):
        with tempfile.TemporaryDirectory() as raw:
            out, bindings = _published(raw)
            env = dict(os.environ, **ENVIRON)
            proc = subprocess.run([
                sys.executable, str(Path(owned.__file__)), "seal",
                "--candidate-revision", bindings["candidate_revision"],
                "--runner-revision", bindings["runner_revision"],
                "--image-digest", bindings["image_digest"],
                "--packet-release-tag", "owned-contained-v1-packet-r8",
                "--packet-manifest-sha256", "e" * 64, "--gate-outcome", "success",
                "--out", str(out),
            ], capture_output=True, text=True, env=env, check=False)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("subjects", json.loads(proc.stdout))
            again = subprocess.run(proc.args, capture_output=True, text=True, env=env,
                                   check=False)
            self.assertEqual(again.returncode, 2)
            self.assertIn("statement:statement_occupied", again.stderr)


class OwnedStatementReadback(unittest.TestCase):
    def _run(self, cmd):
        return subprocess.run(cmd, capture_output=True, text=True, check=False)

    def test_statement_and_report_verify_together(self):
        with tempfile.TemporaryDirectory() as raw:
            out, bindings = _published(raw)
            _seal(out, bindings)
            proc = self._run(_readback_cmd(
                out, bindings,
                "--report", str(out / publication.REPORT_FILENAME),
                "--statement", str(out / statement.STATEMENT_DIRNAME)))
            self.assertEqual(proc.returncode, 0, proc.stderr)
            summary = json.loads(proc.stdout)
            self.assertEqual(summary["statement"], "verified-unsigned")
            self.assertEqual(summary["report"], "verified")

    def test_statement_without_the_sealed_report_is_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            out, bindings = _published(raw)
            _seal(out, bindings)
            proc = self._run(_readback_cmd(
                out, bindings, "--statement", str(out / statement.STATEMENT_DIRNAME)))
            self.assertEqual(proc.returncode, 2, proc.stdout)
            self.assertIn("statement:statement_subjects", proc.stderr)

    def test_a_statement_sealed_for_another_rail_is_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            out, bindings = _published(raw)
            _seal(out, bindings)
            loaded = statement.load_statement_dir(out / statement.STATEMENT_DIRNAME)
            files = publication._statement_subject_files(
                setup_path=out / publication.SETUP_STATUS_FILENAME,
                candidate_path=out / publication.CANDIDATE_RESULT_FILENAME,
                rerun_path=out / publication.RERUN_EVIDENCE_FILENAME,
                collection_dir=out / publication.COLLECTION_DIRNAME,
                report_path=out / publication.REPORT_FILENAME)
            with self.assertRaises(statement.StatementError) as ctx:
                statement.check_statement_against_files(
                    loaded, files, bindings=bindings,
                    run_identity={"run_id": RUN_ID, "run_attempt": RUN_ATTEMPT},
                    rail=owned_tests.LEGACY_RAIL.name)
            self.assertEqual(str(ctx.exception), "statement_rail")

    def test_a_tampered_report_is_refused_before_the_statement_is_read(self):
        with tempfile.TemporaryDirectory() as raw:
            out, bindings = _published(raw)
            _seal(out, bindings)
            report = out / publication.REPORT_FILENAME
            report.write_bytes(report.read_bytes() + b"\n")
            proc = self._run(_readback_cmd(
                out, bindings, "--report", str(report),
                "--statement", str(out / statement.STATEMENT_DIRNAME)))
            self.assertEqual(proc.returncode, 2, proc.stdout)
            self.assertIn("hosted publication refused: report_round_trip", proc.stderr)


class OwnedStatementWorkflow(unittest.TestCase):
    def setUp(self):
        self.text = OWNED_WORKFLOW.read_text(encoding="utf-8")

    def test_seal_upload_and_attest_are_pinned(self):
        tree = parse_workflow_yaml(self.text)
        self.assertEqual(tree, OWNED_PUBLICATION_WORKFLOW)
        names = [step["name"] for step in tree["jobs"]["owned-contained"]["steps"]]
        self.assertLess(names.index("Gate owned publication"),
                        names.index("Seal owned attempt statement"))
        self.assertLess(names.index("Seal owned attempt statement"),
                        names.index("Attest owned attempt statement"))
        self.assertEqual(tree["permissions"],
                         {"contents": "read", "id-token": "write", "attestations": "write"})

    def test_mutations_are_red(self):
        for old, new in (
            ("uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6",
             "uses: actions/attest@v4"),
            ("  attestations: write\n", ""),
            ("  contents: read\n", "  contents: write\n"),
            ('--gate-outcome "$GATE_OUTCOME" --out owned-contained-v1-artifacts',
             "--gate-outcome success --out owned-contained-v1-artifacts"),
            ("GATE_OUTCOME: ${{ steps.gate.outcome }}", "GATE_OUTCOME: success"),
            ("        if: always() && !cancelled() && steps.seal.outcome == 'success'\n"
             "        uses: actions/attest",
             "        if: steps.gate.outcome == 'success' && !cancelled()\n"
             "        uses: actions/attest"),
            ("SHA256SUMS\n          predicate-type",
             "SHA256SUMS.txt\n          predicate-type"),
        ):
            with self.subTest(old=old):
                self.assertIn(old, self.text)
                self.assertNotEqual(parse_workflow_yaml(self.text.replace(old, new, 1)),
                                    OWNED_PUBLICATION_WORKFLOW)
        start = self.text.index("      # Seals whatever the gate left on the upload surface, report")
        end = self.text.index("      - name: Upload setup")
        self.assertNotEqual(parse_workflow_yaml(self.text[:start] + self.text[end:]),
                            OWNED_PUBLICATION_WORKFLOW)


if __name__ == "__main__":
    unittest.main()
