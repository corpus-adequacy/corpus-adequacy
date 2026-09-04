#!/usr/bin/env python3
"""Behavioral RED/GREEN + mutations for the hosted publication gate (#107)."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "measurements"))

import contained_hosted_publication as hosted  # noqa: E402
import contained_oci as contained  # noqa: E402

CANDIDATE = "a" * 40
RUNNER = "b" * 40
IMAGE = "sha256:" + ("c" * 64)
BINDINGS = {
    "candidate_revision": CANDIDATE,
    "runner_revision": RUNNER,
    "image_digest": IMAGE,
}


def _permitted_envelope(**over):
    doc = {
        "schema": "corpus-adequacy.execution-envelope.v0",
        "setup_status": "ready",
        "envelope_status": "verified",
        "publication_permission": "permitted",
        "candidate_outcome": "completed",
        "cleanup": "removed-and-absent",
        "withheld_reason": None,
    }
    doc.update(over)
    return doc


def _facts_file(dirpath: Path) -> Path:
    path = Path(dirpath) / "workflow-facts.json"
    hosted.write_workflow_facts(
        path,
        runs_on=hosted.RUNS_ON,
        persist_credentials=False,
        mounts=[],
        env_names=[],
    )
    return path


def _load_mutated_module(source: str, name: str):
    root = Path(tempfile.mkdtemp())
    path = root / "contained_hosted_publication.py"
    path.write_text(source, encoding="utf-8")
    measurements = REPO_ROOT / "measurements"
    sys.path.insert(0, str(measurements))
    sys.path.insert(0, str(root))
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class BindingsAndProfile(unittest.TestCase):
    def test_bindings_require_candidate_runner_and_image_digests(self):
        self.assertEqual(hosted.require_bindings(CANDIDATE, RUNNER, IMAGE), BINDINGS)
        with self.assertRaises(hosted.HostedPublicationError):
            hosted.require_bindings("short", RUNNER, IMAGE)
        with self.assertRaises(hosted.HostedPublicationError):
            hosted.require_bindings(CANDIDATE, "short", IMAGE)
        with self.assertRaises(hosted.HostedPublicationError):
            hosted.require_bindings(CANDIDATE, RUNNER, "sha256:dead")

    def test_operator_profile_refuses_trusted_local(self):
        self.assertEqual(
            hosted.require_operator_profile(hosted.REQUIRED_PROFILE),
            hosted.REQUIRED_PROFILE,
        )
        with self.assertRaises(hosted.HostedPublicationError):
            hosted.require_operator_profile("trusted-local")


class HostileWorkflowRefusals(unittest.TestCase):
    def test_refuse_hostile_surfaces(self):
        hosted.refuse_hostile_workflow(
            runs_on=hosted.RUNS_ON, persist_credentials=False, mounts=(), env_names=()
        )
        with self.assertRaises(hosted.HostedPublicationError):
            hosted.refuse_hostile_workflow(
                runs_on="self-hosted", persist_credentials=False, mounts=(), env_names=()
            )
        with self.assertRaises(hosted.HostedPublicationError):
            hosted.refuse_hostile_workflow(
                runs_on=hosted.RUNS_ON, persist_credentials=True, mounts=(), env_names=()
            )
        with self.assertRaises(hosted.HostedPublicationError):
            hosted.refuse_hostile_workflow(
                runs_on=hosted.RUNS_ON,
                persist_credentials=False,
                mounts=[{"source": "/var/run/docker.sock", "destination": "/var/run/docker.sock"}],
                env_names=(),
            )
        with self.assertRaises(hosted.HostedPublicationError):
            hosted.refuse_hostile_workflow(
                runs_on=hosted.RUNS_ON,
                persist_credentials=False,
                mounts=[{"destination": "/github/workspace", "rw": True}],
                env_names=(),
            )
        with self.assertRaises(hosted.HostedPublicationError):
            hosted.refuse_hostile_workflow(
                runs_on=hosted.RUNS_ON,
                persist_credentials=False,
                mounts=(),
                env_names=("GITHUB_TOKEN",),
            )


class PublicationDecisionAndArtifacts(unittest.TestCase):
    def test_verified_envelope_only_publication_guard(self):
        self.assertEqual(
            hosted.publication_decision(_permitted_envelope(), setup_status="ready")["decision"],
            "publish",
        )
        self.assertEqual(
            hosted.publication_decision(
                _permitted_envelope(envelope_status="unverified"), setup_status="ready"
            )["decision"],
            "withhold",
        )
        absent = _permitted_envelope()
        del absent["envelope_status"]
        self.assertEqual(
            hosted.publication_decision(absent, setup_status="ready")["decision"],
            "withhold",
        )
        self.assertEqual(
            hosted.publication_decision(None, setup_status="ready")["decision"],
            "withhold",
        )

    def test_unverified_and_absent_status_independently_withhold(self):
        # Unmasked: each failure mode is its own assertion.
        unverified = hosted.publication_decision(
            _permitted_envelope(envelope_status="unverified"), setup_status="ready"
        )
        self.assertEqual(unverified["decision"], "withhold")
        self.assertEqual(unverified["envelope_status"], "unverified")
        absent_status = _permitted_envelope()
        del absent_status["envelope_status"]
        absent = hosted.publication_decision(absent_status, setup_status="ready")
        self.assertEqual(absent["decision"], "withhold")
        self.assertIsNone(absent["envelope_status"])

    def test_missing_containment_is_unavailable_void_never_score(self):
        with tempfile.TemporaryDirectory() as raw:
            out = Path(raw) / "artifacts"
            facts = _facts_file(Path(raw))

            def boom():
                raise contained.DockerUnavailable("docker executable is not available")

            decision = hosted.run_gate(
                candidate_revision=CANDIDATE,
                runner_revision=RUNNER,
                image_digest=IMAGE,
                operator_profile=hosted.REQUIRED_PROFILE,
                out_dir=out,
                workflow_facts_path=facts,
                docker_ready=boom,
            )
            self.assertEqual(decision["decision"], "unavailable")
            self.assertEqual(decision["score_status"], "none")
            cand = json.loads((out / hosted.CANDIDATE_RESULT_FILENAME).read_text())
            self.assertEqual(cand["kind"], "void-hosted-result")
            self.assertNotIn("score_percent", cand)
            self.assertTrue((out / hosted.RERUN_EVIDENCE_FILENAME).is_file())

    def test_publish_requires_separate_setup_envelope_candidate_artifacts(self):
        setup = hosted.setup_status_doc(
            status="unavailable", reason="x", bindings=BINDINGS
        )
        env = hosted.withheld_envelope_stub(reason="x", bindings=BINDINGS)
        cand = hosted.void_candidate_result(reason="x", bindings=BINDINGS)
        with tempfile.TemporaryDirectory() as raw:
            hosted.write_separate_artifacts(raw, setup, env, cand)
            with self.assertRaises(hosted.HostedPublicationError):
                hosted.write_separate_artifacts(raw, setup, None, cand)
            with self.assertRaises(hosted.HostedPublicationError):
                hosted.write_separate_artifacts(raw, setup, setup, cand)

    def test_append_only_rerun_preserves_first_infrastructure_failure(self):
        with tempfile.TemporaryDirectory() as raw:
            log = Path(raw) / "rerun.jsonl"
            hosted.append_rerun_evidence(log, {"reason": "first"})
            before = log.read_bytes()
            hosted.append_rerun_evidence(log, {"reason": "second"})
            self.assertTrue(log.read_bytes().startswith(before))
            self.assertEqual(json.loads(log.read_text().splitlines()[0])["reason"], "first")

    def test_sealed_execute_path_publishes_only_verified_permitted(self):
        with tempfile.TemporaryDirectory() as raw:
            out = Path(raw) / "artifacts"
            facts = _facts_file(Path(raw))

            def ready():
                return "27.0.0"

            def execute(**kwargs):
                Path(kwargs["envelope_dest"]).write_text(
                    json.dumps(_permitted_envelope()), encoding="utf-8"
                )

            decision = hosted.run_gate(
                candidate_revision=CANDIDATE,
                runner_revision=RUNNER,
                image_digest=IMAGE,
                operator_profile=hosted.REQUIRED_PROFILE,
                out_dir=out,
                workflow_facts_path=facts,
                authorize_path="a",
                prepare_path="b",
                pins_dir="c",
                docker_ready=ready,
                sealed_execute=execute,
            )
            self.assertEqual(decision["decision"], "publish")

            def execute_unverified(**kwargs):
                Path(kwargs["envelope_dest"]).write_text(
                    json.dumps(_permitted_envelope(envelope_status="unverified")),
                    encoding="utf-8",
                )

            out2 = Path(raw) / "artifacts2"
            decision2 = hosted.run_gate(
                candidate_revision=CANDIDATE,
                runner_revision=RUNNER,
                image_digest=IMAGE,
                operator_profile=hosted.REQUIRED_PROFILE,
                out_dir=out2,
                workflow_facts_path=facts,
                authorize_path="a",
                prepare_path="b",
                pins_dir="c",
                docker_ready=ready,
                sealed_execute=execute_unverified,
            )
            self.assertEqual(decision2["decision"], "withhold")


class SourceMutations(unittest.TestCase):
    def test_mutation_delete_verified_envelope_guard_is_red(self):
        original = Path(hosted.__file__).read_text(encoding="utf-8")
        needle = 'envelope_status != "verified"'
        mutated = original.replace(
            needle,
            'False and envelope_status != "verified"',
            1,
        )
        self.assertNotEqual(mutated, original)
        bad = _load_mutated_module(mutated, "mut_guard")
        leaked = bad.publication_decision(
            _permitted_envelope(envelope_status="unverified"), setup_status="ready"
        )
        self.assertEqual(leaked["decision"], "publish")
        self.assertEqual(
            hosted.publication_decision(
                _permitted_envelope(envelope_status="unverified"), setup_status="ready"
            )["decision"],
            "withhold",
        )

    def test_mutation_delete_refuse_hostile_call_is_red(self):
        original = Path(hosted.__file__).read_text(encoding="utf-8")
        # Remove the consumer call inside run_gate (second occurrence after write_workflow_facts).
        call = (
            "    refuse_hostile_workflow(\n"
            '        runs_on=facts["runs_on"],\n'
            '        persist_credentials=facts["persist_credentials"],\n'
            '        mounts=facts["mounts"],\n'
            '        env_names=facts["env_names"],\n'
            "    )\n"
        )
        self.assertEqual(original.count(call), 1)
        mutated = original.replace(call, "    pass  # mutated: refuse unwired\n", 1)
        self.assertNotEqual(mutated, original)
        bad = _load_mutated_module(mutated, "mut_refuse")
        with tempfile.TemporaryDirectory() as raw:
            facts_path = Path(raw) / "facts.json"
            # Hostile facts: self-hosted. Live gate must refuse; mutant skips refuse.
            facts_path.write_text(
                json.dumps(
                    {
                        "runs_on": "self-hosted",
                        "persist_credentials": False,
                        "mounts": [],
                        "env_names": [],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(hosted.HostedPublicationError):
                hosted.run_gate(
                    candidate_revision=CANDIDATE,
                    runner_revision=RUNNER,
                    image_digest=IMAGE,
                    operator_profile=hosted.REQUIRED_PROFILE,
                    out_dir=Path(raw) / "good",
                    workflow_facts_path=facts_path,
                    docker_ready=lambda: (_ for _ in ()).throw(
                        contained.DockerUnavailable("x")
                    ),
                )
            # Mutant proceeds past refuse (may fail later on docker) — must NOT raise runs_on.
            def boom():
                raise contained.DockerUnavailable("docker executable is not available")

            decision = bad.run_gate(
                candidate_revision=CANDIDATE,
                runner_revision=RUNNER,
                image_digest=IMAGE,
                operator_profile=hosted.REQUIRED_PROFILE,
                out_dir=Path(raw) / "bad",
                workflow_facts_path=facts_path,
                docker_ready=boom,
            )
            self.assertEqual(decision["decision"], "unavailable")

    def test_mutation_turn_unavailable_into_score_is_red(self):
        original = Path(hosted.__file__).read_text(encoding="utf-8")
        mutated = original.replace(
            '"decision": "unavailable",\n            "score_status": "none",',
            '"decision": "unavailable",\n            "score_status": "scored", "score_percent": 100.0,',
            1,
        )
        self.assertNotEqual(mutated, original)
        bad = _load_mutated_module(mutated, "mut_score")
        decision = bad.publication_decision(None, setup_status="unavailable")
        self.assertEqual(decision["score_status"], "scored")
        self.assertEqual(
            hosted.publication_decision(None, setup_status="unavailable")["score_status"],
            "none",
        )

    def test_mutation_erase_first_failure_on_rerun_is_red(self):
        original = Path(hosted.__file__).read_text(encoding="utf-8")
        mutated = original.replace(
            'with path.open("ab") as handle:\n        handle.write(line)',
            "path.write_bytes(line)",
            1,
        )
        self.assertNotEqual(mutated, original)
        bad = _load_mutated_module(mutated, "mut_rerun")
        with tempfile.TemporaryDirectory() as raw:
            log = Path(raw) / "rerun.jsonl"
            bad.append_rerun_evidence(log, {"reason": "first"})
            bad.append_rerun_evidence(log, {"reason": "second"})
            self.assertEqual(len(log.read_text().splitlines()), 1)
            good = Path(raw) / "good.jsonl"
            hosted.append_rerun_evidence(good, {"reason": "first"})
            before = good.read_bytes()
            hosted.append_rerun_evidence(good, {"reason": "second"})
            self.assertTrue(good.read_bytes().startswith(before))

    def test_python_comment_only_noop_control_stays_green(self):
        original = Path(hosted.__file__).read_text(encoding="utf-8")
        mutated = original.replace(
            '"""Hosted contained publication gate (#107).',
            '"""Hosted contained publication gate (#107).\n# noop',
            1,
        )
        mod = _load_mutated_module(mutated, "noop")
        self.assertEqual(
            mod.publication_decision(None, setup_status="unavailable")["decision"],
            "unavailable",
        )


class ExportedConstants(unittest.TestCase):
    def test_closed_constants(self):
        self.assertEqual(hosted.REQUIRED_PROFILE, "contained-oci-v0")
        self.assertEqual(hosted.RETENTION_DAYS, 14)
        self.assertEqual(hosted.MAX_ARTIFACT_BYTES, 5242880)
        self.assertEqual(hosted.ARTIFACT_RERUN, "rerun-evidence")


if __name__ == "__main__":
    unittest.main()
