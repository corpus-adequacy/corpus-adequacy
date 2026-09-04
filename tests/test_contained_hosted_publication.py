#!/usr/bin/env python3
"""Behavioral RED/GREEN + mutations for the hosted publication gate (#107)."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = REPO_ROOT / "measurements" / "contained_hosted_publication.py"
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "measurements"))

import contained_hosted_publication as hosted  # noqa: E402

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


def _load_mutated_module(source: str, name: str):
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        path = root / "contained_hosted_publication.py"
        path.write_text(source, encoding="utf-8")
        # Sibling imports: copy contained_oci stub surface by path injection.
        measurements = REPO_ROOT / "measurements"
        sys.path.insert(0, str(measurements))
        sys.path.insert(0, str(root))
        try:
            spec = importlib.util.spec_from_file_location(name, path)
            mod = importlib.util.module_from_spec(spec)
            assert spec.loader is not None
            sys.modules[name] = mod
            spec.loader.exec_module(mod)
            return mod
        finally:
            sys.modules.pop(name, None)
            if str(root) in sys.path:
                sys.path.remove(str(root))
            if str(measurements) in sys.path and sys.path.count(str(measurements)) > 1:
                sys.path.remove(str(measurements))


class BindingsAndProfile(unittest.TestCase):
    def test_bindings_require_candidate_runner_and_image_digests(self):
        got = hosted.require_bindings(CANDIDATE, RUNNER, IMAGE)
        self.assertEqual(got, BINDINGS)
        for kwargs in (
            {"candidate_revision": "short", "runner_revision": RUNNER,
             "image_digest": IMAGE},
            {"candidate_revision": CANDIDATE, "runner_revision": "short",
             "image_digest": IMAGE},
            {"candidate_revision": CANDIDATE, "runner_revision": RUNNER,
             "image_digest": "sha256:dead"},
            {"candidate_revision": None, "runner_revision": RUNNER,
             "image_digest": IMAGE},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(hosted.HostedPublicationError):
                    hosted.require_bindings(**kwargs)

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
            runs_on=hosted.RUNS_ON,
            persist_credentials=False,
            mounts=[],
            env_names=["PYTHON_VERSION"],
        )
        cases = (
            {"runs_on": "self-hosted", "persist_credentials": False,
             "mounts": [], "env_names": []},
            {"runs_on": "local", "persist_credentials": False,
             "mounts": [], "env_names": []},
            {"runs_on": "ubuntu-latest", "persist_credentials": True,
             "mounts": [], "env_names": []},
            {"runs_on": "ubuntu-latest", "persist_credentials": False,
             "mounts": [{"source": "/var/run/docker.sock",
                         "destination": "/var/run/docker.sock"}],
             "env_names": []},
            {"runs_on": "ubuntu-latest", "persist_credentials": False,
             "mounts": [{"kind": "checkout", "source": "checkout",
                         "destination": "/github/workspace", "writable": True}],
             "env_names": []},
            {"runs_on": "ubuntu-latest", "persist_credentials": False,
             "mounts": [], "env_names": ["GITHUB_TOKEN"]},
            {"runs_on": "ubuntu-latest", "persist_credentials": False,
             "mounts": [], "env_names": ["AWS_SECRET_ACCESS_KEY"]},
        )
        for kwargs in cases:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(hosted.HostedPublicationError):
                    hosted.refuse_hostile_workflow(**kwargs)


class PublicationDecisionAndArtifacts(unittest.TestCase):
    def test_missing_containment_is_unavailable_void_never_score(self):
        decision = hosted.publication_decision(None, setup_status="unavailable")
        self.assertEqual(decision["decision"], "unavailable")
        self.assertEqual(decision["score_status"], "none")
        void = hosted.void_candidate_result(
            reason="setup-unavailable", bindings=BINDINGS)
        self.assertEqual(void["kind"], "void-hosted-result")
        self.assertEqual(void["score_status"], "none")
        self.assertEqual(void["mutant_status"], "not-scored")
        self.assertNotIn("score", void)
        self.assertNotIn("adequacy", void)

    def test_verified_envelope_only_publication_guard(self):
        withheld = hosted.publication_decision(
            {"publication_permission": "withheld"}, setup_status="ready")
        self.assertEqual(withheld["decision"], "withhold")
        missing = hosted.publication_decision(None, setup_status="ready")
        self.assertEqual(missing["decision"], "withhold")
        permitted = hosted.publication_decision(
            _permitted_envelope(), setup_status="ready")
        self.assertEqual(permitted["decision"], "publish")

    def test_publish_requires_separate_setup_envelope_candidate_artifacts(self):
        with tempfile.TemporaryDirectory() as raw:
            out = Path(raw)
            setup = hosted.setup_status_doc(
                status="ready", reason="ok", bindings=BINDINGS)
            envelope = _permitted_envelope()
            candidate = hosted.void_candidate_result(
                reason="placeholder", bindings=BINDINGS)
            written = hosted.write_separate_artifacts(
                out, setup, envelope, candidate)
            self.assertEqual(
                set(written),
                {
                    hosted.SETUP_STATUS_FILENAME,
                    hosted.EFFECTIVE_ENVELOPE_FILENAME,
                    hosted.CANDIDATE_RESULT_FILENAME,
                },
            )
            for path in written.values():
                self.assertTrue(path.is_file())
            with self.assertRaises(hosted.HostedPublicationError):
                hosted.write_separate_artifacts(out, setup, envelope, None)
            with self.assertRaises(hosted.HostedPublicationError):
                hosted.write_separate_artifacts(out, setup, None, candidate)
            with self.assertRaises(hosted.HostedPublicationError):
                hosted.write_separate_artifacts(out, None, envelope, candidate)

    def test_append_only_rerun_preserves_first_infrastructure_failure(self):
        with tempfile.TemporaryDirectory() as raw:
            log = Path(raw) / "rerun-evidence.jsonl"
            first = {"kind": "infrastructure-failure", "reason": "docker-missing",
                     "seq": 1}
            second = {"kind": "infrastructure-failure", "reason": "docker-missing",
                      "seq": 2}
            hosted.append_rerun_evidence(log, first)
            first_bytes = log.read_bytes()
            hosted.append_rerun_evidence(log, second)
            after = log.read_bytes()
            self.assertTrue(after.startswith(first_bytes))
            self.assertEqual(after[:len(first_bytes)], first_bytes)
            lines = after.splitlines()
            self.assertEqual(len(lines), 2)
            self.assertEqual(json.loads(lines[0]), first)


class GateCLI(unittest.TestCase):
    def test_default_gate_writes_unavailable_void_and_withheld_stub(self):
        with tempfile.TemporaryDirectory() as raw:
            out = Path(raw) / "artifacts"
            log = out / "rerun-evidence.jsonl"
            rc = hosted.main([
                "gate",
                "--candidate-revision", CANDIDATE,
                "--runner-revision", RUNNER,
                "--image-digest", IMAGE,
                "--operator-profile", hosted.REQUIRED_PROFILE,
                "--out", str(out),
                "--rerun-log", str(log),
            ])
            self.assertEqual(rc, 0)
            setup = json.loads(
                (out / hosted.SETUP_STATUS_FILENAME).read_text(encoding="utf-8"))
            envelope = json.loads(
                (out / hosted.EFFECTIVE_ENVELOPE_FILENAME).read_text(
                    encoding="utf-8"))
            candidate = json.loads(
                (out / hosted.CANDIDATE_RESULT_FILENAME).read_text(
                    encoding="utf-8"))
            self.assertEqual(setup["setup_status"], "unavailable")
            self.assertEqual(envelope["publication_permission"], "withheld")
            self.assertEqual(candidate["kind"], "void-hosted-result")
            self.assertEqual(candidate["score_status"], "none")
            self.assertTrue(log.is_file())
            first = log.read_bytes()
            hosted.append_rerun_evidence(log, {"kind": "retry", "n": 2})
            self.assertEqual(log.read_bytes()[:len(first)], first)

    def test_permitted_envelope_publishes_separate_artifacts(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            env_path = root / "envelope.json"
            env_path.write_text(
                json.dumps(_permitted_envelope(), indent=2) + "\n",
                encoding="utf-8",
            )
            out = root / "artifacts"
            rc = hosted.main([
                "gate",
                "--candidate-revision", CANDIDATE,
                "--runner-revision", RUNNER,
                "--image-digest", IMAGE,
                "--out", str(out),
                "--envelope", str(env_path),
            ])
            self.assertEqual(rc, 0)
            candidate = json.loads(
                (out / hosted.CANDIDATE_RESULT_FILENAME).read_text(
                    encoding="utf-8"))
            self.assertEqual(candidate["decision"], "publish")
            self.assertEqual(candidate["score_status"], "none")


class SourceMutations(unittest.TestCase):
    def _source(self) -> str:
        return MODULE_PATH.read_text(encoding="utf-8")

    def test_mutation_delete_verified_envelope_guard_is_red(self):
        """Temp rewrite that always publishes must fail the contract oracle."""
        source = self._source()
        poisoned = source.replace(
            "if envelope is None or permission != \"permitted\":",
            "if False and (envelope is None or permission != \"permitted\"):",
            1,
        )
        self.assertNotEqual(poisoned, source)
        mod = _load_mutated_module(poisoned, "hosted_mut_delete_guard")
        # Oracle living in the test: withhold required when permission absent.
        decision = mod.publication_decision(None, setup_status="ready")
        self.assertEqual(
            decision["decision"], "publish",
            "mutated guard must mis-behave (publish without envelope)",
        )
        # Contract oracle: live module still withholds.
        live = hosted.publication_decision(None, setup_status="ready")
        self.assertEqual(live["decision"], "withhold")
        self.assertNotEqual(decision["decision"], live["decision"])

    def test_mutation_turn_unavailable_into_score_is_red(self):
        source = self._source()
        poisoned = source.replace(
            '"score_status": "none"',
            '"score_status": "scored"',
            1,
        )
        self.assertNotEqual(poisoned, source)
        mod = _load_mutated_module(poisoned, "hosted_mut_unavail_score")
        decision = mod.publication_decision(None, setup_status="unavailable")
        self.assertEqual(decision["decision"], "unavailable")
        self.assertEqual(decision["score_status"], "scored")
        # Oracle: unavailable must never carry a score status other than none.
        self.assertEqual(
            hosted.publication_decision(None, setup_status="unavailable")
            ["score_status"],
            "none",
        )
        self.assertNotEqual(decision["score_status"], "none")

    def test_mutation_erase_first_failure_on_rerun_is_red(self):
        source = self._source()
        poisoned = source.replace(
            'with path.open("ab") as handle:\n        handle.write(line)',
            'with path.open("wb") as handle:\n        handle.write(line)',
            1,
        )
        self.assertNotEqual(poisoned, source)
        mod = _load_mutated_module(poisoned, "hosted_mut_erase_first")
        with tempfile.TemporaryDirectory() as raw:
            log = Path(raw) / "rerun.jsonl"
            first = {"reason": "first", "n": 1}
            second = {"reason": "second", "n": 2}
            mod.append_rerun_evidence(log, first)
            first_bytes = log.read_bytes()
            mod.append_rerun_evidence(log, second)
            after = log.read_bytes()
            # Mutated truncate path erases the first failure.
            self.assertFalse(after.startswith(first_bytes) and after != first_bytes)
            self.assertEqual(json.loads(after.splitlines()[0]), second)
            # Live oracle still appends.
            live = Path(raw) / "live.jsonl"
            hosted.append_rerun_evidence(live, first)
            kept = live.read_bytes()
            hosted.append_rerun_evidence(live, second)
            self.assertTrue(live.read_bytes().startswith(kept))

    def test_python_comment_only_noop_control_stays_green(self):
        source = self._source()
        commented = source.replace(
            '"""Hosted contained publication gate (#107).',
            '"""Hosted contained publication gate (#107).\n# comment-only noop',
            1,
        )
        self.assertNotEqual(commented, source)
        mod = _load_mutated_module(commented, "hosted_mut_comment_noop")
        self.assertEqual(
            mod.publication_decision(None, setup_status="unavailable")["decision"],
            "unavailable",
        )
        self.assertEqual(
            mod.publication_decision(_permitted_envelope(), setup_status="ready")
            ["decision"],
            "publish",
        )
        with tempfile.TemporaryDirectory() as raw:
            out = Path(raw)
            mod.write_separate_artifacts(
                out,
                mod.setup_status_doc(status="ready", reason="ok", bindings=BINDINGS),
                _permitted_envelope(),
                mod.void_candidate_result(reason="ok", bindings=BINDINGS),
            )
            self.assertTrue((out / mod.SETUP_STATUS_FILENAME).is_file())


class ExportedConstants(unittest.TestCase):
    def test_closed_constants(self):
        self.assertEqual(hosted.REQUIRED_PROFILE, "contained-oci-v0")
        self.assertEqual(hosted.CONCURRENCY_GROUP, "contained-hosted-publication")
        self.assertIs(hosted.CANCEL_IN_PROGRESS, False)
        self.assertEqual(hosted.RETENTION_DAYS, 14)
        self.assertEqual(hosted.MAX_ARTIFACT_BYTES, 5242880)
        self.assertEqual(hosted.TIMEOUT_MINUTES, 15)
        self.assertEqual(hosted.RUNS_ON, "ubuntu-latest")
        self.assertEqual(
            hosted.HOSTED_SCHEMA, "corpus-adequacy.hosted-publication.v0")
        self.assertEqual(hosted.ARTIFACT_SETUP, "setup")
        self.assertEqual(hosted.ARTIFACT_ENVELOPE, "effective-envelope")
        self.assertEqual(hosted.ARTIFACT_CANDIDATE, "candidate-result")


if __name__ == "__main__":
    unittest.main()
