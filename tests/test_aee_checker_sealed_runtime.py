#!/usr/bin/env python3
"""Synthetic contract for the generic-engine to sealed-candidate adapter."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "measurements"))

import aee_checker_sealed_common as common  # noqa: E402
import aee_checker_sealed_runtime as runtime  # noqa: E402
import aee_checker_sealed_run as run  # noqa: E402
import corpus_adequacy as ca  # noqa: E402

PREPARE_V0 = REPO_ROOT / "measurements" / "aee-go-run" / "prepare.v0.json"


def _prepare_v1() -> bytes:
    doc = json.loads(PREPARE_V0.read_text(encoding="utf-8"))
    doc["schema"] = run.PREPARE_V1_SCHEMA
    doc["candidate_profile"] = dict(common.CANDIDATE_RESOURCE_PROFILE)
    return common.encode_json(doc)


class SealedRuntimeBackend(unittest.TestCase):
    def test_uses_isolated_subject_and_prepare_bound_candidate_contract(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            materialized = {
                key: root / key for key in ("corpus", "vendor", "tool")
            }
            for path in materialized.values():
                path.mkdir()
            isolated = root / "isolated-subject"
            isolated.mkdir()
            manifest = {
                "_repo_root": isolated,
                "accepted_exit_codes": [0],
                "unproved_exit_codes": [75],
                "runner": "batch",
                "outcome_from": ["rows"],
                "diagnostic_from": ["diagnostics"],
                "build": list(runtime.candidate.CONTAINER_BUILD),
                "entrypoint_command": list(runtime.candidate.CONTAINER_ENTRYPOINT),
            }
            completed = subprocess.CompletedProcess(
                args=[], returncode=0,
                stdout='{"diagnostics":["d"],"rows":["r"]}', stderr="")
            with mock.patch.object(
                    runtime.candidate, "run_sealed_candidate",
                    return_value=completed) as sealed:
                result = runtime.make_sealed_backend(
                    prepare_raw=_prepare_v1(), materialized=materialized,
                    transport=object(),
                )(manifest, [{"vector_id": "<batch>"}], rebuild=True)

        kwargs = sealed.call_args.kwargs
        self.assertEqual(kwargs["prepare_raw"], _prepare_v1())
        self.assertIs(kwargs["execution_contract"], manifest)
        self.assertEqual(kwargs["mounts"]["subject"], isolated)
        self.assertEqual(set(kwargs["mounts"]), {"input", "vendor", "tool", "subject"})
        self.assertEqual(result.outcomes, {"<batch>": (("r",),)})
        self.assertEqual(result.diagnostics, {"<batch>": (("d",),)})
        self.assertEqual(
            result.selector_keys_seen,
            {"outcome_from": {"rows"}, "diagnostic_from": {"diagnostics"}},
        )

    def test_returncode_75_is_unproved_and_never_an_empty_success(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            materialized = {key: root / key for key in ("corpus", "vendor", "tool")}
            for path in materialized.values():
                path.mkdir()
            subject = root / "subject"
            subject.mkdir()
            manifest = {
                "_repo_root": subject,
                "accepted_exit_codes": [0], "unproved_exit_codes": [75],
                "runner": "batch", "outcome_from": ["rows"],
                "build": list(runtime.candidate.CONTAINER_BUILD),
                "entrypoint_command": list(runtime.candidate.CONTAINER_ENTRYPOINT),
            }
            completed = subprocess.CompletedProcess(
                args=[], returncode=75, stdout='{"rows":[]}', stderr="")
            with mock.patch.object(
                    runtime.candidate, "run_sealed_candidate",
                    return_value=completed):
                result = runtime.make_sealed_backend(
                    prepare_raw=_prepare_v1(), materialized=materialized,
                )(manifest, [{"vector_id": "<batch>"}], rebuild=True)
        self.assertEqual(result.raised, {"<batch>": "unproved"})
        self.assertEqual(result.outcomes, {})

    def test_refuses_compile_only_or_reused_build_calls(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            materialized = {key: root / key for key in ("corpus", "vendor", "tool")}
            for path in materialized.values():
                path.mkdir()
            backend = runtime.make_sealed_backend(
                prepare_raw=_prepare_v1(), materialized=materialized)
            manifest = {"_repo_root": root}
            for vectors, rebuild in ((None, True), ([{}], False)):
                with self.subTest(vectors=vectors, rebuild=rebuild), \
                        self.assertRaisesRegex(Exception, "combined"):
                    backend(manifest, vectors, rebuild=rebuild)



class ClosedUnprovedRuntime(unittest.TestCase):
    def _backend_result(self, completed):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            materialized = {key: root / key for key in ("corpus", "vendor", "tool")}
            for path in materialized.values():
                path.mkdir()
            subject = root / "subject"
            subject.mkdir()
            manifest = {
                "_repo_root": subject,
                "accepted_exit_codes": [0], "unproved_exit_codes": [75],
                "runner": "batch", "outcome_from": ["rows"],
                "build": list(runtime.candidate.CONTAINER_BUILD),
                "entrypoint_command": list(runtime.candidate.CONTAINER_ENTRYPOINT),
            }
            with mock.patch.object(
                    runtime.candidate, "run_sealed_candidate",
                    return_value=completed):
                return runtime.make_sealed_backend(
                    prepare_raw=_prepare_v1(), materialized=materialized,
                )(manifest, [{"vector_id": "<batch>"}], rebuild=True)

    def test_timeout_reason_becomes_execution_detail(self):
        completed = subprocess.CompletedProcess(
            args=[], returncode=75, stdout="", stderr="")
        completed.unproved_reason = "timeout"
        result = self._backend_result(completed)
        self.assertEqual(result.raised, {"<batch>": "unproved"})
        self.assertEqual(result.detail, "timeout")
        self.assertEqual(result.outcomes, {})

    def test_foreign_reason_is_not_copied_into_detail(self):
        completed = subprocess.CompletedProcess(
            args=[], returncode=75, stdout="/host/secret", stderr="trace")
        completed.unproved_reason = "/host/secret"
        result = self._backend_result(completed)
        self.assertEqual(result.raised, {"<batch>": "unproved"})
        self.assertEqual(result.detail, "sealed candidate completed")
        self.assertNotIn("/host", result.detail)

    def test_ok_completion_does_not_take_unproved_reason(self):
        completed = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout='{"diagnostics":["d"],"rows":["r"]}', stderr="")
        completed.unproved_reason = "timeout"
        result = self._backend_result(completed)
        self.assertEqual(result.raised, {})
        self.assertEqual(result.detail, "sealed candidate completed")


class ClosedUnprovedVoidSuffix(unittest.TestCase):
    @unittest.skipIf(ca.fcntl is None, "process scoring requires an advisory lock")
    def test_unmutated_unproved_suffix_keeps_closed_reason(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / "check.py").write_text("print('x')\n", encoding="utf-8")
            (tmp / "v1.json").write_text("{}\n", encoding="utf-8")
            (tmp / "vectors.json").write_text(json.dumps({
                "vectors": [{"vector_id": "v1", "path": "v1.json"}],
            }), encoding="utf-8")
            raw = {
                "schema": ca.SCHEMA, "runner": "process", "repo_root": ".",
                "implementation": "check.py",
                "implementation_sources": ["check.py"],
                "build": [],
                "entrypoint_command": [sys.executable, "check.py", "{vector}"],
                "outcome_from": ["ok"], "vectors": "vectors.json",
                "id_key": "vector_id", "vector_path_key": "path",
                "default_group": "g",
                "unproved_exit_codes": [75],
                "mutants": {"g": [
                    {"label": "threshold",
                     "anchor": "print('x')", "replacement": "print('y')"},
                    {"label": "CONTROL", "control": True,
                     "anchor": "print", "replacement": "print  # c"},
                ]},
            }
            manifest_path = tmp / "m.json"
            manifest_path.write_text(json.dumps(raw), encoding="utf-8")
            loaded = ca.load_manifest(manifest_path)

            def backend(manifest, vectors, rebuild=True):
                if not vectors:
                    return ca._ProcessExecution(True, "built", {}, {}, {}, {})
                return ca._ProcessExecution(
                    True, "timeout", {}, {}, {"<batch>": "unproved"}, {})

            report = ca._run_process(
                loaded, manifest_path, execution_backend=backend,
                separate_build_phase=True)
        self.assertTrue(
            any(
                "failed (unproved) [timeout] on" in item
                for item in report["failures"]),
            report["failures"])

    @unittest.skipIf(ca.fcntl is None, "process scoring requires an advisory lock")
    def test_suffix_reason_allowlist_tracks_common_closed_set(self):
        saved = common.CLOSED_UNPROVED_REASONS
        common.CLOSED_UNPROVED_REASONS = tuple(
            token for token in saved if token != "timeout")
        try:
            with tempfile.TemporaryDirectory() as d:
                tmp = Path(d)
                (tmp / "check.py").write_text("print('x')\n", encoding="utf-8")
                (tmp / "v1.json").write_text("{}\n", encoding="utf-8")
                (tmp / "vectors.json").write_text(json.dumps({
                    "vectors": [{"vector_id": "v1", "path": "v1.json"}],
                }), encoding="utf-8")
                raw = {
                    "schema": ca.SCHEMA, "runner": "process", "repo_root": ".",
                    "implementation": "check.py",
                    "implementation_sources": ["check.py"],
                    "build": [],
                    "entrypoint_command": [sys.executable, "check.py", "{vector}"],
                    "outcome_from": ["ok"], "vectors": "vectors.json",
                    "id_key": "vector_id", "vector_path_key": "path",
                    "default_group": "g",
                    "unproved_exit_codes": [75],
                    "mutants": {"g": [
                        {"label": "threshold",
                         "anchor": "print('x')", "replacement": "print('y')"},
                        {"label": "CONTROL", "control": True,
                         "anchor": "print", "replacement": "print  # c"},
                    ]},
                }
                manifest_path = tmp / "m.json"
                manifest_path.write_text(json.dumps(raw), encoding="utf-8")
                loaded = ca.load_manifest(manifest_path)

                def backend(manifest, vectors, rebuild=True):
                    if not vectors:
                        return ca._ProcessExecution(True, "built", {}, {}, {}, {})
                    return ca._ProcessExecution(
                        True, "timeout", {}, {}, {"<batch>": "unproved"}, {})

                report = ca._run_process(
                    loaded, manifest_path, execution_backend=backend,
                    separate_build_phase=True)
        finally:
            common.CLOSED_UNPROVED_REASONS = saved
        self.assertFalse(
            any("[timeout]" in item for item in report["failures"]),
            report["failures"])

if __name__ == "__main__":
    unittest.main()
