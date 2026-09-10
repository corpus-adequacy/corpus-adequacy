#!/usr/bin/env python3
"""Synthetic contract for the generic-engine to sealed-candidate adapter."""

from __future__ import annotations

import hashlib
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


def _prepare_v2() -> bytes:
    """Canonical prepare.v2 bytes from the real codec, pinning the frozen v2 fixture."""
    from tests.test_aee_checker_sealed_candidate import _prepare_raw
    import contained_oci as contained
    return _prepare_raw(contained.CANDIDATE_RESOURCE_PROFILE_V2)


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
                    transport=object(), execution_profile="contained-oci-v0",
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
                    execution_profile="contained-oci-v0",
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
                prepare_raw=_prepare_v1(), materialized=materialized,
                execution_profile="contained-oci-v0")
            manifest = {"_repo_root": root}
            for vectors, rebuild in ((None, True), ([{}], False)):
                with self.subTest(vectors=vectors, rebuild=rebuild), \
                        self.assertRaisesRegex(Exception, "combined"):
                    backend(manifest, vectors, rebuild=rebuild)



class RuntimeReachesTheRealCandidate(unittest.TestCase):
    """#102 A3: the backend passes the profile it declares to the real `run_sealed_candidate`.

    Nothing at or above admission is mocked. The transport is fake, and `_run_sealed_candidate`
    (below admission) is observed with `wraps`, so the real funnel still runs underneath it.
    """

    def _run(self, prepare_raw, resource_profile, execution_profile):
        from tests.test_aee_checker_sealed_candidate import (
            ObservingTransport, _observed_inspect)
        toolchain = json.loads(prepare_raw)["toolchain"]["image_id"]
        transport = ObservingTransport(
            stdout="", inspect=_observed_inspect(resource_profile, image=toolchain))
        records = []
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
                    runtime.candidate, "_run_sealed_candidate",
                    wraps=runtime.candidate._run_sealed_candidate) as below:
                backend = runtime.make_sealed_backend(
                    prepare_raw=prepare_raw, materialized=materialized,
                    transport=transport, envelope_sink=records.append,
                    execution_profile=execution_profile)
                self.assertEqual(backend.execution_profile, execution_profile)
                result = backend(manifest, [{"vector_id": "<batch>"}], rebuild=True)
        self.assertEqual(below.call_count, 1)
        self.assertEqual(below.call_args.kwargs["execution_profile"], execution_profile)
        self.assertEqual(below.call_args.kwargs["resource_profile"], resource_profile)
        self.assertEqual(len(transport.created), 1)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["requested"]["execution_profile"], execution_profile)
        self.assertEqual(records[0]["envelope_status"], "verified",
                         records[0]["unverified_field"])
        self.assertEqual(
            records[0]["prepare_sha256"], hashlib.sha256(prepare_raw).hexdigest())
        self.assertEqual(
            records[0]["execution_commit"], json.loads(prepare_raw)["execution"]["commit"])
        self.assertEqual(result.raised, {"<batch>": "unproved"})
        return transport.created[0], records[0]

    def test_runtime_passes_contained_oci_v0_to_the_real_candidate(self):
        argv, record = self._run(
            _prepare_v1(), common.CANDIDATE_RESOURCE_PROFILE, "contained-oci-v0")
        for flag in ("--cpu-period", "--cpu-quota", "--ulimit", "--cpus"):
            self.assertNotIn(flag, argv)
        self.assertEqual(record["schema"], "corpus-adequacy.execution-envelope.v0")

    def test_runtime_passes_contained_oci_v1_to_the_real_candidate(self):
        import contained_oci as contained
        argv, record = self._run(
            _prepare_v2(), contained.CANDIDATE_RESOURCE_PROFILE_V2, "contained-oci-v1")
        for flag in ("--cpu-period", "--cpu-quota", "--ulimit"):
            self.assertEqual(argv.count(flag), 1, flag)
        self.assertNotIn("--cpus", argv)
        self.assertEqual(record["schema"], "corpus-adequacy.execution-envelope.v1")


class RuntimeDeclaresAndAdmitsByProfile(unittest.TestCase):
    """#102 A3: the backend carries its profile, and the binding PREPARE goes through the one
    dispatcher, so the envelope binding is never read with a loader the profile did not select."""

    def _materialized(self, root: Path) -> dict:
        materialized = {key: root / key for key in ("corpus", "vendor", "tool")}
        for path in materialized.values():
            path.mkdir()
        return materialized

    def test_backend_declares_the_profile_it_was_built_for(self):
        with tempfile.TemporaryDirectory() as d:
            materialized = self._materialized(Path(d))
            for raw, profile in ((_prepare_v1(), "contained-oci-v0"),
                                 (_prepare_v2(), "contained-oci-v1")):
                with self.subTest(profile=profile):
                    backend = runtime.make_sealed_backend(
                        prepare_raw=raw, materialized=materialized,
                        execution_profile=profile, envelope_sink=[].append)
                    self.assertEqual(backend.execution_profile, profile)

    def test_a_relabelled_backend_passes_its_declaration_and_admission_refuses(self):
        """The declaration is the one source: relabelling a v0-built backend as v1 does not run
        the v0 PREPARE under a v1 label, because admission then runs under v1 and refuses."""
        from tests.test_aee_checker_sealed_candidate import NoEffectTransport
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            materialized = self._materialized(root)
            subject = root / "subject"
            subject.mkdir()
            backend = runtime.make_sealed_backend(
                prepare_raw=_prepare_v1(), materialized=materialized,
                execution_profile="contained-oci-v0", transport=NoEffectTransport(),
                envelope_sink=[].append)
            backend.execution_profile = "contained-oci-v1"
            with mock.patch.object(
                    runtime.candidate, "run_sealed_candidate",
                    wraps=runtime.candidate.run_sealed_candidate) as sealed, \
                    self.assertRaisesRegex(
                        common.PrepareError, "contained-oci-v1 admits only prepare.v2"):
                backend({"_repo_root": subject}, [{"vector_id": "<batch>"}], rebuild=True)
        self.assertEqual(sealed.call_args.kwargs["execution_profile"], "contained-oci-v1")

    def test_binding_prepare_goes_through_the_dispatcher(self):
        with tempfile.TemporaryDirectory() as d:
            materialized = self._materialized(Path(d))
            with mock.patch.object(
                    runtime, "load_prepare_for_profile",
                    wraps=run.load_prepare_for_profile) as dispatcher:
                runtime.make_sealed_backend(
                    prepare_raw=_prepare_v2(), materialized=materialized,
                    execution_profile="contained-oci-v1", envelope_sink=[].append)
        dispatcher.assert_called_once_with(
            _prepare_v2(), execution_profile="contained-oci-v1")

    def test_crossed_binding_prepare_refuses_at_construction(self):
        with tempfile.TemporaryDirectory() as d:
            materialized = self._materialized(Path(d))
            for raw, profile, message in (
                    (_prepare_v2(), "contained-oci-v0", "prepare.v2 requires contained-oci-v1"),
                    (_prepare_v1(), "contained-oci-v1",
                     "contained-oci-v1 admits only prepare.v2")):
                with self.subTest(profile=profile), \
                        self.assertRaisesRegex(common.PrepareError, message):
                    runtime.make_sealed_backend(
                        prepare_raw=raw, materialized=materialized,
                        execution_profile=profile, envelope_sink=[].append)

    def test_omitting_execution_profile_is_typeerror(self):
        import inspect
        parameter = inspect.signature(runtime.make_sealed_backend).parameters[
            "execution_profile"]
        self.assertIs(parameter.default, inspect.Parameter.empty)
        with tempfile.TemporaryDirectory() as d:
            materialized = self._materialized(Path(d))
            with self.assertRaises(TypeError):
                runtime.make_sealed_backend(
                    prepare_raw=_prepare_v1(), materialized=materialized)

    def test_runtime_code_names_no_profile_literal(self):
        """Code, not prose: no executable string in the runtime names a profile."""
        import ast
        import inspect
        tree = ast.parse(inspect.getsource(runtime))
        docstrings = {
            id(node.body[0].value) for node in ast.walk(tree)
            if isinstance(node, (ast.Module, ast.FunctionDef)) and node.body
            and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)}
        literals = [node.value for node in ast.walk(tree)
                    if isinstance(node, ast.Constant) and isinstance(node.value, str)
                    and id(node) not in docstrings]
        self.assertFalse([v for v in literals if "contained-oci-v" in v], literals)


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
                    execution_profile="contained-oci-v0",
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
                separate_build_phase=True,
                execution_profile="trusted-local")
        self.assertTrue(
            any(
                "failed (unproved) [timeout] on" in item
                for item in report["failures"]),
            report["failures"])

    @unittest.skipIf(ca.fcntl is None, "process scoring requires an advisory lock")
    def test_suffix_reason_allowlist_tracks_core_closed_set(self):
        saved = ca.CLOSED_UNPROVED_REASONS
        ca.CLOSED_UNPROVED_REASONS = tuple(
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
                    separate_build_phase=True,
                    execution_profile="trusted-local")
        finally:
            ca.CLOSED_UNPROVED_REASONS = saved
        self.assertFalse(
            any("[timeout]" in item for item in report["failures"]),
            report["failures"])

if __name__ == "__main__":
    unittest.main()
