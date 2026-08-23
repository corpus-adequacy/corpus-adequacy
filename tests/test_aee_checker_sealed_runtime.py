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


if __name__ == "__main__":
    unittest.main()
