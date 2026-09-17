"""Behavioral closure checks for the owned contained execution identity."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
for candidate in (str(ROOT), str(ROOT / "measurements")):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

import aee_checker_sealed_candidate as sealed_candidate  # noqa: E402
import aee_checker_sealed_runtime as runtime  # noqa: E402
from sealed_measurement_contract import OWNED_CONTAINED_V1_CONTRACT  # noqa: E402


class _Ledger:
    def register(self, *, step=None):
        return 1

    def no_envelope(self, _ordinal):
        pass

    def recorded(self, _ordinal, _record, *, returncode=None):
        pass

    def raised(self, _ordinal, _name):
        pass


class OwnedExecutionIdentityClosure(unittest.TestCase):
    def test_real_owned_projection_and_diagnostic_route_stay_inside_identity(self):
        observed = set()

        def trace(frame, event, _arg):
            if event == "call":
                if frame.f_code.co_filename.startswith("<"):
                    return trace
                try:
                    rel = Path(frame.f_code.co_filename).resolve().relative_to(ROOT).as_posix()
                except (OSError, ValueError):
                    return trace
                if not rel.startswith("tests/"):
                    observed.add(rel)
            return trace

        fixture = ROOT / "fixtures" / "contained-v1-owned" / "corpus"
        ids = sealed_candidate.sealed_adapter_for(
            OWNED_CONTAINED_V1_CONTRACT).expected_ids(fixture / "vectors")
        inner = {"vectors": [
            {"id": row_id, "accepted": True, "reason": "accepted", "detail": "ok"}
            for row_id in ids
        ]}
        rows = []
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            materialized = {key: root / key for key in ("corpus", "vendor", "tool")}
            for path in materialized.values():
                path.mkdir()
            subject = root / "subject"
            subject.mkdir()
            manifest = {
                "_repo_root": subject,
                "accepted_exit_codes": [0],
                "unproved_exit_codes": [75],
                "runner": "batch",
                "outcome_from": ["rows"],
                "diagnostic_from": ["diagnostics"],
                "build": list(OWNED_CONTAINED_V1_CONTRACT.candidate_build),
                "entrypoint_command": list(OWNED_CONTAINED_V1_CONTRACT.candidate_entrypoint),
            }
            projected = sealed_candidate.normalize_inner_event(
                returncode=0,
                stdout=json.dumps(inner, sort_keys=True, separators=(",", ":")) + "\n",
                vectors=fixture / "vectors",
                contract=OWNED_CONTAINED_V1_CONTRACT,
            )
            self.assertEqual(projected.returncode, 0)
            completed = subprocess.CompletedProcess(
                args=[], returncode=0,
                stdout='{"diagnostics":["d"],"rows":["r"]}', stderr="")
            sys.setprofile(trace)
            try:
                with mock.patch.object(runtime, "normalize_readonly_bind_modes"), \
                        mock.patch.object(
                            runtime.candidate, "run_sealed_candidate", return_value=completed):
                    result = runtime.make_sealed_backend(
                        prepare_raw=b"{}", materialized=materialized,
                        execution_profile="contained-oci-v0", ledger=_Ledger(),
                        diagnostic_sink=rows.append,
                        contract=OWNED_CONTAINED_V1_CONTRACT,
                    )(manifest, [{"vector_id": "<batch>"}], rebuild=True)
            finally:
                sys.setprofile(None)

        self.assertEqual(result.outcomes, {"<batch>": (("r",),)})
        self.assertEqual(rows, [{
            "ordinal": 1,
            "candidate_outcome": "completed",
            "unproved_reason": None,
        }])
        self.assertIn("measurements/candidate_diagnostics.py", observed)
        unbound = sorted(observed - set(OWNED_CONTAINED_V1_CONTRACT.execution_paths))
        self.assertEqual(unbound, [], "unbound executed Python source: %s" % unbound)


if __name__ == "__main__":
    unittest.main()
