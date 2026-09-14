"""RED-first contract for the bounded candidate-diagnostics.v0 sidecar (#172)."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "measurements"))

import candidate_diagnostics as diagnostics  # noqa: E402


BINDINGS = {
    "candidate_revision": "a" * 40,
    "runner_revision": "b" * 40,
    "image_digest": "sha256:" + "c" * 64,
    "prepare_sha256": "d" * 64,
    "report_sha256": "e" * 64,
    "collection_index_sha256": "f" * 64,
    "workflow_run_id": "1001",
    "run_attempt": "2",
}


class CandidateDiagnosticsContract(unittest.TestCase):
    def test_closed_reason_survives_canonical_write_and_readback(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / diagnostics.FILENAME
            doc = diagnostics.build_document(
                bindings=BINDINGS,
                members=[diagnostics.observation(0, "unproved", "inner-exit")],
            )
            encoded = diagnostics.write_document(path, doc)
            loaded = diagnostics.load_document(path, expected_bindings=BINDINGS)
        self.assertEqual(loaded["members"], [{
            "ordinal": 0,
            "candidate_outcome": "unproved",
            "unproved_reason": "inner-exit",
        }])
        self.assertEqual(encoded, diagnostics.encode_document(doc))
        self.assertLessEqual(len(encoded), diagnostics.MAX_BYTES)

    def test_private_reason_becomes_unknown_without_value_or_hash(self):
        secret = "/host/secret"
        row = diagnostics.observation(0, "unproved", secret)
        raw = diagnostics.encode_document(
            diagnostics.build_document(bindings=BINDINGS, members=[row]))
        self.assertEqual(row["unproved_reason"], "unknown")
        self.assertNotIn(secret.encode(), raw)
        self.assertNotIn(hashlib.sha256(secret.encode()).hexdigest().encode(), raw)

    def test_outcome_reason_consistency_is_closed(self):
        self.assertEqual(
            diagnostics.observation(0, "completed", None)["unproved_reason"], None)
        for outcome, reason in (("completed", "timeout"), ("unproved", None)):
            with self.subTest(outcome=outcome, reason=reason), \
                    self.assertRaises(diagnostics.DiagnosticError):
                diagnostics.observation(0, outcome, reason)

    def test_count_and_encoded_byte_ceilings_refuse_before_write(self):
        rows = [diagnostics.observation(i, "unproved", "timeout")
                for i in range(diagnostics.MAX_MEMBERS)]
        diagnostics.build_document(bindings=BINDINGS, members=rows)
        with self.assertRaisesRegex(diagnostics.DiagnosticError, "member count"):
            diagnostics.build_document(
                bindings=BINDINGS,
                members=rows + [{"ordinal": 256, "candidate_outcome": "unproved",
                                 "unproved_reason": "timeout"}])

        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / diagnostics.FILENAME
            with self.assertRaisesRegex(diagnostics.DiagnosticError, "byte ceiling"):
                diagnostics.write_document(
                    path,
                    diagnostics.build_document(bindings=BINDINGS, members=rows),
                    max_bytes=100,
                )
            self.assertFalse(path.exists())

    def test_unknown_keys_and_binding_drift_are_refused(self):
        doc = diagnostics.build_document(
            bindings=BINDINGS,
            members=[diagnostics.observation(0, "unproved", "malformed")],
        )
        doc["extra"] = True
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / diagnostics.FILENAME
            path.write_bytes((json.dumps(doc) + "\n").encode())
            with self.assertRaisesRegex(diagnostics.DiagnosticError, "keys"):
                diagnostics.load_document(path)


if __name__ == "__main__":
    unittest.main()
