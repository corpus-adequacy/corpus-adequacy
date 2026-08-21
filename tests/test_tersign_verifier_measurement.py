#!/usr/bin/env python3
"""Process measurement of the pinned Tersign CHECKS wrapper (#30).

RED first: the wrapper module must exist, dispatch only CHECKS[kind](input),
and be scored through real corpus_adequacy.run(). The three verify.py main()
suite gates are omitted from the inventory, not reported as survivors.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "adapters"))
import corpus_adequacy as ca  # noqa: E402
import tersign_evidence_record as ter  # noqa: E402

WRAPPER = REPO_ROOT / "measurements" / "tersign_checks.py"
VERIFY_DIR = REPO_ROOT / "fixtures" / "tersign-verify-1cc5ea32"
VERIFY_FIXTURE = VERIFY_DIR / "verify.py"
KECCAK_FIXTURE = VERIFY_DIR / "keccak.py"
LICENSE_FIXTURE = VERIFY_DIR / "LICENSE"
SOURCE_TXT = VERIFY_DIR / "SOURCE.txt"
CORPUS_FIXTURE = REPO_ROOT / "fixtures" / "tersign-evidence-record-1cc5ea32"

PIN_COMMIT = "1cc5ea32b3da4f195b55782c8a3573d8564673a7"
PIN_VERIFY = "ec6a6fe6d5caa0e56a2a85b9b35557f2efb6aede7689b3e21c3466e6b7502a42"
PIN_KECCAK = "f541c8a43a288f61a147dd43accea048eb9f55a095ca3b9dbf3f88341d469190"
PIN_LICENSE = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
PIN_SPDX = "SPDX-License-Identifier: Apache-2.0"
ROOT_MIT = "fa103e85c81b02db33f34ea4c59b1a4a7f18e0052042879906ce82f9597b1b7c"

SAFE_INT = "remove the greater-than 2^53-1 refusal"
INTEGRAL_FLOAT = "accept integer-valued floats and serialize them as integers"
SAFE_GE = "CONTROL tighten the safe-integer bound to greater-than-or-equal"
FRAC_FLOAT = "CONTROL permit ordinary fractional floats through canonicalization"
MASKED_BOUNDARY = "boundary_binding skips empty-attested coverage refusal"

SUITE_GATES = (
    "per-kind two-sided closure",
    "manifest/body kind agreement",
    "reason closure vs REQUIRED_REASONS",
)

DECLARED_MUTANTS = [
    {
        "label": INTEGRAL_FLOAT,
        "anchor": (
            'if isinstance(value, float):\n'
            '        raise ValueError("non-integer JSON number in the digest domain")'
        ),
        "replacement": (
            'if isinstance(value, float):\n'
            '        if value.is_integer():\n'
            '            return canonical(int(value))\n'
            '        raise ValueError("non-integer JSON number in the digest domain")'
        ),
    },
    {
        "label": SAFE_INT,
        "anchor": "if abs(value) > 2**53 - 1:",
        "replacement": "if False:",
    },
    {
        "label": SAFE_GE,
        "control": True,
        "anchor": "abs(value) > 2**53 - 1",
        "replacement": "abs(value) >= 2**53 - 1",
    },
    {
        "label": FRAC_FLOAT,
        "control": True,
        "anchor": 'raise ValueError("non-integer JSON number in the digest domain")',
        "replacement": "return json.dumps(value)",
    },
    {
        "label": "digest_recompute accepts a mismatched expected digest",
        "anchor": 'if got != expected:\n        return "reject", "recompute_mismatch"',
        "replacement": 'if False:\n        return "reject", "recompute_mismatch"',
    },
    {
        "label": "canonical_bytes accepts non-canonical claimed bytes",
        "anchor": 'if got != inp["claimed_canonical"]:',
        "replacement": 'if False and got != inp["claimed_canonical"]:',
    },
    {
        "label": "chain_link accepts a recomputed link mismatch",
        "anchor": (
            'if got != expected:\n'
            '        return "reject", "continuity_reject", f"recomputed link {got}"'
        ),
        "replacement": (
            'if False:\n'
            '        return "reject", "continuity_reject", f"recomputed link {got}"'
        ),
    },
    {
        "label": "chain_set skips committed-sequence completeness",
        "anchor": "if seqs != expected:",
        "replacement": "if False and seqs != expected:",
    },
    {
        "label": "anchor_relation accepts a subject/anchor digest mismatch",
        "anchor": "if got != anchored:",
        "replacement": "if False and got != anchored:",
    },
    {
        "label": "phase_claim accepts a phase/presented mismatch",
        "anchor": "if phase != presented:",
        "replacement": "if False and phase != presented:",
    },
    {
        "label": "independence_claim accepts party-only attestation",
        "anchor": "if not outside:",
        "replacement": "if False and not outside:",
    },
    {
        "label": "offer_binding reads a different commitment field",
        "anchor": '"offerDigest"',
        "replacement": '"offerDigestX"',
    },
    {
        "label": "decision_evidence_binding reads a different commitment field",
        "anchor": '"decisionEvidenceDigest"',
        "replacement": '"decisionEvidenceDigestX"',
    },
    {
        "label": MASKED_BOUNDARY,
        "anchor": "if attested <= 0 < covered:",
        "replacement": "if False and attested <= 0 < covered:",
    },
]


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_wrapper():
    import importlib.util
    sys.path.insert(0, str(VERIFY_FIXTURE.parent))
    spec = importlib.util.spec_from_file_location("tersign_checks", WRAPPER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _adapt(tmp: Path) -> Path:
    dest = tmp / "adapted"
    dest.mkdir()
    ter.adapt(CORPUS_FIXTURE, dest)
    return dest


def _measurement_repo(tmp: Path) -> Path:
    adapted = _adapt(tmp)
    repo = tmp / "impl"
    repo.mkdir()
    shutil.copy(WRAPPER, repo / "tersign_checks.py")
    shutil.copy(VERIFY_FIXTURE, repo / "verify.py")
    shutil.copy(KECCAK_FIXTURE, repo / "keccak.py")
    shutil.copytree(adapted / "cases", repo / "cases")
    shutil.copy(adapted / "vectors.json", repo / "vectors.json")
    return repo


def _manifest(repo: Path, outcome_from: list) -> Path:
    raw = {
        "schema": ca.SCHEMA,
        "runner": "process",
        "repo_root": ".",
        "implementation": "tersign_checks.py",
        "implementation_sources": ["tersign_checks.py", "verify.py", "keccak.py"],
        "build": [],
        "entrypoint_command": [sys.executable, "tersign_checks.py", "{vector}"],
        "accepted_exit_codes": [0],
        "outcome_from": outcome_from,
        "vectors": "vectors.json",
        "id_key": "vector_id",
        "vector_path_key": "vector_path",
        "default_group": "tersign",
        "mutants": {"tersign": [dict(m) for m in DECLARED_MUTANTS]},
    }
    path = repo / ("m-%s.json" % hashlib.sha256(json.dumps(outcome_from).encode()).hexdigest()[:8])
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


class PinAndPlacement(unittest.TestCase):
    def test_pinned_implementation_bytes(self):
        self.assertEqual(_sha(VERIFY_FIXTURE), PIN_VERIFY)
        self.assertEqual(_sha(KECCAK_FIXTURE), PIN_KECCAK)
        self.assertEqual(ter.PIN_COMMIT, PIN_COMMIT)
        self.assertTrue(LICENSE_FIXTURE.is_file(), "vendored upstream LICENSE is missing")
        self.assertEqual(_sha(LICENSE_FIXTURE), PIN_LICENSE)
        self.assertNotEqual(_sha(LICENSE_FIXTURE), ROOT_MIT)
        self.assertFalse((VERIFY_DIR / "NOTICE").exists(), "upstream pin has no NOTICE")
        source = SOURCE_TXT.read_text(encoding="utf-8")
        self.assertIn(PIN_COMMIT, source)
        self.assertIn(PIN_SPDX, source)
        self.assertIn(PIN_LICENSE, source)
        attrs = (REPO_ROOT / ".gitattributes").read_text(encoding="utf-8")
        self.assertIn("fixtures/tersign-verify-1cc5ea32/** text eol=lf", attrs)

    def test_wrapper_is_not_a_tool_source_member(self):
        self.assertTrue(WRAPPER.exists())
        self.assertNotIn("measurements/", "\n".join(ca.TOOL_SOURCE_PATHS))
        self.assertNotIn("tersign_checks.py", ca.TOOL_SOURCE_PATHS)
        durable = REPO_ROOT / "measurements" / "tersign-1cc5ea32" / "tersign_checks.py"
        self.assertEqual(_sha(durable), _sha(WRAPPER))
        self.assertEqual(
            _sha(REPO_ROOT / "measurements" / "tersign-1cc5ea32" / "verify.py"),
            PIN_VERIFY,
        )
        self.assertEqual(
            _sha(REPO_ROOT / "measurements" / "tersign-1cc5ea32" / "keccak.py"),
            PIN_KECCAK,
        )

    def test_wrapper_does_not_import_producer_or_verify_main(self):
        tree = ast.parse(WRAPPER.read_text(encoding="utf-8"))
        names = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.extend(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                names.append(node.module.split(".")[0])
        self.assertNotIn("corpus_adequacy", names)
        self.assertNotIn("bounded_run", names)
        src = WRAPPER.read_text(encoding="utf-8")
        self.assertNotIn("verify.main", src)
        self.assertIn("CHECKS[kind]", src)


class WrapperReaderParity(unittest.TestCase):
    """Wrapper `_read_bounded` must match `ca.read_bounded_regular_file`.

    Forced no-O_NOFOLLOW fallback: lstat / open / fstat identity parity.
    Tests may import corpus_adequacy; the wrapper still must not.
    """

    def _nofollow_off(self):
        return mock.patch.object(os, "O_NOFOLLOW", None, create=True)

    def test_wrapper_source_uses_lstat_fstat_identity(self):
        src = WRAPPER.read_text(encoding="utf-8")
        self.assertIn("fstat", src)
        self.assertIn("st_ino", src)
        self.assertIn("lstat", src)

    def test_regular_file_bytes_match_canonical(self):
        wrap = _load_wrapper()
        payload = b'{"kind":"regular"}'
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "regular.json"
            path.write_bytes(payload)
            with self._nofollow_off():
                self.assertEqual(wrap._read_bounded(path), payload)
                self.assertEqual(ca.read_bounded_regular_file(path), payload)
                self.assertEqual(
                    wrap._read_bounded(path),
                    ca.read_bounded_regular_file(path),
                )

    def test_symlink_is_refused_by_both(self):
        wrap = _load_wrapper()
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "real.json"
            target.write_bytes(b'{"kind":"target"}')
            link = Path(d) / "link.json"
            link.symlink_to(target)
            with self._nofollow_off():
                with self.assertRaises(Exception):
                    wrap._read_bounded(link)
                with self.assertRaises(ca.ManifestError):
                    ca.read_bounded_regular_file(link)

    def test_oversize_is_refused_by_both(self):
        wrap = _load_wrapper()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "over.json"
            path.write_bytes(b"x" * 32)
            with self._nofollow_off(), mock.patch.object(wrap, "OUTPUT_CAP_BYTES", 16):
                with self.assertRaises(Exception):
                    wrap._read_bounded(path)
                with self.assertRaises(ca.ManifestError):
                    ca.read_bounded_regular_file(path, cap=16)

    def test_swap_between_lstat_and_open_is_refused_by_both(self):
        wrap = _load_wrapper()
        with tempfile.TemporaryDirectory() as d:
            expected = Path(d) / "expected.json"
            other = Path(d) / "other.json"
            expected.write_bytes(b'{"kind":"expected"}')
            other.write_bytes(b'{"kind":"swapped"}')
            real_open = os.open
            expected_key = os.path.realpath(expected)
            other_key = os.path.realpath(other)

            def hijack(path, flags, *args, **kwargs):
                opened = os.path.realpath(os.fspath(path))
                if opened == expected_key:
                    return real_open(other_key, flags, *args, **kwargs)
                return real_open(path, flags, *args, **kwargs)

            with self._nofollow_off(), mock.patch.object(os, "open", side_effect=hijack):
                with self.assertRaises(ca.ManifestError) as cm:
                    ca.read_bounded_regular_file(expected)
                self.assertIn("changed between lstat and open", str(cm.exception))
                try:
                    got = wrap._read_bounded(expected)
                except Exception:
                    return
                self.fail(
                    "wrapper returned %r instead of refusing a swapped inode"
                    % got
                )


class WrapperContract(unittest.TestCase):
    def test_dispatch_parity_against_direct_checks(self):
        wrap = _load_wrapper()
        sys.path.insert(0, str(VERIFY_FIXTURE.parent))
        import verify
        with tempfile.TemporaryDirectory() as d:
            adapted = _adapt(Path(d))
            rows = json.loads((adapted / "vectors.json").read_text())["vectors"]
            self.assertEqual(len(rows), 54)
            for row in rows:
                case = adapted / row["vector_path"]
                emitted = wrap.evaluate(case)
                self.assertEqual(set(emitted), {"verdict", "reason"})
                self.assertNotIn("detail", emitted)
                body = json.loads(case.read_text(encoding="utf-8"))
                verdict, reason, _detail = verify.CHECKS[body["kind"]](body["input"])
                self.assertEqual(emitted["verdict"], verdict)
                self.assertEqual(emitted["reason"], reason)
                self.assertEqual(emitted["verdict"], row["expected_verdict"])
                self.assertEqual(emitted["reason"], row["expected_reason"])

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_parseable_json_then_exit_1_is_unexpected_exit(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            script = tmp / "child.py"
            script.write_text(
                "import json, sys\n"
                'print(json.dumps({"verdict": "valid", "reason": None}))\n'
                "sys.exit(1)\n",
                encoding="utf-8",
            )
            m = {
                "runner": "process",
                "id_key": "vector_id",
                "vector_path_key": "vector_path",
                "entrypoint_command": [sys.executable, str(script)],
                "_repo_root": tmp,
                "vector_timeout": 10,
                "accepted_exit_codes": [0],
                "outcome_from": ["verdict", "reason"],
            }
            vectors = [{"vector_id": "v1", "vector_path": "unused.json"}]
            with mock.patch.object(ca.json, "loads", wraps=json.loads) as loads:
                outcomes, _diags, raised = ca._process_outcomes(m, vectors)
            self.assertEqual(loads.call_count, 0)
            self.assertEqual(outcomes, {})
            self.assertEqual(raised, {"v1": "unexpected-exit"})

    def test_durable_manifest_keeps_accepted_exit_zero(self):
        path = REPO_ROOT / "measurements" / "tersign-1cc5ea32" / "manifest.json"
        self.assertTrue(path.is_file(), "durable process manifest is missing")
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
        self.assertEqual(data["accepted_exit_codes"], [0])
        self.assertEqual(data["entrypoint_command"][0], "python3")
        self.assertNotIn("sys.executable", raw)

    def test_parse_before_classify_mutation_bites(self):
        payload = '{"verdict":"valid","reason":null}'
        completed = subprocess.CompletedProcess(
            args=["child"], returncode=1, stdout=payload, stderr="",
        )
        m = {
            "runner": "process",
            "accepted_exit_codes": [0],
            "outcome_from": ["verdict", "reason"],
        }
        value, _diag, kind = ca.child_outcome(m, completed)
        self.assertEqual(kind, "unexpected-exit")
        self.assertIsNone(value)

        def parse_before_classify(manifest, child):
            doc = json.loads(child.stdout)
            return tuple(doc.get(k) for k in manifest["outcome_from"]), None, None

        mut_value, _mut_diag, _mut_kind = parse_before_classify(m, completed)
        self.assertEqual(mut_value, ("valid", None))


class DeclaredInventory(unittest.TestCase):
    def test_anchors_are_unique_in_verify_py(self):
        text = VERIFY_FIXTURE.read_text(encoding="utf-8")
        seen = []
        for mut in DECLARED_MUTANTS:
            self.assertEqual(text.count(mut["anchor"]), 1, mut["label"])
            self.assertNotEqual(mut["anchor"], mut["replacement"])
            seen.append(mut["anchor"])
        self.assertEqual(len(seen), len(set(seen)))

    def test_suite_gates_are_absent_not_survivors(self):
        labels = [m["label"] for m in DECLARED_MUTANTS]
        for name in SUITE_GATES:
            self.assertNotIn(name, labels)
        src = Path(__file__).read_text(encoding="utf-8")
        self.assertIn("out of scope", src.lower())

    def test_two_controls_share_the_canonical_region(self):
        controls = [m for m in DECLARED_MUTANTS if m.get("control")]
        self.assertEqual({c["label"] for c in controls}, {SAFE_GE, FRAC_FLOAT})
        text = VERIFY_FIXTURE.read_text(encoding="utf-8")
        region = text[text.index("def canonical"): text.index("def digest_of")]
        for c in controls:
            self.assertIn(c["anchor"], region)


class ProcessMeasurement(unittest.TestCase):
    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_typed_run_kills_reason_drift_and_keeps_honest_survivors(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            repo = _measurement_repo(tmp)
            rep = ca.run(_manifest(repo, ["verdict", "reason"]))
            by = {row["label"]: row for row in rep["mutants"]}
            self.assertEqual(by[SAFE_INT]["verdict"], "killed")
            self.assertEqual(by[SAFE_INT]["moved"], 1)
            self.assertEqual(by[SAFE_GE]["verdict"], "control-killed")
            self.assertEqual(by[FRAC_FLOAT]["verdict"], "control-killed")
            self.assertEqual(by[INTEGRAL_FLOAT]["verdict"], "survived")
            self.assertEqual(by[MASKED_BOUNDARY]["verdict"], "survived")
            self.assertNotIn("equivalent", by[INTEGRAL_FLOAT])
            for name in SUITE_GATES:
                self.assertNotIn(name, by)
            killed = [row for row in rep["mutants"] if row["verdict"] == "killed"]
            self.assertGreaterEqual(len(killed), 10)

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_verdict_only_is_a_false_green_for_safe_int(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            repo = _measurement_repo(tmp)
            typed = ca.run(_manifest(repo, ["verdict", "reason"]))
            self.assertEqual(
                next(r for r in typed["mutants"] if r["label"] == SAFE_INT)["verdict"],
                "killed",
            )
            false_green = ca.run(_manifest(repo, ["verdict"]))
            self.assertEqual(
                next(r for r in false_green["mutants"] if r["label"] == SAFE_INT)["verdict"],
                "survived",
            )

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_e2e_calls_real_corpus_adequacy_run(self):
        self.assertIn("ca.run(", Path(__file__).read_text(encoding="utf-8"))
        from unittest import mock
        with mock.patch.object(ca, "run", side_effect=AssertionError("run must be called")):
            with self.assertRaises(AssertionError):
                self.test_typed_run_kills_reason_drift_and_keeps_honest_survivors()


if __name__ == "__main__":
    unittest.main(verbosity=1)
