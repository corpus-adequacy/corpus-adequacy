#!/usr/bin/env python3
"""Pinned Tersign evidence-record adapter. Standard library only.

First REDs are source-copy parity (n11 body reason vs MANIFEST) and runtime
reason drift through the real process runner.
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
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "adapters"))
import corpus_adequacy as ca  # noqa: E402
import tersign_evidence_record as ter  # noqa: E402
ADAPTER = REPO_ROOT / "adapters" / "tersign_evidence_record.py"

FIXTURE = REPO_ROOT / "fixtures" / "tersign-evidence-record-1cc5ea32"
N11 = "n11-integer-beyond-ijson-range"
N10 = "n10-float-in-digest-domain"
P12 = "p12-ijson-integer-boundary"


def _copy_source(tmp: Path) -> Path:
    dest = tmp / "src"
    shutil.copytree(FIXTURE, dest)
    return dest


def _read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


class SourceParity(unittest.TestCase):
    def test_n11_body_reason_drift_refuses_before_output(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            src = _copy_source(tmp)
            body = src / "vectors" / ("%s.json" % N11)
            doc = _read_json(body)
            doc["reason"] = "recompute_mismatch"
            body.write_text(json.dumps(doc), encoding="utf-8")
            dest = tmp / "out"
            dest.mkdir()
            with self.assertRaises(ter.AdapterError) as ctx:
                ter.adapt(src, dest)
            self.assertRegex(str(ctx.exception).lower(), r"manifest|body|reason")
            self.assertEqual(list(dest.iterdir()), [])

    def test_wrong_manifest_digest_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            src = _copy_source(tmp)
            (src / "MANIFEST.json").write_bytes(
                (src / "MANIFEST.json").read_bytes() + b"\n")
            dest = tmp / "out"
            dest.mkdir()
            with self.assertRaises(ter.AdapterError) as ctx:
                ter.adapt(src, dest)
            self.assertIn("digest", str(ctx.exception).lower())
            self.assertEqual(list(dest.iterdir()), [])


class HappyPath(unittest.TestCase):
    def test_pinned_source_emits_54_exact_cases_and_typed_outcomes(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            src = _copy_source(tmp)
            dest = tmp / "out"
            dest.mkdir()
            ter.adapt(src, dest)
            vectors = _read_json(dest / "vectors.json")["vectors"]
            self.assertEqual(len(vectors), 54)
            self.assertEqual(
                [row["vector_id"] for row in vectors],
                sorted(row["vector_id"] for row in vectors))
            valid = [r for r in vectors if r["expected_verdict"] == "valid"]
            reject = [r for r in vectors if r["expected_verdict"] == "reject"]
            self.assertEqual((len(valid), len(reject)), (22, 32))
            for row in vectors:
                self.assertNotIn("path", row)
                case = dest / row["vector_path"]
                src_case = src / "vectors" / (row["vector_id"] + ".json")
                self.assertEqual(case.read_bytes(), src_case.read_bytes())
                self.assertEqual(row["authored_kind"], _read_json(src_case)["kind"])
                if row["expected_verdict"] == "valid":
                    self.assertIsNone(row["expected_reason"])
                else:
                    self.assertEqual(row["expected_reason"], _read_json(src_case)["reason"])
            source = _read_json(dest / "source.json")
            self.assertEqual(source["schema"], ter.SOURCE_SCHEMA)
            self.assertNotEqual(source["schema"], ca.SURVIVORS_SCHEMA)
            self.assertNotEqual(source["schema"], ca.REPORT_SCHEMA)
            self.assertNotIn("verdict", source)
            self.assertNotIn("findings", source)
            self.assertEqual(source["commit"], ter.PIN_COMMIT)
            self.assertEqual(source["manifest_sha256"], ter.PIN_MANIFEST_SHA256)
            self.assertEqual(source["vectors_tree"], ter.PIN_VECTORS_TREE)
            self.assertEqual(source["counts"], {"vectors": 54, "valid": 22, "reject": 32})
            self.assertTrue(source["source_validation"]["body_manifest_agreement"])
            self.assertTrue(source["source_validation"]["closures_match_pin"])
            self.assertTrue(source["source_validation"]["two_sided_per_kind"])

    def test_emitted_case_bytes_match_source_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            src = _copy_source(tmp)
            dest = tmp / "out"
            dest.mkdir()
            ter.adapt(src, dest)
            n10 = dest / "cases" / ("%s.json" % N10)
            raw = n10.read_bytes()
            self.assertEqual(raw, (src / "vectors" / ("%s.json" % N10)).read_bytes())
            self.assertEqual(hashlib.sha256(raw).hexdigest(),
                             "fd2c1edd4a24d1e45f90ca2072fa7a797fb03d7cd66b494a541092e6a23a4703")
            self.assertIn(b"1.1", raw)
            self.assertNotIn(b"1.10", raw)

    def test_output_is_deterministic(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            src = _copy_source(tmp)
            a, b = tmp / "a", tmp / "b"
            a.mkdir()
            b.mkdir()
            ter.adapt(src, a)
            ter.adapt(src, b)
            self.assertEqual((a / "vectors.json").read_bytes(),
                             (b / "vectors.json").read_bytes())
            self.assertEqual((a / "source.json").read_bytes(),
                             (b / "source.json").read_bytes())

    def test_pinned_reason_closure_not_derived_from_manifest(self):
        src = Path(ter.__file__).read_text(encoding="utf-8")
        self.assertIn("number_domain_reject", src)
        self.assertNotIn(
            "{v[\"reason\"] for v in",
            src.replace(" ", ""),
        )


class HostileInput(unittest.TestCase):
    def test_file_field_rejects_traversal_and_ntfs_stream(self):
        with self.assertRaises(ter.AdapterError):
            ter._require_basename("../x.json", "file")
        with self.assertRaises(ter.AdapterError):
            ter._require_basename("a\\b.json", "file")
        with self.assertRaises(ter.AdapterError):
            ter._require_basename("x.json:ads", "file")

    def test_unlisted_file_under_vectors_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            src = _copy_source(tmp)
            (src / "vectors" / "extra.json").write_text("{}", encoding="utf-8")
            dest = tmp / "out"
            dest.mkdir()
            with self.assertRaises(ter.AdapterError):
                ter.adapt(src, dest)
            self.assertEqual(list(dest.iterdir()), [])

    def test_duplicate_body_id_is_refused_before_rename(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            src = _copy_source(tmp)
            man_path = src / "MANIFEST.json"
            man = _read_json(man_path)
            man["vectors"].append(dict(man["vectors"][0], file="dup.json"))
            # Keep digest from matching by rewriting after we also copy a file.
            shutil.copy(src / "vectors" / man["vectors"][0]["file"],
                        src / "vectors" / "dup.json")
            man_path.write_text(json.dumps(man), encoding="utf-8")
            dest = tmp / "out"
            dest.mkdir()
            with self.assertRaises(ter.AdapterError) as ctx:
                ter.adapt(src, dest)
            self.assertRegex(str(ctx.exception).lower(), r"duplicate|digest")
            self.assertEqual(list(dest.iterdir()), [])

    def test_unknown_body_field_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            src = _copy_source(tmp)
            path = src / "vectors" / ("%s.json" % P12)
            doc = _read_json(path)
            doc["surprise"] = True
            path.write_text(json.dumps(doc), encoding="utf-8")
            dest = tmp / "out"
            dest.mkdir()
            with self.assertRaises(ter.AdapterError):
                ter.adapt(src, dest)

    def test_nan_in_vector_json_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            src = _copy_source(tmp)
            path = src / "vectors" / ("%s.json" % P12)
            raw = path.read_bytes().replace(b'"valid"', b"NaN", 1)
            path.write_bytes(raw)
            dest = tmp / "out"
            dest.mkdir()
            with self.assertRaises(ter.AdapterError):
                ter.adapt(src, dest)

    def test_duplicate_json_key_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            src = _copy_source(tmp)
            path = src / "vectors" / ("%s.json" % P12)
            path.write_bytes(b'{"id":"x","id":"y","kind":"digest_recompute",'
                             b'"expect":"valid","input":{},"description":"d"}')
            dest = tmp / "out"
            dest.mkdir()
            with self.assertRaises(ter.AdapterError):
                ter.adapt(src, dest)

    def test_invalid_utf8_vector_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            src = _copy_source(tmp)
            path = src / "vectors" / ("%s.json" % P12)
            path.write_bytes(b'{"id":"\xff"}')
            dest = tmp / "out"
            dest.mkdir()
            with self.assertRaises(ter.AdapterError):
                ter.adapt(src, dest)

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "O_NOFOLLOW required")
    def test_symlink_vector_is_refused_and_outside_bytes_unchanged(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            src = _copy_source(tmp)
            outside = tmp / "secret"
            outside.write_bytes(b"keep")
            target = src / "vectors" / ("%s.json" % P12)
            target.unlink()
            target.symlink_to(outside)
            dest = tmp / "out"
            dest.mkdir()
            with self.assertRaises((ter.AdapterError, ca.ManifestError)):
                ter.adapt(src, dest)
            self.assertEqual(outside.read_bytes(), b"keep")
            self.assertEqual(list(dest.iterdir()), [])

    def test_exact_output_cap_copies_and_one_byte_past_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            src = _copy_source(tmp)
            dest = tmp / "out"
            dest.mkdir()
            read_paths = [src / "MANIFEST.json", *sorted((src / "vectors").iterdir())]
            cap = max(p.stat().st_size for p in read_paths)
            with mock.patch.object(ca, "OUTPUT_CAP_BYTES", cap):
                ter.adapt(src, dest)
            dest2 = tmp / "out2"
            dest2.mkdir()
            grown = src / "MANIFEST.json"
            grown.write_bytes(grown.read_bytes() + b"x")
            with mock.patch.object(ca, "OUTPUT_CAP_BYTES", cap):
                with self.assertRaises((ter.AdapterError, ca.ManifestError)):
                    ter.adapt(src, dest2)
            self.assertEqual(list(dest2.iterdir()), [])

    def test_dest_file_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            src = _copy_source(tmp)
            dest = tmp / "out"
            dest.write_text("nope", encoding="utf-8")
            with self.assertRaises(ter.AdapterError):
                ter.adapt(src, dest)
            self.assertEqual(dest.read_text(encoding="utf-8"), "nope")

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "O_NOFOLLOW required")
    def test_dest_symlink_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            src = _copy_source(tmp)
            real = tmp / "real"
            real.mkdir()
            dest = tmp / "out"
            dest.symlink_to(real)
            with self.assertRaises(ter.AdapterError):
                ter.adapt(src, dest)
            self.assertTrue(dest.is_symlink())
            self.assertEqual(list(real.iterdir()), [])

    def test_nonempty_dest_is_refused_and_untouched(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            src = _copy_source(tmp)
            dest = tmp / "out"
            dest.mkdir()
            marker = dest / "stay"
            marker.write_text("here", encoding="utf-8")
            with self.assertRaises(ter.AdapterError):
                ter.adapt(src, dest)
            self.assertEqual(marker.read_text(encoding="utf-8"), "here")

    def test_mid_copy_failure_leaves_no_consumable_dest(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            src = _copy_source(tmp)
            dest = tmp / "out"
            dest.mkdir()
            real_replace = os.replace

            def boom(src_path, dst_path):
                raise OSError("rename failed")

            with mock.patch.object(os, "replace", side_effect=boom):
                with self.assertRaises((ter.AdapterError, OSError)):
                    ter.adapt(src, dest)
            if dest.exists():
                self.assertEqual(list(dest.iterdir()), [])
            self.assertFalse(any(tmp.glob("tersign-adapt-*")))
            del real_replace

    def test_uses_existing_bounded_reader_not_a_second_cap(self):
        src = Path(ter.__file__).read_text(encoding="utf-8")
        self.assertIn("read_bounded_regular_file", src)
        self.assertNotIn("1024 * 1024", src)
        self.assertNotIn("PROJECTION_INPUT_CAP_BYTES", src)


class ProcessE2E(unittest.TestCase):
    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_n11_reason_drift_kills_and_verdict_only_survives(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            src = _copy_source(tmp)
            adapted = tmp / "adapted"
            adapted.mkdir()
            ter.adapt(src, adapted)
            impl = (
                "import json, sys\n"
                "from pathlib import Path\n"
                "doc = json.loads(Path(sys.argv[1]).read_bytes())\n"
                "verdict = doc['expect']\n"
                "reason = doc.get('reason')\n"
                "print(json.dumps({'verdict': verdict, 'reason': reason}))\n"
            )
            repo = tmp / "impl"
            repo.mkdir()
            (repo / "echo.py").write_text(impl, encoding="utf-8")
            shutil.copytree(adapted / "cases", repo / "cases")
            shutil.copy(adapted / "vectors.json", repo / "vectors.json")
            mutants = {
                "tersign": [
                    {
                        "label": "n11 reason drift",
                        "anchor": "reason = doc.get('reason')",
                        "replacement": (
                            "reason = ('recompute_mismatch' if doc['id'] == "
                            "'%s' else doc.get('reason'))" % N11
                        ),
                    },
                    {
                        "label": "CONTROL flip every verdict",
                        "control": True,
                        "anchor": "verdict = doc['expect']",
                        "replacement": "verdict = 'valid'",
                    },
                ]
            }
            typed = _process_manifest(tmp, repo, mutants, ["verdict", "reason"])
            rep = ca.run(typed)
            drift = next(r for r in rep["mutants"] if r["label"] == "n11 reason drift")
            self.assertEqual(drift["verdict"], "killed")
            self.assertEqual(drift["moved"], 1)
            verdict_only = _process_manifest(tmp, repo, mutants, ["verdict"])
            false_green = ca.run(verdict_only)
            survived = next(r for r in false_green["mutants"]
                            if r["label"] == "n11 reason drift")
            self.assertEqual(survived["verdict"], "survived")

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_e2e_calls_real_corpus_adequacy_run(self):
        self.assertIn("ca.run(", Path(__file__).read_text(encoding="utf-8"))
        with mock.patch.object(ca, "run", side_effect=AssertionError("run must be called")):
            with self.assertRaises(AssertionError):
                self.test_n11_reason_drift_kills_and_verdict_only_survives()

    def test_e2e_outcome_from_is_verdict_and_reason_not_kind(self):
        src = Path(__file__).read_text(encoding="utf-8")
        self.assertIn('["verdict", "reason"]', src)
        self.assertNotIn("outcome_from\": [\"authored_kind\"]", src)
        self.assertIn("_process_manifest(tmp, repo, mutants, [\"verdict\", \"reason\"])", src)

    def test_cli_failure_exits_2_not_1(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            dest = tmp / "out"
            dest.mkdir()
            r = subprocess.run(
                [sys.executable, str(ADAPTER),
                 str(tmp / "missing"), str(dest)],
                capture_output=True, text=True)
            self.assertEqual(r.returncode, 2)

    def test_adapter_source_does_not_import_verify_or_keccak(self):
        tree = ast.parse(Path(ter.__file__).read_text(encoding="utf-8"))
        names = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.extend(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                names.append(node.module.split(".")[0])
        self.assertNotIn("verify", names)
        self.assertNotIn("keccak", names)
        self.assertNotIn("runpy", names)


def _process_manifest(tmp: Path, repo: Path, mutants: dict, outcome_from: list) -> Path:
    raw = {
        "schema": ca.SCHEMA,
        "runner": "process",
        "repo_root": ".",
        "implementation": "echo.py",
        "implementation_sources": ["echo.py"],
        "build": [],
        "entrypoint_command": [sys.executable, "echo.py", "{vector}"],
        "outcome_from": outcome_from,
        "vectors": "vectors.json",
        "id_key": "vector_id",
        "vector_path_key": "vector_path",
        "default_group": "tersign",
        "mutants": mutants,
    }
    path = repo / ("m-%s.json" % hashlib.sha256(json.dumps(outcome_from).encode()).hexdigest()[:8])
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


if __name__ == "__main__":
    unittest.main(verbosity=1)
