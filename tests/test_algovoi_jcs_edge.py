#!/usr/bin/env python3
"""Contract for the pinned AlgoVoi jcs_edge_v1 adapter. Standard library only.

The load-bearing test is the mechanism boundary, not output equality. On this
pinned file a whole-document `json.loads` then `json.dumps(ensure_ascii=True,
indent=2)` plus LF is byte-identical to the source, so source digest plus
emitted-byte equality does not by itself prove the adapter sliced `preimage`
structurally. `test_whole_document_round_trip_is_byte_identical` pins that
trap, and the raw-slice tests pin the mechanism independently.
"""

from __future__ import annotations

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
import algovoi_jcs_edge as adapter  # noqa: E402

ADAPTER = REPO_ROOT / "adapters" / "algovoi_jcs_edge.py"
FIXTURE_DIR = REPO_ROOT / "fixtures" / "algovoi-jcs-edge-aa53149c"
ANCHOR = FIXTURE_DIR / "jcs_edge_v1.json"

FLOAT_ID = "jcs-edge-005-number-one-float"
INT_ID = "jcs-edge-006-number-one-int"

# The exact source slices, with the source's own indentation, plus one LF.
FLOAT_CASE_BYTES = b'{\n        "n": 1.0\n      }\n'
INT_CASE_BYTES = b'{\n        "n": 1\n      }\n'

SYNTHETIC_IMPL = '''\
import hashlib, json, sys
raw = open(sys.argv[1], "rb").read()
text = raw.decode("utf-8")
start = text.index(":") + 1
lexeme = text[start:text.index("\\n", start)].strip()
print(json.dumps({
    "raw_sha256": hashlib.sha256(raw).hexdigest(),
    "lexeme": lexeme,
}))
'''


def _adapt_to_temp(tmp: Path) -> Path:
    dest = tmp / "adapted"
    adapter.adapt(ANCHOR, dest)
    return dest


def _process_manifest(repo: Path, mutants: dict, outcome_from: list) -> Path:
    raw = {
        "schema": ca.SCHEMA,
        "runner": "process",
        "repo_root": ".",
        "implementation": "impl.py",
        "implementation_sources": ["impl.py"],
        "build": [],
        "entrypoint_command": [sys.executable, "impl.py", "{vector}"],
        "outcome_from": outcome_from,
        "vectors": "vectors.json",
        "id_key": "vector_id",
        "vector_path_key": "vector_path",
        "default_group": "algovoi",
        "mutants": mutants,
    }
    digest = hashlib.sha256(json.dumps(outcome_from).encode()).hexdigest()[:8]
    path = repo / ("m-%s.json" % digest)
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


class MechanismBoundary(unittest.TestCase):
    """Why emitted-byte equality alone cannot prove structural slicing."""

    def test_whole_document_round_trip_is_byte_identical(self):
        raw = ANCHOR.read_bytes()
        parsed = json.loads(raw.decode("utf-8"))
        rendered = (json.dumps(parsed, ensure_ascii=True, indent=2) + "\n").encode("utf-8")
        self.assertEqual(
            rendered, raw,
            "the trap this suite exists for has changed; re-derive the RED")

    def test_raw_slices_preserve_the_two_numeric_lexemes(self):
        slices = adapter.raw_preimage_slices(ANCHOR.read_bytes())
        self.assertEqual(len(slices), adapter.PIN_VECTOR_COUNT)
        self.assertIn(b'"n": 1.0', slices[4])
        self.assertIn(b'"n": 1\n', slices[5])
        self.assertNotEqual(slices[4], slices[5])

    def test_emitted_case_bytes_are_the_exact_source_slices(self):
        with tempfile.TemporaryDirectory() as d:
            dest = _adapt_to_temp(Path(d))
            self.assertEqual(
                (dest / "cases" / (FLOAT_ID + ".json")).read_bytes(),
                FLOAT_CASE_BYTES)
            self.assertEqual(
                (dest / "cases" / (INT_ID + ".json")).read_bytes(),
                INT_CASE_BYTES)

    def test_per_preimage_parse_and_reserialize_fails_this_contract(self):
        """MUTATION 2: re-serializing each preimage must turn this suite RED."""
        def reserializing(raw: bytes) -> list[bytes]:
            document = json.loads(raw.decode("utf-8"))
            return [json.dumps(v["preimage"], ensure_ascii=True, indent=2).encode("utf-8")
                    for v in document["vectors"]]

        with mock.patch.object(adapter, "raw_preimage_slices", reserializing):
            with tempfile.TemporaryDirectory() as d:
                dest = _adapt_to_temp(Path(d))
                emitted = (dest / "cases" / (FLOAT_ID + ".json")).read_bytes()
                self.assertNotEqual(
                    emitted, FLOAT_CASE_BYTES,
                    "a re-serializing scanner must not satisfy the byte contract")


class PinAndProvenance(unittest.TestCase):
    def test_vendored_anchor_matches_the_declared_digest_and_size(self):
        raw = ANCHOR.read_bytes()
        self.assertEqual(len(raw), adapter.PIN_SIZE_BYTES)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), adapter.PIN_SHA256)

    def test_mutation_1_a_different_digest_is_refused(self):
        """The forgery is otherwise valid, so only the digest gate can catch it."""
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            raw = ANCHOR.read_bytes()
            drifted = tmp / "drifted.json"
            # One description byte. Same length, same structure, same vector
            # count, same labels: every gate except the digest still passes.
            forged_bytes = raw.replace(b"1.0 canonicalises", b"1,0 canonicalises", 1)
            self.assertNotEqual(forged_bytes, raw)
            self.assertEqual(len(forged_bytes), len(raw))
            drifted.write_bytes(forged_bytes)
            with self.assertRaises(adapter.AdapterError) as caught:
                adapter.adapt(drifted, tmp / "out")
            self.assertIn("does not match the pin", str(caught.exception))
            self.assertIn("digest", str(caught.exception))

    def test_mutation_1_a_different_canon_version_is_refused(self):
        """Pin the forged digest so the canon-version gate is the one under test."""
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            document = json.loads(ANCHOR.read_text(encoding="utf-8"))
            document["canon_version"] = "jcs-rfc8785-v2"
            forged_bytes = (json.dumps(document, ensure_ascii=True, indent=2)
                            + "\n").encode("utf-8")
            forged = tmp / "forged.json"
            forged.write_bytes(forged_bytes)
            with mock.patch.object(adapter, "PIN_SHA256",
                                   hashlib.sha256(forged_bytes).hexdigest()), \
                 mock.patch.object(adapter, "PIN_SIZE_BYTES", len(forged_bytes)):
                with self.assertRaises(adapter.AdapterError) as caught:
                    adapter.adapt(forged, tmp / "out")
            self.assertIn("canon_version", str(caught.exception))

    def test_source_json_records_pin_licence_and_labels(self):
        with tempfile.TemporaryDirectory() as d:
            dest = _adapt_to_temp(Path(d))
            source = json.loads((dest / "source.json").read_text(encoding="utf-8"))
            self.assertEqual(source["repository"], adapter.PIN_REPOSITORY)
            self.assertEqual(source["commit"], adapter.PIN_COMMIT)
            self.assertEqual(source["anchor_sha256"], adapter.PIN_SHA256)
            self.assertEqual(source["manifest_version"], adapter.PIN_MANIFEST_VERSION)
            self.assertEqual(source["license"], "Apache-2.0")
            self.assertEqual(source["authored_sections"],
                             ["3.2.2.2", "3.2.2.3", "3.2.3", "3.2.4"])
            self.assertTrue(source["non_claims"])

    def test_upstream_licence_and_notice_are_retained(self):
        self.assertTrue((FIXTURE_DIR / "LICENSE").is_file())
        notice = (FIXTURE_DIR / "NOTICE").read_text(encoding="utf-8")
        self.assertIn("AlgoVoi", notice)
        source_text = ADAPTER.read_text(encoding="utf-8")
        self.assertIn("Apache-2.0", source_text)


class VectorAccounting(unittest.TestCase):
    def test_ten_vectors_are_emitted_with_authored_sections(self):
        with tempfile.TemporaryDirectory() as d:
            dest = _adapt_to_temp(Path(d))
            rows = json.loads((dest / "vectors.json").read_text(encoding="utf-8"))["vectors"]
            self.assertEqual(len(rows), 10)
            for row in rows:
                self.assertEqual(sorted(row),
                                 ["authored_section", "vector_id", "vector_path"])
                self.assertTrue((dest / row["vector_path"]).is_file())

    def test_mutation_3_a_dropped_vector_is_refused(self):
        """Pin the forged digest so the vector-count gate is the one under test."""
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            document = json.loads(ANCHOR.read_text(encoding="utf-8"))
            document["vectors"].pop()
            forged_bytes = (json.dumps(document, ensure_ascii=True, indent=2)
                            + "\n").encode("utf-8")
            short = tmp / "short.json"
            short.write_bytes(forged_bytes)
            with mock.patch.object(adapter, "PIN_SHA256",
                                   hashlib.sha256(forged_bytes).hexdigest()), \
                 mock.patch.object(adapter, "PIN_SIZE_BYTES", len(forged_bytes)):
                with self.assertRaises(adapter.AdapterError) as caught:
                    adapter.adapt(short, tmp / "out")
            self.assertIn("expected 10 vectors", str(caught.exception))

    def test_mutation_3_a_duplicate_vector_id_is_refused(self):
        document = json.loads(ANCHOR.read_text(encoding="utf-8"))
        document["vectors"][1]["vector_id"] = document["vectors"][0]["vector_id"]
        with self.assertRaises(adapter.AdapterError) as caught:
            adapter._vector_rows(document)
        self.assertIn("duplicate vector_id", str(caught.exception))

    def test_a_traversing_vector_id_is_refused(self):
        document = json.loads(ANCHOR.read_text(encoding="utf-8"))
        document["vectors"][0]["vector_id"] = "../escape"
        with self.assertRaises(adapter.AdapterError):
            adapter._vector_rows(document)

    def test_a_slice_count_mismatch_refuses_rather_than_guesses(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            with mock.patch.object(adapter, "raw_preimage_slices",
                                   lambda raw: [b"{}"] * 9):
                with self.assertRaises(adapter.AdapterError) as caught:
                    adapter.adapt(ANCHOR, tmp / "out")
            self.assertIn("refusing to guess", str(caught.exception))


class InvariantDisposition(unittest.TestCase):
    def _disposition(self):
        with tempfile.TemporaryDirectory() as d:
            dest = _adapt_to_temp(Path(d))
            source = json.loads((dest / "source.json").read_text(encoding="utf-8"))
            return source["pair_invariants"]

    def test_exactly_two_invariants_are_accounted_for(self):
        self.assertEqual(len(self._disposition()), adapter.PIN_INVARIANT_COUNT)

    def test_mutation_5_the_unknown_relation_is_typed_refused_not_skipped(self):
        entries = self._disposition()
        refused = [e for e in entries if e["disposition"] == "refused"]
        self.assertEqual(len(refused), 1)
        self.assertEqual(refused[0]["relation"], "emoji_key_precedes_ffff")
        self.assertEqual(refused[0]["reason"], adapter.REFUSAL_REASON)
        self.assertNotIn("skipped", {e["disposition"] for e in entries})
        self.assertNotIn("passed", {e["disposition"] for e in entries})

    def test_mutation_6_equal_sha256_is_really_evaluated(self):
        entries = self._disposition()
        projected = [e for e in entries if e["disposition"] == "projected"]
        self.assertEqual(len(projected), 1)
        self.assertEqual(projected[0]["relation"], "equal_sha256")
        self.assertEqual(sorted(projected[0]["vectors"]), sorted([FLOAT_ID, INT_ID]))
        document = json.loads(ANCHOR.read_text(encoding="utf-8"))
        declared = {v["vector_id"]: v["expected_sha256"] for v in document["vectors"]}
        self.assertEqual(projected[0]["declared_sha256"], declared[FLOAT_ID])

    def test_a_false_declared_equal_sha256_is_a_hard_error(self):
        document = json.loads(ANCHOR.read_text(encoding="utf-8"))
        by_id = {v["vector_id"]: v for v in document["vectors"]}
        by_id[INT_ID]["expected_sha256"] = "0" * 64
        with self.assertRaises(adapter.AdapterError) as caught:
            adapter._invariant_disposition(document, by_id)
        self.assertIn("declared digests differ", str(caught.exception))

    def test_mutation_4_ignoring_invariants_changes_the_accounted_total(self):
        document = json.loads(ANCHOR.read_text(encoding="utf-8"))
        by_id = {v["vector_id"]: v for v in document["vectors"]}
        document["pair_invariants"] = []
        with self.assertRaises(adapter.AdapterError) as caught:
            adapter._invariant_disposition(document, by_id)
        self.assertIn("expected 2 pair invariants", str(caught.exception))

    def test_an_invariant_naming_a_missing_vector_is_refused(self):
        document = json.loads(ANCHOR.read_text(encoding="utf-8"))
        by_id = {v["vector_id"]: v for v in document["vectors"]}
        document["pair_invariants"][0]["a"] = "jcs-edge-999-absent"
        with self.assertRaises(adapter.AdapterError) as caught:
            adapter._invariant_disposition(document, by_id)
        self.assertIn("unknown vector", str(caught.exception))

    def test_an_unknown_invariant_field_is_refused(self):
        document = json.loads(ANCHOR.read_text(encoding="utf-8"))
        by_id = {v["vector_id"]: v for v in document["vectors"]}
        document["pair_invariants"][0]["extra"] = True
        with self.assertRaises(adapter.AdapterError) as caught:
            adapter._invariant_disposition(document, by_id)
        self.assertIn("unknown fields", str(caught.exception))


class HostileInput(unittest.TestCase):
    def test_mutation_9_a_symlinked_source_is_refused(self):
        if not hasattr(os, "symlink"):
            self.skipTest("no symlink support on this platform")
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            link = tmp / "link.json"
            try:
                os.symlink(ANCHOR, link)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation is not permitted here")
            with self.assertRaises(adapter.AdapterError) as caught:
                adapter.adapt(link, tmp / "out")
            self.assertIn("regular file", str(caught.exception))

    def test_mutation_9_an_oversized_source_is_refused_before_materialization(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            big = tmp / "big.json"
            big.write_bytes(b"{}" + b" " * (adapter.SOURCE_CAP_BYTES + 1))
            with self.assertRaises(adapter.AdapterError) as caught:
                adapter.adapt(big, tmp / "out")
            self.assertIn("cap", str(caught.exception))
            self.assertFalse((tmp / "out").exists())

    def test_duplicate_metadata_keys_are_refused(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            forged = tmp / "dup.json"
            forged.write_bytes(b'{"name": "jcs_edge_v1", "name": "other"}')
            with self.assertRaises(adapter.AdapterError):
                adapter.adapt(forged, tmp / "out")

    def test_non_finite_constants_are_refused(self):
        raw = b'{"name": "jcs_edge_v1", "vectors": [NaN]}'
        with self.assertRaises(adapter.AdapterError):
            adapter._parse_strict(raw)

    def test_malformed_utf8_is_refused(self):
        with self.assertRaises(adapter.AdapterError):
            adapter.raw_preimage_slices(b'{"preimage": "\xff\xfe"}')

    def test_an_unknown_document_field_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            document = json.loads(ANCHOR.read_text(encoding="utf-8"))
            document["surprise"] = 1
            forged = tmp / "forged.json"
            forged.write_bytes(json.dumps(document).encode("utf-8"))
            with self.assertRaises(adapter.AdapterError):
                adapter.adapt(forged, tmp / "out")

    def test_a_non_empty_destination_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            dest = tmp / "out"
            dest.mkdir()
            (dest / "occupied").write_text("x", encoding="utf-8")
            with self.assertRaises(adapter.AdapterError) as caught:
                adapter.adapt(ANCHOR, dest)
            self.assertIn("not empty", str(caught.exception))

    def test_mutation_10_a_failure_leaves_no_consumable_partial_output(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            dest = tmp / "out"
            real = adapter._encode

            def explode(doc):
                if doc.get("schema") == adapter.SOURCE_SCHEMA:
                    raise adapter.AdapterError("injected failure after cases")
                return real(doc)

            with mock.patch.object(adapter, "_encode", explode):
                with self.assertRaises(adapter.AdapterError):
                    adapter.adapt(ANCHOR, dest)
            self.assertFalse(dest.exists(), "destination must not exist after failure")
            leftovers = [p for p in tmp.iterdir() if p.name.startswith("algovoi-adapt-")]
            self.assertEqual(leftovers, [], "temp directory must be removed")

    def test_cli_failure_exits_2_not_1(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            result = subprocess.run(
                [sys.executable, str(ADAPTER), str(tmp / "missing"), str(tmp / "out")],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)


class NoUpstreamImport(unittest.TestCase):
    def test_mutation_7_the_adapter_imports_no_upstream_runner(self):
        source = ADAPTER.read_text(encoding="utf-8")
        for forbidden in ("import rfc8785", "from rfc8785", "import generate",
                          "from generate", "upstream_runner"):
            self.assertNotIn(forbidden, source)

    def test_the_adapter_does_not_reimplement_canonicalization(self):
        source = ADAPTER.read_text(encoding="utf-8")
        self.assertNotIn("def canonical", source)
        self.assertNotIn("utf16", source.lower().replace("utf-16", "utf16")
                         .replace("utf16 code-unit", ""))


@unittest.skipIf(ca.fcntl is None,
                 "process scoring requires an advisory lock; see the portability note")
class EndToEnd(unittest.TestCase):
    """The real `corpus_adequacy.run()` over the adapted corpus."""

    def _prepare(self, tmp: Path) -> Path:
        dest = _adapt_to_temp(tmp)
        repo = tmp / "impl"
        repo.mkdir()
        (repo / "impl.py").write_text(SYNTHETIC_IMPL, encoding="utf-8")
        shutil.copytree(dest / "cases", repo / "cases")
        shutil.copy(dest / "vectors.json", repo / "vectors.json")
        return repo

    def test_numeric_round_trip_mutant_is_killed_by_the_lexeme_vector(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self._prepare(Path(d))
            mutants = {
                "algovoi": [
                    {
                        "label": "normalize the preimage through a JSON round trip",
                        "anchor": 'raw = open(sys.argv[1], "rb").read()',
                        "replacement": (
                            'raw = json.dumps(json.loads('
                            'open(sys.argv[1], "rb").read().decode("utf-8"))'
                            ').encode("utf-8")'),
                    },
                    {
                        "label": "CONTROL blank every lexeme",
                        "control": True,
                        "anchor": 'lexeme = text[start:text.index("\\n", start)].strip()',
                        "replacement": 'lexeme = ""',
                    },
                ]
            }
            manifest = _process_manifest(repo, mutants, ["raw_sha256", "lexeme"])
            report = ca.run(manifest)
            declared = next(r for r in report["mutants"]
                            if r["label"].startswith("normalize"))
            self.assertEqual(declared["verdict"], "killed")
            self.assertEqual(report["control_status"], "killed")

    def test_all_ten_cases_are_consumed_by_the_real_runner(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self._prepare(Path(d))
            outputs = {}
            for vector_id in (FLOAT_ID, INT_ID):
                result = subprocess.run(
                    [sys.executable, "impl.py", "cases/%s.json" % vector_id],
                    cwd=repo, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                outputs[vector_id] = json.loads(result.stdout)
            self.assertEqual(outputs[FLOAT_ID]["lexeme"], "1.0")
            self.assertEqual(outputs[INT_ID]["lexeme"], "1")
            self.assertNotEqual(outputs[FLOAT_ID]["raw_sha256"],
                                outputs[INT_ID]["raw_sha256"])

    def test_mutation_8_bypassing_the_real_run_fails_this_suite(self):
        self.assertIn("ca.run(", Path(__file__).read_text(encoding="utf-8"))
        with mock.patch.object(ca, "run",
                               side_effect=AssertionError("run must be called")):
            with self.assertRaises(AssertionError):
                self.test_numeric_round_trip_mutant_is_killed_by_the_lexeme_vector()


class Portability(unittest.TestCase):
    def test_the_end_to_end_skip_is_declared_not_silent(self):
        source = Path(__file__).read_text(encoding="utf-8")
        self.assertIn("process scoring requires an advisory lock", source)

    def test_adapter_writes_no_platform_specific_path_separator(self):
        with tempfile.TemporaryDirectory() as d:
            dest = _adapt_to_temp(Path(d))
            rows = json.loads((dest / "vectors.json").read_text(encoding="utf-8"))["vectors"]
            for row in rows:
                self.assertNotIn("\\", row["vector_path"])
                self.assertTrue(row["vector_path"].startswith("cases/"))


if __name__ == "__main__":
    unittest.main(verbosity=1)
