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
import isolated_tree as iso  # noqa: E402
import tersign_evidence_record as ter  # noqa: E402
ADAPTER = REPO_ROOT / "adapters" / "tersign_evidence_record.py"

FIXTURE = REPO_ROOT / "fixtures" / "tersign-evidence-record-1cc5ea32"
NEW_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "tersign-evidence-record-0e560c1"
NEW_COMMIT = "0e560c1ad47f08177042c62754ebe6e0b482ad9a"
NEW_MANIFEST_SHA256 = "40abdf703b3b731c685142aa24a2561f1cc4679a013d51fdcb9764a1658819c6"
NEW_VECTORS_TREE = "fecf642073dd6b971aebba52bb67153efb1a1dfe"
NEW_VECTORS_FILES_SHA256 = "f4244e4bbcb86126f70cd4750d0a6ce8c729a0ef9baca428fdea9929dc97afd3"
N11 = "n11-integer-beyond-ijson-range"
N10 = "n10-float-in-digest-domain"
P12 = "p12-ijson-integer-boundary"


def _copy_source(tmp: Path) -> Path:
    dest = tmp / "src"
    shutil.copytree(FIXTURE, dest)
    return dest


def _copy_new_source(tmp: Path) -> Path:
    dest = tmp / "src"
    shutil.copytree(NEW_FIXTURE, dest)
    return dest


def _read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix().encode("utf-8")
        data = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


class SourceParity(unittest.TestCase):
    def test_exact_new_upstream_pin_adapts(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            src = _copy_new_source(tmp)
            dest = tmp / "out"
            dest.mkdir()
            with mock.patch.object(
                    ter, "_git_ids", return_value=(NEW_COMMIT, NEW_VECTORS_TREE)):
                ter.adapt(src, dest)
            source = _read_json(dest / "source.json")
            self.assertEqual(source["commit"], NEW_COMMIT)
            self.assertEqual(source["vectors_tree"], NEW_VECTORS_TREE)

    def test_non_git_new_fixture_requires_exact_digest_and_files_identity(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            src = _copy_new_source(tmp)
            dest = tmp / "out"
            dest.mkdir()
            ter.adapt(src, dest)
            source = _read_json(dest / "source.json")
            self.assertEqual(source["manifest_sha256"], NEW_MANIFEST_SHA256)
            self.assertEqual(source["counts"], {"vectors": 60, "valid": 25, "reject": 35})

            changed_root = tmp / "changed"
            changed_root.mkdir()
            changed = _copy_new_source(changed_root)
            p25 = changed / "vectors" / "p25-integer-token-in-text.json"
            p25.write_bytes(p25.read_bytes().replace(b'{\\"amount\\": 2}', b'{\\"amount\\":2}'))
            refused = tmp / "refused"
            refused.mkdir()
            with self.assertRaisesRegex(ter.AdapterError, r"digest|identity|pin"):
                ter.adapt(changed, refused)
            self.assertEqual(list(refused.iterdir()), [])

    def test_unknown_and_mixed_git_identities_fail_closed(self):
        identities = (
            ("f" * 40, NEW_VECTORS_TREE),
            (ter.PIN_COMMIT, NEW_VECTORS_TREE),
            (NEW_COMMIT, ter.PIN_VECTORS_TREE),
        )
        for commit, tree in identities:
            with self.subTest(commit=commit, tree=tree):
                with tempfile.TemporaryDirectory() as d:
                    tmp = Path(d)
                    src = _copy_new_source(tmp)
                    dest = tmp / "out"
                    dest.mkdir()
                    with mock.patch.object(ter, "_git_ids", return_value=(commit, tree)):
                        with self.assertRaisesRegex(
                                ter.AdapterError,
                                "source manifest/vector body digest identity "
                                "does not match any allowed pin"):
                            ter.adapt(src, dest)
                    self.assertEqual(list(dest.iterdir()), [])

    def test_payload_text_pair_is_preserved_as_distinct_exact_strings(self):
        expected = {
            "p25-integer-token-in-text": '{"amount": 2}',
            "n35-integer-valued-float-token": '{"amount": 2.0}',
        }
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            src = _copy_new_source(tmp)
            dest = tmp / "out"
            dest.mkdir()
            ter.adapt(src, dest)
            for vector_id, payload_text in expected.items():
                source_case = src / "vectors" / (vector_id + ".json")
                emitted_case = dest / "cases" / (vector_id + ".json")
                self.assertEqual(emitted_case.read_bytes(), source_case.read_bytes())
                self.assertEqual(_read_json(emitted_case)["input"]["payload_text"], payload_text)

    def test_historical_output_bytes_are_unchanged(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "out"
            dest.mkdir()
            ter.adapt(FIXTURE, dest)
            self.assertEqual(
                hashlib.sha256((dest / "vectors.json").read_bytes()).hexdigest(),
                "678315a30887a5b899e8cc0cc36c4c8e8361cc4a587c7ed839b4f51ef717475d",
            )
            self.assertEqual(
                hashlib.sha256((dest / "source.json").read_bytes()).hexdigest(),
                "bf7094942d119fc5b57c917423c5fb7b6de110c26589690a800fa448db441cf2",
            )
            self.assertEqual(
                _tree_digest(dest),
                "a3029ef1daeed991a8ca3fc87cb7bf6e685174e5611c957c451c1f54649998dd",
            )

    def test_profile_table_is_closed_to_exactly_two_pins(self):
        self.assertEqual(
            {profile.commit for profile in ter.PIN_PROFILES},
            {ter.PIN_COMMIT, NEW_COMMIT},
        )
        self.assertEqual(len(ter.PIN_PROFILES), 2)
        new_profile = next(
            profile for profile in ter.PIN_PROFILES if profile.commit == NEW_COMMIT)
        self.assertEqual(new_profile.counts, (60, 25, 35))
        self.assertEqual(new_profile.vectors_files_sha256, NEW_VECTORS_FILES_SHA256)
        self.assertEqual(new_profile.kinds, ter.PINNED_KINDS)
        self.assertEqual(new_profile.reasons, ter.PINNED_REASONS)

    def test_new_counts_and_closures_are_profile_authoritative(self):
        new_profile = next(
            profile for profile in ter.PIN_PROFILES if profile.commit == NEW_COMMIT)
        mutations = (
            new_profile._replace(counts=(59, 25, 34)),
            new_profile._replace(kinds=new_profile.kinds - {"canonical_bytes"}),
            new_profile._replace(reasons=new_profile.reasons - {"number_domain_reject"}),
        )
        for mutated_profile in mutations:
            with self.subTest(profile=mutated_profile):
                with tempfile.TemporaryDirectory() as d:
                    tmp = Path(d)
                    src = _copy_new_source(tmp)
                    dest = tmp / "out"
                    dest.mkdir()
                    profiles = tuple(
                        mutated_profile if profile.commit == NEW_COMMIT else profile
                        for profile in ter.PIN_PROFILES
                    )
                    with mock.patch.object(ter, "PIN_PROFILES", profiles):
                        with self.assertRaises(ter.AdapterError):
                            ter.adapt(src, dest)
                    self.assertEqual(list(dest.iterdir()), [])

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
        pin = "fd2c1edd4a24d1e45f90ca2072fa7a797fb03d7cd66b494a541092e6a23a4703"
        fixture = (FIXTURE / "vectors" / ("%s.json" % N10)).read_bytes()
        self.assertEqual(hashlib.sha256(fixture).hexdigest(), pin)
        self.assertNotIn(b"\r\n", fixture)
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            src = _copy_source(tmp)
            dest = tmp / "out"
            dest.mkdir()
            ter.adapt(src, dest)
            n10 = dest / "cases" / ("%s.json" % N10)
            raw = n10.read_bytes()
            self.assertEqual(raw, (src / "vectors" / ("%s.json" % N10)).read_bytes())
            self.assertEqual(hashlib.sha256(raw).hexdigest(), pin)
            self.assertIn(b"1.1", raw)
            self.assertNotIn(b"1.10", raw)
            self.assertNotIn(b"\r\n", raw)

    def test_windows_opens_are_binary(self):
        reader = Path(ca.__file__).read_text(encoding="utf-8")
        adapter = Path(ter.__file__).read_text(encoding="utf-8")
        self.assertIn("O_BINARY", reader)
        self.assertIn("O_BINARY", adapter)

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

    def test_short_os_write_refuses_and_leaves_no_consumable_dest(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            src = _copy_source(tmp)
            dest = tmp / "out"
            dest.mkdir()
            real_write = os.write
            seen_fds = set()
            short_calls = []

            def first_half_then_zero(fd, data):
                if fd not in seen_fds:
                    seen_fds.add(fd)
                    chunk = data[: max(1, len(data) // 2)]
                    wrote = real_write(fd, chunk)
                    short_calls.append(wrote)
                    return wrote
                return 0

            with mock.patch.object(os, "write", side_effect=first_half_then_zero):
                with self.assertRaises((ter.AdapterError, OSError)) as ctx:
                    ter.adapt(src, dest)
            self.assertGreaterEqual(len(short_calls), 1)
            self.assertRegex(str(ctx.exception).lower(), r"write|short|progress")
            if dest.exists():
                self.assertFalse((dest / "cases").exists())
                self.assertFalse((dest / "vectors.json").exists())
                self.assertFalse((dest / "source.json").exists())
                self.assertEqual(list(dest.iterdir()), [])
            self.assertFalse(any(tmp.glob("tersign-adapt-*")))

    def test_partial_progress_still_emits_exact_n10_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            src = _copy_source(tmp)
            dest = tmp / "out"
            dest.mkdir()
            real_write = os.write

            def half_of_remaining(fd, data):
                if not data:
                    return 0
                return real_write(fd, data[: max(1, len(data) // 2)])

            with mock.patch.object(os, "write", side_effect=half_of_remaining):
                ter.adapt(src, dest)
            n10 = dest / "cases" / ("%s.json" % N10)
            raw = n10.read_bytes()
            self.assertEqual(len(raw), 641)
            self.assertEqual(
                hashlib.sha256(raw).hexdigest(),
                "fd2c1edd4a24d1e45f90ca2072fa7a797fb03d7cd66b494a541092e6a23a4703",
            )

    def test_zero_progress_write_is_refusal_not_a_spin(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            src = _copy_source(tmp)
            dest = tmp / "out"
            dest.mkdir()

            def always_zero(fd, data):
                return 0

            with mock.patch.object(os, "write", side_effect=always_zero):
                with self.assertRaises((ter.AdapterError, OSError)):
                    ter.adapt(src, dest)
            if dest.exists():
                self.assertFalse((dest / "cases").exists())
                self.assertEqual(list(dest.iterdir()), [])
            self.assertFalse(any(tmp.glob("tersign-adapt-*")))

    def test_eintr_then_complete_write_still_emits(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            src = _copy_source(tmp)
            dest = tmp / "out"
            dest.mkdir()
            real_write = os.write
            interrupted = {"left": 1}

            def eintr_then_write(fd, data):
                if interrupted["left"]:
                    interrupted["left"] -= 1
                    raise InterruptedError("EINTR")
                return real_write(fd, data)

            with mock.patch.object(os, "write", side_effect=eintr_then_write):
                ter.adapt(src, dest)
            n10 = dest / "cases" / ("%s.json" % N10)
            self.assertEqual(len(n10.read_bytes()), 641)

    def test_emit_calls_the_public_write_all(self):
        """Name check only. Partial/zero/EINTR behavior is in the tests above."""
        src = Path(ter.__file__).read_text(encoding="utf-8")
        self.assertIn("write_all", src)
        self.assertNotIn("._write_all", src)
        self.assertNotRegex(
            src,
            r"os\.write\(fd, data\)\s*$",
            msg="bare os.write(fd, data) is the ignored-short-write defect",
        )

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
            rep = ca.run(typed, execution_profile="trusted-local")
            drift = next(r for r in rep["mutants"] if r["label"] == "n11 reason drift")
            self.assertEqual(drift["verdict"], "killed")
            self.assertEqual(drift["moved"], 1)
            verdict_only = _process_manifest(tmp, repo, mutants, ["verdict"])
            false_green = ca.run(verdict_only, execution_profile="trusted-local")
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
