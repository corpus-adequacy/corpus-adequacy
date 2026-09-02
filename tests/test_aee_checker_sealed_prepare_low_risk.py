#!/usr/bin/env python3
"""Characterization guards for #49 streaming download and docker_ok.

Fake urlopen and mocked docker only. No network, Docker daemon, checker,
corpus, baseline, control, mutant, or artifact generation.
"""

from __future__ import annotations

import importlib.util
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

import aee_checker_sealed_materialize as mat  # noqa: E402
import aee_checker_sealed_oci as oci  # noqa: E402
import contained_oci as contained  # noqa: E402
from aee_checker_sealed_common import (  # noqa: E402
    MATERIALIZE_CEILINGS,
    MaterializeBudget,
    PrepareError,
)

PINS_PATH = REPO_ROOT / "measurements" / "aee-checker-25b9dfa" / "pins.json"
CHUNK_256K = 256 * 1024
BUDGET_1K = 1024


def _pins(path=PINS_PATH):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _pairs_from_pins(pins=None):
    pins = _pins() if pins is None else pins
    return (
        (pins["subject"]["repository"], pins["subject"]["commit"]),
        (pins["corpus"]["repository"], pins["corpus"]["commit"]),
    )


def _budget(disk_bytes=BUDGET_1K):
    spec = dict(MATERIALIZE_CEILINGS)
    spec["disk_bytes"] = disk_bytes
    return MaterializeBudget(spec)


class _FakeResponse:
    def __init__(self, chunks):
        self._chunks = list(chunks)

    def read(self, size=-1):
        if not self._chunks:
            return b""
        return self._chunks.pop(0)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def _urlopen_chunks(chunks):
    def urlopen(url, timeout=None):
        return _FakeResponse(chunks)

    return urlopen


def _download(dest, chunks, *, cap_bytes=BUDGET_1K, module=mat):
    with mock.patch.object(module.urllib.request, "urlopen", _urlopen_chunks(chunks)):
        return module.download_bounded(
            "https://example.invalid/archive.tar.gz",
            dest,
            cap_bytes=cap_bytes,
            deadline_seconds=30,
        )


def _oversize_prewrite_guard(module=mat):
    """Production-facing download: refuse oversize, dest gone, unlink saw 0 bytes."""
    with tempfile.TemporaryDirectory() as raw:
        dest = Path(raw) / "archive.tar.gz"
        sizes = []
        real_unlink = Path.unlink

        def spy(self, *args, **kwargs):
            if self.name == dest.name and self.exists():
                sizes.append(self.stat().st_size)
            return real_unlink(self, *args, **kwargs)

        with mock.patch.object(Path, "unlink", spy):
            raised = None
            try:
                _download(dest, [b"x" * CHUNK_256K], module=module)
            except PrepareError as exc:
                raised = exc
        return raised, dest.exists(), sizes


FROZEN_ARCHIVE_PAIRS = (
    ("Rul1an/aee-checker", "25b9dfa797986624f2d680530a7228232aa3ddda"),
    ("astrogilda/aee-conformance", "59faf842098183ae7b5387ad13e6351c44687279"),
)


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _scratch_materialize(text: str, tmp: Path, *, name="mut_materialize"):
    path = tmp / ("%s.py" % name)
    path.write_text(text, encoding="utf-8")
    return _load_module(path, name)


def _scratch_oci(text: str, tmp: Path, *, name="mut_oci"):
    path = tmp / ("%s.py" % name)
    path.write_text(text, encoding="utf-8")
    return _load_module(path, name)


class StreamingDownloadCeiling(unittest.TestCase):
    def test_oversize_chunk_refuses_before_unbounded_write(self):
        raised, exists, sizes = _oversize_prewrite_guard(mat)
        self.assertIsInstance(raised, PrepareError)
        self.assertFalse(exists)
        self.assertEqual(sizes, [0])

    def test_exact_cap_is_accepted(self):
        with tempfile.TemporaryDirectory() as raw:
            dest = Path(raw) / "archive.tar.gz"
            got = _download(dest, [b"y" * BUDGET_1K])
            self.assertEqual(got, dest)
            self.assertEqual(dest.stat().st_size, BUDGET_1K)

    def test_small_positive_control(self):
        with tempfile.TemporaryDirectory() as raw:
            dest = Path(raw) / "archive.tar.gz"
            got = _download(dest, [b"ok"])
            self.assertEqual(got.read_bytes(), b"ok")


class DockerOkReturncode(unittest.TestCase):
    def test_nonzero_completed_process_is_prepare_error(self):
        failed = subprocess.CompletedProcess(
            args=["docker", "info"], returncode=1, stdout="", stderr="denied")
        with mock.patch.object(contained.br, "_run_capped", return_value=failed):
            with self.assertRaises(PrepareError):
                oci.docker_ok(["info"])

    def test_rc0_positive_control(self):
        ok = subprocess.CompletedProcess(
            args=["docker", "info"], returncode=0, stdout="ok", stderr="")
        with mock.patch.object(contained.br, "_run_capped", return_value=ok):
            proc = oci.docker_ok(["info"])
        self.assertIs(proc, ok)


class PinnedArchiveUrl(unittest.TestCase):
    def test_frozen_manifest_pairs_use_github_archive_tarball(self):
        pairs = _pairs_from_pins()
        self.assertEqual(pairs, FROZEN_ARCHIVE_PAIRS)
        for repository, commit in pairs:
            self.assertEqual(
                mat.pinned_archive_url(repository, commit),
                "https://github.com/%s/archive/%s.tar.gz" % (repository, commit),
            )


class ScratchMutations(unittest.TestCase):
    def test_removing_budget_charge_turns_oversize_green_path_red(self):
        source = (REPO_ROOT / "measurements" / "aee_checker_sealed_materialize.py").read_text(
            encoding="utf-8")
        mutated = source.replace(
            "                    budget.charge(bytes=len(chunk))\n"
            "                    written += len(chunk)\n",
            "                    written += len(chunk)\n",
        )
        self.assertNotEqual(mutated, source)
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            module = _scratch_materialize(mutated, tmp)
            dest = tmp / "out.tar.gz"
            _download(dest, [b"x" * CHUNK_256K], module=module)
            self.assertTrue(dest.exists())
            self.assertGreater(dest.stat().st_size, BUDGET_1K)

    def test_relaxing_byte_ceiling_refusal_turns_red(self):
        source = (REPO_ROOT / "measurements" / "aee_checker_sealed_common.py").read_text(
            encoding="utf-8")
        mutated = source.replace(
            'if nxt_bytes > self.ceilings["disk_bytes"]:',
            "if False and nxt_bytes > self.ceilings[\"disk_bytes\"]:",
        )
        self.assertNotEqual(mutated, source)
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            (tmp / "mut_common.py").write_text(mutated, encoding="utf-8")
            common = _load_module(tmp / "mut_common.py", "mut_common")
            spec = dict(MATERIALIZE_CEILINGS)
            spec["disk_bytes"] = BUDGET_1K
            budget = common.MaterializeBudget(spec)
            budget.charge(bytes=CHUNK_256K)
            self.assertGreater(budget.used_bytes, BUDGET_1K)

    def test_charging_after_write_reddens_production_prewrite_guard(self):
        source = (REPO_ROOT / "measurements" / "aee_checker_sealed_materialize.py").read_text(
            encoding="utf-8")
        old = (
            "                    budget.charge(bytes=len(chunk))\n"
            "                    written += len(chunk)\n"
            "                    out.write(chunk)\n"
        )
        new = (
            "                    written += len(chunk)\n"
            "                    out.write(chunk)\n"
            "                    budget.charge(bytes=len(chunk))\n"
        )
        mutated = source.replace(old, new)
        self.assertNotEqual(mutated, source)
        with tempfile.TemporaryDirectory() as raw:
            module = _scratch_materialize(mutated, Path(raw), name="mut_charge_after")
            raised, exists, sizes = _oversize_prewrite_guard(module)
        self.assertIsInstance(raised, PrepareError)
        with self.assertRaises(AssertionError):
            self.assertEqual(sizes, [0])
        self.assertIn(CHUNK_256K, sizes)

    def test_ignoring_docker_returncode_turns_red(self):
        source = (REPO_ROOT / "measurements" / "contained_oci.py").read_text(
            encoding="utf-8")
        mutated = source.replace("if proc.returncode != 0:\n", "if False and proc.returncode != 0:\n")
        self.assertNotEqual(mutated, source)
        failed = subprocess.CompletedProcess(
            args=["docker", "info"], returncode=7, stdout="x", stderr="")
        with tempfile.TemporaryDirectory() as raw:
            module = _scratch_oci(mutated, Path(raw))
            with mock.patch.object(module.br, "_run_capped", return_value=failed):
                proc = module.docker_ok(["info"])
        self.assertEqual(proc.returncode, 7)

    def test_mutating_pins_subject_commit_reddens_frozen_pair_guard(self):
        with tempfile.TemporaryDirectory() as raw:
            dest = Path(raw) / "pins.json"
            dest.write_bytes(PINS_PATH.read_bytes())
            doc = json.loads(dest.read_text(encoding="utf-8"))
            original = doc["subject"]["commit"]
            self.assertEqual(original, FROZEN_ARCHIVE_PAIRS[0][1])
            doc["subject"]["commit"] = "a" * 40
            dest.write_text(json.dumps(doc), encoding="utf-8")
            mutated = _pins(dest)
            self.assertEqual(
                mutated["corpus"]["commit"], FROZEN_ARCHIVE_PAIRS[1][1])
            self.assertEqual(
                mutated["subject"]["repository"], FROZEN_ARCHIVE_PAIRS[0][0])
            pairs = _pairs_from_pins(mutated)
        with self.assertRaises(AssertionError):
            self.assertEqual(pairs, FROZEN_ARCHIVE_PAIRS)

    def test_rewriting_archive_commit_reddens_literal_pair_guard(self):
        source = (REPO_ROOT / "measurements" / "aee_checker_sealed_materialize.py").read_text(
            encoding="utf-8")
        mutated = source.replace(
            '"https://github.com/%s/archive/%s.tar.gz" % (repository, commit)',
            '"https://github.com/%s/archive/%s.tar.gz" % (repository, commit[::-1])',
        )
        self.assertNotEqual(mutated, source)
        with tempfile.TemporaryDirectory() as raw:
            module = _scratch_materialize(mutated, Path(raw), name="mut_commit")
            repository, commit = FROZEN_ARCHIVE_PAIRS[0]
            got = module.pinned_archive_url(repository, commit)
        expected = "https://github.com/%s/archive/%s.tar.gz" % (repository, commit)
        with self.assertRaises(AssertionError):
            self.assertEqual(got, expected)

    def test_rewriting_archive_url_host_or_scheme_turns_red(self):
        source = (REPO_ROOT / "measurements" / "aee_checker_sealed_materialize.py").read_text(
            encoding="utf-8")
        mutated = source.replace(
            '"https://github.com/%s/archive/%s.tar.gz"',
            '"http://example.invalid/%s/archive/%s.tar.gz"',
        )
        self.assertNotEqual(mutated, source)
        pins = _pins()
        with tempfile.TemporaryDirectory() as raw:
            module = _scratch_materialize(mutated, Path(raw), name="mut_url")
            got = module.pinned_archive_url(
                pins["subject"]["repository"], pins["subject"]["commit"])
        self.assertNotEqual(
            got,
            "https://github.com/%s/archive/%s.tar.gz" % (
                pins["subject"]["repository"], pins["subject"]["commit"]),
        )
        self.assertTrue(got.startswith("http://example.invalid/"))

    def test_noop_scratch_copy_stays_green(self):
        mat_src = (REPO_ROOT / "measurements" / "aee_checker_sealed_materialize.py").read_text(
            encoding="utf-8")
        oci_src = (REPO_ROOT / "measurements" / "contained_oci.py").read_text(
            encoding="utf-8")
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            module = _scratch_materialize(mat_src, tmp, name="noop_mat")
            docker = _scratch_oci(oci_src, tmp, name="noop_oci")
            dest = tmp / "ok.tar.gz"
            _download(dest, [b"z" * 16], module=module)
            self.assertEqual(dest.read_bytes(), b"z" * 16)
            ok = subprocess.CompletedProcess(
                args=["docker", "info"], returncode=0, stdout="ok", stderr="")
            with mock.patch.object(docker.br, "_run_capped", return_value=ok):
                self.assertIs(docker.docker_ok(["info"]), ok)
            repository, commit = FROZEN_ARCHIVE_PAIRS[1]
            self.assertEqual(
                module.pinned_archive_url(repository, commit),
                mat.pinned_archive_url(repository, commit),
            )


if __name__ == "__main__":
    unittest.main()
