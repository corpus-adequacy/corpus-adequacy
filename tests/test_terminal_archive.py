#!/usr/bin/env python3
"""Archived terminal attempts (#188): the helper, and the retained r4 set read back at HEAD."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(REPO_ROOT / "measurements"))
sys.path.insert(0, str(REPO_ROOT))

import terminal_archive as archive  # noqa: E402
import contained_hosted_publication as hosted  # noqa: E402

SCRIPT = REPO_ROOT / "scripts" / "terminal_archive.py"
R4 = REPO_ROOT / "tests" / "fixtures" / "hosted-r4-terminal"
R4_DIGESTS = {
    "setup-status.json": "1c2cac5834145edf22997a29ab00aa2beea2ba33e1e388b46127a5041025d32e",
    "candidate-result.json": "0ac4b193e23cfff205f68bcb51c065d5a4223c05089c5aa222c3cee6a77acb38",
    "rerun-evidence.jsonl": "90f3f0609a5b01625ef624870941b8ea0b2db0e271ab392f4d7782b8854197db",
    "effective-envelope/collection-index.v0.json":
        "b899299ac8f8c85f3acda6f739bfe30dbe11aa62fa1f3f5f12f46d3c9764cb61",
}
R4_BINDINGS = {
    "candidate_revision": "25b9dfa797986624f2d680530a7228232aa3ddda",
    "runner_revision": "1345bac5d5853824a6de00dda9a7b03efd906236",
    "image_digest":
        "sha256:d5373500f56281009855ee607358ab237ea1564ded3e58491e1045380dbfa245",
}
R4_RUN_ID, R4_RUN_ATTEMPT = "35194072925", "1"
R4_REPORT_SHA256 = "8b9ec543f891b0a88aaffac9a49230d98b4c6e1d6a09e2cf28c62749e7408c98"


def _r4_readback(*, setup, candidate, rerun, collection_dir):
    loaded = hosted.load_hosted_attempt_artifacts(
        setup_path=setup, candidate_path=candidate, rerun_path=rerun,
        collection_dir=collection_dir, expected_bindings=R4_BINDINGS,
        expected_run_id=R4_RUN_ID, expected_run_attempt=R4_RUN_ATTEMPT)
    return hosted._readback_summary(loaded["projection"])


def _zip(path: Path, members: dict) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as out:
        for name, data in members.items():
            out.writestr(name, data)
    return path


def _r4_archive(root: Path) -> Path:
    """The release's asset shape, built from the retained r4 bytes (ZIP bytes are not the
    Actions API's; the members are)."""
    root.mkdir(parents=True)
    _zip(root / "setup.zip", {"setup-status.json": (R4 / "setup-status.json").read_bytes()})
    _zip(root / "candidate-result.zip",
         {"candidate-result.json": (R4 / "candidate-result.json").read_bytes()})
    _zip(root / "rerun-evidence-35194072925-1.zip",
         {"rerun-evidence.jsonl": (R4 / "rerun-evidence.jsonl").read_bytes()})
    _zip(root / "effective-envelope.zip", {
        p.name: p.read_bytes() for p in sorted((R4 / "effective-envelope").iterdir())})
    (root / "api-run.json").write_bytes(b'{"id": 35194072925}\n')
    (root / "run-35194072925-1.log").write_bytes(b"log\n")
    return root


class RetainedR4ReadsBackAtHead(unittest.TestCase):
    """Historical published bytes must stay readable by the current loaders."""

    def test_fixture_bytes_are_the_retained_ones(self):
        for rel, digest in R4_DIGESTS.items():
            with self.subTest(rel=rel):
                self.assertEqual(hashlib.sha256((R4 / rel).read_bytes()).hexdigest(), digest)

    def test_r4_set_reads_back(self):
        with tempfile.TemporaryDirectory() as raw:
            collection_dir = Path(raw) / "effective-envelope"
            shutil.copytree(R4 / "effective-envelope", collection_dir)
            summary = _r4_readback(
                setup=R4 / "setup-status.json", candidate=R4 / "candidate-result.json",
                rerun=R4 / "rerun-evidence.jsonl", collection_dir=collection_dir)
        self.assertEqual(summary["decision"], "publish")
        self.assertEqual(summary["collection_state"], "collection_present")
        self.assertEqual((summary["attempts"], summary["members"]), (9, 9))
        self.assertEqual(summary["report_sha256"], R4_REPORT_SHA256)
        self.assertEqual(summary["publication_permission"], "permitted")
        self.assertEqual(summary["step_attribution"], "not-carried")
        self.assertEqual({(m["candidate_outcome"], m["cleanup"])
                          for m in summary["member_observations"]},
                         {("completed", "removed-and-absent")})

    def test_r4_set_refuses_the_wrong_run(self):
        with tempfile.TemporaryDirectory() as raw:
            collection_dir = Path(raw) / "effective-envelope"
            shutil.copytree(R4 / "effective-envelope", collection_dir)
            with self.assertRaises(hosted.HostedPublicationError) as ctx:
                hosted.load_hosted_attempt_artifacts(
                    setup_path=R4 / "setup-status.json",
                    candidate_path=R4 / "candidate-result.json",
                    rerun_path=R4 / "rerun-evidence.jsonl", collection_dir=collection_dir,
                    expected_bindings=R4_BINDINGS, expected_run_id="35071237962",
                    expected_run_attempt=R4_RUN_ATTEMPT)
            self.assertEqual(str(ctx.exception), "attempt_binding")


class ArchiveRoundTrip(unittest.TestCase):
    def test_sums_check_extract_then_readback_equals_the_direct_readback(self):
        with tempfile.TemporaryDirectory() as raw:
            root = _r4_archive(Path(raw) / "release")
            written = archive.write_sums(root)
            self.assertEqual(written["assets"], 6)
            (root / "NOTES.md").write_text("notes are the release body\n")
            self.assertEqual(archive.check_archive(root)["assets"], 6)
            extracted = archive.extract_archive(root, Path(raw) / "x")
            self.assertEqual(sorted(extracted), [
                "candidate-result", "effective-envelope",
                "rerun-evidence-35194072925-1", "setup"])
            x = Path(raw) / "x"
            via_archive = _r4_readback(
                setup=x / "setup" / "setup-status.json",
                candidate=x / "candidate-result" / "candidate-result.json",
                rerun=x / "rerun-evidence-35194072925-1" / "rerun-evidence.jsonl",
                collection_dir=x / "effective-envelope")
            direct_dir = Path(raw) / "direct"
            shutil.copytree(R4 / "effective-envelope", direct_dir)
            direct = _r4_readback(
                setup=R4 / "setup-status.json", candidate=R4 / "candidate-result.json",
                rerun=R4 / "rerun-evidence.jsonl", collection_dir=direct_dir)
            self.assertEqual(via_archive, direct)

    def test_cli(self):
        with tempfile.TemporaryDirectory() as raw:
            root = _r4_archive(Path(raw) / "release")
            run = lambda *a: subprocess.run(  # noqa: E731
                [sys.executable, str(SCRIPT), *a], capture_output=True, text=True, check=False)
            printed = run("sums", str(root))
            self.assertEqual(printed.returncode, 0, printed.stderr)
            self.assertEqual(printed.stdout.encode(), archive.compute_sums(root))
            self.assertFalse((root / "SHA256SUMS").exists(), "printing writes nothing")
            self.assertEqual(run("sums", str(root), "--write").returncode, 0)
            self.assertEqual(json.loads(run("check", str(root)).stdout)["assets"], 6)
            refused = run("sums", str(root), "--write")
            self.assertEqual(refused.returncode, 2)
            self.assertIn("archive refused: sums_exists", refused.stderr)
            done = run("extract", str(root), str(Path(raw) / "x"))
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertIn("effective-envelope", json.loads(done.stdout)["extracted"])
            again = run("extract", str(root), str(Path(raw) / "x"))
            self.assertEqual(again.returncode, 2)
            self.assertIn("extract_target_exists", again.stderr)


class ArchiveIsNeverAWorkflowStep(unittest.TestCase):
    def test_no_workflow_runs_the_archive_helper(self):
        for workflow in sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml")):
            with self.subTest(workflow=workflow.name):
                self.assertNotIn("terminal_archive", workflow.read_text(encoding="utf-8"))

    def test_the_helper_opens_no_network_and_calls_no_subprocess(self):
        source = SCRIPT.read_text(encoding="utf-8")
        for token in ("urllib", "http", "socket", "subprocess", "requests", "os.system"):
            self.assertNotIn(token, source)


class ArchiveRefusals(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = _r4_archive(Path(self.tmp.name) / "release")
        archive.write_sums(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def _refused(self, reason, fn=None):
        fn = fn or (lambda: archive.check_archive(self.root))
        with self.assertRaises(archive.ArchiveError) as ctx:
            fn()
        self.assertEqual(str(ctx.exception), reason)

    def test_a_changed_asset_is_refused_not_repaired(self):
        target = self.root / "api-run.json"
        target.write_bytes(target.read_bytes() + b" ")
        sums_before = (self.root / "SHA256SUMS").read_bytes()
        self._refused("archive_digest:api-run.json")
        self.assertEqual((self.root / "SHA256SUMS").read_bytes(), sums_before)

    def test_missing_and_extra_assets(self):
        (self.root / "run-35194072925-1.log").unlink()
        self._refused("archive_set:missing=run-35194072925-1.log,extra=")
        (self.root / "run-35194072925-1.log").write_bytes(b"log\n")
        (self.root / "api-jobs.json").write_bytes(b"{}\n")
        self._refused("archive_set:missing=,extra=api-jobs.json")

    def test_non_canonical_sums(self):
        sums = self.root / "SHA256SUMS"
        good = sums.read_bytes()
        lines = good.decode().splitlines(keepends=True)
        for data, reason in (
            ("".join(reversed(lines)).encode(), "sums_canonical"),
            (good.replace(b"  ", b" *", 1), "sums_mode"),
            (good[:-1], "sums_shape"),
            (good + lines[0].encode(), "sums_duplicate"),
            (good.replace(b"  api-run.json", b"  sub/api-run.json"), "sums_name"),
            (good.replace(b"\n", b"\r\n"), "sums_name"),
            (good + ("0" * 64 + "  SHA256SUMS\n").encode(), "sums_name"),
        ):
            with self.subTest(reason=reason):
                sums.write_bytes(data)
                self._refused(reason)
        sums.write_bytes(good)
        self.assertEqual(archive.check_archive(self.root)["assets"], 6)

    def test_entries_that_are_not_plain_files(self):
        (self.root / "nested").mkdir()
        self._refused("archive_entry:nested")
        (self.root / "nested").rmdir()
        try:
            os.symlink(self.root / "api-run.json", self.root / "api-link.json")
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are not available on this host")
        self._refused("archive_entry:api-link.json")
        (self.root / "api-link.json").unlink()
        (self.root / ".hidden").write_bytes(b"x")
        self._refused("archive_name:.hidden")

    def _replace_zip(self, name, members, *, raw_info=None):
        path = self.root / name
        path.unlink()
        with zipfile.ZipFile(path, "w") as out:
            for member, data in members.items():
                out.writestr(member, data)
            if raw_info is not None:
                out.writestr(*raw_info)
        (self.root / "SHA256SUMS").unlink()
        archive.write_sums(self.root)

    def _extract_refused(self, reason):
        dest = Path(self.tmp.name) / "x"
        self._refused(reason, lambda: archive.extract_archive(self.root, dest))
        self.assertFalse(dest.exists(), "a refused extraction writes nothing")

    def test_zip_member_traversal_nesting_and_duplicates(self):
        for members, reason in (
            ({"../escape.json": b"x"}, "zip_member_name:setup.zip"),
            ({"/abs.json": b"x"}, "zip_member_name:setup.zip"),
            ({"dir/setup-status.json": b"x"}, "zip_member_name:setup.zip"),
            ({"..": b"x"}, "zip_member_name:setup.zip"),
        ):
            with self.subTest(reason=reason, members=members):
                self._replace_zip("setup.zip", members)
                self._extract_refused(reason)

    def test_zip_symlink_member_and_oversize(self):
        link = zipfile.ZipInfo("setup-status.json")
        link.external_attr = (0o120777 << 16)
        self._replace_zip("setup.zip", {}, raw_info=(link, "/etc/passwd"))
        self._extract_refused("zip_member_type:setup.zip")
        big = b"0" * (archive.MAX_EXTRACTED_BYTES + 1)
        self._replace_zip("setup.zip", {"setup-status.json": big})
        self._extract_refused("zip_extracted_bytes:setup.zip")

    def test_zip_duplicate_member(self):
        path = self.root / "setup.zip"
        path.unlink()
        with zipfile.ZipFile(path, "w") as out:
            out.writestr("setup-status.json", b"a")
            with self.assertWarns(UserWarning):
                out.writestr("setup-status.json", b"b")
        (self.root / "SHA256SUMS").unlink()
        archive.write_sums(self.root)
        self._extract_refused("zip_member_duplicate:setup.zip")

    def test_not_a_zip(self):
        (self.root / "setup.zip").write_bytes(b"not a zip")
        (self.root / "SHA256SUMS").unlink()
        archive.write_sums(self.root)
        self._extract_refused("zip_corrupt:setup.zip")

    def test_extraction_needs_a_checking_set_first(self):
        (self.root / "api-run.json").write_bytes(b"changed\n")
        self._extract_refused("archive_digest:api-run.json")


if __name__ == "__main__":
    unittest.main()
