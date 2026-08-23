#!/usr/bin/env python3
"""Synthetic sealed-candidate backend tests. No live checker/corpus/#211."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "measurements"))
sys.path.insert(0, str(REPO_ROOT / "adapters"))

import aee_checker_sealed as sealed_adapter  # noqa: E402
import aee_checker_sealed_candidate as cand  # noqa: E402
import aee_checker_sealed_oci as oci  # noqa: E402
import corpus_adequacy as ca  # noqa: E402

from aee_checker_sealed_common import INERT_RESOURCE_PROFILE, PrepareError  # noqa: E402

IMAGE = "sha256:" + ("ab" * 32)
POLICY = {"accepted_exit_codes": [0], "unproved_exit_codes": [75]}
GOOD_ROW = {
    "id": "v1",
    "verdict": "valid",
    "result": "ok",
    "reason": "prose",
    "code": "MUST-NOT-LEAK",
    "tiersWithPinnedKey": ["t"],
    "tiersWithoutKey": [],
}
RICH_REPORT = {"vectors": [GOOD_ROW]}


def _mounts(root: Path, *, subject=True, manifest=True):
    names = ("input", "vendor", "tool", "subject") if subject else ("input", "vendor", "tool")
    mounts = {}
    for name in names:
        path = root / name
        path.mkdir(exist_ok=True)
        mounts[name] = path
    if manifest and "input" in mounts:
        vectors = mounts["input"] / "vectors"
        vectors.mkdir(exist_ok=True)
        (vectors / "MANIFEST.json").write_text(json.dumps({
            "vectors": [{"id": "v1", "file": "v1.json"}],
        }), encoding="utf-8")
    return mounts


def _classify(completed):
    return ca.classify(
        completed.returncode,
        POLICY["accepted_exit_codes"],
        POLICY["unproved_exit_codes"],
    )


def _inspect(dests):
    return {
        "HostConfig": {
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "Memory": 4294967296,
            "MemorySwap": 4294967296,
            "PidsLimit": 512,
            "NetworkMode": "none",
            "Tmpfs": {
                "/tmp": "rw,size=1048576,nr_inodes=128,mode=1777",
                "/work": "rw,size=1048576,nr_inodes=128,mode=1777",
            },
        },
        "Config": {"User": "65532:65532", "Env": ["CARGO_NET_OFFLINE=true"]},
        "Mounts": [
            {"Type": "bind", "Destination": dest, "RW": False}
            for dest in dests
        ],
    }


class FakeTransport:
    def __init__(
            self, *, returncode=0, stdout="", inspect=None,
            timeout=False, output_cap=False, skip_absent=False,
            leave_present=False, fail_create=False):
        self.returncode = returncode
        self.stdout = stdout
        self.inspect_doc = inspect
        self.timeout = timeout
        self.output_cap = output_cap
        self.skip_absent = skip_absent
        self.leave_present = leave_present
        self.fail_create = fail_create
        self.created = []
        self.removed = []
        self.absent_checked = []
        self.started = []

    def create(self, argv):
        self.created.append(list(argv))
        if self.fail_create:
            raise PrepareError("partial create")

    def start(self, name, deadline_seconds=None):
        self.started.append(name)
        self.deadline_seconds = deadline_seconds
        if self.timeout:
            raise subprocess.TimeoutExpired(["docker", "start", "-a", name], 1)
        if self.output_cap:
            raise Exception("output_cap")
        return subprocess.CompletedProcess(
            ["docker", "start", "-a", name],
            self.returncode,
            self.stdout,
            "",
        )

    def inspect(self, name):
        return self.inspect_doc

    def remove(self, name):
        self.removed.append(name)

    def require_absent(self, name):
        self.absent_checked.append(name)
        if self.leave_present:
            raise PrepareError("container still present: %s" % name)


def _load_mutated(text: str, tmp: Path):
    path = tmp / "mut_candidate.py"
    path.write_text(text)
    spec = importlib.util.spec_from_file_location("mut_candidate", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class InertByteCompat(unittest.TestCase):
    def test_default_create_argv_stays_probe_and_three_mounts(self):
        with tempfile.TemporaryDirectory() as d:
            mounts = _mounts(Path(d), subject=False, manifest=False)
            argv = oci.docker_create_argv(
                image_id=IMAGE, name="inert", mounts=mounts, command=["ok"])
        self.assertEqual(argv[argv.index(IMAGE) + 1], "/probe")
        text = " ".join(argv)
        self.assertIn("destination=/input,readonly", text)
        self.assertNotIn("/bin/sh", text)

    def test_explicit_default_entrypoint_matches_omitted(self):
        with tempfile.TemporaryDirectory() as d:
            mounts = _mounts(Path(d), subject=False, manifest=False)
            omitted = oci.docker_create_argv(
                image_id=IMAGE, name="inert", mounts=mounts, command=["ok"])
            explicit = oci.docker_create_argv(
                image_id=IMAGE, name="inert", mounts=mounts, command=["ok"],
                entrypoint="/probe")
        self.assertEqual(omitted, explicit)


class CandidateArgv(unittest.TestCase):
    def test_command_uses_release_binary_and_tool_cargo_home(self):
        script = cand.CANDIDATE_SCRIPT
        self.assertIn("/work/target/release/aee-checker", script)
        self.assertIn("/input/vectors", script)
        self.assertIn("CARGO_HOME=/tool", script)
        self.assertIn("cargo build --release --locked --offline", script)
        self.assertIn("/work/report.json", script)
        self.assertNotIn("/tool/checker", script)
        self.assertNotIn("CARGO_HOME=/vendor", script)
        self.assertNotIn("aee-checker /input --json", script)
        self.assertNotIn("cargo test", script)
        self.assertIn("--json /work/report.json 1>&2", script)

    def test_human_stdout_on_protocol_channel_turns_valid_report_unproved(self):
        self.assertIn("--json /work/report.json 1>&2", cand.CANDIDATE_SCRIPT)
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            report = root / "report.json"
            report.write_text(json.dumps(RICH_REPORT), encoding="utf-8")
            mixed = subprocess.run(
                ["sh", "-lc", "printf 'wrote %s\\n'; cat report.json"],
                cwd=root, capture_output=True, text=True, check=True)
            (root / "host").mkdir()
            vectors = cand.host_vectors_path(_mounts(root / "host"))
            bitten = cand.normalize_inner_event(
                returncode=0, stdout=mixed.stdout, vectors=vectors)
            self.assertEqual(bitten.returncode, 75)
            redirected = subprocess.run(
                ["sh", "-lc",
                 "printf 'wrote %s\\n' 1>&2; cat report.json"],
                cwd=root, capture_output=True, text=True, check=True)
            clean = cand.normalize_inner_event(
                returncode=0, stdout=redirected.stdout, vectors=vectors)
            self.assertEqual(clean.returncode, 0)
            self.assertIn("rows", json.loads(clean.stdout))

    def test_candidate_selects_bin_sh_lc_and_subject_readonly(self):

        with tempfile.TemporaryDirectory() as d:
            mounts = _mounts(Path(d))
            argv = cand.candidate_create_argv(
                image_id=IMAGE, name="cand", mounts=mounts)
        idx = argv.index(IMAGE)
        self.assertEqual(argv[idx + 1], "/bin/sh")
        self.assertEqual(argv[idx + 2], "-lc")
        text = " ".join(argv)
        for dest in ("/input", "/vendor", "/tool", "/subject"):
            self.assertIn("destination=%s,readonly" % dest, text)

    def test_readonly_drop_mutation_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            argv = cand.candidate_create_argv(
                image_id=IMAGE, name="cand", mounts=_mounts(Path(d)))
        for token in argv:
            if token.startswith("type=bind,"):
                self.assertTrue(token.endswith(",readonly"), token)

    def test_explicit_entrypoint_omitted_falls_back_to_probe(self):
        with tempfile.TemporaryDirectory() as d:
            forgotten = oci.docker_create_argv(
                image_id=IMAGE, name="cand", mounts=_mounts(Path(d)),
                command=["-lc", cand.CANDIDATE_SCRIPT],
                mount_spec=cand.CANDIDATE_MOUNT_SPEC)
        self.assertEqual(forgotten[forgotten.index(IMAGE) + 1], "/probe")

    def test_writable_result_bind_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            mounts = _mounts(root)
            mounts["result"] = root / "result"
            mounts["result"].mkdir()
            with self.assertRaises(PrepareError):
                cand.candidate_create_argv(
                    image_id=IMAGE, name="cand", mounts=mounts)


class InnerNormalize(unittest.TestCase):
    def test_rich_report_projects_rows_and_diagnostics(self):
        with tempfile.TemporaryDirectory() as d:
            mounts = _mounts(Path(d))
            vectors = cand.host_vectors_path(mounts)
            for rc in (0, 1):
                completed = cand.normalize_inner_event(
                    returncode=rc, stdout=json.dumps(RICH_REPORT), vectors=vectors)
                self.assertEqual(completed.returncode, 0)
                outer = json.loads(completed.stdout)
                expected = sealed_adapter.project(
                    RICH_REPORT, sealed_adapter.expected_ids(vectors))
                self.assertEqual(outer, expected)
                self.assertIn("rows", outer)
                self.assertIn("diagnostics", outer)
                self.assertNotIn("vectors", outer)
                self.assertNotIn("MUST-NOT-LEAK", completed.stdout)
                self.assertEqual(outer["rows"]["v1"]["verdict"], "valid")
                self.assertEqual(outer["diagnostics"]["v1"]["reason"], "prose")
                self.assertEqual(_classify(completed), "ok")

    def test_raw_vectors_without_project_is_unproved(self):
        with tempfile.TemporaryDirectory() as d:
            vectors = cand.host_vectors_path(_mounts(Path(d)))
            # Four scalar fields, or a vectors document returned verbatim, is not outer.
            completed = cand.normalize_inner_event(
                returncode=0,
                stdout=json.dumps({
                    "verdict": "valid", "result": "ok",
                    "tiersWithPinnedKey": ["t"], "tiersWithoutKey": [],
                }),
                vectors=vectors,
            )
            self.assertEqual(completed.returncode, 75)
            self.assertEqual(completed.stdout, "")

    def test_empty_or_missing_projection_is_unproved(self):
        with tempfile.TemporaryDirectory() as d:
            vectors = cand.host_vectors_path(_mounts(Path(d)))
            for raw in ("{}", json.dumps({"vectors": []})):
                completed = cand.normalize_inner_event(
                    returncode=0, stdout=raw, vectors=vectors)
                self.assertEqual(completed.returncode, 75)

    def test_rc2_passthrough_is_unexpected_exit_then_killed(self):
        leaked = subprocess.CompletedProcess(["x"], 2, json.dumps(RICH_REPORT), "")
        self.assertEqual(_classify(leaked), "unexpected-exit")
        with tempfile.TemporaryDirectory() as d:
            vectors = cand.host_vectors_path(_mounts(Path(d)))
            normalized = cand.normalize_inner_event(
                returncode=2, stdout=json.dumps(RICH_REPORT), vectors=vectors)
        self.assertEqual(normalized.returncode, 75)
        self.assertEqual(_classify(normalized), "unproved")

    def test_stdout_prefix_is_unproved_without_inner_parse(self):
        with tempfile.TemporaryDirectory() as d:
            vectors = cand.host_vectors_path(_mounts(Path(d)))
            completed = cand.normalize_inner_event(
                returncode=0, stdout="noise\n" + json.dumps(RICH_REPORT),
                vectors=vectors)
        self.assertEqual(completed.returncode, 75)

    def test_copy_mutation_local_four_key_extractor_turns_red(self):
        src = Path(cand.__file__).read_text()
        needle = "projected = sealed_adapter.project(inner, expected)"
        self.assertIn(needle, src)
        mutated = src.replace(
            needle,
            "projected = {key: inner.get(key) for key in ("
            "'verdict', 'result', 'tiersWithPinnedKey', 'tiersWithoutKey')}",
        )
        self.assertNotEqual(src, mutated)
        with tempfile.TemporaryDirectory() as d:
            mounts = _mounts(Path(d))
            module = _load_mutated(mutated, Path(d))
            completed = module.normalize_inner_event(
                returncode=0, stdout=json.dumps(RICH_REPORT),
                vectors=cand.host_vectors_path(mounts))
        outer = json.loads(completed.stdout)
        self.assertNotIn("rows", outer)

    def test_copy_mutation_drops_rc1_acceptance(self):
        src = Path(cand.__file__).read_text()
        mutated = src.replace("COMPLETE_RETURNCODES = (0, 1)", "COMPLETE_RETURNCODES = (0,)")
        self.assertNotEqual(src, mutated)
        with tempfile.TemporaryDirectory() as d:
            module = _load_mutated(mutated, Path(d))
            completed = module.normalize_inner_event(
                returncode=1, stdout=json.dumps(RICH_REPORT),
                vectors=cand.host_vectors_path(_mounts(Path(d))))
        self.assertEqual(completed.returncode, 75)


class SealedLifecycle(unittest.TestCase):
    def test_absence_proof_runs_on_success_and_error(self):
        with tempfile.TemporaryDirectory() as d:
            mounts = _mounts(Path(d))
            dests = ("/input", "/vendor", "/tool", "/subject")
            transport = FakeTransport(
                stdout=json.dumps(RICH_REPORT), inspect=_inspect(dests))
            cand._run_sealed_candidate(
                image_id=IMAGE, mounts=mounts, transport=transport,
                resource_profile=INERT_RESOURCE_PROFILE)
            self.assertEqual(len(transport.removed), 1)
            broken = FakeTransport(returncode=2, stdout="fail", inspect=_inspect(dests))
            cand._run_sealed_candidate(
                image_id=IMAGE, mounts=mounts, transport=broken,
                resource_profile=INERT_RESOURCE_PROFILE)
            self.assertEqual(len(broken.absent_checked), 1)

    def test_partial_create_still_removes_then_proves_absent(self):
        with tempfile.TemporaryDirectory() as d:
            transport = FakeTransport(fail_create=True)
            with self.assertRaises(PrepareError) as ctx:
                cand._run_sealed_candidate(
                    image_id=IMAGE, mounts=_mounts(Path(d)), transport=transport,
                    resource_profile=INERT_RESOURCE_PROFILE)
            self.assertEqual(str(ctx.exception), "partial create")
            self.assertEqual(len(transport.removed), 1)
            present = FakeTransport(fail_create=True, leave_present=True)
            with self.assertRaises(PrepareError) as ctx:
                cand._run_sealed_candidate(
                    image_id=IMAGE, mounts=_mounts(Path(d)), transport=present,
                    resource_profile=INERT_RESOURCE_PROFILE)
            self.assertIn("still present", str(ctx.exception))

    def test_absence_proof_skipped_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            transport = FakeTransport(
                stdout=json.dumps(RICH_REPORT),
                inspect=_inspect(("/input", "/vendor", "/tool", "/subject")),
                skip_absent=True,
            )
            with self.assertRaises(PrepareError):
                cand._run_sealed_candidate(
                    image_id=IMAGE, mounts=_mounts(Path(d)), transport=transport,
                    resource_profile=INERT_RESOURCE_PROFILE)

    def test_noop_control_stays_green(self):
        with tempfile.TemporaryDirectory() as d:
            mounts = _mounts(Path(d))
            completed = cand._run_sealed_candidate(
                image_id=IMAGE, mounts=mounts,
                resource_profile=INERT_RESOURCE_PROFILE,
                transport=FakeTransport(
                    stdout=json.dumps(RICH_REPORT),
                    inspect=_inspect(("/input", "/vendor", "/tool", "/subject")),
                ))
        self.assertEqual(_classify(completed), "ok")


if __name__ == "__main__":
    unittest.main()
