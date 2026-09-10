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
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "measurements"))
sys.path.insert(0, str(REPO_ROOT / "adapters"))

import aee_checker_sealed as sealed_adapter  # noqa: E402
import aee_checker_sealed_candidate as cand  # noqa: E402
import aee_checker_sealed_common as common  # noqa: E402
import bounded_run as br  # noqa: E402
import contained_oci as contained  # noqa: E402
import aee_checker_sealed_materialize as mat  # noqa: E402
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


def _inspect(dests, *, exit_code=0):
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
        "State": {
            "Error": "",
            "ExitCode": exit_code,
            "Running": False,
            "Status": "exited",
        },
    }


class FakeTransport:
    def __init__(
            self, *, returncode=0, stdout="", inspect=None,
            timeout=False, output_too_large=False,
            skip_absent=False,
            leave_present=False, fail_create=False, create_error=None,
            remove_error=None, absent_error=None):
        self.returncode = returncode
        self.stdout = stdout
        self.inspect_doc = inspect
        self.timeout = timeout
        self.output_too_large = output_too_large
        self.skip_absent = skip_absent
        self.leave_present = leave_present
        self.fail_create = fail_create
        self.create_error = create_error
        self.remove_error = remove_error
        self.absent_error = absent_error
        self.created = []
        self.removed = []
        self.absent_checked = []
        self.started = []

    def create(self, argv):
        self.created.append(list(argv))
        if self.create_error is not None:
            raise self.create_error
        if self.fail_create:
            raise PrepareError("partial create")

    def start(self, name, deadline_seconds=None):
        self.started.append(name)
        self.deadline_seconds = deadline_seconds
        if self.timeout:
            raise subprocess.TimeoutExpired(["docker", "start", "-a", name], 1)
        if self.output_too_large:
            raise br._OutputTooLarge()
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
        if self.remove_error is not None:
            raise self.remove_error

    def require_absent(self, name):
        self.absent_checked.append(name)
        if self.absent_error is not None:
            raise self.absent_error
        if self.leave_present:
            raise PrepareError("container still present: %s" % name)


def _load_mutated(text: str, tmp: Path):
    path = tmp / "mut_candidate.py"
    path.write_text(text)
    spec = importlib.util.spec_from_file_location("mut_candidate", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_contained_mutation(text: str, tmp: Path):
    path = tmp / "mut_contained_oci.py"
    path.write_text(text)
    spec = importlib.util.spec_from_file_location("mut_contained_oci", path)
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
    def test_old_host_checker_or_build_contract_is_refused(self):
        old = {
            "build": ["cargo", "build", "--locked", "--release"],
            "entrypoint_command": [
                "python3", "aee_checker_sealed.py", "--checker",
                "./target/release/aee-checker", "corpus/vectors",
            ],
        }
        with self.assertRaisesRegex(PrepareError, "execution contract"):
            cand.candidate_script(old)
        with self.assertRaisesRegex(PrepareError, "execution contract"):
            cand.candidate_create_argv(
                image_id=IMAGE, name="cand", mounts={}, execution_contract={})

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
            report.write_text(json.dumps(RICH_REPORT) + "\n", encoding="utf-8")
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
                    returncode=rc, stdout=json.dumps(RICH_REPORT) + "\n", vectors=vectors)
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
            for raw in ("{}\n", json.dumps({"vectors": []}) + "\n"):
                completed = cand.normalize_inner_event(
                    returncode=0, stdout=raw, vectors=vectors)
                self.assertEqual(completed.returncode, 75)

    def test_rc2_passthrough_is_unexpected_exit_then_killed(self):
        leaked = subprocess.CompletedProcess(["x"], 2, json.dumps(RICH_REPORT), "")
        self.assertEqual(_classify(leaked), "unexpected-exit")
        with tempfile.TemporaryDirectory() as d:
            vectors = cand.host_vectors_path(_mounts(Path(d)))
            normalized = cand.normalize_inner_event(
                returncode=2, stdout=json.dumps(RICH_REPORT) + "\n", vectors=vectors)
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
                returncode=0, stdout=json.dumps(RICH_REPORT) + "\n",
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
                returncode=1, stdout=json.dumps(RICH_REPORT) + "\n",
                vectors=cand.host_vectors_path(_mounts(Path(d))))
        self.assertEqual(completed.returncode, 75)


class SealedLifecycle(unittest.TestCase):
    def test_public_entrypoint_forces_sealed_mode(self):
        prepare = {
            "toolchain": {"image_id": IMAGE},
            "image": {"id": "sha256:" + ("cd" * 32)},
            "candidate_profile": INERT_RESOURCE_PROFILE,
        }
        completed = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch.object(
                    cand, "load_prepare_for_profile", return_value=prepare) as admit, \
                mock.patch.object(
                    cand, "_run_sealed_candidate", return_value=completed) as inner:
            actual = cand.run_sealed_candidate(
                prepare_raw=b"prepare", mounts={"input": Path("input")},
                execution_profile="contained-oci-v0")

        self.assertIs(actual, completed)
        self.assertIs(inner.call_args.kwargs["sealed"], True)
        admit.assert_called_once_with(b"prepare", execution_profile="contained-oci-v0")
        self.assertEqual(inner.call_args.kwargs["execution_profile"], "contained-oci-v0")

    def test_absence_proof_runs_on_success_and_error(self):
        with tempfile.TemporaryDirectory() as d:
            mounts = _mounts(Path(d))
            dests = ("/input", "/vendor", "/tool", "/subject")
            transport = FakeTransport(
                stdout=json.dumps(RICH_REPORT) + "\n", inspect=_inspect(dests))
            cand._run_sealed_candidate(
                image_id=IMAGE, mounts=mounts, transport=transport,
                resource_profile=INERT_RESOURCE_PROFILE)
            self.assertEqual(len(transport.removed), 1)
            broken = FakeTransport(
                returncode=2, stdout="fail", inspect=_inspect(dests, exit_code=2))
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
            self.assertEqual(str(ctx.exception), "partial create")
            failures = getattr(ctx.exception, "cleanup_failures", ())
            self.assertEqual(
                str(failures[0][1]),
                "container still present: %s" % present.removed[0])

    def test_remove_failure_without_primary_is_chained_and_absence_still_runs(self):
        with tempfile.TemporaryDirectory() as d:
            underlying = OSError("remove refused")
            transport = FakeTransport(
                stdout=json.dumps(RICH_REPORT) + "\n",
                inspect=_inspect(("/input", "/vendor", "/tool", "/subject")),
                remove_error=underlying,
            )
            with self.assertRaises(PrepareError) as ctx:
                cand._run_sealed_candidate(
                    image_id=IMAGE, mounts=_mounts(Path(d)), transport=transport,
                    resource_profile=INERT_RESOURCE_PROFILE)
        self.assertRegex(str(ctx.exception), r"remove|cleanup")
        self.assertIs(ctx.exception.__cause__, underlying)
        self.assertEqual(len(transport.absent_checked), 1)

    def test_absence_failure_without_primary_is_chained(self):
        with tempfile.TemporaryDirectory() as d:
            underlying = OSError("absence unavailable")
            transport = FakeTransport(
                stdout=json.dumps(RICH_REPORT) + "\n",
                inspect=_inspect(("/input", "/vendor", "/tool", "/subject")),
                absent_error=underlying,
            )
            with self.assertRaises(PrepareError) as ctx:
                cand._run_sealed_candidate(
                    image_id=IMAGE, mounts=_mounts(Path(d)), transport=transport,
                    resource_profile=INERT_RESOURCE_PROFILE)
        self.assertRegex(str(ctx.exception), r"absence")
        self.assertIs(ctx.exception.__cause__, underlying)

    def test_cleanup_failures_do_not_replace_prepare_primary(self):
        with tempfile.TemporaryDirectory() as d:
            primary = PrepareError("primary create refusal")
            transport = FakeTransport(
                create_error=primary,
                remove_error=OSError("remove refused"),
                absent_error=PrepareError("absence refused"),
            )
            with self.assertRaises(PrepareError) as ctx:
                cand._run_sealed_candidate(
                    image_id=IMAGE, mounts=_mounts(Path(d)), transport=transport,
                    resource_profile=INERT_RESOURCE_PROFILE)
        self.assertIs(ctx.exception, primary)
        self.assertEqual(len(transport.absent_checked), 1)
        failures = getattr(primary, "cleanup_failures", ())
        self.assertEqual([action for action, _failure in failures], [
            "candidate remove", "candidate absence proof"])
        self.assertEqual([str(failure) for _action, failure in failures], [
            "remove refused", "absence refused"])

    def test_cleanup_failures_do_not_replace_baseexception_in_flight(self):
        class FlightSignal(BaseException):
            pass

        with tempfile.TemporaryDirectory() as d:
            primary = FlightSignal("stop now")
            transport = FakeTransport(
                create_error=primary,
                remove_error=OSError("remove refused"),
                absent_error=PrepareError("absence refused"),
            )
            with self.assertRaises(FlightSignal) as ctx:
                cand._run_sealed_candidate(
                    image_id=IMAGE, mounts=_mounts(Path(d)), transport=transport,
                    resource_profile=INERT_RESOURCE_PROFILE)
        self.assertIs(ctx.exception, primary)
        self.assertEqual(len(transport.absent_checked), 1)
        failures = getattr(primary, "cleanup_failures", ())
        self.assertEqual([str(failure) for _action, failure in failures], [
            "remove refused", "absence refused"])

    def test_shared_cleanup_context_is_legacy_safe_without_add_note(self):
        class LegacyPrimary(PrepareError):
            add_note = None

        with tempfile.TemporaryDirectory() as d:
            primary = LegacyPrimary("legacy primary")
            remove_error = OSError("legacy remove")
            transport = FakeTransport(
                create_error=primary,
                remove_error=remove_error,
                absent_error=PrepareError("legacy absence"),
            )
            try:
                cand._run_sealed_candidate(
                    image_id=IMAGE, mounts=_mounts(Path(d)), transport=transport,
                    resource_profile=INERT_RESOURCE_PROFILE)
            except BaseException as actual:
                self.assertIs(actual, primary)
            else:
                self.fail("legacy primary did not propagate")
        self.assertIs(
            getattr(cand, "preserve_cleanup_failure", None),
            getattr(common, "preserve_cleanup_failure", None))
        self.assertIs(
            getattr(mat, "preserve_cleanup_failure", None),
            getattr(common, "preserve_cleanup_failure", None))
        failures = getattr(primary, "cleanup_failures", ())
        self.assertIs(failures[0][1], remove_error)
        self.assertEqual(str(failures[1][1]), "legacy absence")
        frames = []
        traceback = primary.__traceback__
        while traceback is not None:
            frames.append(traceback.tb_frame.f_code.co_name)
            traceback = traceback.tb_next
        self.assertEqual(frames.count("_run_sealed_candidate"), 1)

    def test_cleanup_context_survives_a_broken_optional_note_hook(self):
        class NoteHookFailure(BaseException):
            pass

        class BrokenNoteHook(BaseException):
            def add_note(self, _note):
                raise NoteHookFailure("note hook failed")

        primary = BrokenNoteHook("primary")
        cleanup = OSError("cleanup refused")
        common.preserve_cleanup_failure(primary, "candidate cleanup", cleanup)

        failures = getattr(primary, "cleanup_failures", ())
        self.assertEqual(failures, (("candidate cleanup", cleanup),))

    def test_absence_proof_skipped_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            transport = FakeTransport(
                stdout=json.dumps(RICH_REPORT) + "\n",
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
                    stdout=json.dumps(RICH_REPORT) + "\n",
                    inspect=_inspect(("/input", "/vendor", "/tool", "/subject")),
                ))
        self.assertEqual(_classify(completed), "ok")



class ClosedInnerProtocol(unittest.TestCase):
    """#81: exactly one final LF; retain a closed unproved reason. No live checker."""

    def _vectors(self, tmp):
        return cand.host_vectors_path(_mounts(tmp))

    def test_zero_final_lf_is_malformed(self):
        with tempfile.TemporaryDirectory() as d:
            completed = cand.normalize_inner_event(
                returncode=0, stdout=json.dumps(RICH_REPORT),
                vectors=self._vectors(Path(d)))
        self.assertEqual(completed.returncode, 75)
        self.assertEqual(getattr(completed, "unproved_reason", None), "malformed")

    def test_one_final_lf_on_compact_json_projects(self):
        with tempfile.TemporaryDirectory() as d:
            completed = cand.normalize_inner_event(
                returncode=0, stdout=json.dumps(RICH_REPORT) + "\n",
                vectors=self._vectors(Path(d)))
        self.assertEqual(completed.returncode, 0)
        self.assertIn("rows", json.loads(completed.stdout))

    def test_pretty_json_with_one_final_lf_projects(self):
        pretty = common.encode_json(RICH_REPORT).decode("utf-8")
        self.assertTrue(pretty.endswith("\n"))
        self.assertIn("\n", pretty[:-1])
        self.assertFalse(pretty.endswith("\n\n"))
        with tempfile.TemporaryDirectory() as d:
            completed = cand.normalize_inner_event(
                returncode=0, stdout=pretty, vectors=self._vectors(Path(d)))
        self.assertEqual(completed.returncode, 0)
        self.assertIn("rows", json.loads(completed.stdout))

    def test_internal_cr_crlf_and_bare_trailing_cr_are_malformed(self):
        compact = json.dumps(RICH_REPORT)
        cases = (
            compact.replace(": ", ":\r "),
            "{\r\n\"vectors\": []\n}",
            compact + "\r",
            compact + "\r\n",
        )
        with tempfile.TemporaryDirectory() as d:
            vectors = self._vectors(Path(d))
            for raw in cases:
                self.assertIn("\r", raw)
                completed = cand.normalize_inner_event(
                    returncode=0, stdout=raw, vectors=vectors)
                self.assertEqual(completed.returncode, 75, raw)
                self.assertEqual(
                    getattr(completed, "unproved_reason", None), "malformed", raw)

    def test_oversized_protocol_stdout_is_output_cap(self):
        import bounded_run as br
        body = "{" + ("a" * br.OUTPUT_CAP_BYTES) + "}\n"
        self.assertGreater(len(body.encode("utf-8")), br.OUTPUT_CAP_BYTES)
        with tempfile.TemporaryDirectory() as d:
            completed = cand.normalize_inner_event(
                returncode=0, stdout=body, vectors=self._vectors(Path(d)))
        self.assertEqual(completed.returncode, 75)
        self.assertEqual(getattr(completed, "unproved_reason", None), "output-cap")

    def test_project_manifest_error_is_closed_projection(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(
                    cand.sealed_adapter, "project",
                    side_effect=ca.ManifestError("/host/secret")):
                completed = cand.normalize_inner_event(
                    returncode=0, stdout=json.dumps(RICH_REPORT) + "\n",
                    vectors=self._vectors(Path(d)))
        self.assertEqual(completed.returncode, 75)
        self.assertEqual(getattr(completed, "unproved_reason", None), "projection")
        self.assertEqual(completed.stdout, "")
        self.assertEqual(completed.stderr, "")

    def test_human_prefix_stays_unproved_as_malformed(self):
        with tempfile.TemporaryDirectory() as d:
            completed = cand.normalize_inner_event(
                returncode=0, stdout="noise\n" + json.dumps(RICH_REPORT),
                vectors=self._vectors(Path(d)))
        self.assertEqual(completed.returncode, 75)
        self.assertEqual(getattr(completed, "unproved_reason", None), "malformed")

    def test_leading_space_with_one_final_lf_is_malformed(self):
        with tempfile.TemporaryDirectory() as d:
            completed = cand.normalize_inner_event(
                returncode=0,
                stdout=" " + json.dumps(RICH_REPORT) + "\n",
                vectors=self._vectors(Path(d)))
        self.assertEqual(completed.returncode, 75)
        self.assertEqual(getattr(completed, "unproved_reason", None), "malformed")

    def test_human_prefix_with_one_final_lf_is_malformed(self):
        with tempfile.TemporaryDirectory() as d:
            completed = cand.normalize_inner_event(
                returncode=0,
                stdout="noise\n" + json.dumps(RICH_REPORT) + "\n",
                vectors=self._vectors(Path(d)))
        self.assertEqual(completed.returncode, 75)
        self.assertEqual(getattr(completed, "unproved_reason", None), "malformed")

    def test_space_or_tab_before_final_lf_is_malformed(self):
        compact = json.dumps(RICH_REPORT)
        with tempfile.TemporaryDirectory() as d:
            vectors = self._vectors(Path(d))
            for raw in (compact + " \n", compact + "\t\n"):
                completed = cand.normalize_inner_event(
                    returncode=0, stdout=raw, vectors=vectors)
                self.assertEqual(completed.returncode, 75, raw)
                self.assertEqual(
                    getattr(completed, "unproved_reason", None), "malformed", raw)

    def test_human_suffix_before_final_lf_is_malformed(self):
        with tempfile.TemporaryDirectory() as d:
            completed = cand.normalize_inner_event(
                returncode=0,
                stdout=json.dumps(RICH_REPORT) + " note\n",
                vectors=self._vectors(Path(d)))
        self.assertEqual(completed.returncode, 75)
        self.assertEqual(getattr(completed, "unproved_reason", None), "malformed")

    def _two_line_guard(self, src, prefix):
        start = src.find(prefix)
        self.assertNotEqual(start, -1, prefix)
        first_nl = src.find("\n", start)
        second_nl = src.find("\n", first_nl + 1)
        return src[start:second_nl + 1]

    def test_mutation_dropping_leading_object_guard_accepts_leading_space(self):
        src = Path(cand.__file__).read_text()
        guard = self._two_line_guard(src, '    if body == "" or body[0] != "{":')
        mutated = src.replace(guard, "")
        self.assertNotEqual(src, mutated)
        with tempfile.TemporaryDirectory() as d:
            module = _load_mutated(mutated, Path(d))
            completed = module.normalize_inner_event(
                returncode=0,
                stdout=" " + json.dumps(RICH_REPORT) + "\n",
                vectors=module.host_vectors_path(_mounts(Path(d))))
        self.assertEqual(completed.returncode, 0)

    def test_mutation_dropping_trailing_body_guard_accepts_space_before_lf(self):
        src = Path(cand.__file__).read_text()
        guard = self._two_line_guard(src, "    if body.endswith((")
        mutated = src.replace(guard, "")
        self.assertNotEqual(src, mutated)
        with tempfile.TemporaryDirectory() as d:
            module = _load_mutated(mutated, Path(d))
            completed = module.normalize_inner_event(
                returncode=0,
                stdout=json.dumps(RICH_REPORT) + " \n",
                vectors=module.host_vectors_path(_mounts(Path(d))))
        self.assertEqual(completed.returncode, 0)

    def test_bare_cr_in_otherwise_valid_object_is_malformed(self):
        compact = json.dumps(RICH_REPORT)
        raw = "{" + "\r" + compact[1:] + "\n"
        self.assertTrue(raw.startswith("{"))
        self.assertTrue(raw.endswith("\n"))
        self.assertFalse(raw.endswith("\n\n"))
        self.assertIn("\r", raw)
        with tempfile.TemporaryDirectory() as d:
            completed = cand.normalize_inner_event(
                returncode=0, stdout=raw, vectors=self._vectors(Path(d)))
        self.assertEqual(completed.returncode, 75)
        self.assertEqual(getattr(completed, "unproved_reason", None), "malformed")

    def test_mutation_dropping_cr_guard_accepts_bare_cr_in_body(self):
        src = Path(cand.__file__).read_text()
        guard = self._two_line_guard(src, "    if \"" + chr(92) + "r\" in stdout:")
        mutated = src.replace(guard, "")
        self.assertNotEqual(src, mutated)
        compact = json.dumps(RICH_REPORT)
        raw = "{" + "\r" + compact[1:] + "\n"
        with tempfile.TemporaryDirectory() as d:
            module = _load_mutated(mutated, Path(d))
            completed = module.normalize_inner_event(
                returncode=0, stdout=raw,
                vectors=module.host_vectors_path(_mounts(Path(d))))
        self.assertEqual(completed.returncode, 0)

    def test_transport_output_too_large_is_output_cap(self):
        dests = ("/input", "/vendor", "/tool", "/subject")
        with tempfile.TemporaryDirectory() as d:
            completed = cand._run_sealed_candidate(
                image_id=IMAGE, mounts=_mounts(Path(d)),
                resource_profile=INERT_RESOURCE_PROFILE,
                transport=FakeTransport(
                    output_too_large=True, inspect=_inspect(dests)))
        self.assertEqual(completed.returncode, 75)
        self.assertEqual(getattr(completed, "unproved_reason", None), "output-cap")

    def test_mutation_dropping_output_too_large_arm_raises(self):
        src = Path(contained.__file__).read_text()
        guard = self._two_line_guard(src, "        except br._OutputTooLarge:")
        mutated = src.replace(guard, "")
        self.assertNotEqual(src, mutated)
        dests = ("/input", "/vendor", "/tool", "/subject")
        with tempfile.TemporaryDirectory() as d:
            module = _load_contained_mutation(mutated, Path(d))
            with mock.patch.object(cand, "contained", module):
                with self.assertRaises(br._OutputTooLarge):
                    cand._run_sealed_candidate(
                        image_id=IMAGE, mounts=_mounts(Path(d)),
                        resource_profile=INERT_RESOURCE_PROFILE,
                        transport=FakeTransport(
                            output_too_large=True, inspect=_inspect(dests)))

    def test_crlf_and_extra_trailing_space_are_malformed(self):
        with tempfile.TemporaryDirectory() as d:
            vectors = self._vectors(Path(d))
            for raw in (
                    json.dumps(RICH_REPORT) + "\r\n",
                    json.dumps(RICH_REPORT) + "\n\n",
                    " " + json.dumps(RICH_REPORT),
                    json.dumps(RICH_REPORT) + " "):
                completed = cand.normalize_inner_event(
                    returncode=0, stdout=raw, vectors=vectors)
                self.assertEqual(completed.returncode, 75, raw)
                self.assertEqual(
                    getattr(completed, "unproved_reason", None), "malformed", raw)

    def test_empty_stdout_is_empty_or_missing(self):
        with tempfile.TemporaryDirectory() as d:
            completed = cand.normalize_inner_event(
                returncode=0, stdout="", vectors=self._vectors(Path(d)))
        self.assertEqual(completed.returncode, 75)
        self.assertEqual(
            getattr(completed, "unproved_reason", None), "empty-or-missing")

    def test_inner_rc2_is_inner_exit(self):
        with tempfile.TemporaryDirectory() as d:
            completed = cand.normalize_inner_event(
                returncode=2, stdout=json.dumps(RICH_REPORT),
                vectors=self._vectors(Path(d)))
        self.assertEqual(completed.returncode, 75)
        self.assertEqual(getattr(completed, "unproved_reason", None), "inner-exit")
        self.assertEqual(_classify(completed), "unproved")

    def test_unprojectable_document_is_projection(self):
        with tempfile.TemporaryDirectory() as d:
            completed = cand.normalize_inner_event(
                returncode=0, stdout="{}\n", vectors=self._vectors(Path(d)))
        self.assertEqual(completed.returncode, 75)
        self.assertEqual(getattr(completed, "unproved_reason", None), "projection")

    def test_truncated_object_is_malformed_not_projection(self):
        with tempfile.TemporaryDirectory() as d:
            completed = cand.normalize_inner_event(
                returncode=0, stdout="{", vectors=self._vectors(Path(d)))
        self.assertEqual(completed.returncode, 75)
        self.assertEqual(getattr(completed, "unproved_reason", None), "malformed")

    def test_trailing_extra_json_is_malformed_not_projection(self):
        extras = (
            json.dumps(RICH_REPORT) + "{}\n",
            json.dumps(RICH_REPORT) + "\n{}\n",
            "{}{}\n",
            "{ }{}\n",
        )
        with tempfile.TemporaryDirectory() as d:
            vectors = self._vectors(Path(d))
            for raw in extras:
                completed = cand.normalize_inner_event(
                    returncode=0, stdout=raw, vectors=vectors)
                self.assertEqual(completed.returncode, 75, raw)
                self.assertEqual(
                    getattr(completed, "unproved_reason", None), "malformed", raw)

    def test_duplicate_key_and_nonfinite_are_malformed(self):
        with tempfile.TemporaryDirectory() as d:
            vectors = self._vectors(Path(d))
            for raw in ('{"vectors":[],"vectors":[]}\n', '{"n":1e999}\n'):
                completed = cand.normalize_inner_event(
                    returncode=0, stdout=raw, vectors=vectors)
                self.assertEqual(completed.returncode, 75, raw)
                self.assertEqual(
                    getattr(completed, "unproved_reason", None), "malformed", raw)

    def test_mutation_collapsing_parse_into_projection_turns_red(self):
        src = Path(cand.__file__).read_text()
        collapsed = src.replace(
            """    try:
        inner = load_strict(body.encode("utf-8"))
    except (PrepareError, json.JSONDecodeError, TypeError, ValueError):
        return _unproved("malformed")
    if type(inner) is not dict:
        return _unproved("malformed")
    try:
        expected = sealed_adapter.expected_ids(vectors)
        projected = sealed_adapter.project(inner, expected)
    except (PrepareError, ca.ManifestError, KeyError, TypeError, ValueError, OSError):
        return _unproved("projection")
""",
            """    try:
        inner = load_strict(body.encode("utf-8"))
        expected = sealed_adapter.expected_ids(vectors)
        projected = sealed_adapter.project(inner, expected)
    except (PrepareError, ca.ManifestError, KeyError, TypeError, ValueError, OSError):
        return _unproved("projection")
    if type(inner) is not dict:
        return _unproved("malformed")
""")
        self.assertNotEqual(src, collapsed)
        with tempfile.TemporaryDirectory() as d:
            module = _load_mutated(collapsed, Path(d))
            completed = module.normalize_inner_event(
                returncode=0, stdout="{\n",
                vectors=module.host_vectors_path(_mounts(Path(d))))
        self.assertEqual(completed.returncode, 75)
        self.assertEqual(getattr(completed, "unproved_reason", None), "projection")

    def test_timeout_transport_retains_timeout(self):
        dests = ("/input", "/vendor", "/tool", "/subject")
        with tempfile.TemporaryDirectory() as d:
            completed = cand._run_sealed_candidate(
                image_id=IMAGE, mounts=_mounts(Path(d)),
                resource_profile=INERT_RESOURCE_PROFILE,
                transport=FakeTransport(timeout=True, inspect=_inspect(dests)))
        self.assertEqual(completed.returncode, 75)
        self.assertEqual(getattr(completed, "unproved_reason", None), "timeout")
        self.assertEqual(completed.stdout, "")
        self.assertEqual(completed.stderr, "")

    def test_output_cap_transport_retains_output_cap(self):
        dests = ("/input", "/vendor", "/tool", "/subject")
        with tempfile.TemporaryDirectory() as d:
            completed = cand._run_sealed_candidate(
                image_id=IMAGE, mounts=_mounts(Path(d)),
                resource_profile=INERT_RESOURCE_PROFILE,
                transport=FakeTransport(
                    output_too_large=True,
                    inspect=_inspect(dests),
                ))
        self.assertEqual(completed.returncode, 75)
        self.assertEqual(getattr(completed, "unproved_reason", None), "output-cap")

    def test_mutation_reinstating_strip_rejects_final_lf(self):
        orig = cand.inner_protocol_stdout

        def stripped(stdout):
            if type(stdout) is str and stdout != stdout.strip():
                return None
            return orig(stdout)

        with mock.patch.object(cand, "inner_protocol_stdout", stripped):
            with tempfile.TemporaryDirectory() as d:
                completed = cand.normalize_inner_event(
                    returncode=0, stdout=json.dumps(RICH_REPORT) + "\n",
                    vectors=self._vectors(Path(d)))
        self.assertEqual(completed.returncode, 75)

    def test_mutation_dropping_reason_collapses_timeout(self):
        orig = cand._unproved

        def mute(reason="malformed"):
            completed = orig(reason)
            if hasattr(completed, "unproved_reason"):
                del completed.unproved_reason
            return completed

        dests = ("/input", "/vendor", "/tool", "/subject")
        with mock.patch.object(cand, "_unproved", mute):
            with tempfile.TemporaryDirectory() as d:
                completed = cand._run_sealed_candidate(
                    image_id=IMAGE, mounts=_mounts(Path(d)),
                    resource_profile=INERT_RESOURCE_PROFILE,
                    transport=FakeTransport(timeout=True, inspect=_inspect(dests)))
        self.assertEqual(completed.returncode, 75)
        self.assertIsNone(getattr(completed, "unproved_reason", None))

    def test_noop_loaded_copy_keeps_one_lf_and_timeout(self):
        src = Path(cand.__file__).read_text()
        dests = ("/input", "/vendor", "/tool", "/subject")
        with tempfile.TemporaryDirectory() as d:
            module = _load_mutated(src, Path(d))
            pretty = common.encode_json(RICH_REPORT).decode("utf-8")
            completed = module.normalize_inner_event(
                returncode=0, stdout=pretty,
                vectors=module.host_vectors_path(_mounts(Path(d))))
            timed = module._run_sealed_candidate(
                image_id=IMAGE, mounts=_mounts(Path(d)),
                resource_profile=INERT_RESOURCE_PROFILE,
                transport=FakeTransport(timeout=True, inspect=_inspect(dests)))
        self.assertIsNot(module, cand)
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(getattr(timed, "unproved_reason", None), "timeout")


# --- #102 A2: candidate admission keyed by the resolved execution profile ----------------------

V0_PROFILE = "contained-oci-v0"
V1_PROFILE = "contained-oci-v1"
TOOLCHAIN_IMAGE = "sha256:" + ("cd" * 32)
A2_BINDING = {"execution_commit": "f" * 40, "prepare_sha256": "e" * 64}
A2_IMAGE_ENV = ("CARGO_HOME", "PATH")
A2_DAEMON = {
    "KernelVersion": "synthetic-kernel", "CgroupVersion": "2",
    "CgroupDriver": "systemd", "SecurityOptions": ["name=seccomp"],
}
# The frozen v2 policy (one CPU, 1024:1024) written as literals, not derived from the codec.
FROZEN_V2_FLAGS = [
    "--cpu-period", "100000", "--cpu-quota", "100000", "--ulimit", "nofile=1024:1024",
]
V2_FLAG_NAMES = ("--cpu-period", "--cpu-quota", "--ulimit", "--cpus")


def _prepare_raw(profile) -> bytes:
    """Canonical PREPARE bytes pinning `profile`, emitted by the real codec for its version."""
    import aee_checker_sealed_run as run
    from tests.test_aee_checker_sealed_run import PrepareEvidence
    parts = PrepareEvidence._parts(None)
    parts["candidate_profile"] = dict(profile)
    parts["image"] = {**parts["image"], "id_scope": "host-local", "platform": "linux/arm64"}
    emit = (run.emit_prepare_v2
            if profile["schema"] == contained.RESOURCE_PROFILE_V2_SCHEMA
            else run.emit_prepare_v1)
    with tempfile.TemporaryDirectory() as d:
        return emit(parts, Path(d) / "prepare.json")


def _observed_inspect(profile, *, image=TOOLCHAIN_IMAGE) -> dict:
    """What a daemon that honoured `profile` stores. Tests then take pieces away."""
    work = "rw,size=%d,nr_inodes=%d,mode=1777" % (
        profile["work_bytes"], profile["work_inodes"])
    if profile["work_exec"]:
        work += ",exec"
    host = {
        "CapAdd": None, "CapDrop": ["ALL"], "Devices": None,
        "Memory": profile["memory_bytes"], "MemorySwap": profile["memory_swap_bytes"],
        "NetworkMode": "none", "PidMode": "", "PidsLimit": profile["pids"],
        "Privileged": False, "ReadonlyRootfs": True,
        "SecurityOpt": ["no-new-privileges:true"],
        "Tmpfs": {
            "/tmp": "rw,size=%d,nr_inodes=%d,mode=1777" % (
                profile["tmp_bytes"], profile["tmp_inodes"]),
            "/work": work,
        },
        "UsernsMode": "",
    }
    if "cpu_rate_millicpu" in profile:
        host["CpuPeriod"] = 100000
        host["CpuQuota"] = profile["cpu_rate_millicpu"] * 100
        host["Ulimits"] = [{
            "Name": "nofile", "Soft": profile["nofile_soft"], "Hard": profile["nofile_hard"]}]
    return {
        "Image": image,
        "Config": {
            "User": "65532:65532",
            "Env": ["PATH=/usr/local/cargo/bin", "CARGO_HOME=/tool", "CARGO_NET_OFFLINE=true"],
        },
        "HostConfig": host,
        "Mounts": [
            {"Type": "bind", "Destination": dest, "RW": False}
            for _key, dest in cand.CANDIDATE_MOUNT_SPEC
        ],
        "State": {"Error": "", "ExitCode": 0, "Running": False, "Status": "exited"},
    }


class ObservingTransport(FakeTransport):
    """A fake daemon that also answers the observations an envelope record reads."""

    def __init__(self, *, daemon=None, **kwargs):
        kwargs.setdefault("stdout", json.dumps(RICH_REPORT) + "\n")
        super().__init__(**kwargs)
        self.daemon = dict(A2_DAEMON) if daemon is None else daemon

    def inspect(self, name):
        return json.loads(json.dumps(self.inspect_doc))

    def version(self):
        return "27.1.1"

    def image_env_names(self, _image_id):
        return A2_IMAGE_ENV

    def daemon_info(self):
        return dict(self.daemon)


class NoEffectTransport:
    """Every attribute is a sentinel, so a refusal that arrives after admission surfaces here."""

    def __getattr__(self, name):
        raise AssertionError("transport.%s reached before the refusal" % name)


def _contains_run(argv, run_tokens) -> bool:
    return any(argv[i:i + len(run_tokens)] == run_tokens for i in range(len(argv)))


def _base_v1_argv(name: str, mounts: dict) -> list[str]:
    """The v1 candidate argv as the pre-A2 base (69fbc40) builds it, written out by hand."""
    argv = [
        "docker", "create", "--name", name, "--network", "none", "--read-only",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
        "--user", "65532:65532", "--memory", "4g", "--memory-swap", "4g",
        "--pids-limit", "512",
        "--tmpfs", "/tmp:rw,size=16777216,nr_inodes=2048,mode=1777",
        "--tmpfs", "/work:rw,size=268435456,nr_inodes=16384,mode=1777,exec",
        "--env", "CARGO_NET_OFFLINE=true",
    ]
    for key, dest in cand.CANDIDATE_MOUNT_SPEC:
        argv.extend([
            "--mount", "type=bind,source=%s,destination=%s,readonly" % (
                Path(mounts[key]).resolve(), dest)])
    return argv + [TOOLCHAIN_IMAGE, "/bin/sh", "-lc", cand.CANDIDATE_SCRIPT]


class ProfileDispatchedCandidateAdmission(unittest.TestCase):
    """The resolved execution profile, not the PREPARE schema, selects what is admitted."""

    def _admit(self, prepare_raw, profile, transport, **over):
        with tempfile.TemporaryDirectory() as d:
            mounts = _mounts(Path(d))
            completed = cand.run_sealed_candidate(
                prepare_raw=prepare_raw, mounts=mounts, execution_profile=profile,
                transport=transport, binding=over.pop("binding", A2_BINDING), **over)
        return completed, mounts

    def _v1_record(self, mutate=None, **transport_kwargs):
        doc = _observed_inspect(contained.CANDIDATE_RESOURCE_PROFILE_V2)
        if mutate is not None:
            mutate(doc)
        transport = ObservingTransport(inspect=doc, **transport_kwargs)
        completed, _mounts_used = self._admit(
            _prepare_raw(contained.CANDIDATE_RESOURCE_PROFILE_V2), V1_PROFILE, transport)
        return transport, completed.envelope_record

    def test_v2_prepare_under_v1_reaches_create_with_exactly_the_v2_flags(self):
        transport = ObservingTransport(
            inspect=_observed_inspect(contained.CANDIDATE_RESOURCE_PROFILE_V2))
        completed, _ = self._admit(
            _prepare_raw(contained.CANDIDATE_RESOURCE_PROFILE_V2), V1_PROFILE, transport)
        self.assertEqual(len(transport.created), 1)
        argv = transport.created[0]
        self.assertTrue(_contains_run(argv, FROZEN_V2_FLAGS), argv)
        for flag in ("--cpu-period", "--cpu-quota", "--ulimit"):
            self.assertEqual(argv.count(flag), 1, flag)
        self.assertNotIn("--cpus", argv)
        record = completed.envelope_record
        self.assertEqual(record["schema"], "corpus-adequacy.execution-envelope.v1")
        self.assertEqual(record["envelope_status"], "verified", record["unverified_field"])
        self.assertEqual(record["requested"]["execution_profile"], V1_PROFILE)
        self.assertEqual(record["requested"]["resource_profile"],
                         contained.CANDIDATE_RESOURCE_PROFILE_V2)
        self.assertEqual(record["candidate_outcome"], "completed")
        self.assertEqual(
            (record["effective"]["cpu_period"], record["effective"]["cpu_quota"],
             record["effective"]["ulimit_nofile"]),
            (100000, 100000, {"soft": 1024, "hard": 1024}))
        self.assertEqual(record["effective"]["daemon"]["kernel_version"], "synthetic-kernel")

    def test_v2_prepare_under_v0_refuses_before_create(self):
        with self.assertRaisesRegex(PrepareError, "prepare.v2 requires contained-oci-v1"):
            self._admit(_prepare_raw(contained.CANDIDATE_RESOURCE_PROFILE_V2),
                        V0_PROFILE, NoEffectTransport())

    def test_v1_prepare_under_v1_refuses_before_create(self):
        with self.assertRaisesRegex(
                PrepareError, "contained-oci-v1 admits only prepare.v2"):
            self._admit(_prepare_raw(contained.CANDIDATE_RESOURCE_PROFILE),
                        V1_PROFILE, NoEffectTransport())

    def test_every_other_profile_refuses_before_create(self):
        for raw in (_prepare_raw(contained.CANDIDATE_RESOURCE_PROFILE),
                    _prepare_raw(contained.CANDIDATE_RESOURCE_PROFILE_V2)):
            for profile in ("trusted-local", "contained-oci-v2", "", None,
                            ["contained-oci-v0"], b"contained-oci-v0"):
                with self.subTest(profile=profile), self.assertRaisesRegex(
                        PrepareError, "no PREPARE loader"):
                    self._admit(raw, profile, NoEffectTransport())

    def test_execution_profile_is_a_required_keyword_without_default(self):
        import inspect as inspect_mod
        parameter = inspect_mod.signature(cand.run_sealed_candidate).parameters.get(
            "execution_profile")
        self.assertIsNotNone(parameter)
        self.assertIs(parameter.kind, inspect_mod.Parameter.KEYWORD_ONLY)
        self.assertIs(parameter.default, inspect_mod.Parameter.empty)
        with self.assertRaises(TypeError):
            cand.run_sealed_candidate(
                prepare_raw=_prepare_raw(contained.CANDIDATE_RESOURCE_PROFILE),
                mounts={}, transport=NoEffectTransport())

    def test_a_recorded_run_below_admission_without_a_profile_refuses_before_create(self):
        """A record names the profile it ran under; there is no default to fill it in."""
        for profile in (None, "trusted-local"):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as d:
                with self.assertRaisesRegex(PrepareError, "^execution_profile$"):
                    cand._run_sealed_candidate(
                        image_id=TOOLCHAIN_IMAGE, mounts=_mounts(Path(d)),
                        resource_profile=contained.CANDIDATE_RESOURCE_PROFILE,
                        execution_profile=profile, transport=NoEffectTransport(),
                        binding=A2_BINDING)

    def test_base_v1_argv_literal_is_what_create_argv_builds(self):
        """Anchor: the hand-written base argv equals the argv builder for a v1 profile."""
        with tempfile.TemporaryDirectory() as d:
            mounts = _mounts(Path(d))
            argv = cand.candidate_create_argv(
                image_id=TOOLCHAIN_IMAGE, name="c", mounts=mounts,
                resource_profile=contained.CANDIDATE_RESOURCE_PROFILE)
            self.assertEqual(argv, _base_v1_argv("c", mounts))

    def test_v1_prepare_under_v0_argv_is_byte_identical_and_the_record_stays_v0(self):
        transport = ObservingTransport(
            inspect=_observed_inspect(contained.CANDIDATE_RESOURCE_PROFILE))
        with mock.patch.object(
                cand.envelope, "project_effective_envelope_v1",
                side_effect=AssertionError("v1 projector on the v0 route")):
            completed, mounts = self._admit(
                _prepare_raw(contained.CANDIDATE_RESOURCE_PROFILE), V0_PROFILE, transport)
        argv = transport.created[0]
        self.assertEqual(argv, _base_v1_argv(argv[3], mounts))
        for flag in V2_FLAG_NAMES:
            self.assertNotIn(flag, argv)
        record = completed.envelope_record
        self.assertEqual(record["schema"], "corpus-adequacy.execution-envelope.v0")
        self.assertEqual(record["envelope_status"], "verified", record["unverified_field"])
        self.assertEqual(record["requested"]["execution_profile"], V0_PROFILE)
        self.assertEqual(len(record["effective"]), 19)

    def test_mismatched_cpu_quota_is_unverified_and_the_outcome_is_kept(self):
        transport, record = self._v1_record(
            lambda d: d["HostConfig"].__setitem__("CpuQuota", 50000))
        self.assertEqual(len(transport.started), 1)
        self.assertEqual(record["setup_status"], "ready")
        self.assertEqual(record["envelope_status"], "unverified")
        self.assertEqual(record["unverified_field"], "cpu_quota")
        self.assertEqual(record["candidate_outcome"], "completed")
        self.assertIsNone(record["effective"])
        self.assertEqual(record["publication_permission"], "withheld")
        self.assertEqual(record["withheld_reason"], "envelope_status")

    def test_unset_or_absent_cpu_values_are_unverified(self):
        cases = {
            "cpu_quota": lambda d: d["HostConfig"].__setitem__("CpuQuota", 0),
            "cpu_period": lambda d: d["HostConfig"].__setitem__("CpuPeriod", 0),
            "HostConfig.CpuQuota": lambda d: d["HostConfig"].pop("CpuQuota"),
            "HostConfig.CpuPeriod": lambda d: d["HostConfig"].pop("CpuPeriod"),
        }
        for field, mutate in cases.items():
            with self.subTest(field=field):
                _transport, record = self._v1_record(mutate)
                self.assertEqual(record["envelope_status"], "unverified")
                self.assertEqual(record["unverified_field"], field)
                self.assertEqual(record["candidate_outcome"], "completed")

    def test_nofile_mismatch_or_discard_is_unverified(self):
        def limit(soft, hard):
            return lambda d: d["HostConfig"].__setitem__(
                "Ulimits", [{"Name": "nofile", "Soft": soft, "Hard": hard}])
        cases = {
            "soft": limit(512, 1024),
            "hard": limit(1024, 2048),
            "discarded-null": lambda d: d["HostConfig"].__setitem__("Ulimits", None),
            "discarded-empty": lambda d: d["HostConfig"].__setitem__("Ulimits", []),
        }
        for name, mutate in cases.items():
            with self.subTest(case=name):
                _transport, record = self._v1_record(mutate)
                self.assertEqual(record["envelope_status"], "unverified")
                self.assertEqual(record["unverified_field"], "ulimit_nofile")
                self.assertEqual(record["candidate_outcome"], "completed")

    def test_missing_daemon_kernel_fields_are_unverified(self):
        for wire in ("KernelVersion", "CgroupVersion"):
            with self.subTest(missing=wire):
                daemon = dict(A2_DAEMON)
                del daemon[wire]
                _transport, record = self._v1_record(daemon=daemon)
                self.assertEqual(record["envelope_status"], "unverified")
                self.assertEqual(record["unverified_field"], "daemon." + wire)
                self.assertEqual(record["candidate_outcome"], "completed")

    def test_a_transport_without_a_daemon_reader_is_unverified(self):
        class NoDaemon(ObservingTransport):
            daemon_info = None

        transport = NoDaemon(inspect=_observed_inspect(contained.CANDIDATE_RESOURCE_PROFILE_V2))
        completed, _ = self._admit(
            _prepare_raw(contained.CANDIDATE_RESOURCE_PROFILE_V2), V1_PROFILE, transport)
        record = completed.envelope_record
        self.assertEqual(record["envelope_status"], "unverified")
        self.assertEqual(record["unverified_field"], "daemon_info")
        self.assertEqual(record["schema"], "corpus-adequacy.execution-envelope.v1")

    def test_refused_setup_under_v1_still_records_the_v1_schema(self):
        transport = ObservingTransport(
            inspect=_observed_inspect(contained.CANDIDATE_RESOURCE_PROFILE_V2),
            create_error=contained.DockerUnavailable("docker missing"))
        completed, _ = self._admit(
            _prepare_raw(contained.CANDIDATE_RESOURCE_PROFILE_V2), V1_PROFILE, transport)
        record = completed.envelope_record
        self.assertEqual(record["setup_status"], "unavailable")
        self.assertEqual(record["candidate_outcome"], "not-run")
        self.assertEqual(record["schema"], "corpus-adequacy.execution-envelope.v1")
        self.assertEqual(record["requested"]["execution_profile"], V1_PROFILE)

    def test_alternate_values_below_admission_match_argv_and_verify(self):
        profile = {**contained.CANDIDATE_RESOURCE_PROFILE_V2,
                   "cpu_rate_millicpu": 2500, "nofile_soft": 512, "nofile_hard": 2048}
        transport = ObservingTransport(inspect=_observed_inspect(profile))
        with tempfile.TemporaryDirectory() as d:
            completed = cand._run_sealed_candidate(
                image_id=TOOLCHAIN_IMAGE, mounts=_mounts(Path(d)),
                resource_profile=profile, execution_profile=V1_PROFILE,
                transport=transport, binding=A2_BINDING)
        self.assertTrue(_contains_run(transport.created[0], [
            "--cpu-period", "100000", "--cpu-quota", "250000",
            "--ulimit", "nofile=512:2048"]), transport.created[0])
        record = completed.envelope_record
        self.assertEqual(record["envelope_status"], "verified", record["unverified_field"])
        self.assertEqual(record["effective"]["cpu_quota"], 250000)
        self.assertEqual(record["effective"]["ulimit_nofile"], {"soft": 512, "hard": 2048})
        self.assertEqual(record["requested"]["resource_profile"], profile)

    def test_alternate_values_are_compared_not_defaulted_to_the_frozen_policy(self):
        """The inspect that verifies the frozen profile must not verify the alternate one."""
        profile = {**contained.CANDIDATE_RESOURCE_PROFILE_V2,
                   "cpu_rate_millicpu": 2500, "nofile_soft": 512, "nofile_hard": 2048}
        transport = ObservingTransport(
            inspect=_observed_inspect(contained.CANDIDATE_RESOURCE_PROFILE_V2))
        with tempfile.TemporaryDirectory() as d:
            completed = cand._run_sealed_candidate(
                image_id=TOOLCHAIN_IMAGE, mounts=_mounts(Path(d)),
                resource_profile=profile, execution_profile=V1_PROFILE,
                transport=transport, binding=A2_BINDING)
        record = completed.envelope_record
        self.assertEqual(record["envelope_status"], "unverified")
        self.assertEqual(record["unverified_field"], "cpu_quota")

    def test_loaders_are_reached_only_through_the_dispatcher_for_their_profile(self):
        import aee_checker_sealed_run as run
        cases = (
            (V0_PROFILE, contained.CANDIDATE_RESOURCE_PROFILE, "load_prepare_v1",
             "load_prepare_v2"),
            (V1_PROFILE, contained.CANDIDATE_RESOURCE_PROFILE_V2, "load_prepare_v2",
             "load_prepare_v1"),
        )
        for profile, resource, reached, untouched in cases:
            with self.subTest(profile=profile):
                raw = _prepare_raw(resource)
                transport = ObservingTransport(inspect=_observed_inspect(resource))
                with mock.patch.object(
                        run, reached, wraps=getattr(run, reached)) as used, \
                        mock.patch.object(
                            run, untouched,
                            side_effect=AssertionError("other loader reached")) as other:
                    completed, _ = self._admit(raw, profile, transport)
                used.assert_called_once_with(raw)
                other.assert_not_called()
                self.assertEqual(completed.envelope_record["envelope_status"], "verified")

    def test_noop_loaded_copy_keeps_both_profile_routes(self):
        src = Path(cand.__file__).read_text()
        with tempfile.TemporaryDirectory() as d:
            module = _load_mutated(src, Path(d))
            for profile, resource in (
                    (V0_PROFILE, contained.CANDIDATE_RESOURCE_PROFILE),
                    (V1_PROFILE, contained.CANDIDATE_RESOURCE_PROFILE_V2)):
                transport = ObservingTransport(inspect=_observed_inspect(resource))
                completed = module.run_sealed_candidate(
                    prepare_raw=_prepare_raw(resource), mounts=_mounts(Path(d)),
                    execution_profile=profile, transport=transport, binding=A2_BINDING)
                with self.subTest(profile=profile):
                    self.assertEqual(
                        completed.envelope_record["envelope_status"], "verified")
                    self.assertEqual(
                        _contains_run(transport.created[0], FROZEN_V2_FLAGS),
                        profile == V1_PROFILE)
        self.assertIsNot(module, cand)


if __name__ == "__main__":
    unittest.main()
