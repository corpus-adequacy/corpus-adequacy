#!/usr/bin/env python3
"""#65 inert vs candidate resource contract. Synthetic only. No AEE run."""

from __future__ import annotations

import inspect
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

import aee_checker_sealed_candidate as cand  # noqa: E402
import aee_checker_sealed_common as common  # noqa: E402
import aee_checker_sealed_oci as oci  # noqa: E402
import aee_checker_sealed_run as run  # noqa: E402
import contained_oci as contained  # noqa: E402
from aee_checker_sealed_common import PrepareError  # noqa: E402

PROBE = "sha256:" + ("11" * 32)
TOOLCHAIN = "sha256:" + ("cd" * 32)
IMAGE = TOOLCHAIN


def _mounts(root: Path, *, subject=True):
    names = ("input", "vendor", "tool", "subject") if subject else ("input", "vendor", "tool")
    mounts = {}
    for name in names:
        path = root / name
        path.mkdir()
        mounts[name] = path
    if "input" in mounts:
        vectors = mounts["input"] / "vectors"
        vectors.mkdir()
        (vectors / "MANIFEST.json").write_text(
            json.dumps({"vectors": [{"id": "v1", "file": "v1.json"}]}),
            encoding="utf-8",
        )
    return mounts


def _inspect(dests, *, profile):
    work = "rw,size=%d,nr_inodes=%d,mode=1777" % (
        profile["work_bytes"], profile["work_inodes"])
    if profile["work_exec"]:
        work += ",exec"
    tmp = "rw,size=%d,nr_inodes=%d,mode=1777" % (
        profile["tmp_bytes"], profile["tmp_inodes"])
    return {
        "HostConfig": {
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "Memory": profile["memory_bytes"],
            "MemorySwap": profile["memory_swap_bytes"],
            "PidsLimit": profile["pids"],
            "NetworkMode": "none",
            "Tmpfs": {"/tmp": tmp, "/work": work},
        },
        "Config": {
            "User": "65532:65532",
            "Env": ["CARGO_NET_OFFLINE=true"],
        },
        "Mounts": [
            {"Type": "bind", "Destination": dest, "RW": False}
            for dest in dests
        ],
        "State": {
            "Error": "",
            "ExitCode": 0,
            "Running": False,
            "Status": "exited",
        },
    }


class RedCandidateCannotUseInert(unittest.TestCase):
    def test_candidate_refuses_prepare_image_id(self):
        with self.assertRaises(PrepareError) as ctx:
            cand.require_candidate_image(
                image_id=PROBE, toolchain_image_id=TOOLCHAIN,
                probe_image_id=PROBE)
        self.assertRegex(str(ctx.exception).lower(), r"inert|probe|toolchain")

    def test_candidate_profile_argv_does_not_reuse_inert_tmpfs(self):
        with tempfile.TemporaryDirectory() as d:
            argv = cand.candidate_create_argv(
                image_id=TOOLCHAIN, name="cand", mounts=_mounts(Path(d)),
                resource_profile=common.CANDIDATE_RESOURCE_PROFILE)
        text = " ".join(argv)
        self.assertNotIn("size=1048576", text)
        self.assertNotIn("nr_inodes=128", text)
        self.assertIn("size=%d" % common.CANDIDATE_RESOURCE_PROFILE["work_bytes"], text)


class InertDefaultByteIdentical(unittest.TestCase):
    def test_omitted_resource_profile_matches_explicit_inert_argv(self):
        with tempfile.TemporaryDirectory() as d:
            mounts = _mounts(Path(d), subject=False)
            omitted = oci.docker_create_argv(
                image_id=PROBE, name="inert", mounts=mounts, command=["ok"])
            explicit = oci.docker_create_argv(
                image_id=PROBE, name="inert", mounts=mounts, command=["ok"],
                resource_profile=common.INERT_RESOURCE_PROFILE)
        self.assertEqual(omitted, explicit)
        text = " ".join(omitted)
        self.assertIn("size=1048576,nr_inodes=128", text)
        self.assertEqual(omitted[omitted.index("--memory") + 1], "4g")
        self.assertEqual(omitted[omitted.index("--memory-swap") + 1], "4g")
        self.assertEqual(omitted[omitted.index("--pids-limit") + 1], "512")

    def test_raising_candidate_work_does_not_rewrite_inert_ceilings(self):
        self.assertEqual(common.TMPFS_BYTES, 1048576)
        self.assertEqual(common.TMPFS_INODES, 128)
        self.assertEqual(common.DECLARED_CEILINGS["deadline_seconds"], 8)
        self.assertEqual(common.INERT_RESOURCE_PROFILE["work_bytes"], 1048576)
        self.assertGreater(
            common.CANDIDATE_RESOURCE_PROFILE["work_bytes"],
            common.INERT_RESOURCE_PROFILE["work_bytes"])
        self.assertNotEqual(
            common.CANDIDATE_RESOURCE_PROFILE, common.INERT_RESOURCE_PROFILE)


class CandidateImageBinding(unittest.TestCase):
    def test_toolchain_image_id_is_accepted(self):
        self.assertEqual(
            cand.require_candidate_image(
                image_id=TOOLCHAIN, toolchain_image_id=TOOLCHAIN,
                probe_image_id=PROBE),
            TOOLCHAIN)

    def test_mutation_selects_prepare_image_id(self):
        with self.assertRaises(PrepareError):
            cand.require_candidate_image(
                image_id=PROBE, toolchain_image_id=TOOLCHAIN,
                probe_image_id=PROBE)


class CandidateDeadline(unittest.TestCase):
    def test_docker_transport_uses_the_bounded_runner(self):
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="{}", stderr="")
        with mock.patch.object(cand.br, "_run_capped", return_value=completed) as bounded:
            self.assertIs(cand._DockerTransport().start("candidate", 120), completed)
        bounded.assert_called_once_with(
            ["docker", "start", "-a", "candidate"], Path.cwd(), 120)

    def test_transport_start_uses_profile_deadline_not_sixty(self):
        src = inspect.getsource(cand._DockerTransport.start)
        self.assertNotIn("60", src)
        profile = common.CANDIDATE_RESOURCE_PROFILE
        self.assertEqual(profile["deadline_seconds"], 120)
        self.assertNotEqual(profile["deadline_seconds"], 60)

        class Capture:
            skip_absent = False

            def __init__(self):
                self.deadline = None

            def create(self, argv):
                return None

            def start(self, name, deadline_seconds):
                self.deadline = deadline_seconds
                raise subprocess.TimeoutExpired(["docker", "start", "-a", name], 1)

            def inspect(self, name):
                return _inspect(
                    ("/input", "/vendor", "/tool", "/subject"), profile=profile)

            def remove(self, name):
                return None

            def require_absent(self, name):
                return None

        transport = Capture()
        with tempfile.TemporaryDirectory() as d:
            cand._run_sealed_candidate(
                image_id=TOOLCHAIN, mounts=_mounts(Path(d)),
                resource_profile=profile, transport=transport,
            )
        self.assertEqual(transport.deadline, profile["deadline_seconds"])

    def test_mutation_unbound_or_60_deadline(self):
        src = inspect.getsource(cand._DockerTransport.start)
        self.assertNotIn("60", src)
        self.assertNotIn("None", src.split("deadline")[1][:80] if "deadline" in src else "60")


class CandidateCapacity(unittest.TestCase):
    def test_candidate_restores_the_pinned_image_toolchain_path(self):
        self.assertIn(
            "PATH=/usr/local/cargo/bin:$PATH CARGO_HOME=/tool cargo build",
            cand.CANDIDATE_SCRIPT,
        )

    def test_candidate_copy_does_not_preserve_host_metadata_on_tmpfs(self):
        self.assertNotIn("cp -a", cand.CANDIDATE_SCRIPT)
        self.assertIn("cp -R /subject/. /work/", cand.CANDIDATE_SCRIPT)

    def test_candidate_profile_can_hold_a_bounded_offline_rust_build(self):
        profile = common.CANDIDATE_RESOURCE_PROFILE
        self.assertGreaterEqual(profile["work_bytes"], 256 * 1024 * 1024)
        self.assertGreaterEqual(profile["tmp_bytes"], 16 * 1024 * 1024)
        self.assertGreaterEqual(profile["work_inodes"], 16384)
        self.assertGreaterEqual(profile["tmp_inodes"], 2048)
        self.assertGreaterEqual(profile["deadline_seconds"], 120)
        self.assertIs(profile["work_exec"], True)

    def test_candidate_work_tmpfs_is_executable_without_changing_inert_default(self):
        with tempfile.TemporaryDirectory() as d:
            candidate = cand.candidate_create_argv(
                image_id=TOOLCHAIN,
                name="candidate-exec",
                mounts=_mounts(Path(d)),
                resource_profile=common.CANDIDATE_RESOURCE_PROFILE,
            )
        candidate_work = next(value for value in candidate if value.startswith("/work:"))
        self.assertIn(",exec", candidate_work)

        with tempfile.TemporaryDirectory() as d:
            inert = oci.docker_create_argv(
                image_id=PROBE,
                name="inert-noexec",
                mounts=_mounts(Path(d), subject=False),
                command=["ok"],
            )
        inert_work = next(value for value in inert if value.startswith("/work:"))
        self.assertNotIn(",exec", inert_work)


class CandidateProfileExactKeys(unittest.TestCase):
    def test_fixture_profile_validates(self):
        self.assertEqual(
            common.require_resource_profile(common.CANDIDATE_RESOURCE_PROFILE),
            common.CANDIDATE_RESOURCE_PROFILE)

    def test_mutation_extra_or_missing_candidate_profile_key(self):
        extra = dict(common.CANDIDATE_RESOURCE_PROFILE)
        extra["nice"] = 1
        with self.assertRaises(PrepareError):
            common.require_resource_profile(extra)
        missing = dict(common.CANDIDATE_RESOURCE_PROFILE)
        missing.pop("work_bytes")
        with self.assertRaises(PrepareError):
            common.require_resource_profile(missing)
        wrong_exec = dict(common.CANDIDATE_RESOURCE_PROFILE)
        wrong_exec["work_exec"] = 1
        with self.assertRaises(PrepareError):
            common.require_resource_profile(wrong_exec)

    def test_output_limit_cannot_drift_from_the_executor_cap(self):
        drifted = dict(common.CANDIDATE_RESOURCE_PROFILE)
        drifted["output_bytes"] += 1
        with self.assertRaises(PrepareError):
            common.require_resource_profile(drifted)


class InspectFollowsSuppliedProfile(unittest.TestCase):
    def test_memory_swap_and_pids_flow_independently_through_argv_and_inspect(self):
        profile = {
            **common.CANDIDATE_RESOURCE_PROFILE,
            "memory_bytes": 2 * 1024 * 1024 * 1024,
            "memory_swap_bytes": 3 * 1024 * 1024 * 1024,
            "pids": 313,
        }
        common.require_resource_profile(profile)
        with tempfile.TemporaryDirectory() as d:
            argv = cand.candidate_create_argv(
                image_id=TOOLCHAIN,
                name="distinct-host-limits",
                mounts=_mounts(Path(d)),
                resource_profile=profile,
            )
        self.assertEqual(argv[argv.index("--memory") + 1], str(profile["memory_bytes"]))
        self.assertEqual(
            argv[argv.index("--memory-swap") + 1], str(profile["memory_swap_bytes"]))
        self.assertEqual(argv[argv.index("--pids-limit") + 1], "313")

        observed = _inspect(("/input", "/vendor", "/tool"), profile=profile)
        oci.validate_inspect_contract(
            observed, sealed=True, resource_profile=profile)
        for field, inert_value in (
                ("Memory", common.INERT_RESOURCE_PROFILE["memory_bytes"]),
                ("MemorySwap", common.INERT_RESOURCE_PROFILE["memory_swap_bytes"]),
                ("PidsLimit", common.INERT_RESOURCE_PROFILE["pids"])):
            mutated = _inspect(("/input", "/vendor", "/tool"), profile=profile)
            mutated["HostConfig"][field] = inert_value
            with self.subTest(field=field), self.assertRaises(PrepareError):
                oci.validate_inspect_contract(
                    mutated, sealed=True, resource_profile=profile)

    def test_candidate_inspect_accepts_fixture_tmpfs(self):
        profile = common.CANDIDATE_RESOURCE_PROFILE
        oci.validate_inspect_contract(
            _inspect(("/input", "/vendor", "/tool"), profile=profile),
            sealed=True, resource_profile=profile)

    def test_mutation_accepts_inspect_payload_that_differs_from_profile(self):
        profile = common.CANDIDATE_RESOURCE_PROFILE
        inspect_doc = _inspect(("/input", "/vendor", "/tool"), profile=profile)
        inspect_doc["HostConfig"]["Tmpfs"]["/work"] = (
            "rw,size=1048576,nr_inodes=128,mode=1777,exec")
        with self.assertRaises(PrepareError):
            oci.validate_inspect_contract(
                inspect_doc, sealed=True, resource_profile=profile)

    def test_work_exec_must_equal_the_supplied_profile_in_both_directions(self):
        inert = common.INERT_RESOURCE_PROFILE
        inspect_doc = _inspect(("/input", "/vendor", "/tool"), profile=inert)
        inspect_doc["HostConfig"]["Tmpfs"]["/work"] += ",exec"
        with self.assertRaises(PrepareError):
            oci.validate_inspect_contract(
                inspect_doc, sealed=True, resource_profile=inert)

        candidate = common.CANDIDATE_RESOURCE_PROFILE
        inspect_doc = _inspect(("/input", "/vendor", "/tool"), profile=candidate)
        inspect_doc["HostConfig"]["Tmpfs"]["/work"] = (
            inspect_doc["HostConfig"]["Tmpfs"]["/work"].replace(",exec", ""))
        with self.assertRaises(PrepareError):
            oci.validate_inspect_contract(
                inspect_doc, sealed=True, resource_profile=candidate)

    def test_explicit_empty_profile_is_not_an_omitted_profile(self):
        with tempfile.TemporaryDirectory() as d:
            mounts = _mounts(Path(d), subject=False)
            with self.assertRaises(PrepareError):
                oci.docker_create_argv(
                    image_id=PROBE,
                    name="empty-profile",
                    mounts=mounts,
                    command=["ok"],
                    resource_profile={},
                )
        with self.assertRaises(PrepareError):
            oci.validate_inspect_contract(
                _inspect(
                    ("/input", "/vendor", "/tool"),
                    profile=common.INERT_RESOURCE_PROFILE,
                ),
                sealed=True,
                resource_profile={},
            )


class InertArgvMutation(unittest.TestCase):
    def test_mutation_changes_inert_default_argv_while_adding_candidate(self):
        with tempfile.TemporaryDirectory() as d:
            mounts = _mounts(Path(d), subject=False)
            argv = oci.docker_create_argv(
                image_id=PROBE, name="inert", mounts=mounts, command=["ok"])
        text = " ".join(argv)
        self.assertIn("--tmpfs /tmp:rw,size=1048576,nr_inodes=128,mode=1777", text)
        self.assertIn("--tmpfs /work:rw,size=1048576,nr_inodes=128,mode=1777", text)
        self.assertIn("--memory 4g", text)


class VersionedPrepare(unittest.TestCase):
    def _v0_parts(self):
        from tests.test_aee_checker_sealed_run import PrepareEvidence
        return PrepareEvidence._parts(self)

    def _v1_parts(self):
        parts = {
            **self._v0_parts(),
            "candidate_profile": dict(common.CANDIDATE_RESOURCE_PROFILE),
        }
        parts["image"] = {
            **parts["image"],
            "id_scope": "host-local",
            "platform": "linux/arm64",
        }
        return parts

    def test_v1_emission_writes_only_the_final_schema(self):
        with mock.patch.object(
                Path, "write_bytes", autospec=True, return_value=None) as write_bytes:
            raw = run.emit_prepare_v1(self._v1_parts(), Path("prepare.v1.json"))
        self.assertEqual(write_bytes.call_count, 1)
        self.assertEqual(json.loads(raw)["schema"], run.PREPARE_V1_SCHEMA)

    def test_v1_bytes_have_a_canonical_validation_path(self):
        with tempfile.TemporaryDirectory() as d:
            raw = run.emit_prepare_v1(self._v1_parts(), Path(d) / "prepare.v1.json")
        self.assertEqual(run.load_prepare_v1(raw)["candidate_profile"],
                         common.CANDIDATE_RESOURCE_PROFILE)
        with self.assertRaises(PrepareError):
            run.load_prepare_v1(raw + b"\n")

    def test_v1_requires_the_inert_probe_image_identity(self):
        parts = self._v1_parts()
        parts["image"] = {key: value for key, value in parts["image"].items()
                          if key != "id"}
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(PrepareError):
                run.emit_prepare_v1(parts, Path(d) / "prepare.v1.json")

    def test_prepare_v1_cli_selects_v1_without_changing_prepare_default(self):
        with mock.patch.object(run, "prepare", return_value=b"") as prepare:
            self.assertEqual(
                run.main(["aee_checker_sealed_run.py", "prepare-v1", "pins", "out"]),
                0,
            )
        prepare.assert_called_once()
        self.assertEqual(prepare.call_args.kwargs["schema"], run.PREPARE_V1_SCHEMA)

    def test_production_prepare_v1_never_calls_the_v0_emitter(self):
        from tests.test_aee_checker_sealed_run import ExplicitPrepareImage

        fixture = ExplicitPrepareImage()
        patches = fixture._patches()
        with tempfile.TemporaryDirectory() as d, \
                patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5], patches[6], patches[7], patches[8], patches[9], \
                mock.patch.object(
                    run, "emit_prepare_v0",
                    side_effect=AssertionError("prepare-v1 called v0 emitter"),
                ) as v0, \
                mock.patch.object(
                    run, "emit_prepare_v1", wraps=run.emit_prepare_v1,
                ) as v1:
            raw = run.prepare(
                Path(d) / "pins",
                Path(d) / "out",
                root=Path(d) / "root",
                image_id=fixture.IMAGE,
                schema=run.PREPARE_V1_SCHEMA,
            )
        v0.assert_not_called()
        v1.assert_called_once()
        self.assertEqual(json.loads(raw)["schema"], run.PREPARE_V1_SCHEMA)


class MountContractResiduals(unittest.TestCase):
    def test_malformed_mount_specs_are_refused_by_the_shared_validator(self):
        malformed = (
            (),
            (("input", "/input"), ("input", "/other")),
            (("input", "/input"), ("other", "/input")),
            (("input", "relative"),),
            (("", "/input"),),
            (("input",),),
        )
        for mount_spec in malformed:
            with self.subTest(mount_spec=mount_spec):
                with self.assertRaises(PrepareError):
                    oci._require_mount_spec(mount_spec)

    def test_missing_mount_source_is_a_contract_error_not_keyerror(self):
        with tempfile.TemporaryDirectory() as d:
            mounts = _mounts(Path(d), subject=False)
            mounts.pop("tool")
            with self.assertRaises(PrepareError) as ctx:
                oci.docker_create_argv(
                    image_id=PROBE,
                    name="missing-source",
                    mounts=mounts,
                    command=["ok"],
                )
        self.assertIn("mount source missing: tool", str(ctx.exception))


class CandidatePrepareBinding(unittest.TestCase):
    def _parts(self):
        from tests.test_aee_checker_sealed_run import PrepareEvidence
        parts = PrepareEvidence._parts(self)
        parts["candidate_profile"] = dict(common.CANDIDATE_RESOURCE_PROFILE)
        parts["image"] = {
            **parts["image"],
            "id": PROBE,
            "id_scope": "host-local",
            "platform": "linux/arm64",
        }
        parts["toolchain"]["image_id"] = TOOLCHAIN
        return parts

    def _raw(self, parts=None):
        with tempfile.TemporaryDirectory() as d:
            return run.emit_prepare_v1(
                parts or self._parts(), Path(d) / "prepare.v1.json")

    def test_public_candidate_entrypoint_accepts_only_canonical_prepare_bytes(self):
        parameters = inspect.signature(cand.run_sealed_candidate).parameters
        self.assertIn("prepare_raw", parameters)
        self.assertNotIn("image_id", parameters)
        self.assertNotIn("resource_profile", parameters)
        self.assertNotIn("sealed", parameters)
        # The resolved profile is the one input besides the bytes, and it has no default:
        # omission is TypeError, never an implied contained-oci-v0.
        profile = parameters["execution_profile"]
        self.assertIs(profile.kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertIs(profile.default, inspect.Parameter.empty)

    def test_public_candidate_derives_toolchain_image_and_profile_from_prepare(self):
        profile = common.CANDIDATE_RESOURCE_PROFILE

        class Capture:
            skip_absent = False

            def create(self, argv):
                self.argv = argv

            def start(self, name, deadline_seconds):
                self.deadline = deadline_seconds
                raise subprocess.TimeoutExpired(["docker", "start", "-a", name], 1)

            def inspect(self, name):
                return _inspect(
                    ("/input", "/vendor", "/tool", "/subject"), profile=profile)

            def remove(self, name):
                return None

            def require_absent(self, name):
                return None

        transport = Capture()
        with tempfile.TemporaryDirectory() as d:
            cand.run_sealed_candidate(
                prepare_raw=self._raw(), mounts=_mounts(Path(d)), transport=transport,
                execution_profile="contained-oci-v0")
        self.assertIn(TOOLCHAIN, transport.argv)
        self.assertNotIn(PROBE, transport.argv)
        self.assertEqual(transport.deadline, profile["deadline_seconds"])

    def test_prepare_probe_image_cannot_be_substituted_for_toolchain(self):
        parts = self._parts()
        parts["toolchain"]["image_id"] = PROBE
        with tempfile.TemporaryDirectory() as d:
            mounts = _mounts(Path(d))
            with self.assertRaises(PrepareError):
                cand.run_sealed_candidate(
                    prepare_raw=self._raw(parts), mounts=mounts, transport=object(),
                    execution_profile="contained-oci-v0")

class ExecutionIdentity(unittest.TestCase):
    def test_profile_helpers_live_on_listed_execution_paths(self):
        listed = set(run.EXECUTION_PATHS)
        for rel in (
                "measurements/aee_checker_sealed_common.py",
                "measurements/contained_oci.py",
                "measurements/aee_checker_sealed_oci.py",
                "measurements/aee_checker_sealed_candidate.py",
                "measurements/aee_checker_sealed_run.py"):
            self.assertIn(rel, listed)
        stray = REPO_ROOT / "measurements" / "aee_checker_sealed_resources.py"
        self.assertFalse(stray.exists())
        common_src = (REPO_ROOT / "measurements" / "contained_oci.py").read_text(
            encoding="utf-8")
        self.assertIn("CANDIDATE_RESOURCE_PROFILE", common_src)
        self.assertIn("require_resource_profile", common_src)

    def test_mutation_omits_new_runtime_path_from_execution_identity(self):
        self.assertIn("measurements/contained_oci.py", run.EXECUTION_PATHS)
        self.assertIn("require_resource_profile", common.__dict__)


class NoOpControl(unittest.TestCase):
    def test_noop_profile_helpers_stay_green(self):
        self.assertEqual(
            common.require_resource_profile(dict(common.INERT_RESOURCE_PROFILE)),
            common.INERT_RESOURCE_PROFILE)
        self.assertEqual(
            cand.require_candidate_image(
                image_id=TOOLCHAIN, toolchain_image_id=TOOLCHAIN,
                probe_image_id=PROBE),
            TOOLCHAIN)


class MutationReuseInertTmpfs(unittest.TestCase):
    def test_mutation_reuses_inert_tmpfs_limits_for_candidate_work(self):
        with tempfile.TemporaryDirectory() as d:
            argv = cand.candidate_create_argv(
                image_id=TOOLCHAIN, name="cand", mounts=_mounts(Path(d)),
                resource_profile=common.CANDIDATE_RESOURCE_PROFILE)
        work = [item for item in argv if item.startswith("/work:")]
        self.assertEqual(len(work), 1)
        self.assertNotIn("size=1048576", work[0])
        self.assertIn(
            "size=%d" % common.CANDIDATE_RESOURCE_PROFILE["work_bytes"], work[0])


if __name__ == "__main__":
    unittest.main()


class ResourceProfileV2Codec(unittest.TestCase):
    """The v2 profile is a sibling of v1, validated by the same rule under its own policy.

    v1 keeps its exact keys, its exact fixture and its named loader; nothing here widens it.
    """

    def _v2(self, **over):
        base = dict(contained.CANDIDATE_RESOURCE_PROFILE_V2)
        base.update(over)
        return base

    # --- v1 is untouched, and its named loader still refuses v2 ---
    def test_v1_keys_and_fixture_are_unchanged(self):
        self.assertEqual(contained.RESOURCE_PROFILE_KEYS, (
            "schema", "work_bytes", "tmp_bytes", "work_inodes", "tmp_inodes",
            "work_exec", "deadline_seconds", "output_bytes", "memory_bytes",
            "memory_swap_bytes", "pids"))
        self.assertNotIn("cpu_rate_millicpu", contained.CANDIDATE_RESOURCE_PROFILE)
        self.assertNotIn("nofile_soft", contained.CANDIDATE_RESOURCE_PROFILE)

    def test_named_v1_loader_refuses_a_v2_profile(self):
        with self.assertRaises(PrepareError):
            contained.require_resource_profile(self._v2())

    def test_named_v2_loader_refuses_a_v1_profile(self):
        with self.assertRaises(PrepareError):
            contained.require_resource_profile_v2(
                dict(contained.CANDIDATE_RESOURCE_PROFILE))

    # --- the v2 policy values are the frozen constant, not merely a valid shape ---
    def test_candidate_v2_equals_its_one_canonical_constant(self):
        profile = contained.require_resource_profile_v2(
            dict(contained.CANDIDATE_RESOURCE_PROFILE_V2))
        self.assertEqual(profile, contained.CANDIDATE_RESOURCE_PROFILE_V2)
        self.assertEqual(profile["cpu_rate_millicpu"], 1000)
        self.assertEqual(profile["nofile_soft"], 1024)
        self.assertEqual(profile["nofile_hard"], 1024)
        # Other ceilings are carried over unchanged from v1 policy.
        for key in ("memory_bytes", "pids", "deadline_seconds", "work_bytes"):
            self.assertEqual(profile[key], contained.CANDIDATE_RESOURCE_PROFILE[key])

    # --- exact, bounded CPU and nofile: no float, NaN, bool or reordered pair ---
    def test_cpu_rate_refuses_non_integer_and_non_positive(self):
        for bad in (1000.0, float("nan"), float("inf"), True, "1000", None, 0, -1):
            with self.assertRaises(PrepareError, msg=repr(bad)):
                contained.require_resource_profile_v2(
                    self._v2(cpu_rate_millicpu=bad))

    def test_nofile_refuses_bad_types_and_soft_above_hard(self):
        for over in ({"nofile_soft": 2048},            # soft > hard
                     {"nofile_soft": True},
                     {"nofile_hard": 1024.0},
                     {"nofile_hard": 0},
                     {"nofile_soft": "1024"}):
            with self.assertRaises(PrepareError, msg=repr(over)):
                contained.require_resource_profile_v2(self._v2(**over))

    def test_unknown_and_missing_keys_refuse(self):
        extra = self._v2()
        extra["unexpected"] = 1
        with self.assertRaises(PrepareError):
            contained.require_resource_profile_v2(extra)
        missing = self._v2()
        del missing["nofile_hard"]
        with self.assertRaises(PrepareError):
            contained.require_resource_profile_v2(missing)

    def test_wrong_schema_string_refuses(self):
        with self.assertRaises(PrepareError):
            contained.require_resource_profile_v2(
                self._v2(schema=contained.RESOURCE_PROFILE_SCHEMA))

    # --- argv: the effective arguments come from the validated profile ---
    def test_v2_argv_emits_cpu_rate_and_nofile_from_the_profile(self):
        argv = contained.docker_resource_argv_v2(
            contained.CANDIDATE_RESOURCE_PROFILE_V2)
        # Exact integer mapping: quota/period, no float formatting anywhere.
        self.assertIn("--cpu-period", argv)
        self.assertIn("--cpu-quota", argv)
        period = argv[argv.index("--cpu-period") + 1]
        quota = argv[argv.index("--cpu-quota") + 1]
        self.assertEqual(int(quota) * 1000, 1000 * int(period))
        self.assertNotIn(".", quota + period)
        self.assertIn("--ulimit", argv)
        self.assertIn("nofile=1024:1024", argv)

    def test_v2_argv_binds_alternate_values_not_only_the_default(self):
        """F1: the frozen default cannot discriminate a hardcoded constant."""
        argv = contained.docker_resource_argv_v2(
            self._v2(cpu_rate_millicpu=2500, nofile_soft=512, nofile_hard=2048))
        self.assertEqual(argv[argv.index("--cpu-quota") + 1], "250000")
        self.assertEqual(argv[argv.index("--cpu-period") + 1], "100000")
        self.assertEqual(argv[argv.index("--ulimit") + 1], "nofile=512:2048")

    def test_cpu_rate_has_a_finite_representational_ceiling(self):
        """F2: bounded, not merely positive. This is a wire-representation limit."""
        with self.assertRaises(PrepareError):
            contained.require_resource_profile_v2(
                self._v2(cpu_rate_millicpu=10 ** 100))
        with self.assertRaises(PrepareError):
            contained.docker_resource_argv_v2(
                self._v2(cpu_rate_millicpu=10 ** 100))

    def test_cpu_rate_ceiling_boundary_is_exact(self):
        at_bound = contained.MAX_CPU_RATE_MILLICPU
        accepted = contained.require_resource_profile_v2(
            self._v2(cpu_rate_millicpu=at_bound))
        self.assertEqual(accepted["cpu_rate_millicpu"], at_bound)
        with self.assertRaises(PrepareError):
            contained.require_resource_profile_v2(
                self._v2(cpu_rate_millicpu=at_bound + 1))

    def test_nofile_has_a_finite_ceiling_too(self):
        with self.assertRaises(PrepareError):
            contained.require_resource_profile_v2(
                self._v2(nofile_soft=1, nofile_hard=10 ** 100))

    def test_v2_argv_is_independent_of_the_wall_deadline(self):
        slower = dict(contained.CANDIDATE_RESOURCE_PROFILE_V2)
        slower["deadline_seconds"] = contained.CANDIDATE_RESOURCE_PROFILE_V2[
            "deadline_seconds"] * 2
        self.assertEqual(contained.docker_resource_argv_v2(slower),
                         contained.docker_resource_argv_v2(
                             contained.CANDIDATE_RESOURCE_PROFILE_V2))

    def test_v2_argv_refuses_an_unvalidated_profile(self):
        with self.assertRaises(PrepareError):
            contained.docker_resource_argv_v2(
                dict(contained.CANDIDATE_RESOURCE_PROFILE))

    def test_v1_create_argv_still_carries_no_cpu_or_nofile(self):
        """Behavioural, not lexical: the v1 argv the runner actually builds is unchanged.

        This slice is codec infrastructure. Nothing here may start applying a limit on the
        production v1 path.
        """
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            keys = [k for k, _dest in contained.DEFAULT_MOUNT_SPEC]
            for key in keys:
                (base / key).mkdir()
            argv = contained.docker_create_argv(
                name="c", image_id=IMAGE, entrypoint="/entry", command=[],
                resource_profile=contained.CANDIDATE_RESOURCE_PROFILE,
                mounts={k: base / k for k in keys},
                mount_spec=contained.DEFAULT_MOUNT_SPEC, sealed=True)
        flat = " ".join(argv)
        for token in ("--cpus", "--cpu-quota", "--cpu-period", "--ulimit"):
            self.assertNotIn(token, flat)


class DaemonObservationV1(unittest.TestCase):
    def test_explicit_daemon_observer_uses_bounded_injected_transport(self):
        import contained_oci as c
        from unittest.mock import patch
        raw = b'{"KernelVersion":"synthetic","CgroupVersion":"2","CgroupDriver":"systemd","SecurityOptions":null}'
        with patch.object(c, "docker_bounded", return_value=raw) as bounded:
            result = c.observe_daemon_info(c.DockerTransport())
        bounded.assert_called_once_with(["info", "--format", "{{json .}}"])
        self.assertEqual(result["KernelVersion"], "synthetic")

    def test_missing_or_malformed_daemon_output_is_not_defaulted(self):
        import contained_oci as c
        from unittest.mock import patch
        for raw in (b'', b'[]', b'{"x":1,"x":2}', b'{'):
            with self.subTest(raw=raw), patch.object(c, "docker_bounded", return_value=raw):
                with self.assertRaises(c.PrepareError):
                    c.observe_daemon_info(c.DockerTransport())

    def test_existing_create_argv_and_readiness_do_not_activate_v1(self):
        import contained_oci as c
        from unittest.mock import patch
        with patch.object(c.DockerTransport, "daemon_info", side_effect=AssertionError("activated")), patch.object(c, "require_docker_ready", return_value="fixture-version"):
            self.assertEqual(c.DockerTransport().version(), "fixture-version")


# --- #102 A2: v2 resource flags at create, and the one PREPARE dispatcher ----------------------

V2_FLAGS = ["--cpu-period", "100000", "--cpu-quota", "100000", "--ulimit", "nofile=1024:1024"]
_INT64_MAX = 2 ** 63 - 1


def _contains_run(argv, run_tokens) -> bool:
    return any(argv[i:i + len(run_tokens)] == run_tokens for i in range(len(argv)))


def _create_argv(profile, root: Path):
    keys = [k for k, _dest in contained.DEFAULT_MOUNT_SPEC]
    for key in keys:
        (root / key).mkdir(exist_ok=True)
    return contained.docker_create_argv(
        name="c", image_id=IMAGE, entrypoint="/entry", command=[],
        resource_profile=profile, mounts={k: root / k for k in keys},
        mount_spec=contained.DEFAULT_MOUNT_SPEC, sealed=True)


class V2FlagsAtCreate(unittest.TestCase):
    def _v2(self, **over):
        return {**contained.CANDIDATE_RESOURCE_PROFILE_V2, **over}

    def test_v2_profile_adds_exactly_the_flags_and_nothing_else(self):
        with tempfile.TemporaryDirectory() as raw:
            v1 = _create_argv(contained.CANDIDATE_RESOURCE_PROFILE, Path(raw))
            v2 = _create_argv(contained.CANDIDATE_RESOURCE_PROFILE_V2, Path(raw))
        self.assertTrue(_contains_run(v2, V2_FLAGS), v2)
        start = next(i for i in range(len(v2)) if v2[i:i + len(V2_FLAGS)] == V2_FLAGS)
        # Removing the six v2 tokens leaves the v1 argv of the same ceilings, byte for byte.
        self.assertEqual(v2[:start] + v2[start + len(V2_FLAGS):], v1)
        self.assertNotIn("--cpus", v2)

    def test_representational_cpu_maximum_passes_create_and_one_more_refuses(self):
        at_bound = contained.MAX_CPU_RATE_MILLICPU
        with tempfile.TemporaryDirectory() as raw:
            argv = _create_argv(self._v2(cpu_rate_millicpu=at_bound), Path(raw))
            quota = int(argv[argv.index("--cpu-quota") + 1])
            self.assertEqual(quota, at_bound * 100000 // 1000)
            self.assertLessEqual(quota, _INT64_MAX)
            with self.assertRaises(PrepareError):
                _create_argv(self._v2(cpu_rate_millicpu=at_bound + 1), Path(raw))

    def test_representational_nofile_maximum_passes_create_and_one_more_refuses(self):
        self.assertEqual(contained.MAX_NOFILE, _INT64_MAX)
        with tempfile.TemporaryDirectory() as raw:
            argv = _create_argv(
                self._v2(nofile_soft=_INT64_MAX, nofile_hard=_INT64_MAX), Path(raw))
            self.assertEqual(argv[argv.index("--ulimit") + 1],
                             "nofile=%d:%d" % (_INT64_MAX, _INT64_MAX))
            with self.assertRaises(PrepareError):
                _create_argv(
                    self._v2(nofile_soft=1024, nofile_hard=_INT64_MAX + 1), Path(raw))

    def test_run_contained_admits_a_v2_profile_with_alternate_values(self):
        profile = self._v2(cpu_rate_millicpu=2500, nofile_soft=512, nofile_hard=2048)

        class Capture:
            skip_absent = False

            def create(self, argv):
                self.argv = argv

            def start(self, name, deadline_seconds):
                return subprocess.CompletedProcess([], 0, "{}\n", "")

            def inspect(self, name):
                # No CpuPeriod/CpuQuota/Ulimits at all: the inspect contract is not where CPU
                # or nofile is compared, so a completed container is never turned into refused.
                return _inspect(("/input", "/vendor", "/tool"), profile=profile)

            def remove(self, name):
                return None

            def require_absent(self, name):
                return None

        transport = Capture()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            for key, _dest in contained.DEFAULT_MOUNT_SPEC:
                (root / key).mkdir()
            result = contained.run_contained(
                image_id=IMAGE, mounts={k: root / k for k, _ in contained.DEFAULT_MOUNT_SPEC},
                command=[], entrypoint="/entry", mount_spec=contained.DEFAULT_MOUNT_SPEC,
                resource_profile=profile, sealed=True, name_prefix="a2-",
                transport=transport)
        self.assertEqual(result["state"], "completed")
        self.assertTrue(_contains_run(transport.argv, [
            "--cpu-period", "100000", "--cpu-quota", "250000",
            "--ulimit", "nofile=512:2048"]), transport.argv)

    def test_inspect_contract_reads_the_same_fields_for_v1_and_v2(self):
        doc = _inspect(("/input", "/vendor", "/tool"), profile=contained.CANDIDATE_RESOURCE_PROFILE)
        v1 = oci.validate_inspect_contract(
            doc, sealed=True, resource_profile=contained.CANDIDATE_RESOURCE_PROFILE)
        v2 = oci.validate_inspect_contract(
            doc, sealed=True, resource_profile=contained.CANDIDATE_RESOURCE_PROFILE_V2)
        self.assertEqual(v1, v2)

    def test_unknown_resource_profile_schema_refuses_at_create(self):
        for schema in ("corpus-adequacy.aee-checker-sealed.resource-profile.v3", None, ["x"]):
            with self.subTest(schema=schema), tempfile.TemporaryDirectory() as raw:
                with self.assertRaises(PrepareError):
                    _create_argv(self._v2(schema=schema), Path(raw))


class PrepareDispatcher(unittest.TestCase):
    def _raw(self, profile):
        from tests.test_aee_checker_sealed_run import PrepareEvidence
        parts = PrepareEvidence._parts(self)
        parts["candidate_profile"] = dict(profile)
        parts["image"] = {**parts["image"], "id_scope": "host-local", "platform": "linux/arm64"}
        emit = (run.emit_prepare_v2 if profile is contained.CANDIDATE_RESOURCE_PROFILE_V2
                else run.emit_prepare_v1)
        with tempfile.TemporaryDirectory() as d:
            return emit(parts, Path(d) / "prepare.json")

    def test_dispatcher_vocabulary_is_exactly_the_contained_profiles(self):
        import corpus_adequacy as ca
        self.assertEqual(set(run.PREPARE_SCHEMA_BY_PROFILE), set(ca._CONTAINED_PROFILES))
        self.assertEqual(run.PREPARE_SCHEMA_BY_PROFILE, {
            "contained-oci-v0": run.PREPARE_V1_SCHEMA,
            "contained-oci-v1": run.PREPARE_V2_SCHEMA,
        })

    def test_dispatcher_returns_exactly_the_named_loader_result(self):
        v1_raw = self._raw(contained.CANDIDATE_RESOURCE_PROFILE)
        v2_raw = self._raw(contained.CANDIDATE_RESOURCE_PROFILE_V2)
        self.assertEqual(
            run.load_prepare_for_profile(v1_raw, execution_profile="contained-oci-v0"),
            run.load_prepare_v1(v1_raw))
        self.assertEqual(
            run.load_prepare_for_profile(v2_raw, execution_profile="contained-oci-v1"),
            run.load_prepare_v2(v2_raw))

    def test_each_loader_is_reached_only_for_its_profile(self):
        for profile, resource, reached, untouched in (
                ("contained-oci-v0", contained.CANDIDATE_RESOURCE_PROFILE,
                 "load_prepare_v1", "load_prepare_v2"),
                ("contained-oci-v1", contained.CANDIDATE_RESOURCE_PROFILE_V2,
                 "load_prepare_v2", "load_prepare_v1")):
            raw = self._raw(resource)
            with self.subTest(profile=profile), \
                    mock.patch.object(run, reached, wraps=getattr(run, reached)) as used, \
                    mock.patch.object(
                        run, untouched, side_effect=AssertionError("wrong loader")) as other:
                run.load_prepare_for_profile(raw, execution_profile=profile)
            used.assert_called_once_with(raw)
            other.assert_not_called()

    def test_crossed_versions_refuse_under_their_own_names(self):
        v1_raw = self._raw(contained.CANDIDATE_RESOURCE_PROFILE)
        v2_raw = self._raw(contained.CANDIDATE_RESOURCE_PROFILE_V2)
        with self.assertRaisesRegex(
                PrepareError, "^prepare.v2 requires contained-oci-v1; "
                              "contained-oci-v0 admits only prepare.v1$"):
            run.load_prepare_for_profile(v2_raw, execution_profile="contained-oci-v0")
        with self.assertRaisesRegex(
                PrepareError, "^contained-oci-v1 admits only prepare.v2; a prepare.v1 is "
                              "never reinterpreted as CPU- or descriptor-limited$"):
            run.load_prepare_for_profile(v1_raw, execution_profile="contained-oci-v1")

    def test_other_refusals_keep_the_loader_message(self):
        v1_raw = self._raw(contained.CANDIDATE_RESOURCE_PROFILE)
        with self.assertRaisesRegex(PrepareError, "prepare.v1 is not canonical"):
            run.load_prepare_for_profile(v1_raw + b"\n", execution_profile="contained-oci-v0")
        for garbage in (b"", b"[]", b'{"schema": ["x"]}'):
            with self.subTest(raw=garbage), self.assertRaises(PrepareError):
                run.load_prepare_for_profile(garbage, execution_profile="contained-oci-v1")

    def test_every_other_profile_has_no_loader(self):
        raw = self._raw(contained.CANDIDATE_RESOURCE_PROFILE)
        for profile in ("trusted-local", "contained-oci-v2", "", None, ["contained-oci-v0"]):
            with self.subTest(profile=profile), mock.patch.object(
                    run, "load_prepare_v1", side_effect=AssertionError("loader reached")):
                with self.assertRaisesRegex(PrepareError, "no PREPARE loader"):
                    run.load_prepare_for_profile(raw, execution_profile=profile)

    def test_execution_profile_is_required(self):
        with self.assertRaises(TypeError):
            run.load_prepare_for_profile(self._raw(contained.CANDIDATE_RESOURCE_PROFILE))
