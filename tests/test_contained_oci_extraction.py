import importlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MEASUREMENTS = ROOT / "measurements"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(MEASUREMENTS) not in sys.path:
    sys.path.insert(0, str(MEASUREMENTS))

import aee_checker_sealed_candidate as candidate  # noqa: E402
import aee_checker_sealed_common as common  # noqa: E402
import aee_checker_sealed_materialize as materialize  # noqa: E402
import aee_checker_sealed_oci as aee_oci  # noqa: E402


def _inspect_fixture(contained, *, process_returncode=0, state_over=None):
    profile = contained.INERT_RESOURCE_PROFILE
    state = {
        "Error": "",
        "ExitCode": process_returncode,
        "Running": False,
        "Status": "exited",
    }
    state.update(state_over or {})
    return {
        "Config": {
            "Env": ["CARGO_NET_OFFLINE=true"],
            "User": "65532:65532",
        },
        "HostConfig": {
            "CapDrop": ["ALL"],
            "Memory": profile["memory_bytes"],
            "MemorySwap": profile["memory_swap_bytes"],
            "NetworkMode": "none",
            "PidsLimit": profile["pids"],
            "ReadonlyRootfs": True,
            "SecurityOpt": ["no-new-privileges:true"],
            "Tmpfs": {
                "/tmp": "rw,size=%d,nr_inodes=%d,mode=1777" % (
                    profile["tmp_bytes"], profile["tmp_inodes"]),
                "/work": "rw,size=%d,nr_inodes=%d,mode=1777" % (
                    profile["work_bytes"], profile["work_inodes"]),
            },
        },
        "Mounts": [
            {"Destination": destination, "RW": False, "Type": "bind"}
            for _key, destination in contained.DEFAULT_MOUNT_SPEC
        ],
        "State": state,
    }


class SharedEnvelopeOwnership(unittest.TestCase):
    def _contained_oci(self):
        try:
            return importlib.import_module("contained_oci")
        except ModuleNotFoundError:
            self.fail("the contained OCI rules still have no shared owner")

    def test_aee_facades_reexport_the_shared_effective_envelope_rules(self):
        contained = self._contained_oci()

        self.assertIs(common.require_resource_profile, contained.require_resource_profile)
        self.assertIs(aee_oci.require_image_id, contained.require_image_id)
        self.assertIs(aee_oci.docker_create_argv, contained.docker_create_argv)
        self.assertIs(
            aee_oci.validate_inspect_contract,
            contained.validate_inspect_contract,
        )

    def test_aee_candidate_delegates_the_bounded_lifecycle(self):
        contained = self._contained_oci()
        raw = {
            "container_absent_after": True,
            "contract": {},
            "inspect": {},
            "name": "candidate",
            "process": None,
            "state": "timeout",
        }

        with mock.patch.object(
            contained, "run_contained", return_value=raw
        ) as shared:
            actual = candidate._run_sealed_candidate(
                image_id="sha256:" + ("ab" * 32),
                mounts={},
                resource_profile=common.CANDIDATE_RESOURCE_PROFILE,
                transport=object(),
            )

        self.assertEqual(actual.returncode, 75)
        self.assertEqual(actual.unproved_reason, "timeout")
        self.assertEqual(shared.call_count, 1)
        call = shared.call_args.kwargs
        self.assertEqual(call["entrypoint"], "/bin/sh")
        self.assertEqual(call["mount_spec"], candidate.CANDIDATE_MOUNT_SPEC)
        self.assertIs(call["sealed"], True)
        self.assertEqual(
            call["resource_profile"], common.CANDIDATE_RESOURCE_PROFILE
        )

    def test_aee_inert_probe_delegates_the_same_bounded_lifecycle(self):
        contained = self._contained_oci()
        raw = {
            "container_absent_after": True,
            "contract": {"network_mode": "none"},
            "inspect": {"HostConfig": {}, "Config": {}},
            "name": "probe",
            "process": subprocess.CompletedProcess([], 0, "", ""),
            "state": "completed",
        }

        with mock.patch.object(contained, "run_contained", return_value=raw) as shared:
            actual = aee_oci.run_inert_probe(
                image_id="sha256:" + ("cd" * 32),
                mode="ok",
                mounts={},
                name_prefix="probe-",
            )

        self.assertEqual(actual["state"], "completed")
        self.assertIs(actual["container_absent_after"], True)
        call = shared.call_args.kwargs
        self.assertEqual(call["entrypoint"], "/probe")
        self.assertEqual(call["command"], ["ok"])
        self.assertEqual(call["mount_spec"], contained.DEFAULT_MOUNT_SPEC)
        self.assertEqual(call["resource_profile"], contained.INERT_RESOURCE_PROFILE)

    def test_missing_docker_is_unavailable_not_a_local_success(self):
        contained = self._contained_oci()

        with mock.patch.object(
            contained.br, "_run_capped", side_effect=FileNotFoundError("docker")
        ):
            with self.assertRaises(contained.DockerUnavailable):
                contained.docker_ok(["info"])

    def test_every_docker_phase_classifies_a_missing_executable_unavailable(self):
        contained = self._contained_oci()

        with mock.patch.object(
            contained.br, "_run_capped", side_effect=FileNotFoundError("docker")
        ):
            with self.assertRaises(contained.DockerUnavailable):
                contained.DockerTransport().start("candidate", 1)
            with self.assertRaises(contained.DockerUnavailable):
                contained.inspect_lookup("candidate")

    def test_completed_process_must_match_an_executed_inspect_state(self):
        contained = self._contained_oci()

        class FailedStart:
            skip_absent = False

            def __init__(self, state_over, process_returncode=1):
                self.state_over = state_over
                self.process_returncode = process_returncode

            def create(self, _argv):
                pass

            def start(self, _name, _deadline):
                return subprocess.CompletedProcess(
                    [], self.process_returncode, "", "")

            def inspect(self, _name):
                inspect = _inspect_fixture(
                    contained,
                    process_returncode=1,
                    state_over=(
                        self.state_over
                        if isinstance(self.state_over, dict)
                        else None
                    ),
                )
                if not isinstance(self.state_over, dict):
                    inspect["State"] = self.state_over
                return inspect

            def remove(self, _name):
                pass

            def require_absent(self, _name):
                pass

        cases = (
            ({"Status": "created"}, 1),
            ({"Running": True}, 1),
            ({"Error": "failed to start container"}, 1),
            ({"ExitCode": 0}, 1),
            ({"ExitCode": True}, 1),
            ([], 1),
            ({}, True),
        )
        for state_over, process_returncode in cases:
            with self.subTest(
                state_over=state_over,
                process_returncode=process_returncode,
            ):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    mounts = {}
                    for key, _destination in contained.DEFAULT_MOUNT_SPEC:
                        path = root / key
                        path.mkdir()
                        mounts[key] = path
                    with self.assertRaises(contained.ContainerSetupError):
                        contained.run_contained(
                            image_id="sha256:" + ("ab" * 32),
                            mounts=mounts,
                            command=["disk"],
                            entrypoint="/probe",
                            mount_spec=contained.DEFAULT_MOUNT_SPEC,
                            resource_profile=contained.INERT_RESOURCE_PROFILE,
                            sealed=True,
                            name_prefix="probe-",
                            transport=FailedStart(
                                state_over,
                                process_returncode=process_returncode,
                            ),
                        )

    def test_exceptional_start_requires_an_observed_started_container(self):
        contained = self._contained_oci()

        class ExceptionalStart:
            skip_absent = False

            def __init__(self, failure, state_over):
                self.failure = failure
                self.state_over = state_over

            def create(self, _argv):
                pass

            def start(self, _name, _deadline):
                raise self.failure

            def inspect(self, _name):
                return _inspect_fixture(
                    contained,
                    state_over=self.state_over,
                )

            def remove(self, _name):
                pass

            def require_absent(self, _name):
                pass

        failures = (
            subprocess.TimeoutExpired(["docker", "start"], 1),
            contained.br._OutputTooLarge(),
        )
        invalid_states = (
            {"Status": "created"},
            {"Error": "failed to start container"},
        )
        for failure in failures:
            for state_over in invalid_states:
                with self.subTest(
                    failure=type(failure).__name__,
                    state_over=state_over,
                ):
                    with tempfile.TemporaryDirectory() as raw:
                        root = Path(raw)
                        mounts = {}
                        for key, _destination in contained.DEFAULT_MOUNT_SPEC:
                            path = root / key
                            path.mkdir()
                            mounts[key] = path
                        with self.assertRaises(contained.ContainerSetupError):
                            contained.run_contained(
                                image_id="sha256:" + ("ab" * 32),
                                mounts=mounts,
                                command=["deadline"],
                                entrypoint="/probe",
                                mount_spec=contained.DEFAULT_MOUNT_SPEC,
                                resource_profile=contained.INERT_RESOURCE_PROFILE,
                                sealed=True,
                                name_prefix="probe-",
                                transport=ExceptionalStart(
                                    failure,
                                    state_over,
                                ),
                            )

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            mounts = {}
            for key, _destination in contained.DEFAULT_MOUNT_SPEC:
                path = root / key
                path.mkdir()
                mounts[key] = path
            result = contained.run_contained(
                image_id="sha256:" + ("ab" * 32),
                mounts=mounts,
                command=["deadline"],
                entrypoint="/probe",
                mount_spec=contained.DEFAULT_MOUNT_SPEC,
                resource_profile=contained.INERT_RESOURCE_PROFILE,
                sealed=True,
                name_prefix="probe-",
                transport=ExceptionalStart(
                    subprocess.TimeoutExpired(["docker", "start"], 1),
                    {"Status": "running", "Running": True},
                ),
            )
        self.assertEqual(result["state"], "timeout")

    def test_materialize_docker_phases_share_missing_executable_mapping(self):
        contained = self._contained_oci()
        missing = FileNotFoundError("docker")

        with mock.patch.object(contained.br, "_run_capped", side_effect=missing):
            with self.assertRaises(contained.DockerUnavailable):
                materialize._observe_image_cmd(
                    "sha256:" + ("ab" * 32), ["rustc", "-Vv"])
            with self.assertRaises(contained.DockerUnavailable):
                materialize.pull_rust_image()

            toolchain = {
                "cargo_V": "cargo %s" % materialize.RUSTC_RELEASE,
                "image_id": "sha256:" + ("cd" * 32),
                "index": materialize.RUST_IMAGE,
                "observation": "vendor-image; checker was not run",
                "platform": "linux/amd64",
                "rustc_Vv": "rustc %s" % materialize.RUSTC_RELEASE,
            }
            with tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                subject = root / "subject"
                vendor = root / "vendor"
                subject.mkdir()
                with mock.patch.object(
                    materialize, "docker_bounded", return_value=b""
                ), mock.patch.object(
                    materialize, "docker_ok", return_value=None
                ), mock.patch.object(
                    materialize, "require_container_absent", return_value=None
                ):
                    with self.assertRaises(contained.DockerUnavailable):
                        materialize.vendor_locked(
                            subject,
                            vendor,
                            toolchain=toolchain,
                        )

    def test_cleanup_failure_has_a_named_cleanup_type(self):
        contained = self._contained_oci()

        class FailedRemove:
            def remove(self, _name):
                raise contained.PrepareError("remove failed")

            def require_absent(self, _name):
                pass

        with self.assertRaises(contained.ContainerCleanupError):
            contained.cleanup_container(
                FailedRemove(), "candidate", None, "candidate")

    def test_shared_create_argv_owns_every_required_limit(self):
        contained = self._contained_oci()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            mounts = {}
            for key, _destination in contained.DEFAULT_MOUNT_SPEC:
                path = root / key
                path.mkdir()
                mounts[key] = path
            argv = contained.docker_create_argv(
                image_id="sha256:" + ("ef" * 32),
                name="candidate",
                mounts=mounts,
                command=["ok"],
            )

        self.assertIn("--read-only", argv)
        self.assertEqual(argv[argv.index("--cap-drop") + 1], "ALL")
        self.assertEqual(
            argv[argv.index("--security-opt") + 1],
            "no-new-privileges:true",
        )
        self.assertEqual(argv[argv.index("--network") + 1], "none")
        self.assertEqual(argv[argv.index("--memory") + 1], "4g")
        self.assertEqual(argv[argv.index("--memory-swap") + 1], "4g")
        self.assertEqual(argv[argv.index("--pids-limit") + 1], "512")
        self.assertIn("CARGO_NET_OFFLINE=true", argv)
        bind_specs = [argv[i + 1] for i, value in enumerate(argv) if value == "--mount"]
        self.assertEqual(len(bind_specs), len(contained.DEFAULT_MOUNT_SPEC))
        self.assertTrue(all(spec.endswith(",readonly") for spec in bind_specs))

    def test_candidate_lifecycle_refuses_mounts_outside_its_declared_spec(self):
        contained = self._contained_oci()

        class UnexpectedCreate:
            skip_absent = False

            def create(self, _argv):
                raise AssertionError("extra mounts reached docker create")

            def remove(self, _name):
                pass

            def require_absent(self, _name):
                pass

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            mounts = {}
            for key, _destination in candidate.CANDIDATE_MOUNT_SPEC:
                path = root / key
                path.mkdir()
                mounts[key] = path
            extra = root / "extra"
            extra.mkdir()
            mounts["extra"] = extra

            with self.assertRaisesRegex(contained.PrepareError, "unexpected mount"):
                candidate._run_sealed_candidate(
                    image_id="sha256:" + ("ab" * 32),
                    mounts=mounts,
                    resource_profile=common.CANDIDATE_RESOURCE_PROFILE,
                    transport=UnexpectedCreate(),
                )


if __name__ == "__main__":
    unittest.main()
