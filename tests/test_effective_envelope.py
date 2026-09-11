#!/usr/bin/env python3
"""RED-first sibling execution-envelope record (#106).

Standard library only. The record is a sibling artifact: `report.v0`,
`prepare.v1`, `survivors.v0` and published bytes are unchanged. Publication
enforcement is not implemented here; it stays owned by #107.
"""

from __future__ import annotations

import copy
import inspect as inspect_mod
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "measurements"))

import corpus_adequacy as ca  # noqa: E402
import contained_oci as contained  # noqa: E402
import effective_envelope as env  # noqa: E402
import aee_checker_sealed_candidate as candidate  # noqa: E402
import aee_checker_sealed_common as common  # noqa: E402
import aee_checker_sealed_run as run  # noqa: E402

IMAGE = "sha256:" + ("ab" * 32)
OTHER_IMAGE = "sha256:" + ("cd" * 32)
RUNTIME_VERSION = "27.1.1"
PREPARE_RUNTIME_VERSION = "20.10.0"
PREPARE_SHA256 = "e" * 64
EXECUTION_COMMIT = "f" * 40
REPORT_SHA256 = "1" * 64
IMAGE_ENV_NAMES = ("CARGO_HOME", "PATH", "RUSTUP_HOME")


def _profile():
    return contained.CANDIDATE_RESOURCE_PROFILE


def _tmpfs(value: int, inodes: int, *, exec_bit: bool = False) -> str:
    spec = "rw,size=%d,nr_inodes=%d,mode=1777" % (value, inodes)
    return spec + ",exec" if exec_bit else spec


def _inspect(*, profile=None, image=IMAGE) -> dict:
    profile = profile or _profile()
    return {
        "Image": image,
        "Config": {
            "User": "65532:65532",
            "Env": [
                "PATH=/usr/local/bin",
                "RUSTUP_HOME=/usr/local/rustup",
                "CARGO_HOME=/tool",
                "CARGO_NET_OFFLINE=true",
            ],
        },
        "HostConfig": {
            "CapAdd": None,
            "CapDrop": ["ALL"],
            "Devices": None,
            "Memory": profile["memory_bytes"],
            "MemorySwap": profile["memory_swap_bytes"],
            "NetworkMode": "none",
            "PidMode": "",
            "PidsLimit": profile["pids"],
            "Privileged": False,
            "ReadonlyRootfs": True,
            "SecurityOpt": ["no-new-privileges:true"],
            "Tmpfs": {
                "/tmp": _tmpfs(profile["tmp_bytes"], profile["tmp_inodes"]),
                "/work": _tmpfs(profile["work_bytes"], profile["work_inodes"],
                                exec_bit=profile["work_exec"]),
            },
            "UsernsMode": "",
        },
        "Mounts": [
            {"Destination": destination, "RW": False, "Type": "bind"}
            for _key, destination in candidate.CANDIDATE_MOUNT_SPEC
        ],
        "State": {"Error": "", "ExitCode": 0, "Running": False, "Status": "exited"},
    }


def _requested(*, profile=None, image=IMAGE, sealed=True):
    return env.requested_envelope(
        execution_profile="contained-oci-v0",
        image_id=image,
        mount_spec=candidate.CANDIDATE_MOUNT_SPEC,
        resource_profile=profile or _profile(),
        sealed=sealed,
    )


def _effective(doc=None, *, runtime_version=RUNTIME_VERSION):
    return env.project_effective_envelope(
        _inspect() if doc is None else doc,
        image_env_names=IMAGE_ENV_NAMES,
        runtime_version=runtime_version)


def _verified_record(**over):
    fields = {
        "requested": _requested(),
        "setup_status": "ready",
        "envelope_status": "verified",
        "unverified_field": None,
        "effective": _effective(),
        "candidate_outcome": "completed",
        "cleanup": "removed-and-absent",
        "prepare_sha256": PREPARE_SHA256,
        "execution_commit": EXECUTION_COMMIT,
        "report_sha256": REPORT_SHA256,
    }
    fields.update(over)
    return env.build_envelope_record(**fields)


class ObservationOnlyProjector(unittest.TestCase):
    def test_projector_owns_the_closed_effective_keyset(self):
        self.assertEqual(tuple(sorted(_effective())), env.EFFECTIVE_KEYS)

    def test_absent_observation_is_unverified_not_a_satisfied_empty(self):
        paths = {
            "Image": ("Image",),
            "Config.Env": ("Config", "Env"),
            "Config.User": ("Config", "User"),
            "HostConfig.CapAdd": ("HostConfig", "CapAdd"),
            "HostConfig.CapDrop": ("HostConfig", "CapDrop"),
            "HostConfig.Devices": ("HostConfig", "Devices"),
            "HostConfig.Memory": ("HostConfig", "Memory"),
            "HostConfig.MemorySwap": ("HostConfig", "MemorySwap"),
            "HostConfig.NetworkMode": ("HostConfig", "NetworkMode"),
            "HostConfig.PidMode": ("HostConfig", "PidMode"),
            "HostConfig.PidsLimit": ("HostConfig", "PidsLimit"),
            "HostConfig.Privileged": ("HostConfig", "Privileged"),
            "HostConfig.ReadonlyRootfs": ("HostConfig", "ReadonlyRootfs"),
            "HostConfig.SecurityOpt": ("HostConfig", "SecurityOpt"),
            "HostConfig.Tmpfs": ("HostConfig", "Tmpfs"),
            "HostConfig.UsernsMode": ("HostConfig", "UsernsMode"),
            "Mounts": ("Mounts",),
        }
        for name, path in paths.items():
            with self.subTest(observation=name):
                doc = _inspect()
                node = doc
                for key in path[:-1]:
                    node = node[key]
                del node[path[-1]]
                with self.assertRaises(env.EnvelopeError) as ctx:
                    _effective(doc)
                self.assertEqual(str(ctx.exception), name)

    def test_non_bool_boolean_observation_is_never_coerced(self):
        """A daemon that reports a non-bool has not answered the question.

        Coercing `0`, `""` or `null` to False would let a hardening flag be
        satisfied by a value that never said `false`.
        """
        for path in (("HostConfig", "Privileged"),
                     ("HostConfig", "ReadonlyRootfs")):
            for value in (0, 1, "", "true", "false", None, [], {}):
                with self.subTest(observation=".".join(path), value=value):
                    doc = _inspect()
                    doc[path[0]][path[1]] = value
                    with self.assertRaises(env.EnvelopeError) as ctx:
                        _effective(doc)
                    self.assertEqual(str(ctx.exception), ".".join(path))

    def test_json_null_list_is_an_observed_empty_not_an_absence(self):
        doc = _inspect()
        doc["HostConfig"]["CapAdd"] = None
        doc["HostConfig"]["Devices"] = None
        effective = _effective(doc)
        self.assertEqual(effective["cap_add"], [])
        self.assertEqual(effective["devices"], [])

    def test_environment_values_are_never_observed_or_recorded(self):
        doc = _inspect()
        doc["Config"]["Env"].append("AWS_SECRET_ACCESS_KEY=super-secret-value")
        effective = _effective(doc)
        self.assertIn("AWS_SECRET_ACCESS_KEY", effective["env_names"])
        blob = json.dumps(effective, sort_keys=True)
        self.assertNotIn("super-secret-value", blob)
        self.assertNotIn("=", "".join(effective["env_names"]))

    def test_missing_runtime_version_is_unverified(self):
        for bad in (None, "", 27):
            with self.subTest(runtime_version=bad):
                with self.assertRaises(env.EnvelopeError):
                    _effective(runtime_version=bad)

    def test_missing_image_environment_observation_is_unverified(self):
        for bad in (None, "PATH", 3):
            with self.subTest(image_env_names=bad):
                with self.assertRaises(env.EnvelopeError):
                    env.project_effective_envelope(
                        _inspect(), image_env_names=bad,
                        runtime_version=RUNTIME_VERSION)

    def test_mounts_are_a_complete_sorted_inventory(self):
        doc = _inspect()
        doc["Mounts"].append(
            {"Destination": "/var/run/docker.sock", "RW": True, "Type": "bind"})
        effective = _effective(doc)
        self.assertEqual(
            effective["mounts"],
            sorted(effective["mounts"], key=lambda row: row["destination"]))
        self.assertIn(
            {"destination": "/var/run/docker.sock", "rw": True, "type": "bind"},
            effective["mounts"])

    def test_projector_source_uses_no_defaulting_accessor(self):
        source = inspect_mod.getsource(env.project_effective_envelope)
        source += inspect_mod.getsource(env._observed)
        source += inspect_mod.getsource(env._observed_list)
        for banned in (" or []", " or {}", " or ()", " or \"\""):
            self.assertNotIn(banned, source)
        self.assertIsNone(re.search(r"\.get\([^)]*,", source))

    def test_projector_takes_only_observations_never_a_declaration(self):
        signature = inspect_mod.signature(env.project_effective_envelope)
        self.assertEqual(
            list(signature.parameters),
            ["inspect", "image_env_names", "runtime_version"])
        for declared in env.REQUESTED_KEYS:
            self.assertNotIn(declared, signature.parameters)

    def test_allowed_environment_is_observed_from_the_pinned_image(self):
        self.assertIn("image_env_names", env.EFFECTIVE_KEYS)
        self.assertNotIn("image_env_names", env.REQUESTED_KEYS)


class ComparatorRefusals(unittest.TestCase):
    def _refuses(self, mutate, *, field):
        doc = _inspect()
        mutate(doc)
        try:
            effective = _effective(doc)
        except env.EnvelopeError as exc:
            self.assertEqual(str(exc), field)
            return
        with self.assertRaises(env.EnvelopeError) as ctx:
            env.require_envelope_matches_request(effective, _requested())
        self.assertEqual(str(ctx.exception), field)

    def test_conformant_envelope_is_accepted(self):
        env.require_envelope_matches_request(_effective(), _requested())

    def test_privileged_refuses(self):
        self._refuses(
            lambda d: d["HostConfig"].__setitem__("Privileged", True),
            field="privileged")

    def test_added_capability_refuses(self):
        self._refuses(
            lambda d: d["HostConfig"].__setitem__("CapAdd", ["SYS_ADMIN"]),
            field="cap_add")

    def test_dropped_capability_drift_refuses(self):
        self._refuses(
            lambda d: d["HostConfig"].__setitem__("CapDrop", ["NET_RAW"]),
            field="cap_drop")

    def test_host_pid_namespace_refuses(self):
        self._refuses(
            lambda d: d["HostConfig"].__setitem__("PidMode", "host"),
            field="pid_mode")

    def test_host_user_namespace_refuses(self):
        self._refuses(
            lambda d: d["HostConfig"].__setitem__("UsernsMode", "host"),
            field="userns_mode")

    def test_device_entry_refuses(self):
        self._refuses(
            lambda d: d["HostConfig"].__setitem__(
                "Devices", [{"PathInContainer": "/dev/kmsg",
                             "PathOnHost": "/dev/kmsg"}]),
            field="devices")

    def test_observed_image_must_equal_the_requested_immutable_id(self):
        self._refuses(
            lambda d: d.__setitem__("Image", OTHER_IMAGE), field="image")

    def test_unexpected_environment_name_refuses_without_leaking_values(self):
        doc = _inspect()
        doc["Config"]["Env"].append("AWS_SECRET_ACCESS_KEY=super-secret-value")
        with self.assertRaises(env.EnvelopeError) as ctx:
            env.require_envelope_matches_request(_effective(doc), _requested())
        self.assertEqual(str(ctx.exception), "env_names")
        self.assertNotIn("super-secret-value", str(ctx.exception))

    def test_offline_environment_must_match_the_sealed_posture(self):
        doc = _inspect()
        doc["Config"]["Env"] = [
            item for item in doc["Config"]["Env"]
            if not item.startswith("CARGO_NET_OFFLINE=")]
        with self.assertRaises(env.EnvelopeError) as ctx:
            env.require_envelope_matches_request(_effective(doc), _requested())
        self.assertEqual(str(ctx.exception), "env_names")

    def test_docker_socket_mount_refuses(self):
        self._refuses(
            lambda d: d["Mounts"].append(
                {"Destination": "/var/run/docker.sock", "RW": True,
                 "Type": "bind"}),
            field="mounts")

    def test_writable_source_mount_refuses(self):
        def mutate(doc):
            for row in doc["Mounts"]:
                if row["Destination"] == "/subject":
                    row["RW"] = True
        self._refuses(mutate, field="mounts")

    def test_wrong_mount_type_refuses(self):
        def mutate(doc):
            for row in doc["Mounts"]:
                if row["Destination"] == "/subject":
                    row["Type"] = "volume"
        self._refuses(mutate, field="mounts")

    def test_missing_required_mount_refuses(self):
        self._refuses(
            lambda d: d["Mounts"].pop(), field="mounts")

    def test_network_must_match_the_sealed_posture(self):
        self._refuses(
            lambda d: d["HostConfig"].__setitem__("NetworkMode", "bridge"),
            field="network_mode")

    def test_limits_must_match_the_requested_resource_profile(self):
        cases = {
            "memory": lambda d: d["HostConfig"].__setitem__("Memory", 1),
            "memory_swap": lambda d: d["HostConfig"].__setitem__("MemorySwap", 1),
            "pids_limit": lambda d: d["HostConfig"].__setitem__("PidsLimit", 1),
        }
        for field, mutate in cases.items():
            with self.subTest(field=field):
                self._refuses(mutate, field=field)

    def test_tmpfs_byte_and_inode_limits_must_match(self):
        self._refuses(
            lambda d: d["HostConfig"]["Tmpfs"].__setitem__(
                "/work", _tmpfs(64, 4, exec_bit=True)),
            field="tmpfs")

    def test_hardening_flags_must_be_observed_true(self):
        cases = {
            "read_only_root": lambda d: d["HostConfig"].__setitem__(
                "ReadonlyRootfs", False),
            "no_new_privileges": lambda d: d["HostConfig"].__setitem__(
                "SecurityOpt", []),
            "user": lambda d: d["Config"].__setitem__("User", "0:0"),
        }
        for field, mutate in cases.items():
            with self.subTest(field=field):
                self._refuses(mutate, field=field)

    def test_an_inert_probe_envelope_cannot_satisfy_a_candidate_run(self):
        probe = _inspect(profile=contained.INERT_RESOURCE_PROFILE)
        effective = _effective(probe)
        with self.assertRaises(env.EnvelopeError):
            env.require_envelope_matches_request(effective, _requested())

    def test_prepare_runtime_string_cannot_substitute_for_the_run(self):
        record = _verified_record(
            effective=_effective(runtime_version=RUNTIME_VERSION))
        self.assertEqual(record["effective"]["runtime_version"], RUNTIME_VERSION)
        self.assertNotEqual(
            record["effective"]["runtime_version"], PREPARE_RUNTIME_VERSION)
        self.assertNotIn(
            "runtime_version", env.REQUESTED_KEYS)


class ClosedRecordKeyset(unittest.TestCase):
    def test_record_keyset_is_closed_and_frozen(self):
        self.assertEqual(tuple(sorted(_verified_record())), env.ENVELOPE_KEYS)

    def test_requested_keyset_is_closed(self):
        self.assertEqual(tuple(sorted(_requested())), env.REQUESTED_KEYS)

    def test_deleting_any_required_observed_field_prevents_recording(self):
        for field in env.EFFECTIVE_KEYS:
            with self.subTest(field=field):
                effective = _effective()
                del effective[field]
                with self.assertRaises(env.EnvelopeError):
                    _verified_record(effective=effective)

    def test_unknown_observed_field_prevents_recording(self):
        effective = _effective()
        effective["seccomp"] = "unconfined"
        with self.assertRaises(env.EnvelopeError):
            _verified_record(effective=effective)

    def test_comparator_covers_every_projected_field(self):
        for field in env.EFFECTIVE_KEYS:
            with self.subTest(field=field):
                effective = _effective()
                del effective[field]
                with self.assertRaises(env.EnvelopeError):
                    env.require_envelope_matches_request(effective, _requested())

    def test_record_is_canonical_json_bytes(self):
        raw = env.encode_envelope(_verified_record())
        self.assertEqual(raw, common.encode_json(_verified_record()))
        self.assertTrue(raw.endswith(b"\n"))


class ClosedStateModel(unittest.TestCase):
    def test_verified_completed_clean_run_is_permitted(self):
        record = _verified_record()
        self.assertEqual(record["publication_permission"], "permitted")
        self.assertIsNone(record["withheld_reason"])
        self.assertEqual(record["schema"], env.ENVELOPE_SCHEMA)

    def test_completed_candidate_with_failed_absence_proof_is_withheld(self):
        record = _verified_record(cleanup="absence-unproved")
        self.assertEqual(record["candidate_outcome"], "completed")
        self.assertEqual(record["cleanup"], "absence-unproved")
        self.assertEqual(record["publication_permission"], "withheld")
        self.assertEqual(record["withheld_reason"], "cleanup")

    def test_cleanup_success_cannot_validate_a_refused_setup(self):
        record = env.build_envelope_record(
            requested=_requested(),
            setup_status="refused",
            envelope_status="unverified",
            unverified_field="HostConfig.Privileged",
            effective=None,
            candidate_outcome="not-run",
            cleanup="removed-and-absent",
            prepare_sha256=PREPARE_SHA256,
            execution_commit=EXECUTION_COMMIT,
            report_sha256=None,
        )
        self.assertEqual(record["setup_status"], "refused")
        self.assertEqual(record["publication_permission"], "withheld")
        self.assertEqual(record["withheld_reason"], "setup_status")

    def test_unavailable_setup_cannot_carry_a_candidate_outcome(self):
        for outcome in ("completed", "timeout", "output-cap", "unproved"):
            for status in ("unavailable", "refused"):
                with self.subTest(outcome=outcome, setup_status=status):
                    with self.assertRaises(env.EnvelopeError):
                        env.build_envelope_record(
                            requested=_requested(),
                            setup_status=status,
                            envelope_status="unverified",
                            unverified_field="docker",
                            effective=None,
                            candidate_outcome=outcome,
                            cleanup="removed-and-absent",
                            prepare_sha256=PREPARE_SHA256,
                            execution_commit=EXECUTION_COMMIT,
                            report_sha256=None,
                        )

    def test_unverified_envelope_cannot_carry_effective_values(self):
        with self.assertRaises(env.EnvelopeError):
            _verified_record(
                envelope_status="unverified", unverified_field="image")

    def test_verified_envelope_requires_effective_and_no_named_field(self):
        with self.assertRaises(env.EnvelopeError):
            _verified_record(effective=None)
        with self.assertRaises(env.EnvelopeError):
            _verified_record(unverified_field="image")

    def test_non_completed_candidate_outcomes_are_withheld(self):
        for outcome in ("timeout", "output-cap", "unproved"):
            with self.subTest(outcome=outcome):
                record = _verified_record(
                    candidate_outcome=outcome, report_sha256=None)
                self.assertEqual(record["publication_permission"], "withheld")
                self.assertEqual(record["withheld_reason"], "candidate_outcome")

    def test_each_state_withholds_under_its_own_name(self):
        """One deviating state at a time, so no branch can be deleted silently.

        Every case below is otherwise publishable, so a missing branch
        returns `permitted` rather than falling through to another reason.
        """
        publishable = {
            "setup_status": "ready",
            "envelope_status": "verified",
            "candidate_outcome": "completed",
            "cleanup": "removed-and-absent",
        }
        deviations = {
            "setup_status": "unavailable",
            "envelope_status": "unverified",
            "candidate_outcome": "timeout",
            "cleanup": "absence-unproved",
        }
        self.assertEqual(
            env.publication_permission(**publishable), ("permitted", None))
        for state, value in deviations.items():
            with self.subTest(state=state):
                states = dict(publishable)
                states[state] = value
                self.assertEqual(
                    env.publication_permission(**states), ("withheld", state))

    def test_unverified_envelope_withholds_by_envelope_status(self):
        record = env.build_envelope_record(
            requested=_requested(),
            setup_status="ready",
            envelope_status="unverified",
            unverified_field="privileged",
            effective=None,
            candidate_outcome="completed",
            cleanup="removed-and-absent",
            prepare_sha256=PREPARE_SHA256,
            execution_commit=EXECUTION_COMMIT,
            report_sha256=None,
        )
        self.assertEqual(record["publication_permission"], "withheld")
        self.assertEqual(record["withheld_reason"], "envelope_status")

    def test_builder_refuses_a_verified_record_that_contradicts_the_request(self):
        """The record cannot be built around an unchecked observation.

        The comparator is reachable on its own, so calling it directly is
        not evidence that the builder calls it too.
        """
        cases = {
            "privileged": lambda d: d["HostConfig"].__setitem__("Privileged", True),
            "cap_add": lambda d: d["HostConfig"].__setitem__("CapAdd", ["SYS_ADMIN"]),
            "image": lambda d: d.__setitem__("Image", OTHER_IMAGE),
        }
        for field, mutate in cases.items():
            with self.subTest(field=field):
                doc = _inspect()
                mutate(doc)
                effective = _effective(doc)
                self.assertEqual(tuple(sorted(effective)), env.EFFECTIVE_KEYS)
                with self.assertRaises(env.EnvelopeError) as ctx:
                    _verified_record(effective=effective)
                self.assertEqual(str(ctx.exception), field)

    def test_publication_permission_is_never_caller_supplied(self):
        parameters = inspect_mod.signature(env.build_envelope_record).parameters
        self.assertNotIn("publication_permission", parameters)
        self.assertNotIn("withheld_reason", parameters)

    def test_closed_vocabularies_refuse_unknown_members(self):
        for field, bad in (
            ("setup_status", "ok"),
            ("envelope_status", "degraded"),
            ("candidate_outcome", "killed"),
            ("cleanup", "done"),
        ):
            with self.subTest(field=field):
                with self.assertRaises(env.EnvelopeError):
                    _verified_record(**{field: bad})

    def test_v0_has_no_degraded_state(self):
        self.assertEqual(env.ENVELOPE_STATUSES, ("verified", "unverified"))
        self.assertNotIn("degraded", env.ENVELOPE_STATUSES)

    def test_binding_digests_are_shape_checked(self):
        with self.assertRaises(env.EnvelopeError):
            _verified_record(prepare_sha256="short")
        with self.assertRaises(env.EnvelopeError):
            _verified_record(execution_commit="short")
        with self.assertRaises(env.EnvelopeError):
            _verified_record(report_sha256="short")
        self.assertIsNone(_verified_record(report_sha256=None)["report_sha256"])

    def test_record_states_its_non_claims(self):
        text = " ".join(_verified_record()["non_claims"]).lower()
        for phrase in ("escape", "side channel", "certification", "score"):
            self.assertIn(phrase, text)


class ContainedLifecycleRecordsCleanup(unittest.TestCase):
    class _Transport:
        skip_absent = False

        def __init__(self, *, remove=None, absent=None, inspect_doc=None):
            self._remove, self._absent = remove, absent
            self._inspect = inspect_doc

        def create(self, _argv):
            # Observed: no create-time warnings. None would mean "not observed" and leave the
            # recorded envelope unverified as create_warnings.
            return ()

        def start(self, _name, _deadline):
            return subprocess.CompletedProcess([], 0, "{}\n", "")

        def inspect(self, _name):
            return copy.deepcopy(self._inspect)

        def remove(self, _name):
            if self._remove is not None:
                raise self._remove

        def require_absent(self, _name):
            if self._absent is not None:
                raise self._absent

        def version(self):
            return RUNTIME_VERSION

        def image_env_names(self, _image_id):
            return IMAGE_ENV_NAMES

    def _run(self, transport, *, record_cleanup):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            mounts = {}
            for key, _destination in candidate.CANDIDATE_MOUNT_SPEC:
                path = root / key
                path.mkdir()
                mounts[key] = path
            return contained.run_contained(
                image_id=IMAGE,
                mounts=mounts,
                command=["-lc", "true"],
                entrypoint="/bin/sh",
                mount_spec=candidate.CANDIDATE_MOUNT_SPEC,
                resource_profile=_profile(),
                sealed=True,
                name_prefix="probe-",
                transport=transport,
                record_cleanup=record_cleanup,
            )

    def test_clean_lifecycle_records_removed_and_absent(self):
        result = self._run(
            self._Transport(inspect_doc=_inspect()), record_cleanup=True)
        self.assertEqual(result["cleanup"], "removed-and-absent")
        self.assertEqual(result["state"], "completed")

    def test_completed_run_survives_a_failed_absence_proof(self):
        result = self._run(
            self._Transport(
                absent=contained.PrepareError("still present"),
                inspect_doc=_inspect()),
            record_cleanup=True)
        self.assertEqual(result["state"], "completed")
        self.assertEqual(result["cleanup"], "absence-unproved")

    def test_completed_run_survives_a_failed_remove(self):
        result = self._run(
            self._Transport(
                remove=contained.PrepareError("remove failed"),
                inspect_doc=_inspect()),
            record_cleanup=True)
        self.assertEqual(result["state"], "completed")
        self.assertEqual(result["cleanup"], "remove-failed")

    def test_default_lifecycle_still_refuses_a_failed_absence_proof(self):
        with self.assertRaises(contained.ContainerCleanupError):
            self._run(
                self._Transport(
                    absent=contained.PrepareError("still present"),
                    inspect_doc=_inspect()),
                record_cleanup=False)

    def test_cleanup_container_direct_call_still_refuses(self):
        class FailedRemove:
            def remove(self, _name):
                raise contained.PrepareError("remove failed")

            def require_absent(self, _name):
                return None

        with self.assertRaises(contained.ContainerCleanupError):
            contained.cleanup_container(FailedRemove(), "c", None, "candidate")


class CandidatePathBindsTheEnvelope(unittest.TestCase):
    def _run(self, transport):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            mounts = {}
            for key, _destination in candidate.CANDIDATE_MOUNT_SPEC:
                path = root / key
                path.mkdir()
                mounts[key] = path
            (mounts["input"] / "vectors").mkdir()
            return candidate._run_sealed_candidate(
                image_id=IMAGE,
                mounts=mounts,
                resource_profile=_profile(),
                execution_profile="contained-oci-v0",
                transport=transport,
                binding=candidate.envelope_binding(
                    prepare_sha256=PREPARE_SHA256,
                    execution_commit=EXECUTION_COMMIT,
                ),
            )

    def test_candidate_run_attaches_an_envelope_record(self):
        completed = self._run(
            ContainedLifecycleRecordsCleanup._Transport(inspect_doc=_inspect()))
        record = getattr(completed, "envelope_record", None)
        self.assertIsInstance(record, dict)
        self.assertEqual(tuple(sorted(record)), env.ENVELOPE_KEYS)
        self.assertEqual(record["setup_status"], "ready")
        self.assertEqual(record["envelope_status"], "verified")

    def test_docker_unavailable_records_unavailable_and_not_run(self):
        class Unavailable(ContainedLifecycleRecordsCleanup._Transport):
            def create(self, _argv):
                raise contained.DockerUnavailable("docker missing")

        completed = self._run(Unavailable(inspect_doc=_inspect()))
        record = completed.envelope_record
        self.assertEqual(record["setup_status"], "unavailable")
        self.assertEqual(record["candidate_outcome"], "not-run")
        self.assertEqual(record["publication_permission"], "withheld")

    def test_privileged_candidate_is_unverified_and_withheld(self):
        doc = _inspect()
        doc["HostConfig"]["Privileged"] = True
        completed = self._run(
            ContainedLifecycleRecordsCleanup._Transport(inspect_doc=doc))
        record = completed.envelope_record
        self.assertEqual(record["envelope_status"], "unverified")
        self.assertEqual(record["unverified_field"], "privileged")
        self.assertEqual(record["publication_permission"], "withheld")


class SiblingArtifactCompatibility(unittest.TestCase):
    def test_report_v0_gains_no_envelope_field(self):
        for runner in ("module", "process", "batch"):
            with self.subTest(runner=runner):
                keys = ca._report_v0_keys(runner)
                for banned in ("envelope", "execution_profile",
                               "publication_permission", "effective"):
                    self.assertNotIn(banned, keys)

    def test_prepare_keysets_gain_no_envelope_field(self):
        for keys in (run.PREPARE_KEYS, run.PREPARE_V1_KEYS):
            for banned in ("envelope", "effective", "publication_permission"):
                self.assertNotIn(banned, keys)

    def test_new_execution_module_is_a_declared_execution_path(self):
        self.assertIn("measurements/effective_envelope.py", run.EXECUTION_PATHS)

    def test_profile_vocabulary_has_one_source(self):
        self.assertIn(env.CONTAINED_PROFILE, ca.CLOSED_EXECUTION_PROFILES)
        self.assertEqual(env.CONTAINED_USER, contained.CONTAINED_USER)

    def test_legacy_unbound_candidate_run_keeps_no_record(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            mounts = {}
            for key, _destination in candidate.CANDIDATE_MOUNT_SPEC:
                path = root / key
                path.mkdir()
                mounts[key] = path
            (mounts["input"] / "vectors").mkdir()
            completed = candidate._run_sealed_candidate(
                image_id=IMAGE,
                mounts=mounts,
                resource_profile=_profile(),
                transport=ContainedLifecycleRecordsCleanup._Transport(
                    inspect_doc=_inspect()),
            )
        self.assertIsNone(getattr(completed, "envelope_record", None))

    def test_report_digest_binds_envelope_to_report_not_back(self):
        record = _verified_record(report_sha256=None)
        bound = env.bind_report(record, REPORT_SHA256)
        self.assertEqual(bound["report_sha256"], REPORT_SHA256)
        self.assertIsNone(record["report_sha256"])

    def test_slice_implements_no_publication_enforcement(self):
        source = Path(REPO_ROOT / "measurements" / "effective_envelope.py").read_text(
            encoding="utf-8")
        for banned in ("publications/", "render_publication", "handoff", "site/"):
            self.assertNotIn(banned, source)


class PublicStrings(unittest.TestCase):
    def test_readme_states_the_sibling_record_and_its_non_claims(self):
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("envelope.v0", readme)
        self.assertIn("`report.v0` is unchanged", readme)
        self.assertIn("not a sandbox-completeness claim", readme)

    def test_v020_changelog_notes_the_fresh_prepare_requirement(self):
        changelog = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        # Keep the feature's release note pinned after Unreleased becomes empty.
        release = changelog.split("## 0.2.0 — ", 1)[1].split("\n## ", 1)[0]
        self.assertIn("envelope.v0", release)
        self.assertIn("PREPARE", release)



def _wire_v1_record():
    # Full legacy fixture, with literal additions independent of the v1 projector.
    record = _verified_record()
    record["schema"] = "corpus-adequacy.execution-envelope.v1"
    record["effective"].update(cpu_period=100000, cpu_quota=250000, nano_cpus=0,
        ulimit_nofile={"soft": 512, "hard": 2048}, daemon={
            "kernel_version": "synthetic-kernel", "cgroup_version": "2",
            "cgroup_driver": "systemd", "security_options": ["name=seccomp"]})
    return record


class EnvelopeV1Validation(unittest.TestCase):
    def test_explicit_valid_v1_survives_shared_validator_and_report_binding(self):
        record = _wire_v1_record()
        try:
            result = env.validate_envelope_record(record)
        except env.EnvelopeError as exc:
            self.fail("valid explicit v1 refused by actual stored validator: " + str(exc))
        self.assertEqual(result, record)
        effective = _project_v1()
        projected = copy.deepcopy(record); projected["effective"] = effective
        env.require_envelope_matches_request(effective, projected["requested"], schema=env.ENVELOPE_SCHEMA_V1)
        bound = env.bind_report(projected, REPORT_SHA256)
        self.assertEqual(bound["effective"], effective)
        self.assertEqual(env.validate_envelope_record(bound), bound)
        import envelope_collection as collection
        with tempfile.TemporaryDirectory() as raw:
            ledger = collection.Ledger(); ordinal = ledger.register(); ledger.recorded(ordinal, bound)
            dest = Path(raw) / "collection"
            collection.write_collection(ledger, dest, report_sha256=REPORT_SHA256)
            collection.load_collection(dest)
            stored = json.loads(next(dest.glob("member-*.json")).read_bytes())
            self.assertEqual(stored, bound)


    def test_direct_v1_negative_cpu_and_blank_daemon_refuse_at_shared_boundary(self):
        for field, value in (("cpu_quota", -1), ("cpu_period", True),
                             ("ulimit_nofile", {"soft": 5, "hard": 2})):
            record = _wire_v1_record(); record["effective"][field] = value
            with self.subTest(field=field), self.assertRaises(env.EnvelopeError):
                env.validate_envelope_record(record)
        record = _wire_v1_record(); record["effective"]["daemon"]["kernel_version"] = " "
        with self.assertRaisesRegex(env.EnvelopeError, "daemon.kernel_version"):
            env.bind_report(record, REPORT_SHA256)

    def test_v1_observation_shape_matrix(self):
        EnvelopeV1Observation().test_malformed_nested_observations_are_named_refusals()
        record = _wire_v1_record()
        for field, value in (("cpu_period", -1), ("cpu_quota", False),
                             ("ulimit_nofile", {}), ("ulimit_nofile", {"soft": 0, "hard": True})):
            bad = copy.deepcopy(record); bad["effective"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(env.EnvelopeError):
                env.bind_report(bad, REPORT_SHA256)
        for field, value in (("security_options", [None]), ("security_options", ["z", "a"]),
                             ("cgroup_version", ""), ("cgroup_driver", 2)):
            bad = copy.deepcopy(record); bad["effective"]["daemon"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(env.EnvelopeError):
                env.validate_envelope_record(bad)

    def test_stored_nano_cpus_must_be_a_non_negative_integer(self):
        """Stored-value validation, not the v2 comparison: this record carries a v0 request,
        which compares no CPU value, so only the shared stored-value rule can refuse."""
        for value in (-1, True, False, "0", 1.5, 0.0, None):
            record = _wire_v1_record(); record["effective"]["nano_cpus"] = value
            with self.subTest(value=value):
                with self.assertRaisesRegex(env.EnvelopeError, "^nano_cpus$"):
                    env.validate_envelope_record(record)
                with self.assertRaisesRegex(env.EnvelopeError, "^nano_cpus$"):
                    env.bind_report(record, REPORT_SHA256)
        record = _wire_v1_record(); del record["effective"]["nano_cpus"]
        with self.assertRaisesRegex(env.EnvelopeError, "^envelope_schema_shape$"):
            env.validate_envelope_record(record)

    def test_v1_malformed_stored_subtree_is_not_reconstruction_success(self):
        for value in (None, {}, {"kernel_version": "x"}):
            record = _wire_v1_record(); record["effective"]["daemon"] = value
            with self.assertRaises(env.EnvelopeError):
                env.validate_envelope_record(record)

    def test_unknown_or_shape_mismatched_schema_is_refused(self):
        for schema in ("unknown", env.ENVELOPE_SCHEMA):
            record = _wire_v1_record(); record["schema"] = schema
            with self.assertRaises(env.EnvelopeError):
                env.validate_envelope_record(record)
        record = _verified_record(); record["schema"] = env.ENVELOPE_SCHEMA_V1
        with self.assertRaisesRegex(env.EnvelopeError, "envelope_schema_shape"):
            env.validate_envelope_record(record)

    def test_v0_canonical_bytes_and_keysets_are_unchanged(self):
        record = _verified_record()
        encoded = env.encode_envelope(record)
        import hashlib
        # Historical v0 source at 540e9ea; full canonical bytes retained with writer evidence.
        self.assertEqual(hashlib.sha256(encoded).hexdigest(),
                         "f1d985dba1183bfc7848e0db521afb6696b8992fb6c565bb9547f988adb0bc8d")
        self.assertEqual(encoded, (json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode())
        self.assertEqual(len(record), 14)
        self.assertEqual(len(record["effective"]), 19)
        self.assertEqual(env.encode_envelope(env.validate_envelope_record(record)), encoded)


def _v1_inputs():
    doc = _inspect()
    doc["HostConfig"].update(CpuPeriod=100000, CpuQuota=250000, NanoCpus=0,
        Ulimits=[{"Name": "nofile", "Soft": 512, "Hard": 2048}])
    daemon = {"KernelVersion": "synthetic-kernel", "CgroupVersion": "2",
              "CgroupDriver": "systemd", "SecurityOptions": ["z", "a", "a"]}
    return doc, daemon


def _project_v1(doc=None, daemon=None):
    default_doc, default_daemon = _v1_inputs()
    return env.project_effective_envelope_v1(
        default_doc if doc is None else doc, image_env_names=IMAGE_ENV_NAMES,
        runtime_version=RUNTIME_VERSION,
        daemon_info=default_daemon if daemon is None else daemon)


class EnvelopeV1Observation(unittest.TestCase):
    def test_explicit_v1_projects_daemon_and_inspect_observations(self):
        value = _project_v1()
        self.assertEqual(set(value), set(env.EFFECTIVE_KEYS_V1))
        self.assertEqual(value["daemon"]["security_options"], ["a", "a", "z"])
        self.assertEqual(value["daemon"]["kernel_version"], "synthetic-kernel")

    def test_alternate_cpu_and_nofile_values_are_not_defaults(self):
        value = _project_v1()
        self.assertEqual((value["cpu_period"], value["cpu_quota"]), (100000, 250000))
        self.assertEqual(value["ulimit_nofile"], {"soft": 512, "hard": 2048})

    def test_nano_cpus_is_stored_as_the_daemon_reported_it(self):
        """The projector stores the observation; comparing it is the comparator's job."""
        self.assertEqual(_project_v1()["nano_cpus"], 0)
        doc, daemon = _v1_inputs(); doc["HostConfig"]["NanoCpus"] = 1000000000
        self.assertEqual(_project_v1(doc, daemon)["nano_cpus"], 1000000000)

    def test_absent_nano_cpus_is_unverified_not_unset(self):
        doc, daemon = _v1_inputs(); del doc["HostConfig"]["NanoCpus"]
        with self.assertRaisesRegex(env.EnvelopeError, "^HostConfig.NanoCpus$"):
            _project_v1(doc, daemon)

    def test_missing_daemon_fields_is_named_unverified(self):
        doc, daemon = _v1_inputs()
        for key in daemon:
            bad = dict(daemon); del bad[key]
            with self.subTest(key=key), self.assertRaisesRegex(env.EnvelopeError, "daemon." + key):
                _project_v1(doc, bad)

    def test_builder_unverified_state_requires_named_field_and_null_effective(self):
        good = _wire_v1_record()
        good.update(envelope_status="unverified", unverified_field="daemon.KernelVersion",
                    effective=None, publication_permission="withheld", withheld_reason="envelope_status")
        self.assertEqual(env.validate_envelope_record(good), good)
        good["effective"] = _project_v1()
        with self.assertRaisesRegex(env.EnvelopeError, "effective"):
            env.validate_envelope_record(good)

    def test_observed_unset_is_not_missing_or_applied(self):
        for limits in (None, [], [{"Name": "other"}]):
            doc, daemon = _v1_inputs(); doc["HostConfig"].update(CpuPeriod=0, CpuQuota=0, Ulimits=limits)
            value = _project_v1(doc, daemon)
            self.assertEqual((value["cpu_period"], value["cpu_quota"], value["ulimit_nofile"]), (0, 0, None))
        del doc["HostConfig"]["Ulimits"]
        with self.assertRaisesRegex(env.EnvelopeError, "HostConfig.Ulimits"):
            _project_v1(doc, daemon)

    def test_malformed_nested_observations_are_named_refusals(self):
        doc, daemon = _v1_inputs(); valid = doc["HostConfig"]["Ulimits"][0]
        for limits in ([None], [valid, None], [None, valid], [{"Name": 1}],
                       [valid, valid], [{"Name": "nofile", "Soft": True, "Hard": 10}],
                       [{"Name": "nofile", "Soft": 20, "Hard": 10}], {}, ""):
            bad = copy.deepcopy(doc); bad["HostConfig"]["Ulimits"] = limits
            with self.subTest(limits=limits), self.assertRaises(env.EnvelopeError):
                _project_v1(bad, daemon)
        for wire in ("CpuPeriod", "CpuQuota", "NanoCpus"):
            for value in (None, True, -1, 1.5, "1"):
                bad = copy.deepcopy(doc); bad["HostConfig"][wire] = value
                with self.subTest(wire=wire, value=value), self.assertRaisesRegex(env.EnvelopeError, "HostConfig." + wire):
                    _project_v1(bad, daemon)
        for wire in ("KernelVersion", "CgroupVersion", "CgroupDriver"):
            for value in (None, 2, "", " "):
                bad = dict(daemon); bad[wire] = value
                with self.subTest(wire=wire, value=value), self.assertRaisesRegex(env.EnvelopeError, "daemon." + wire):
                    _project_v1(doc, bad)
        for value in (False, {}, [None], [""]):
            bad = dict(daemon); bad["SecurityOptions"] = value
            with self.assertRaisesRegex(env.EnvelopeError, "daemon.SecurityOptions"):
                _project_v1(doc, bad)


class InactiveV1Emission(unittest.TestCase):
    def test_existing_default_builder_and_report_binding_remain_v0(self):
        from unittest.mock import patch
        with patch.object(env, "project_effective_envelope_v1", side_effect=AssertionError("v1 activated")):
            record = _verified_record()
            self.assertEqual(record["schema"], "corpus-adequacy.execution-envelope.v0")
            self.assertEqual(env.bind_report(record, REPORT_SHA256)["schema"], record["schema"])
            self.assertEqual(len(record["effective"]), 19)

    def test_existing_candidate_funnel_emits_v0_without_v1_observer(self):
        from unittest.mock import patch
        with patch.object(env, "project_effective_envelope_v1", side_effect=AssertionError("v1 activated")):
            suite = CandidatePathBindsTheEnvelope()
            record = suite._run(ContainedLifecycleRecordsCleanup._Transport(
                inspect_doc=_inspect())).envelope_record
            self.assertEqual(record["schema"], "corpus-adequacy.execution-envelope.v0")

    def test_unavailable_existing_route_does_not_select_v1_or_local_fallback(self):
        from unittest.mock import patch
        with patch.object(env, "project_effective_envelope_v1", side_effect=AssertionError("v1 activated")):
            CandidatePathBindsTheEnvelope().test_docker_unavailable_records_unavailable_and_not_run()


# --- #102 A2: the requested pairing and the v2 comparator --------------------------------------

V1_PROFILE = "contained-oci-v1"


def _v2_profile(**over):
    return {**contained.CANDIDATE_RESOURCE_PROFILE_V2, **over}


def _requested_v2(profile=None):
    return env.requested_envelope(
        execution_profile=V1_PROFILE, image_id=IMAGE,
        mount_spec=candidate.CANDIDATE_MOUNT_SPEC,
        resource_profile=profile or _v2_profile(), sealed=True)


_FROZEN_NOFILE = [{"Name": "nofile", "Soft": 1024, "Hard": 1024}]


def _v2_effective(*, period=100000, quota=100000, nano=0, limits=_FROZEN_NOFILE,
                  profile=None):
    doc = _inspect(profile=profile or _v2_profile())
    doc["HostConfig"].update(CpuPeriod=period, CpuQuota=quota, NanoCpus=nano,
                             Ulimits=copy.deepcopy(limits))
    return env.project_effective_envelope_v1(
        doc, image_env_names=IMAGE_ENV_NAMES, runtime_version=RUNTIME_VERSION,
        daemon_info={"KernelVersion": "synthetic-kernel", "CgroupVersion": "2",
                     "CgroupDriver": "systemd", "SecurityOptions": None})


class RequestedProfilePairing(unittest.TestCase):
    """contained-oci-v0 pairs only with a v1 resource profile, contained-oci-v1 only with v2."""

    def test_v1_profile_is_accepted_with_a_v2_resource_profile(self):
        requested = _requested_v2()
        self.assertEqual(requested["execution_profile"], V1_PROFILE)
        self.assertEqual(requested["resource_profile"], contained.CANDIDATE_RESOURCE_PROFILE_V2)
        self.assertIs(env.require_requested_record(requested), requested)

    def test_v1_profile_with_a_v1_resource_profile_refuses(self):
        with self.assertRaises(contained.PrepareError):
            env.requested_envelope(
                execution_profile=V1_PROFILE, image_id=IMAGE,
                mount_spec=candidate.CANDIDATE_MOUNT_SPEC,
                resource_profile=_profile(), sealed=True)
        stored = dict(_requested_v2())
        stored["resource_profile"] = dict(_profile())
        with self.assertRaisesRegex(env.EnvelopeError, "^resource_profile$"):
            env.require_requested_record(stored)

    def test_v0_profile_with_a_v2_resource_profile_refuses(self):
        with self.assertRaises(contained.PrepareError):
            env.requested_envelope(
                execution_profile="contained-oci-v0", image_id=IMAGE,
                mount_spec=candidate.CANDIDATE_MOUNT_SPEC,
                resource_profile=_v2_profile(), sealed=True)
        stored = dict(_requested())
        stored["resource_profile"] = _v2_profile()
        with self.assertRaisesRegex(env.EnvelopeError, "^resource_profile$"):
            env.require_requested_record(stored)

    def test_every_other_profile_refuses(self):
        for profile in ("trusted-local", "contained-oci-v2", "", None, ["contained-oci-v0"]):
            with self.subTest(profile=profile):
                with self.assertRaisesRegex(env.EnvelopeError, "^execution_profile$"):
                    env.requested_envelope(
                        execution_profile=profile, image_id=IMAGE,
                        mount_spec=candidate.CANDIDATE_MOUNT_SPEC,
                        resource_profile=_profile(), sealed=True)
                stored = dict(_requested())
                stored["execution_profile"] = profile
                with self.assertRaisesRegex(env.EnvelopeError, "^execution_profile$"):
                    env.require_requested_record(stored)

    def test_pairing_vocabulary_is_exactly_the_contained_profiles(self):
        self.assertEqual(set(env.ENVELOPE_SCHEMA_BY_PROFILE), set(ca._CONTAINED_PROFILES))
        self.assertEqual(env.envelope_schema_for_profile("contained-oci-v0"), env.ENVELOPE_SCHEMA)
        self.assertEqual(env.envelope_schema_for_profile(V1_PROFILE), env.ENVELOPE_SCHEMA_V1)
        for profile in ("trusted-local", None, ["x"]):
            with self.subTest(profile=profile), self.assertRaises(env.EnvelopeError):
                env.envelope_schema_for_profile(profile)


class V2RequestComparator(unittest.TestCase):
    """A v2 request's CPU and nofile are compared exactly; a v1 request's stay shape-checked."""

    def _check(self, effective, requested=None):
        env.require_envelope_matches_request(
            effective, requested or _requested_v2(), schema=env.ENVELOPE_SCHEMA_V1)

    def test_matching_observation_verifies(self):
        self._check(_v2_effective())

    def test_each_mismatch_is_named(self):
        cases = {
            "cpu_period": dict(period=50000),
            "cpu_quota": dict(quota=250000),
        }
        for field, over in cases.items():
            with self.subTest(field=field), self.assertRaisesRegex(
                    env.EnvelopeError, "^%s$" % field):
                self._check(_v2_effective(**over))
        for limits in ([{"Name": "nofile", "Soft": 512, "Hard": 1024}],
                       [{"Name": "nofile", "Soft": 1024, "Hard": 2048}],
                       None, [], [{"Name": "nproc", "Soft": 1, "Hard": 1}]):
            with self.subTest(limits=limits), self.assertRaisesRegex(
                    env.EnvelopeError, "^ulimit_nofile$"):
                self._check(_v2_effective(limits=limits))

    def test_a_nonzero_nano_cpus_next_to_period_and_quota_is_a_mismatch(self):
        """moby refuses NanoCpus with a CFS period, so a nonzero value beside the requested
        period/quota is not what the v2 codec asked for (#102, freeze section 3)."""
        self._check(_v2_effective(nano=0))
        for nano in (1, 1000000000):
            with self.subTest(nano=nano), self.assertRaisesRegex(
                    env.EnvelopeError, "^nano_cpus$"):
                self._check(_v2_effective(nano=nano))

    def test_nano_cpus_is_compared_after_quota_and_before_nofile(self):
        with self.assertRaisesRegex(env.EnvelopeError, "^cpu_period$"):
            self._check(_v2_effective(period=50000, nano=1000000000))
        with self.assertRaisesRegex(env.EnvelopeError, "^cpu_quota$"):
            self._check(_v2_effective(quota=250000, nano=1000000000))
        with self.assertRaisesRegex(env.EnvelopeError, "^nano_cpus$"):
            self._check(_v2_effective(nano=1000000000, limits=[]))

    def test_daemon_discarded_limits_stored_unset_are_mismatches(self):
        for over, field in ((dict(period=0), "cpu_period"), (dict(quota=0), "cpu_quota")):
            with self.subTest(field=field), self.assertRaisesRegex(
                    env.EnvelopeError, "^%s$" % field):
                self._check(_v2_effective(**over))

    def test_the_quota_follows_the_requested_rate(self):
        profile = _v2_profile(cpu_rate_millicpu=2500, nofile_soft=512, nofile_hard=2048)
        requested = _requested_v2(profile)
        self._check(_v2_effective(
            quota=250000, limits=[{"Name": "nofile", "Soft": 512, "Hard": 2048}],
            profile=profile), requested)
        with self.assertRaisesRegex(env.EnvelopeError, "^cpu_quota$"):
            self._check(_v2_effective(
                limits=[{"Name": "nofile", "Soft": 512, "Hard": 2048}], profile=profile),
                requested)

    def test_a_v0_envelope_cannot_verify_a_v2_request(self):
        doc = _inspect(profile=_v2_profile())
        effective = _effective(doc)
        with self.assertRaisesRegex(env.EnvelopeError, "^envelope_schema_profile$"):
            env.require_envelope_matches_request(
                effective, _requested_v2(), schema=env.ENVELOPE_SCHEMA)

    def test_a_v1_request_keeps_shape_only_cpu_and_nofile(self):
        """O fixtures pair a v1 envelope with a v0 request; its CPU values are not compared."""
        env.require_envelope_matches_request(
            _v2_effective(period=0, quota=0, limits=[]), _requested(),
            schema=env.ENVELOPE_SCHEMA_V1)

    def test_a_v1_request_does_not_compare_nano_cpus(self):
        """A v0 request makes no CPU claim, so a nonzero NanoCpus beside it stays valid."""
        effective = _v2_effective(nano=1000000000)
        self.assertEqual(effective["nano_cpus"], 1000000000)
        record = _wire_v1_record(); record["effective"]["nano_cpus"] = 1000000000
        self.assertEqual(record["requested"]["execution_profile"], "contained-oci-v0")
        try:
            env.require_envelope_matches_request(
                effective, _requested(), schema=env.ENVELOPE_SCHEMA_V1)
            validated = env.validate_envelope_record(record)
        except env.EnvelopeError as exc:
            self.fail("a v0 request compared nano_cpus: refused as " + str(exc))
        self.assertEqual(validated, record)


class V1ProfileRecordSchema(unittest.TestCase):
    def _fields(self, schema, **over):
        fields = dict(
            requested=_requested_v2(), setup_status="ready",
            envelope_status="verified", unverified_field=None,
            effective=_v2_effective(), candidate_outcome="completed",
            cleanup="removed-and-absent", prepare_sha256=PREPARE_SHA256,
            execution_commit=EXECUTION_COMMIT, report_sha256=None, schema=schema)
        fields.update(over)
        return fields

    def test_v1_profile_record_is_built_and_validated_as_v1(self):
        record = env.build_envelope_record(**self._fields(env.ENVELOPE_SCHEMA_V1))
        self.assertEqual(record["publication_permission"], "permitted")
        self.assertEqual(record["effective"]["nano_cpus"], 0)
        self.assertEqual(env.validate_envelope_record(record), record)

    def test_a_stored_v2_record_refuses_a_nano_cpus_the_comparison_alone_would_admit(self):
        """False == 0 and 0.0 == 0, so the stored-value rule, not `!= 0`, refuses these."""
        record = env.build_envelope_record(**self._fields(env.ENVELOPE_SCHEMA_V1))
        for value in (False, 0.0):
            bad = copy.deepcopy(record); bad["effective"]["nano_cpus"] = value
            with self.subTest(value=value), self.assertRaisesRegex(
                    env.EnvelopeError, "^nano_cpus$"):
                env.validate_envelope_record(bad)

    def test_v1_profile_record_cannot_use_the_v0_schema(self):
        for over in ({}, dict(envelope_status="unverified", unverified_field="cpu_quota",
                              effective=None),
                     dict(setup_status="refused", envelope_status="unverified",
                          unverified_field="create", effective=None,
                          candidate_outcome="not-run")):
            with self.subTest(over=sorted(over)), self.assertRaisesRegex(
                    env.EnvelopeError, "^envelope_schema_profile$"):
                env.build_envelope_record(**self._fields(env.ENVELOPE_SCHEMA, **over))

    def test_v1_envelope_with_a_v0_request_stays_valid(self):
        record = _wire_v1_record()
        self.assertEqual(record["requested"]["execution_profile"], "contained-oci-v0")
        self.assertEqual(env.validate_envelope_record(record), record)


if __name__ == "__main__":
    unittest.main()
