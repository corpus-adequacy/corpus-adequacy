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
            return None

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

    def test_changelog_notes_the_fresh_prepare_requirement(self):
        changelog = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        unreleased = changelog.split("## ")[1]
        self.assertIn("envelope.v0", unreleased)
        self.assertIn("PREPARE", unreleased)


if __name__ == "__main__":
    unittest.main()
