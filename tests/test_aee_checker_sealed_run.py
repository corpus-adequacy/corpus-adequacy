#!/usr/bin/env python3
"""Phase B PREPARE + inert OCI contract for issue #211. Standard library only.

Does not invoke aee-checker against aee-conformance. Does not emit a report.
Source-string equality is a structural guard. Biting tests feed hostile
input, wrong digests, abnormal exits, and live inert probes.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "measurements"))

import aee_checker_sealed_run as run  # noqa: E402

PREREG = REPO_ROOT / "measurements" / "aee-checker-25b9dfa"
ADAPTER = REPO_ROOT / "adapters" / "aee_checker_sealed.py"
CONTAINERFILE = REPO_ROOT / "execution" / "aee-checker-sealed" / "Containerfile"

PHASE_A_DIGESTS = {
    "adapters/aee_checker_sealed.py": (
        "130b36d50df8a286954649771c9d65f35541ecd2f7007918ce5b261ace3aa769"
    ),
    "measurements/aee-checker-25b9dfa/manifest.json": (
        "2f16654dd57a0b1719ec2ec5be7a833192ccae529d08c4c7695c7df4782c32c8"
    ),
    "measurements/aee-checker-25b9dfa/pins.json": (
        "e2456cbfcbbda17800318703e296e72fcaf138037178bad1fe237bc2c460c7e4"
    ),
    "measurements/aee-checker-25b9dfa/sites.json": (
        "6223a15c5db5a7c19c4633474875615ec61f3d710e092939f46b80ee986e0c4c"
    ),
    "measurements/aee-checker-25b9dfa/control.json": (
        "5a85c46054240a4470da7c6a82e3f13b5f1c30ea301809a2500a47a6e2f91f71"
    ),
}

FORBIDDEN_PUBLIC = (
    "report.v0",
    "GO-RUN",
    "certification",
    "leaderboard",
    "partnership",
    "sandbox",
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_json(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def _docker_available() -> bool:
    exe = shutil.which("docker")
    if exe is None:
        return False
    try:
        proc = subprocess.run([exe, "info"], capture_output=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


DOCKER = _docker_available()


class PhaseAImmutable(unittest.TestCase):
    def test_frozen_phase_a_bytes_match_preregistration_digests(self):
        for rel, digest in PHASE_A_DIGESTS.items():
            raw = (REPO_ROOT / rel).read_bytes()
            self.assertEqual(_sha256(raw), digest, rel)
        run.verify_phase_a_frozen(PREREG, adapter=ADAPTER)

    def test_prepare_refuses_mutated_phase_a_pins(self):
        with tempfile.TemporaryDirectory() as d:
            pins = Path(d) / "pins"
            shutil.copytree(PREREG, pins)
            sites = json.loads((pins / "sites.json").read_text(encoding="utf-8"))
            sites["selected_count"] = 6
            (pins / "sites.json").write_text(json.dumps(sites), encoding="utf-8")
            dest = Path(d) / "out" / "prepare.v0.json"
            with self.assertRaises(run.PrepareError) as ctx:
                run.verify_phase_a_frozen(pins)
            self.assertIn("phase-a", str(ctx.exception).lower())
            with self.assertRaises(run.PrepareError):
                run.prepare(pins, dest, root=REPO_ROOT)
            self.assertFalse(dest.exists())

    def test_frozen_dir_still_has_only_prereg_files(self):
        names = sorted(p.name for p in PREREG.iterdir())
        self.assertEqual(
            names,
            ["control.json", "manifest.json", "pins.json", "sites.json"],
        )
        for forbidden in (
            "ceilings.json",
            "report.v0.json",
            "prepare.v0.json",
            "result.json",
        ):
            self.assertFalse((PREREG / forbidden).exists(), forbidden)


class HostileInputBeforeMaterialize(unittest.TestCase):
    def test_oversized_request_is_refused_before_dest_exists(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            dest = tmp / "dest"
            req = tmp / "request.json"
            req.write_bytes(b'{"schema":"' + b"x" * (run.REQUEST_CAP_BYTES + 1) + b'"}')
            with self.assertRaises(run.PrepareError) as ctx:
                run.load_prepare_request(req)
            self.assertFalse(dest.exists())
            self.assertRegex(str(ctx.exception).lower(), r"cap|bound|ceiling|size")

    def test_duplicate_json_key_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            req = Path(d) / "request.json"
            _write_json(req, '{"schema":"x","schema":"y","pins_dir":"p","dest":"d"}\n')
            with self.assertRaises(run.PrepareError) as ctx:
                run.load_prepare_request(req)
            self.assertIn("duplicate", str(ctx.exception).lower())

    def test_non_finite_number_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            req = Path(d) / "request.json"
            _write_json(
                req,
                '{"schema":"corpus-adequacy.aee-checker-sealed.prepare-request.v0",'
                '"pins_dir":"p","dest":"d","extra":1e999}\n',
            )
            with self.assertRaises(run.PrepareError) as ctx:
                run.load_prepare_request(req)
            self.assertRegex(str(ctx.exception).lower(), r"non-finite|finite")

    def test_unknown_key_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            req = Path(d) / "request.json"
            _write_json(
                req,
                json.dumps({
                    "schema": run.REQUEST_SCHEMA,
                    "pins_dir": "p",
                    "dest": "d",
                    "score": 1,
                }) + "\n",
            )
            with self.assertRaises(run.PrepareError) as ctx:
                run.load_prepare_request(req)
            self.assertRegex(str(ctx.exception).lower(), r"exact|unknown|key")

    def test_missing_key_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            req = Path(d) / "request.json"
            _write_json(req, json.dumps({"schema": run.REQUEST_SCHEMA, "pins_dir": "p"}) + "\n")
            with self.assertRaises(run.PrepareError) as ctx:
                run.load_prepare_request(req)
            self.assertRegex(str(ctx.exception).lower(), r"exact|missing|key")

    def test_valid_request_does_not_create_dest(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            dest = tmp / "out"
            req = tmp / "request.json"
            _write_json(
                req,
                json.dumps({
                    "schema": run.REQUEST_SCHEMA,
                    "pins_dir": str(PREREG),
                    "dest": str(dest),
                }) + "\n",
            )
            loaded = run.load_prepare_request(req)
            self.assertEqual(loaded["dest"], str(dest))
            self.assertFalse(dest.exists())


class VendorOutsideSubject(unittest.TestCase):
    def test_vendor_inside_subject_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            subject = Path(d) / "subject"
            vendor = subject / "vendor"
            subject.mkdir()
            vendor.mkdir()
            with self.assertRaises(run.PrepareError) as ctx:
                run.require_vendor_outside(subject, vendor)
            self.assertIn("outside", str(ctx.exception).lower())

    def test_vendor_outside_subject_is_accepted(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            subject = root / "subject"
            vendor = root / "vendor"
            subject.mkdir()
            vendor.mkdir()
            run.require_vendor_outside(subject, vendor)


class ImageIdentity(unittest.TestCase):
    def test_mutable_tag_is_refused(self):
        with self.assertRaises(run.PrepareError) as ctx:
            run.require_image_id("busybox:latest")
        self.assertIn("sha256", str(ctx.exception).lower())

    def test_digest_reference_is_accepted(self):
        digest = "sha256:" + ("ab" * 32)
        self.assertEqual(run.require_image_id(digest), digest)

    def test_short_or_non_hex_digest_is_refused(self):
        with self.assertRaises(run.PrepareError):
            run.require_image_id("sha256:abcd")
        with self.assertRaises(run.PrepareError):
            run.require_image_id("sha256:" + ("g" * 64))


class ClassifyAbnormal(unittest.TestCase):
    def test_valid_json_plus_exit_2_is_abnormal_never_success(self):
        raw = b'{"ok":true,"rows":{}}\n'
        result = run.classify_container_result(2, raw)
        self.assertEqual(result["state"], "abnormal")
        self.assertNotEqual(result["state"], "completed")
        self.assertNotIn("rows", result)
        self.assertIsNone(result.get("parsed"))

    def test_exit_0_small_output_is_completed_without_scoring(self):
        result = run.classify_container_result(0, b'{"probe":"ok"}\n')
        self.assertEqual(result["state"], "completed")
        self.assertNotIn("score", result)
        self.assertNotIn("verdict", result)

    def test_boolean_exit_is_harness_failure(self):
        result = run.classify_container_result(True, b"{}\n")
        self.assertEqual(result["state"], "harness_failure")


class DockerArgvContract(unittest.TestCase):
    def test_create_argv_binds_immutable_id_and_resource_contract(self):
        image = "sha256:" + ("cd" * 32)
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            mounts = {name: root / name for name in ("input", "vendor", "tool")}
            for path in mounts.values():
                path.mkdir()
            argv = run.docker_create_argv(
                image_id=image,
                name="aee-sealed-inert-ok",
                mounts=mounts,
                command=["ok"],
            )
        text = " ".join(argv)
        self.assertEqual(argv[:2], ["docker", "create"])
        self.assertEqual(argv[argv.index("--network") + 1], "none")
        self.assertIn("--read-only", argv)
        self.assertEqual(argv[argv.index("--cap-drop") + 1], "ALL")
        self.assertIn("no-new-privileges:true", text)
        self.assertIn("65532:65532", text)
        self.assertEqual(argv[argv.index("--memory") + 1], "4g")
        self.assertEqual(argv[argv.index("--memory-swap") + 1], "4g")
        self.assertEqual(argv[argv.index("--pids-limit") + 1], "512")
        self.assertEqual(argv[argv.index("--cpus") + 1], "4")
        self.assertIn("nofile=1024:1024", text)
        self.assertTrue(
            any(item.startswith("/tmp:") and "nr_inodes=" in item for item in argv),
            argv,
        )
        self.assertTrue(
            any(item.startswith("/work:") and "nr_inodes=" in item for item in argv),
            argv,
        )
        self.assertIn(str(run.TMPFS_BYTES), text)
        self.assertIn(str(run.TMPFS_INODES), text)
        self.assertIn(image, argv)
        self.assertNotIn("busybox", text)
        self.assertLess(argv.index("--network"), argv.index(image))
        for dest in ("/input", "/vendor", "/tool"):
            self.assertIn("destination=%s,readonly" % dest, text.replace(" ", ""))

    def test_create_argv_refuses_tag_even_if_caller_bypasses_require(self):
        with tempfile.TemporaryDirectory() as d:
            mounts = {name: Path(d) / name for name in ("input", "vendor", "tool")}
            for path in mounts.values():
                path.mkdir()
            with self.assertRaises(run.PrepareError):
                run.docker_create_argv(
                    image_id="busybox:1.37",
                    name="aee-sealed-inert-bad",
                    mounts=mounts,
                    command=["ok"],
                )


class PrepareEvidence(unittest.TestCase):
    def _parts(self) -> dict:
        return {
            "pins": {
                "subject_commit": "25b9dfa797986624f2d680530a7228232aa3ddda",
                "corpus_commit": "59faf842098183ae7b5387ad13e6351c44687279",
                "corpus_digest": (
                    "b5aa5fdb4a9320e037658b2877f048d5c3dd7351fd93701d3c4977d69ae7a579"
                ),
                "instrument_commit": "1347651c2087cbd5c2e958a758b380a9a6cfc67d",
                "phase_a": dict(PHASE_A_DIGESTS),
            },
            "execution": {
                "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "content_sha256": "cc" * 32,
                "paths": list(run.EXECUTION_PATHS),
            },
            "materialized": {
                "subject_check_rs_sha256": (
                    "1623780ae759c070a85b74e2de6df6dac28f13f068cecbc1ea4b10e070e7a86f"
                ),
                "corpus_digest": (
                    "b5aa5fdb4a9320e037658b2877f048d5c3dd7351fd93701d3c4977d69ae7a579"
                ),
                "corpus_id_set_sha256": "dd" * 32,
                "vendor_sha256": "aa" * 32,
                "vendor_outside_subject": True,
                "subject_binary": False,
            },
            "image": {"id": "sha256:" + ("ab" * 32), "kind": "inert-probe"},
            "toolchain": {
                "rustc_Vv": "rustc test",
                "cargo_V": "cargo test",
                "observation": "host; checker was not run",
            },
            "runtime": {
                "docker": "test",
                "observation": "host-local; not a portable bound",
            },
            "ceilings": dict(run.DECLARED_CEILINGS),
            "host_evidence": dict(run.EMPTY_HOST_EVIDENCE),
            "network": dict(run.NETWORK_CUTOFF),
            "oci": run.OCI_CONTRACT,
            "non_claims": list(run.NON_CLAIMS),
        }

    def test_prepare_v0_has_exact_keys_and_is_not_a_report(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "prepare.v0.json"
            raw = run.emit_prepare_v0(self._parts(), dest)
            doc = json.loads(raw.decode("utf-8"))
            self.assertEqual(doc["schema"], run.PREPARE_SCHEMA)
            self.assertEqual(doc["phase"], "prepare")
            self.assertEqual(set(doc), set(run.PREPARE_KEYS))
            self.assertNotEqual(doc["schema"], "corpus-adequacy.report.v0")
            self.assertNotIn("result", doc)
            self.assertNotIn("score", doc)
            self.assertNotIn("rows", doc)
            self.assertNotIn("vectors", doc["materialized"])
            self.assertIn("not a scientific measurement", " ".join(doc["non_claims"]))
            self.assertEqual(
                doc["pins"]["instrument_commit"], run.PHASE_A_INSTRUMENT_COMMIT)
            self.assertNotEqual(
                doc["execution"]["commit"], doc["pins"]["instrument_commit"])
            self.assertNotIn("instrument_commit", doc["execution"])
            self.assertFalse(doc["materialized"]["subject_binary"])

    def test_execution_must_not_reuse_the_frozen_instrument_commit(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "prepare.v0.json"
            parts = self._parts()
            parts["execution"]["commit"] = run.PHASE_A_INSTRUMENT_COMMIT
            with self.assertRaises(run.PrepareError) as ctx:
                run.emit_prepare_v0(parts, dest)
            self.assertRegex(str(ctx.exception).lower(), r"conflat|instrument|execution")

    def test_network_cutoff_is_named_and_prepare_is_not_offline(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "prepare.v0.json"
            doc = json.loads(run.emit_prepare_v0(self._parts(), dest).decode("utf-8"))
        self.assertEqual(doc["network"]["materialization"], "online")
        self.assertEqual(doc["network"]["sealed_oci"], "none")
        self.assertEqual(doc["network"]["cutoff"], "after_materialization")
        self.assertNotEqual(doc["network"]["materialization"], "none")

    def test_declared_ceilings_are_not_host_timings(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "prepare.v0.json"
            doc = json.loads(run.emit_prepare_v0(self._parts(), dest).decode("utf-8"))
        self.assertEqual(doc["ceilings"], run.DECLARED_CEILINGS)
        self.assertEqual(
            doc["host_evidence"]["portability"],
            "host-local; not a portable bound",
        )
        self.assertNotIn("elapsed_seconds", doc["ceilings"])
        self.assertNotIn("calibration", doc["ceilings"])

    def test_host_evidence_cannot_overwrite_declared_ceilings(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "prepare.v0.json"
            parts = self._parts()
            parts["ceilings"] = dict(run.DECLARED_CEILINGS)
            parts["ceilings"]["deadline_seconds"] = 0.4
            with self.assertRaises(run.PrepareError) as ctx:
                run.emit_prepare_v0(parts, dest)
            self.assertRegex(str(ctx.exception).lower(), r"declared|ceiling")

    def test_per_vector_outcomes_are_refused(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "prepare.v0.json"
            parts = self._parts()
            parts["materialized"]["vectors"] = {"v1": {"verdict": "valid"}}
            with self.assertRaises(run.PrepareError) as ctx:
                run.emit_prepare_v0(parts, dest)
            self.assertRegex(str(ctx.exception).lower(), r"outcome|vector")

    def test_subject_binary_record_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "prepare.v0.json"
            parts = self._parts()
            parts["materialized"]["subject_binary"] = True
            with self.assertRaises(run.PrepareError) as ctx:
                run.emit_prepare_v0(parts, dest)
            self.assertIn("binary", str(ctx.exception).lower())

    def test_regeneration_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as d:
            left = Path(d) / "a.json"
            right = Path(d) / "b.json"
            parts = self._parts()
            self.assertEqual(
                run.emit_prepare_v0(parts, left),
                run.emit_prepare_v0(parts, right),
            )

    def test_extra_prepare_field_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "prepare.v0.json"
            parts = self._parts()
            parts["score"] = 1
            with self.assertRaises(run.PrepareError):
                run.emit_prepare_v0(parts, dest)


class PublicStrings(unittest.TestCase):
    def test_run_module_does_not_claim_a_result(self):
        text = (REPO_ROOT / "measurements" / "aee_checker_sealed_run.py").read_text(
            encoding="utf-8")
        for word in FORBIDDEN_PUBLIC:
            self.assertNotIn(word, text, word)
        self.assertIn("not a scientific measurement", text)
        self.assertIn("checker was not run", text)
        self.assertIn("after_materialization", text)
        self.assertIn("subject binary is not produced here", text)
        self.assertNotIn("cargo build", text)
        self.assertNotIn("entirely offline", text)

    def test_containerfile_is_inert_probe_not_aee_checker(self):
        text = CONTAINERFILE.read_text(encoding="utf-8")
        self.assertNotIn("aee-checker", text)
        self.assertNotIn("aee-conformance", text)
        self.assertNotIn("cargo run", text)


@unittest.skipUnless(DOCKER, "docker daemon is not available")
class LiveInertProbes(unittest.TestCase):
    image_id = ""
    prefix = "aee-sealed-inert-"

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        root = Path(cls._tmp.name)
        cls.mounts = {name: root / name for name in ("input", "vendor", "tool")}
        for path in cls.mounts.values():
            path.mkdir()
        cls.image_id = run.build_inert_image(CONTAINERFILE.parent)
        run.require_image_id(cls.image_id)

    @classmethod
    def tearDownClass(cls):
        run.cleanup_named_containers(cls.prefix)
        cls._tmp.cleanup()

    def _run(self, mode: str, **kwargs):
        return run.run_inert_probe(
            image_id=self.image_id,
            mode=mode,
            mounts=self.mounts,
            name_prefix=self.prefix,
            **kwargs,
        )

    def test_network_none_refuses_outbound_and_allows_local_ok(self):
        good = self._run("ok")
        self.assertEqual(good["state"], "completed", good)
        bad = self._run("network")
        self.assertNotEqual(bad["state"], "completed", bad)
        self.assertTrue(good["container_absent_after"] and bad["container_absent_after"])

    def test_tmpfs_bytes_refuse_over_limit_and_allow_under_limit(self):
        good = self._run("tmpfs-bytes-ok")
        self.assertEqual(good["state"], "completed", good)
        bad = self._run("tmpfs-bytes")
        self.assertNotEqual(bad["state"], "completed", bad)

    def test_tmpfs_inodes_refuse_over_limit_and_allow_under_limit(self):
        good = self._run("tmpfs-inodes-ok")
        self.assertEqual(good["state"], "completed", good)
        bad = self._run("tmpfs-inodes")
        self.assertNotEqual(bad["state"], "completed", bad)

    def test_output_cap_refuses_over_4mib_and_allows_small(self):
        good = self._run("output-ok")
        self.assertEqual(good["state"], "completed", good)
        bad = self._run("output")
        self.assertEqual(bad["state"], "output_cap", bad)

    def test_deadline_kills_descendant_and_short_child_completes(self):
        good = self._run("deadline-ok")
        self.assertEqual(good["state"], "completed", good)
        bad = self._run("deadline")
        self.assertEqual(bad["state"], "deadline", bad)
        self.assertNotIn("elapsed_seconds", run.DECLARED_CEILINGS)

    def test_exit_2_json_is_abnormal_and_exit_0_json_is_completed(self):
        good = self._run("ok")
        self.assertEqual(good["state"], "completed", good)
        self.assertIsNone(good.get("parsed"))
        bad = self._run("exit2-json")
        self.assertEqual(bad["state"], "abnormal", bad)
        self.assertIsNone(bad.get("parsed"))

    def test_image_digest_mismatch_is_refused_and_match_runs(self):
        good = self._run("ok")
        self.assertEqual(good["state"], "completed", good)
        fake = "sha256:" + ("00" * 32)
        with self.assertRaises(run.PrepareError):
            run.run_inert_probe(
                image_id=fake,
                mode="ok",
                mounts=self.mounts,
                name_prefix=self.prefix,
            )

    def test_cleanup_absence_is_verified_after_successful_remove(self):
        good = self._run("ok")
        self.assertTrue(good["container_absent_after"])
        self.assertFalse(run.container_exists(good["name"]))
        self.assertIsNotNone(good["inspect"])
        with self.assertRaises(run.PrepareError):
            run.require_container_absent(good["name"], exists=True)

    def test_prepare_emits_artifact_without_subject_binary_or_outcomes(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "prepare.v0.json"
            raw = run.prepare(PREREG, dest, root=REPO_ROOT, adapter=ADAPTER)
            doc = json.loads(raw.decode("utf-8"))
        self.assertEqual(doc["schema"], run.PREPARE_SCHEMA)
        self.assertFalse(doc["materialized"]["subject_binary"])
        self.assertNotIn("vectors", doc["materialized"])
        self.assertEqual(doc["pins"]["instrument_commit"], run.PHASE_A_INSTRUMENT_COMMIT)
        self.assertNotEqual(doc["execution"]["commit"], doc["pins"]["instrument_commit"])
        self.assertEqual(doc["network"]["cutoff"], "after_materialization")
        self.assertEqual(doc["ceilings"], run.DECLARED_CEILINGS)
        self.assertEqual(doc["image"]["kind"], "inert-probe")
        run.require_image_id(doc["image"]["id"])


class MaterializeVerify(unittest.TestCase):
    def test_subject_digest_mismatch_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "check.rs"
            path.write_text("fn not_the_pin() {}\n", encoding="utf-8")
            pins = {"subject": {"path": "src/check.rs", "check_rs_sha256": "aa" * 32}}
            with self.assertRaises(run.PrepareError) as ctx:
                run.verify_subject_bytes(path, pins)
            self.assertIn("digest", str(ctx.exception).lower())

    def test_matching_subject_digest_is_accepted(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "check.rs"
            path.write_text("fn pinned() {}\n", encoding="utf-8")
            digest = _sha256(path.read_bytes())
            run.verify_subject_bytes(
                path, {"subject": {"path": "src/check.rs", "check_rs_sha256": digest}})

    def test_payload_digest_mismatch_is_refused_before_use(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "payload.json"
            path.write_text('{"ok":true}\n', encoding="utf-8")
            with self.assertRaises(run.PrepareError) as ctx:
                run.verify_file_digest(path, "bb" * 32)
            self.assertIn("digest", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
