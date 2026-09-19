#!/usr/bin/env python3
"""Behavioral contract for issue #174's bounded wrapper-stage protocol."""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "measurements"))

import aee_checker_sealed_candidate as candidate  # noqa: E402
import aee_checker_sealed_materialize as materialize  # noqa: E402
import aee_checker_sealed_runtime as runtime  # noqa: E402
import corpus_adequacy as ca  # noqa: E402
import envelope_collection as collection  # noqa: E402
from sealed_measurement_contract import (  # noqa: E402
    AEE_CHECKER_SEALED_CONTRACT,
    OWNED_CONTAINED_V1_CONTRACT,
)

REPORT = {"vectors": [{
    "id": "v1", "verdict": "valid", "result": "ok", "reason": "bounded",
    "code": "PRIVATE", "tiersWithPinnedKey": ["t"], "tiersWithoutKey": [],
}]}
POSIX_SHELL_ONLY = unittest.skipIf(
    os.name == "nt", "generated candidate wrapper requires POSIX /bin/sh")
POSIX_MODES_ONLY = unittest.skipIf(
    os.name == "nt", "POSIX read and traverse mode bits are not represented by NTFS")


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GeneratedWrapperStages(unittest.TestCase):
    def _run(self, *, build=("true",), entrypoint=("true",), missing=(), fake=(),
             contract=OWNED_CONTAINED_V1_CONTRACT, expose_wrapper_stdout=False):
        contract = replace(
            contract,
            candidate_build=build,
            candidate_entrypoint=entrypoint,
        )
        execution = {"build": list(build), "entrypoint_command": list(entrypoint)}
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            for name in ("input/vectors", "vendor", "tool", "subject", "work", "bin"):
                (root / name).mkdir(parents=True)
            (root / "tool/config.toml").write_text("config", encoding="utf-8")
            for command in fake:
                executable = root / "bin" / command
                executable.write_text("#!/bin/sh\nexit 9\n", encoding="utf-8")
                executable.chmod(0o755)
            for name in missing:
                path = root / name
                if path.is_dir():
                    path.rmdir()
                elif path.exists():
                    path.unlink()
            script = candidate.candidate_script(execution, contract=contract)
            if expose_wrapper_stdout:
                # Portable equivalent of the Linux /proc/$PPID/fd/1 attack: the
                # candidate inherits another descriptor for its parent's stdout.
                script = "exec 3>&1; " + script
            for old, new in (
                ("/input", str(root / "input")),
                ("/vendor", str(root / "vendor")),
                ("/tool", str(root / "tool")),
                ("/subject", str(root / "subject")),
                ("/work", str(root / "work")),
            ):
                script = script.replace(old, new)
            env = dict(os.environ)
            env["PATH"] = str(root / "bin") + os.pathsep + env["PATH"]
            return subprocess.run(
                ["/bin/sh", "-c", script], text=True, capture_output=True,
                env=env, timeout=5, check=False)

    def assertStage(self, proc, stage):
        self.assertEqual(proc.returncode, candidate.wrapper_stage_returncode(stage))
        self.assertEqual(proc.stdout, "")
        normalized = candidate.normalize_inner_event(
            returncode=proc.returncode, stdout=proc.stdout, vectors="unused",
            contract=OWNED_CONTAINED_V1_CONTRACT)
        self.assertEqual(normalized.unproved_reason, "candidate-" + stage)
        self.assertEqual(normalized.stdout, "")
        self.assertEqual(normalized.stderr, "")

    @POSIX_SHELL_ONLY
    def test_each_wrapper_owned_failure_has_one_closed_stage(self):
        cases = (
            ("preflight", dict(missing=("tool/config.toml",))),
            ("copy", dict(fake=("cp",))),
            ("build", dict(build=("false",))),
            ("report-missing", dict()),
            ("report-empty", dict(entrypoint=(
                "/bin/sh", "-c", ": > report.json"))),
            ("report-read", dict(entrypoint=(
                "/bin/sh", "-c", "printf x > report.json"), fake=("cat",))),
        )
        for stage, kwargs in cases:
            with self.subTest(stage=stage):
                self.assertStage(self._run(**kwargs), stage)

    @POSIX_SHELL_ONLY
    def test_report_read_never_replaces_noncomplete_entrypoint_status(self):
        proc = self._run(
            entrypoint=("/bin/sh", "-c", "printf x > report.json; exit 2"),
            fake=("cat",))
        self.assertEqual(proc.returncode, candidate.UNPROVED_EXIT)
        self.assertEqual(proc.stdout, "")
        normalized = candidate.normalize_inner_event(
            returncode=proc.returncode, stdout=proc.stdout, vectors="unused",
            contract=OWNED_CONTAINED_V1_CONTRACT)
        self.assertEqual(normalized.unproved_reason, "inner-exit")

    @POSIX_SHELL_ONLY
    def test_candidate_forging_the_old_exact_frame_remains_generic(self):
        old_frame = "candidate-wrapper-stage.v0:build"
        attack = f"printf '%s\\n' '{old_frame}' >&3; exit 75"
        proc = self._run(
            entrypoint=("/bin/sh", "-c", attack),
            expose_wrapper_stdout=True)
        self.assertEqual(proc.stdout, old_frame + "\n")
        self.assertEqual(proc.returncode, candidate.UNPROVED_EXIT)
        normalized = candidate.normalize_inner_event(
            returncode=proc.returncode, stdout=proc.stdout, vectors="unused",
            contract=OWNED_CONTAINED_V1_CONTRACT)
        self.assertEqual(normalized.unproved_reason, "inner-exit")

    @POSIX_SHELL_ONLY
    def test_every_noncomplete_candidate_exit_is_remapped_before_classification(self):
        statuses = (2, candidate.UNPROVED_EXIT,
                    *candidate.WRAPPER_STAGE_RETURNCODES.values())
        for status in statuses:
            with self.subTest(candidate_status=status):
                proc = self._run(entrypoint=("/bin/sh", "-c", "exit %d" % status))
                self.assertEqual(proc.returncode, candidate.UNPROVED_EXIT)
                normalized = candidate.normalize_inner_event(
                    returncode=proc.returncode, stdout=proc.stdout, vectors="unused",
                    contract=OWNED_CONTAINED_V1_CONTRACT)
                self.assertEqual(normalized.unproved_reason, "inner-exit")

    def test_complete_returncodes_are_contract_specific(self):
        self.assertEqual(AEE_CHECKER_SEALED_CONTRACT.candidate_complete_returncodes, (0, 1))
        self.assertEqual(OWNED_CONTAINED_V1_CONTRACT.candidate_complete_returncodes, (0,))
        self.assertEqual(len(candidate.WRAPPER_STAGE_RETURNCODES), 7)
        self.assertEqual(len(set(candidate.WRAPPER_STAGE_RETURNCODES.values())), 7)
        for contract in (AEE_CHECKER_SEALED_CONTRACT, OWNED_CONTAINED_V1_CONTRACT):
            self.assertTrue(set(contract.candidate_complete_returncodes).isdisjoint(
                candidate.WRAPPER_STAGE_RETURNCODES.values()))
        with self.assertRaisesRegex(ValueError, "overlap wrapper stages"):
            replace(
                OWNED_CONTAINED_V1_CONTRACT,
                candidate_complete_returncodes=(
                    candidate.wrapper_stage_returncode("preflight"),))

        class Adapter:
            @staticmethod
            def expected_ids(_vectors):
                return ["v1"]

            @staticmethod
            def project(inner, _expected):
                return {"rows": {"v1": inner["vectors"][0]}}

        original = candidate.sealed_adapter_for
        candidate.sealed_adapter_for = lambda _contract: Adapter
        try:
            raw = json.dumps(REPORT) + "\n"
            aee = candidate.normalize_inner_event(
                returncode=1, stdout=raw, vectors="unused",
                contract=AEE_CHECKER_SEALED_CONTRACT)
            owned = candidate.normalize_inner_event(
                returncode=1, stdout=raw, vectors="unused",
                contract=OWNED_CONTAINED_V1_CONTRACT)
        finally:
            candidate.sealed_adapter_for = original
        self.assertEqual(aee.returncode, 0)
        self.assertEqual(owned.unproved_reason, "inner-exit")

    @POSIX_SHELL_ONLY
    def test_generated_wrapper_preserves_aee_exit_one_but_owned_v1_refuses_it(self):
        command = ("/bin/sh", "-c", "printf '%s\\n' '{\"vectors\":[]}' > report.json; exit 1")
        aee = self._run(entrypoint=command, contract=AEE_CHECKER_SEALED_CONTRACT)
        owned = self._run(entrypoint=command, contract=OWNED_CONTAINED_V1_CONTRACT)
        self.assertEqual(aee.returncode, 1)
        self.assertEqual(aee.stdout, '{"vectors":[]}\n')
        self.assertEqual(owned.returncode, candidate.UNPROVED_EXIT)
        self.assertEqual(owned.stdout, "")

    def test_only_closed_stage_tokens_are_retained_and_stdout_never_is(self):
        for stage in candidate.WRAPPER_STAGES:
            token = "candidate-" + stage
            self.assertEqual(ca.sanitize_unproved_reason(token), token)
            completed = candidate.normalize_inner_event(
                returncode=candidate.wrapper_stage_returncode(stage),
                stdout="untrusted child or host text", vectors="unused",
                contract=OWNED_CONTAINED_V1_CONTRACT)
            self.assertEqual(completed.unproved_reason, token)
            self.assertEqual(completed.stdout, "")
            self.assertEqual(completed.stderr, "")
        for raw in (
            "candidate-wrapper-stage.v0:build:/private/tmp/secret\n",
            "candidate-wrapper-stage.v0:build command=cargo\n",
            "candidate-wrapper-stage.v0:build sha256=abc\n",
            "stderr: permission denied\n",
        ):
            with self.subTest(raw=raw):
                completed = candidate.normalize_inner_event(
                    returncode=candidate.UNPROVED_EXIT, stdout=raw,
                    vectors="unused", contract=OWNED_CONTAINED_V1_CONTRACT)
                self.assertEqual(completed.unproved_reason, "inner-exit")
                self.assertNotIn(raw.strip(), completed.unproved_reason)

    def test_stage_mapping_mutation_bites_and_noop_stays_green(self):
        source = Path(candidate.__file__).read_text(encoding="utf-8")
        needle = 'return _unproved("candidate-" + stage)'
        self.assertIn(needle, source)
        for label, changed, expected in (
            ("mutation", source.replace(needle, 'return _unproved("inner-exit")'),
             "candidate-build"),
            ("noop", source.replace(needle, needle), "candidate-build"),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as raw:
                path = Path(raw) / (label + ".py")
                path.write_text(changed, encoding="utf-8")
                module = _load(path, "candidate_" + label)
                completed = module.normalize_inner_event(
                    returncode=module.wrapper_stage_returncode("build"),
                    stdout="untrusted", vectors="unused",
                    contract=OWNED_CONTAINED_V1_CONTRACT)
                if label == "mutation":
                    self.assertNotEqual(completed.unproved_reason, expected)
                else:
                    self.assertEqual(completed.unproved_reason, expected)

    def test_fake_transport_and_runtime_retain_only_the_closed_stage(self):
        from tests.test_aee_checker_sealed_candidate import FakeTransport, _observed_inspect
        from tests.test_aee_checker_sealed_runtime import _prepare_v1
        import aee_checker_sealed_common as common

        rows = []
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            materialized = {key: root / key for key in ("corpus", "vendor", "tool")}
            for path in materialized.values():
                path.mkdir()
            subject = root / "subject"
            subject.mkdir()
            manifest = {
                "_repo_root": subject,
                "accepted_exit_codes": [0], "unproved_exit_codes": [75],
                "runner": "batch", "outcome_from": ["rows"],
                "build": list(AEE_CHECKER_SEALED_CONTRACT.candidate_build),
                "entrypoint_command": list(AEE_CHECKER_SEALED_CONTRACT.candidate_entrypoint),
            }
            inspect = _observed_inspect(common.CANDIDATE_RESOURCE_PROFILE)
            stage_returncode = candidate.wrapper_stage_returncode("build")
            inspect["State"]["ExitCode"] = stage_returncode
            transport = FakeTransport(
                returncode=stage_returncode, stdout="untrusted host or child text",
                inspect=inspect)
            result = runtime.make_sealed_backend(
                prepare_raw=_prepare_v1(), materialized=materialized,
                execution_profile="contained-oci-v0", transport=transport,
                ledger=collection.Ledger(), diagnostic_sink=rows.append,
            )(manifest, [{"vector_id": "<batch>"}], rebuild=True)
        self.assertEqual(len(transport.started), 1)
        self.assertEqual(result.raised, {"<batch>": "unproved"})
        self.assertEqual(rows, [{
            "ordinal": 0, "candidate_outcome": "unproved",
            "unproved_reason": "candidate-build",
        }])
        self.assertNotIn("stderr", repr(rows))

    def test_fake_transport_cannot_promote_old_frame_to_a_stage(self):
        from tests.test_aee_checker_sealed_candidate import FakeTransport, _observed_inspect
        from tests.test_aee_checker_sealed_runtime import _prepare_v1
        import aee_checker_sealed_common as common

        rows = []
        old_frame = "candidate-wrapper-stage.v0:build\n"
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            materialized = {key: root / key for key in ("corpus", "vendor", "tool")}
            for path in materialized.values():
                path.mkdir()
            subject = root / "subject"
            subject.mkdir()
            manifest = {
                "_repo_root": subject,
                "accepted_exit_codes": [0], "unproved_exit_codes": [75],
                "runner": "batch", "outcome_from": ["rows"],
                "build": list(AEE_CHECKER_SEALED_CONTRACT.candidate_build),
                "entrypoint_command": list(AEE_CHECKER_SEALED_CONTRACT.candidate_entrypoint),
            }
            inspect = _observed_inspect(common.CANDIDATE_RESOURCE_PROFILE)
            inspect["State"]["ExitCode"] = candidate.UNPROVED_EXIT
            transport = FakeTransport(
                returncode=candidate.UNPROVED_EXIT, stdout=old_frame, inspect=inspect)
            result = runtime.make_sealed_backend(
                prepare_raw=_prepare_v1(), materialized=materialized,
                execution_profile="contained-oci-v0", transport=transport,
                ledger=collection.Ledger(), diagnostic_sink=rows.append,
            )(manifest, [{"vector_id": "<batch>"}], rebuild=True)
        self.assertEqual(result.raised, {"<batch>": "unproved"})
        self.assertEqual(rows[0]["unproved_reason"], "inner-exit")
        self.assertNotIn("wrapper-stage", repr(rows))


class CrossUidMaterializationModes(unittest.TestCase):
    def _private_tree(self, root: Path):
        old = os.umask(0o077)
        try:
            nested = root / "nested"
            nested.mkdir()
            (root / "top.txt").write_text("top", encoding="utf-8")
            (nested / "inner.txt").write_text("inner", encoding="utf-8")
        finally:
            os.umask(old)

    def assertReadableModes(self, root: Path):
        self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((root / "nested").stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((root / "top.txt").stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE((root / "nested/inner.txt").stat().st_mode), 0o644)

    @POSIX_MODES_ONLY
    def test_owned_tree_is_cross_uid_readable_despite_umask_077(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "tree"
            root.mkdir()
            self._private_tree(root)
            materialize.normalize_readonly_bind_modes(root)
            self.assertReadableModes(root)

    def _materialize_with_stubs(self, module, root: Path):
        dest = root / "materialized"
        dest.mkdir()
        template = root / "config.toml"
        template.write_text('directory = "../vendor"\n', encoding="utf-8")

        def extract(_archive, target, **_kwargs):
            target = Path(target)
            target.mkdir()
            (target / "nested").mkdir()
            (target / "nested/input.txt").write_text("input", encoding="utf-8")
            return target

        def vendor(_subject, target, **_kwargs):
            target = Path(target)
            target.mkdir()
            (target / "crate.txt").write_text("crate", encoding="utf-8")
            return {"toolchain": {}, "vendor_sha256": "2" * 64}

        def bind(target, _template):
            target = Path(target)
            target.mkdir()
            (target / "config.toml").write_text("config", encoding="utf-8")
            return "3" * 64

        old = os.umask(0o077)
        try:
            with mock.patch.object(module, "download_bounded", return_value=root / "a.tar"), \
                    mock.patch.object(module, "extract_pinned_archive", side_effect=extract), \
                    mock.patch.object(module.shutil, "rmtree"), \
                    mock.patch.object(module, "verify_materialized", return_value={}), \
                    mock.patch.object(module, "pull_rust_image", return_value={"image_id": "sha256:" + "1" * 64}), \
                    mock.patch.object(module, "vendor_locked", side_effect=vendor), \
                    mock.patch.object(module, "bind_vendor_config", side_effect=bind):
                return module.materialize_pinned(
                    {"subject": {"repository": "r", "commit": "c"},
                     "corpus": {"repository": "r", "commit": "c"}},
                    dest, template=template, contract=OWNED_CONTAINED_V1_CONTRACT)
        finally:
            os.umask(old)

    def test_materializer_wires_all_four_readonly_bind_roots_on_every_platform(self):
        with tempfile.TemporaryDirectory() as raw, mock.patch.object(
                materialize, "normalize_readonly_bind_modes") as normalizer:
            result = self._materialize_with_stubs(materialize, Path(raw))
        self.assertEqual(
            [call.args[0] for call in normalizer.call_args_list],
            [result[name] for name in ("subject", "corpus", "vendor", "tool")],
        )

    @POSIX_MODES_ONLY
    def test_materializer_applies_modes_to_every_mounted_tree(self):
        with tempfile.TemporaryDirectory() as raw:
            result = self._materialize_with_stubs(materialize, Path(raw))
            for name in ("subject", "corpus"):
                self.assertEqual(stat.S_IMODE(result[name].stat().st_mode), 0o755)
                self.assertEqual(
                    stat.S_IMODE((result[name] / "nested/input.txt").stat().st_mode), 0o644)
            self.assertEqual(stat.S_IMODE(result["vendor"].stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE((result["vendor"] / "crate.txt").stat().st_mode), 0o644)
            self.assertEqual(stat.S_IMODE(result["tool"].stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE((result["tool"] / "config.toml").stat().st_mode), 0o644)

    @POSIX_MODES_ONLY
    def test_mode_normalization_mutation_bites_and_noop_is_green(self):
        source = Path(materialize.__file__).read_text(encoding="utf-8")
        needle = "        normalize_readonly_bind_modes(readonly_bind)"
        self.assertIn(needle, source)
        for label, changed, expected in (
            ("mutation", source.replace(
                needle, "        pass  # removed mode normalization"), False),
            ("noop", source.replace(needle, needle), True),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as raw:
                path = Path(raw) / (label + ".py")
                path.write_text(changed, encoding="utf-8")
                module = _load(path, "materialize_" + label)
                tree = Path(raw) / "tree"
                tree.mkdir()
                self._private_tree(tree)
                result = self._materialize_with_stubs(module, Path(raw))
                mode = stat.S_IMODE((result["subject"] / "nested/input.txt").stat().st_mode)
                if expected:
                    self.assertEqual(mode, 0o644)
                else:
                    self.assertNotEqual(mode, 0o644)


if __name__ == "__main__":
    unittest.main()
