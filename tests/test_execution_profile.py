#!/usr/bin/env python3
"""Closed operator-owned execution-profile selection (#105).

Standard library only. Profiles are independent of runner.
report.v0 must not gain a profile field.
"""

from __future__ import annotations

import inspect
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import corpus_adequacy as ca  # noqa: E402
from test_corpus_adequacy import (  # noqa: E402
    KILLABLE,
    _batch_python,
    _manifest,
    _process_kill_manifest,
)

TRUSTED = "trusted-local"
CONTAINED = "contained-oci-v0"


def _batch_manifest(tmp: Path) -> Path:
    (tmp / "check.py").write_text(
        "import json, sys\n"
        "doc = json.load(open(sys.argv[1]))\n"
        "fails = [c['id'] for c in doc['cases'] if c['n'] > 10]\n"
        "print(json.dumps({'ok': not fails, 'failures': fails}))\n",
        encoding="utf-8")
    (tmp / "vectors.json").write_text(json.dumps(
        {"cases": [{"id": "c1", "n": 1}]}), encoding="utf-8")
    path = tmp / "m.json"
    path.write_text(json.dumps({
        "schema": ca.SCHEMA, "runner": "batch", "repo_root": ".",
        "implementation_sources": ["check.py"],
        "outcome_from": ["ok", "failures"], "vectors": "vectors.json",
        "id_key": "vector_id", "default_group": "g",
        "entrypoint_command": [_batch_python(), "check.py", "vectors.json"],
        "mutants": {"g": [
            {"label": "threshold", "anchor": "c['n'] > 10",
             "replacement": "c['n'] > 1"},
            {"label": "CONTROL", "control": True,
             "anchor": "'ok': not fails", "replacement": "'ok': 'MOVED'"}]},
    }), encoding="utf-8")
    return path


def _closed_member(name: str):
    for item in ca.CLOSED_EXECUTION_PROFILES:
        if item == name:
            return item
    raise AssertionError("closed set does not contain %r" % (name,))


def _inert_backend(m, vectors=None, *, rebuild=True):
    return ca._ProcessExecution(True, "contained-backend", {}, {}, {}, {})


class ResolveExecutionProfile(unittest.TestCase):
    def test_unknown_operator_is_refused(self):
        with self.assertRaises(ca.ManifestError) as ctx:
            ca.resolve_execution_profile(operator="host-network", manifest={})
        self.assertIn("host-network", str(ctx.exception))
        env = ca.error_envelope(ctx.exception, operation="measure")
        self.assertEqual(env["schema"], ca.ERROR_SCHEMA)
        self.assertIn("host-network", env["error"])

    def test_non_string_operator_is_refused(self):
        with self.assertRaises(ca.ManifestError) as ctx:
            ca.resolve_execution_profile(operator=["trusted-local"], manifest={})
        self.assertIn("execution_profile", str(ctx.exception))
        self.assertIn("list", str(ctx.exception))

    def test_operator_shaped_key_in_manifest_is_refused(self):
        with self.assertRaises(ca.ManifestError) as ctx:
            ca.resolve_execution_profile(
                operator=TRUSTED,
                manifest={ca.OPERATOR_PROFILE_KEY: TRUSTED})
        self.assertIn(ca.OPERATOR_PROFILE_KEY, str(ctx.exception))
        self.assertIn(TRUSTED, str(ctx.exception))

    def test_unknown_minimum_is_refused(self):
        with self.assertRaises(ca.ManifestError) as ctx:
            ca.resolve_execution_profile(
                operator=TRUSTED,
                manifest={ca.MINIMUM_PROFILE_KEY: "kvm-v0"})
        self.assertIn("kvm-v0", str(ctx.exception))
        self.assertIn(ca.MINIMUM_PROFILE_KEY, str(ctx.exception))

    def test_non_string_minimum_is_refused(self):
        with self.assertRaises(ca.ManifestError) as ctx:
            ca.resolve_execution_profile(
                operator=TRUSTED,
                manifest={ca.MINIMUM_PROFILE_KEY: 1})
        self.assertIn(ca.MINIMUM_PROFILE_KEY, str(ctx.exception))

    def test_trusted_local_below_contained_minimum_is_downgrade(self):
        with self.assertRaises(ca.ManifestError) as ctx:
            ca.resolve_execution_profile(
                operator=TRUSTED,
                manifest={ca.MINIMUM_PROFILE_KEY: CONTAINED})
        message = str(ctx.exception)
        self.assertIn(TRUSTED, message)
        self.assertIn(CONTAINED, message)
        env = ca.error_envelope(ctx.exception, operation="measure")
        self.assertIn(TRUSTED, env["error"])
        self.assertIn(CONTAINED, env["error"])

    def test_contained_operator_with_trusted_minimum_stays_contained(self):
        resolved = ca.resolve_execution_profile(
            operator=CONTAINED,
            manifest={ca.MINIMUM_PROFILE_KEY: TRUSTED})
        self.assertEqual(resolved, CONTAINED)
        self.assertIs(resolved, _closed_member(CONTAINED))

    def test_absent_minimum_is_ok(self):
        resolved = ca.resolve_execution_profile(operator=TRUSTED, manifest={})
        self.assertEqual(resolved, TRUSTED)
        self.assertIs(resolved, _closed_member(TRUSTED))

    def test_resolved_value_is_closed_set_member_not_caller_object(self):
        operator = "trusted-" + "local"
        self.assertEqual(operator, TRUSTED)
        resolved = ca.resolve_execution_profile(operator=operator, manifest={})
        self.assertIsNot(resolved, operator)
        self.assertIs(resolved, _closed_member(TRUSTED))
        self.assertIsInstance(resolved, str)

    def test_runner_tokens_are_not_profiles(self):
        for token in ("module", "process", "batch"):
            with self.subTest(token=token):
                with self.assertRaises(ca.ManifestError) as ctx:
                    ca.resolve_execution_profile(operator=token, manifest={})
                self.assertIn(token, str(ctx.exception))


class RunRefusesMalformedAndDowngrade(unittest.TestCase):
    def test_unknown_profile_through_run_names_the_token(self):
        with tempfile.TemporaryDirectory() as d:
            path = _manifest(Path(d), {"a": [KILLABLE]})
            with self.assertRaises(ca.ManifestError) as ctx:
                ca.run(path, execution_profile="not-a-profile")
        self.assertIn("not-a-profile", str(ctx.exception))
        env = ca.error_envelope(ctx.exception, operation="measure")
        self.assertIn("not-a-profile", env["error"])

    def test_operator_key_in_manifest_json_is_refused_through_run(self):
        with tempfile.TemporaryDirectory() as d:
            path = _manifest(
                Path(d), {"a": [KILLABLE]},
                raw={ca.OPERATOR_PROFILE_KEY: TRUSTED})
            with self.assertRaises(ca.ManifestError) as ctx:
                ca.run(path, execution_profile=TRUSTED)
        self.assertIn(ca.OPERATOR_PROFILE_KEY, str(ctx.exception))

    def test_trusted_local_run_downgrades_when_minimum_is_contained(self):
        with tempfile.TemporaryDirectory() as d:
            path = _manifest(
                Path(d), {"a": [KILLABLE]},
                raw={ca.MINIMUM_PROFILE_KEY: CONTAINED})
            with self.assertRaises(ca.ManifestError) as ctx:
                ca.run(path, execution_profile=TRUSTED)
        self.assertIn(TRUSTED, str(ctx.exception))
        self.assertIn(CONTAINED, str(ctx.exception))


class ContainedDoesNotReachLocalBackend(unittest.TestCase):
    def _trace_local_work(self):
        return mock.patch.multiple(
            ca,
            _build=mock.DEFAULT,
            IsolatedMutationTree=mock.DEFAULT,
            _TreeLock=mock.DEFAULT,
            _default_execution_backend=mock.DEFAULT,
        )

    def test_contained_omitted_backend_refuses_before_lock_build(self):
        with tempfile.TemporaryDirectory() as d:
            path = _process_kill_manifest(Path(d))
            with self._trace_local_work() as patches:
                with self.assertRaises(ca.ManifestError) as ctx:
                    ca.run(path, execution_profile=CONTAINED)
        self.assertIn(CONTAINED, str(ctx.exception))
        patches["_TreeLock"].assert_not_called()
        patches["IsolatedMutationTree"].assert_not_called()
        patches["_build"].assert_not_called()
        patches["_default_execution_backend"].assert_not_called()

    def test_contained_explicit_default_backend_is_refused_not_invoked(self):
        invoked = []

        def tracing_default(m, vectors=None, *, rebuild=True):
            invoked.append(True)
            return ca._ProcessExecution(True, "leaked-local", {}, {}, {}, {})

        with tempfile.TemporaryDirectory() as d:
            path = _process_kill_manifest(Path(d))
            loaded = ca.load_manifest(path)
            with mock.patch.object(
                    ca, "_default_execution_backend", side_effect=tracing_default):
                with mock.patch.object(ca, "_build") as build, \
                        mock.patch.object(ca, "IsolatedMutationTree") as iso, \
                        mock.patch.object(ca, "_TreeLock") as lock:
                    with self.assertRaises(ca.ManifestError) as ctx:
                        ca._run_process(
                            loaded, path,
                            execution_backend=ca._default_execution_backend,
                            execution_profile=CONTAINED)
        self.assertIn(CONTAINED, str(ctx.exception))
        self.assertEqual(invoked, [])
        build.assert_not_called()
        iso.assert_not_called()
        lock.assert_not_called()

    def test_contained_batch_omitted_backend_refuses_before_lock(self):
        with tempfile.TemporaryDirectory() as d:
            path = _batch_manifest(Path(d))
            with self._trace_local_work() as patches:
                with self.assertRaises(ca.ManifestError) as ctx:
                    ca.run(path, execution_profile=CONTAINED)
        self.assertIn(CONTAINED, str(ctx.exception))
        patches["_TreeLock"].assert_not_called()
        patches["IsolatedMutationTree"].assert_not_called()
        patches["_build"].assert_not_called()
        patches["_default_execution_backend"].assert_not_called()


class ContainedModuleRefusesBeforeImplRead(unittest.TestCase):
    def test_contained_module_does_not_read_implementation(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            path = _manifest(tmp, {"a": [KILLABLE]})
            impl = (tmp / "impl.py").resolve()
            reads = []
            original = Path.read_text

            def tracing_read(self, *args, **kwargs):
                if self.resolve() == impl:
                    reads.append(True)
                return original(self, *args, **kwargs)

            with mock.patch.object(Path, "read_text", tracing_read):
                with self.assertRaises(ca.ManifestError) as ctx:
                    ca.run(path, execution_profile=CONTAINED)
        self.assertIn(CONTAINED, str(ctx.exception))
        self.assertIn("module", str(ctx.exception))
        self.assertEqual(reads, [])


class GuardMutationsBite(unittest.TestCase):
    """If production resolve always returns trusted-local, these fail."""

    def test_mutation_always_trusted_local_would_read_module_impl(self):
        def always_trusted(*, operator, manifest):
            return _closed_member(TRUSTED)

        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            path = _manifest(tmp, {"a": [KILLABLE]})
            impl = (tmp / "impl.py").resolve()
            reads = []
            original = Path.read_text

            def tracing_read(self, *args, **kwargs):
                if self.resolve() == impl:
                    reads.append(True)
                return original(self, *args, **kwargs)

            with mock.patch.object(
                    ca, "resolve_execution_profile", side_effect=always_trusted), \
                    mock.patch.object(Path, "read_text", tracing_read):
                try:
                    ca.run(path, execution_profile=CONTAINED)
                except ca.ManifestError:
                    pass
        self.assertTrue(
            reads,
            "sabotaged resolver did not reach impl read; mutation does not bite")

    def test_mutation_always_trusted_local_would_select_default_backend(self):
        def always_trusted(*, operator, manifest):
            return _closed_member(TRUSTED)

        invoked = []

        def tracing_default(m, vectors=None, *, rebuild=True):
            invoked.append(True)
            raise AssertionError("default backend selected under contained operator")

        with tempfile.TemporaryDirectory() as d:
            path = _process_kill_manifest(Path(d))
            loaded = ca.load_manifest(path)
            with mock.patch.object(
                    ca, "resolve_execution_profile", side_effect=always_trusted), \
                    mock.patch.object(
                        ca, "_default_execution_backend",
                        side_effect=tracing_default), \
                    mock.patch.object(ca, "_TreeLock") as lock, \
                    mock.patch.object(ca, "IsolatedMutationTree"):
                lock.return_value.__enter__.return_value = lock.return_value
                lock.return_value.__exit__.return_value = None
                try:
                    ca._run_process(loaded, path, execution_profile=CONTAINED)
                except (ca.ManifestError, AssertionError, TypeError):
                    pass
        self.assertTrue(
            invoked or lock.called,
            "sabotaged resolver did not reach local lock/backend; mutation does not bite")

    def test_mutation_dropping_operator_key_refuse_accepts_manifest_key(self):
        real = ca.resolve_execution_profile

        def skip_operator_key(*, operator, manifest):
            stripped = {k: v for k, v in manifest.items()
                        if k != ca.OPERATOR_PROFILE_KEY}
            return real(operator=operator, manifest=stripped)

        with mock.patch.object(
                ca, "resolve_execution_profile", side_effect=skip_operator_key):
            resolved = ca.resolve_execution_profile(
                operator=TRUSTED,
                manifest={ca.OPERATOR_PROFILE_KEY: TRUSTED})
        self.assertEqual(resolved, TRUSTED)


class ClosedProfilePlumbing(unittest.TestCase):
    def test_run_omission_is_typeerror_not_a_local_run(self):
        run_sig = inspect.signature(ca.run)
        self.assertIs(
            run_sig.parameters["execution_profile"].default, inspect.Parameter.empty)
        with tempfile.TemporaryDirectory() as d:
            path = _manifest(Path(d), {"a": [KILLABLE]})
            with mock.patch.object(
                    ca, "load_manifest",
                    side_effect=AssertionError("run omission reached load")):
                with self.assertRaises(TypeError):
                    ca.run(path)

    def test_run_process_omission_is_typeerror_not_a_local_run(self):
        process_sig = inspect.signature(ca._run_process)
        self.assertIs(
            process_sig.parameters["execution_profile"].default,
            inspect.Parameter.empty)
        with tempfile.TemporaryDirectory() as d:
            path = _process_kill_manifest(Path(d))
            loaded = ca.load_manifest(path)
            with mock.patch.object(
                    ca, "resolve_execution_profile",
                    side_effect=AssertionError(
                        "_run_process omission reached resolver")):
                with self.assertRaises(TypeError):
                    ca._run_process(loaded, path)

    def test_cli_passes_trusted_local_explicitly(self):
        report = {
            "schema": ca.REPORT_SCHEMA, "adequate": True, "mutants": [],
            "runner": "module",
        }
        stdout = io.StringIO()
        with mock.patch.object(sys, "argv", ["corpus_adequacy.py", "m.json", "--json"]), \
                mock.patch.object(sys, "stdout", stdout), \
                mock.patch.object(ca, "run", return_value=report) as run:
            rc = ca.main()
        self.assertEqual(rc, 0)
        run.assert_called_once()
        self.assertEqual(
            run.call_args.kwargs.get("execution_profile"), TRUSTED)

    def test_execution_manifest_projection_drops_profile_keys(self):
        projected = ca._execution_manifest({
            "runner": "process",
            "build": [],
            ca.OPERATOR_PROFILE_KEY: TRUSTED,
            ca.MINIMUM_PROFILE_KEY: CONTAINED,
        })
        self.assertNotIn(ca.OPERATOR_PROFILE_KEY, projected)
        self.assertNotIn(ca.MINIMUM_PROFILE_KEY, projected)
        self.assertNotIn(ca.OPERATOR_PROFILE_KEY, ca._EXECUTION_MANIFEST_KEYS)
        self.assertNotIn(ca.MINIMUM_PROFILE_KEY, ca._EXECUTION_MANIFEST_KEYS)

    @unittest.skipIf(ca.fcntl is None, "process scoring requires an advisory lock")
    def test_contained_with_explicit_backend_reaches_it_not_default(self):
        seen = []

        def recording(m, vectors=None, *, rebuild=True):
            seen.append(dict(m))
            return _inert_backend(m, vectors, rebuild=rebuild)

        with tempfile.TemporaryDirectory() as d:
            path = _process_kill_manifest(Path(d))
            loaded = ca.load_manifest(path)
            loaded[ca.MINIMUM_PROFILE_KEY] = TRUSTED
            with mock.patch.object(
                    ca, "_default_execution_backend",
                    side_effect=AssertionError("contained-to-local fallback")):
                ca._run_process(
                    loaded, path,
                    execution_backend=recording,
                    execution_profile=CONTAINED)
        self.assertTrue(seen)
        for payload in seen:
            self.assertNotIn(ca.OPERATOR_PROFILE_KEY, payload)
            self.assertNotIn(ca.MINIMUM_PROFILE_KEY, payload)


class ReportV0GainsNoProfileField(unittest.TestCase):
    def _assert_no_profile_field(self, report: dict):
        encoded = ca.encode_report_v0(report)
        keys = set(json.loads(encoded))
        self.assertNotIn(ca.OPERATOR_PROFILE_KEY, keys)
        self.assertNotIn(ca.MINIMUM_PROFILE_KEY, keys)
        self.assertNotIn(ca.OPERATOR_PROFILE_KEY.encode("utf-8"), encoded)
        self.assertNotIn(ca.MINIMUM_PROFILE_KEY.encode("utf-8"), encoded)
        self.assertEqual(keys, ca._report_v0_keys(report["runner"]))

    def test_module_report_bytes_gain_no_profile_field(self):
        with tempfile.TemporaryDirectory() as d:
            report = ca.run(_manifest(Path(d), {"a": [KILLABLE]}), execution_profile="trusted-local")
        self._assert_no_profile_field(report)

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_process_report_bytes_gain_no_profile_field(self):
        with tempfile.TemporaryDirectory() as d:
            report = ca.run(_process_kill_manifest(Path(d)), execution_profile="trusted-local")
        self._assert_no_profile_field(report)

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_batch_report_bytes_gain_no_profile_field(self):
        with tempfile.TemporaryDirectory() as d:
            report = ca.run(_batch_manifest(Path(d)), execution_profile="trusted-local")
        self._assert_no_profile_field(report)

    def test_report_key_tables_exclude_profile_fields(self):
        for runner in ("module", "process", "batch"):
            keys = ca._report_v0_keys(runner)
            self.assertNotIn(ca.OPERATOR_PROFILE_KEY, keys)
            self.assertNotIn(ca.MINIMUM_PROFILE_KEY, keys)


class RefusalErrorV0NamesProfile(unittest.TestCase):
    def test_cli_json_error_envelope_names_unknown_minimum(self):
        with tempfile.TemporaryDirectory() as d:
            path = _manifest(
                Path(d), {"a": [KILLABLE]},
                raw={ca.MINIMUM_PROFILE_KEY: "not-a-profile"})
            proc = subprocess.run(
                [sys.executable, str(ca.__file__), str(path), "--json"],
                capture_output=True, timeout=60)
        self.assertEqual(proc.returncode, 2)
        env = json.loads(proc.stdout)
        self.assertEqual(env["schema"], ca.ERROR_SCHEMA)
        self.assertIn("not-a-profile", env["error"])
        self.assertIn(b"not-a-profile", proc.stderr)


class DocsNonClaims(unittest.TestCase):
    def test_readme_and_changelog_state_closed_profiles_without_overclaim(self):
        root = Path(__file__).resolve().parent.parent
        readme = (root / "README.md").read_text(encoding="utf-8")
        changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
        unreleased = changelog.split("## 0.1.3", 1)[0]
        self.assertIn(TRUSTED, readme)
        self.assertIn(CONTAINED, readme)
        self.assertIn(ca.MINIMUM_PROFILE_KEY, readme)
        self.assertIn("downgrade", readme.lower())
        self.assertIn("not complete sandboxing", readme.lower())
        self.assertIn("not author authentication", readme.lower())
        self.assertIn("`report.v0` does not record the profile", readme)
        self.assertNotIn("execution_profile in report", readme.lower())
        self.assertIn(CONTAINED, unreleased)
        self.assertIn("`report.v0` is unchanged", unreleased)
        self.assertNotIn("report.v1", unreleased.lower().replace("not `report.v1`", ""))
        # Non-claims may mention sandbox only as a negation.
        for source, text in (("README", readme), ("CHANGELOG-unreleased", unreleased)):
            for line in text.splitlines():
                lower = line.lower()
                if "sandbox" in lower:
                    self.assertTrue(
                        "not" in lower,
                        "%s overclaims sandbox: %s" % (source, line))


if __name__ == "__main__":
    unittest.main()
