"""Invocation refusals must be readable without entering candidate execution."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import corpus_adequacy as ca


class JsonInvocationErrors(unittest.TestCase):
    def cli(self, *args, cwd=ROOT):
        return subprocess.run(
            [sys.executable, str(ROOT / "corpus_adequacy.py"), *args],
            capture_output=True, text=True, timeout=10, cwd=cwd)

    def assert_envelope(self, result):
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertTrue(result.stdout.strip(), "JSON refusal missing from stdout")
        body = json.loads(result.stdout)  # also rejects a second object/usage text
        self.assertEqual(set(body), {"schema", "ok", "error", "exit"})
        self.assertEqual(body["schema"], "corpus-adequacy.error.v0")
        self.assertIs(body["ok"], False)
        self.assertEqual(body["exit"], 2)
        self.assertTrue(body["error"])
        return body

    def test_invocation_refusals_before_and_after_json_option(self):
        cases = [[], ["--survivors"], ["--diff", "one"],
                 ["--unknown"], ["--survivors", "--rules"],
                 ["--manifest"], ["--inspect"],
                 ["--json", "--diff", "one"],
                 ["--diff", "--json", "one"]]
        for args in cases:
            for argv in (["--json", *args], [*args, "--json"]):
                with self.subTest(argv=argv):
                    body = self.assert_envelope(self.cli(*argv))
                    self.assertNotIn("could not measure:", body["error"])

    def test_missing_file_remains_a_json_refusal_positive_control(self):
        body = self.assert_envelope(self.cli("--inspect", "does-not-exist.json", "--json"))
        self.assertIn("could not inspect:", body["error"])

    def test_json_after_separator_is_not_a_mode_request(self):
        result = self.cli("--diff", "--", "--json")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("error:", result.stderr)

    def test_json_before_separator_still_requests_json_errors(self):
        self.assert_envelope(self.cli("--json", "--diff", "--", "one"))

    def test_unknown_argument_cannot_inject_a_second_stdout_record(self):
        body = self.assert_envelope(self.cli("--json", '--bad\n{"ok":true}\x1b[2J'))
        self.assertIs(body["ok"], False)

    def test_non_json_refusals_stay_text(self):
        for argv in (["--survivors"], ["--diff", "one"], ["--unknown"]):
            with self.subTest(argv=argv):
                result = self.cli(*argv)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertIn("usage:", result.stderr)

    def test_help_and_version_remain_successful_text(self):
        for option in ("--help", "--version"):
            for argv in (["--json", option], [option, "--json"]):
                with self.subTest(argv=argv):
                    result = self.cli(*argv)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertTrue(result.stdout)
                    self.assertNotIn('"schema": "corpus-adequacy.error.v0"', result.stdout)

    def test_successful_diff_json_bytes_are_unchanged(self):
        fixtures = ROOT / "tests/fixtures/report-diff-v0"
        result = self.cli("--diff", str(fixtures / "old.report.v0.json"),
                          str(fixtures / "new.report.v0.json"), "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, (fixtures / "expected.diff.v0.json").read_text())

    def test_json_named_file_with_explicit_relative_path_is_still_a_report(self):
        fixtures = ROOT / "tests/fixtures/report-diff-v0"
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "--json").write_bytes(
                (fixtures / "old.report.v0.json").read_bytes())
            result = self.cli("--diff", "./--json", str(fixtures / "new.report.v0.json"),
                              "--json", cwd=directory)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, (fixtures / "expected.diff.v0.json").read_text())

    def test_refusals_do_not_reach_execution_or_input_reading(self):
        for argv in (["--json"], ["--survivors", "--json"],
                     ["--json", "--diff", "one"],
                     ["--diff", "one", "--json"],
                     ["--json", "--diff", "one", "--json"],
                     ["--json", "--survivors", "--rules"],
                     ["--json", "--unknown", "candidate.json"]):
            with self.subTest(argv=argv), \
                    mock.patch.object(sys, "argv", ["corpus_adequacy.py", *argv]), \
                    mock.patch.object(ca, "run", side_effect=AssertionError("candidate dispatch")), \
                    mock.patch.object(ca, "read_bounded_regular_file",
                                      side_effect=AssertionError("input read")), \
                    contextlib.redirect_stdout(io.StringIO()) as out, \
                    contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as stopped:
                    ca.main()
                self.assertEqual(stopped.exception.code, 2)
                self.assertTrue(out.getvalue().strip(), "JSON refusal missing")
                self.assertIs(json.loads(out.getvalue())["ok"], False)

    def test_positional_json_filename_after_separator_reaches_normal_dispatch(self):
        with mock.patch.object(sys, "argv", ["corpus_adequacy.py", "--json", "--", "--json"]), \
                mock.patch.object(ca, "run", side_effect=RuntimeError("positional file")):
            with self.assertRaisesRegex(RuntimeError, "positional file"):
                ca.main()

    def test_dispatch_sentinel_can_observe_the_measurement_path(self):
        # Positive control: the same main entry point reaches run with valid argv.
        with mock.patch.object(sys, "argv", ["corpus_adequacy.py", "candidate.json"]), \
                mock.patch.object(ca, "run", side_effect=RuntimeError("dispatch witnessed")):
            with self.assertRaisesRegex(RuntimeError, "dispatch witnessed"):
                ca.main()


if __name__ == "__main__":
    unittest.main()
