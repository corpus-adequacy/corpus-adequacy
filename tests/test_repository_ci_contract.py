#!/usr/bin/env python3
"""Structural contract for the repository CI workflow. Standard library only.

Pins the real test job and its executable steps. Comment decoys and unused
keys cannot satisfy these assertions: the workflow is parsed as an indented
YAML subset, then queries run on that tree.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

# One source of truth for the claimed CI pins.
PYTHON_VERSION = "3.13"
TIMEOUT_MINUTES = 10
CLAIMED_OSES = ("ubuntu-latest", "macos-latest", "windows-latest")
CHECKOUT_ACTION = "actions/checkout"
SETUP_PYTHON_ACTION = "actions/setup-python"
CHECKOUT_SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
SETUP_PYTHON_SHA = "5fda3b95a4ea91299a34e894583c3862153e4b97"
PYTHON_VERSION_EXPR = "${{ env.PYTHON_VERSION }}"
UNITTEST_RUN = (
    "python -W error::ResourceWarning -m unittest discover -s tests -v"
)
COMPILE_RUN_PREFIX = "python -m py_compile"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def _strip_comment(line: str) -> str:
    in_single = in_double = escaped = False
    for i, ch in enumerate(line):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_double:
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            return line[:i].rstrip()
    return line.rstrip()


def _parse_scalar(raw: str):
    raw = raw.strip()
    if raw in ("true", "True", "yes"):
        return True
    if raw in ("false", "False", "no"):
        return False
    if raw in ("null", "~"):
        return None
    if raw.startswith("[") and raw.endswith("]"):
        inner = raw[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(part) for part in inner.split(",")]
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'":
        return raw[1:-1]
    if raw.isdigit() or (raw.startswith("-") and raw[1:].isdigit()):
        return int(raw)
    return raw


def parse_workflow_yaml(text: str):
    """Indent-based YAML subset. Comments are discarded before the tree exists."""
    items = []
    for raw in text.splitlines():
        line = _strip_comment(raw)
        if line.strip():
            items.append((len(line) - len(line.lstrip(" ")), line.strip()))
    if not items:
        return {}

    def parse_map(index: int, indent: int):
        mapping = {}
        while index < len(items) and items[index][0] == indent and not items[index][1].startswith("- "):
            _, content = items[index]
            key, _, rest = content.partition(":")
            key, rest = key.strip(), rest.strip()
            index += 1
            if rest:
                mapping[key] = _parse_scalar(rest)
            elif index < len(items) and items[index][0] > indent:
                mapping[key], index = parse(index, items[index][0])
            else:
                mapping[key] = None
        return mapping, index

    def parse_seq(index: int, indent: int):
        seq = []
        while index < len(items) and items[index][0] == indent and items[index][1].startswith("- "):
            body = items[index][1][2:]
            index += 1
            if not body:
                value, index = parse(index, indent + 1)
                seq.append(value)
            elif ":" in body and not body.startswith("${{"):
                key, _, rest = body.partition(":")
                item = {key.strip(): _parse_scalar(rest.strip()) if rest.strip() else None}
                if index < len(items) and items[index][0] > indent and not items[index][1].startswith("- "):
                    extra, index = parse_map(index, items[index][0])
                    item.update(extra)
                seq.append(item)
            else:
                seq.append(_parse_scalar(body))
        return seq, index

    def parse(index: int, indent: int):
        if items[index][1].startswith("- "):
            return parse_seq(index, indent)
        return parse_map(index, indent)

    tree, _ = parse_map(0, items[0][0])
    return tree


def _uses_action(step: dict, name: str) -> bool:
    uses = step.get("uses")
    return isinstance(uses, str) and uses.startswith(name + "@")


def _uses_sha(step: dict) -> str:
    uses = step.get("uses") or ""
    return uses.split("@", 1)[1] if "@" in uses else ""


class RepositoryCiContract(unittest.TestCase):
    def setUp(self):
        self.assertTrue(WORKFLOW.is_file(), f"missing CI workflow: {WORKFLOW}")
        self.tree = parse_workflow_yaml(WORKFLOW.read_text(encoding="utf-8"))
        jobs = self.tree.get("jobs")
        self.assertIsInstance(jobs, dict)
        self.assertIn("test", jobs)
        self.job = jobs["test"]
        self.steps = self.job.get("steps")
        self.assertIsInstance(self.steps, list)
        self.env = self.tree.get("env")
        self.assertIsInstance(self.env, dict)

    def _step_named(self, name: str) -> dict:
        matches = [s for s in self.steps if isinstance(s, dict) and s.get("name") == name]
        self.assertEqual(len(matches), 1, f"need exactly one {name!r} step")
        return matches[0]

    def _action_steps(self, action: str) -> list[dict]:
        return [s for s in self.steps if isinstance(s, dict) and _uses_action(s, action)]

    def test_test_job_has_timeout(self):
        self.assertEqual(self.job.get("timeout-minutes"), TIMEOUT_MINUTES)

    def test_test_job_does_not_continue_on_error(self):
        self.assertIsNot(self.job.get("continue-on-error"), True)
        for step in self.steps:
            if isinstance(step, dict):
                self.assertIsNot(step.get("continue-on-error"), True)

    def test_test_job_matrix_oses(self):
        matrix = ((self.job.get("strategy") or {}).get("matrix") or {})
        oses = matrix.get("os")
        self.assertIsInstance(oses, list)
        for os_name in CLAIMED_OSES:
            with self.subTest(os=os_name):
                self.assertIn(os_name, oses)

    def test_test_job_checkout_is_pinned_official_action(self):
        matches = self._action_steps(CHECKOUT_ACTION)
        self.assertEqual(len(matches), 1)
        self.assertRegex(_uses_sha(matches[0]), SHA_RE)
        self.assertEqual(_uses_sha(matches[0]), CHECKOUT_SHA)

    def test_checkout_does_not_persist_credentials(self):
        checkout = self._action_steps(CHECKOUT_ACTION)
        self.assertEqual(len(checkout), 1)
        with_block = checkout[0].get("with")
        self.assertIsInstance(with_block, dict)
        self.assertIs(with_block.get("persist-credentials"), False)

    def test_setup_python_reads_the_single_pinned_version(self):
        self.assertEqual(self.env.get("PYTHON_VERSION"), PYTHON_VERSION)
        matches = self._action_steps(SETUP_PYTHON_ACTION)
        self.assertEqual(len(matches), 1)
        self.assertRegex(_uses_sha(matches[0]), SHA_RE)
        self.assertEqual(_uses_sha(matches[0]), SETUP_PYTHON_SHA)
        with_block = matches[0].get("with")
        self.assertIsInstance(with_block, dict)
        self.assertEqual(with_block.get("python-version"), PYTHON_VERSION_EXPR)

    def test_test_job_compiles_sources(self):
        compile_steps = [
            s for s in self.steps
            if isinstance(s, dict)
            and isinstance(s.get("run"), str)
            and s["run"].startswith(COMPILE_RUN_PREFIX)
        ]
        self.assertEqual(len(compile_steps), 1)

    def test_test_job_runs_resourcewarning_unittest(self):
        test_steps = [
            s for s in self.steps
            if isinstance(s, dict) and s.get("run") == UNITTEST_RUN
        ]
        self.assertEqual(len(test_steps), 1)
        self.assertFalse(
            any(
                isinstance(s, dict)
                and isinstance(s.get("run"), str)
                and "pip install" in s["run"]
                for s in self.steps
            )
        )

    def test_workflow_does_not_install_dependencies(self):
        for step in self.steps:
            if not isinstance(step, dict):
                continue
            run = step.get("run")
            if isinstance(run, str):
                self.assertNotIn("pip install", run)


class BatchFixturePortability(unittest.TestCase):
    """Batch fixtures must invoke the interpreter CI actually provided."""

    def test_batch_fixtures_use_sys_executable_not_literal_python3(self):
        text = (REPO_ROOT / "tests" / "test_corpus_adequacy.py").read_text(
            encoding="utf-8"
        )
        helper = re.search(
            r"def _batch_python\(.*?\n(?:    .+\n)+",
            text,
        )
        self.assertIsNotNone(helper, "batch fixtures need one _batch_python helper")
        body = helper.group(0)
        self.assertIn("return sys.executable", body)
        self.assertNotRegex(body, r"""return\s+["']python3["']""")

        python_entrypoints = [
            args
            for args in (
                m.group(1)
                for m in re.finditer(r'"entrypoint_command":\s*\[([^\]]+)\]', text)
            )
            if "check.py" in args or "_batch_python" in args or '"python3"' in args
        ]
        self.assertGreaterEqual(len(python_entrypoints), 3)
        for args in python_entrypoints:
            with self.subTest(args=args):
                self.assertIn("_batch_python()", args)
                self.assertNotIn('"python3"', args)
                self.assertNotIn("'python3'", args)


if __name__ == "__main__":
    unittest.main()
