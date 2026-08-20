#!/usr/bin/env python3
"""One allowlisted shape for the repository CI workflow. Standard library only.

The live workflow is pinned by ALLOWED_WORKFLOW, not by scattered string hunts.
This is not a GitHub-expression evaluator: values are compared as literals.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

# One source of truth for allowed actions, SHAs, runs, and job keys.
PYTHON_VERSION = "3.13"
TIMEOUT_MINUTES = 10
CLAIMED_OSES = ("ubuntu-latest", "macos-latest", "windows-latest")
CHECKOUT_ACTION = "actions/checkout"
SETUP_PYTHON_ACTION = "actions/setup-python"
CHECKOUT_SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
SETUP_PYTHON_SHA = "5fda3b95a4ea91299a34e894583c3862153e4b97"
PYTHON_VERSION_EXPR = "${{ env.PYTHON_VERSION }}"
RUNS_ON = "${{ matrix.os }}"
UNITTEST_RUN = (
    "python -W error::ResourceWarning -m unittest discover -s tests -v"
)
COMPILE_RUN = (
    "python -m py_compile corpus_adequacy.py bounded_run.py "
    "tests/test_corpus_adequacy.py tests/test_repository_ci_contract.py"
)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
REQUIRED_ON = {
    "pull_request": None,
    "push": {"branches": ["main"], "tags": ["v*"]},
}
ALLOWED_TOP_LEVEL_KEYS = frozenset({"name", "on", "permissions", "env", "jobs"})
ALLOWED_ENV_KEYS = frozenset({"PYTHON_VERSION"})
ALLOWED_JOB_KEYS = frozenset({
    "name", "runs-on", "timeout-minutes", "strategy", "steps",
})
ALLOWED_STRATEGY_KEYS = frozenset({"fail-fast", "matrix"})
ALLOWED_MATRIX_KEYS = frozenset({"os"})
ALLOWED_ACTION_STEP_KEYS = frozenset({"name", "uses", "with"})
ALLOWED_RUN_STEP_KEYS = frozenset({"name", "shell", "run"})
ALLOWED_PERMISSIONS = {"contents": "read"}
ALLOWED_ACTIONS = {
    "%s@%s" % (CHECKOUT_ACTION, CHECKOUT_SHA): {
        "persist-credentials": False,
        "fetch-depth": 0,
    },
    "%s@%s" % (SETUP_PYTHON_ACTION, SETUP_PYTHON_SHA): {
        "python-version": PYTHON_VERSION_EXPR,
    },
}
ALLOWED_RUNS = frozenset({COMPILE_RUN, UNITTEST_RUN})
ECHO_NOOP_RUN = 'echo "PYTHON_VERSION=${PYTHON_VERSION}"'
ALLOWED_STEPS = (
    {
        "name": "Checkout",
        "uses": "%s@%s" % (CHECKOUT_ACTION, CHECKOUT_SHA),
        "with": {"persist-credentials": False, "fetch-depth": 0},
    },
    {
        "name": "Set up Python",
        "uses": "%s@%s" % (SETUP_PYTHON_ACTION, SETUP_PYTHON_SHA),
        "with": {"python-version": PYTHON_VERSION_EXPR},
    },
    {
        "name": "Syntax compile",
        "shell": "bash",
        "run": COMPILE_RUN,
    },
    {
        "name": "Test",
        "shell": "bash",
        "run": UNITTEST_RUN,
    },
)
ALLOWED_WORKFLOW = {
    "name": "ci",
    "on": REQUIRED_ON,
    "permissions": ALLOWED_PERMISSIONS,
    "env": {"PYTHON_VERSION": PYTHON_VERSION},
    "jobs": {
        "test": {
            "name": "test ${{ matrix.os }}",
            "runs-on": RUNS_ON,
            "timeout-minutes": TIMEOUT_MINUTES,
            "strategy": {
                "fail-fast": False,
                "matrix": {"os": list(CLAIMED_OSES)},
            },
            "steps": list(ALLOWED_STEPS),
        }
    },
}


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


def workflow_shape_violations(tree) -> list[str]:
    """Compare a parsed workflow to ALLOWED_WORKFLOW. Literal presence only."""
    bad = []
    extra_top = set(tree) - ALLOWED_TOP_LEVEL_KEYS
    if extra_top:
        bad.append("unapproved top-level keys: %s" % sorted(extra_top))
    if tree.get("on") != REQUIRED_ON:
        bad.append("on must be exactly pull_request plus push.branches: [main] and push.tags: [v*]")
    if tree.get("permissions") != ALLOWED_PERMISSIONS:
        bad.append("permissions must be exactly {contents: read}")
    env = tree.get("env")
    if not isinstance(env, dict) or set(env) != ALLOWED_ENV_KEYS:
        bad.append("env may pin PYTHON_VERSION only")
    elif env.get("PYTHON_VERSION") != PYTHON_VERSION:
        bad.append("PYTHON_VERSION must be %s" % PYTHON_VERSION)
    jobs = tree.get("jobs")
    if not isinstance(jobs, dict) or set(jobs) != {"test"}:
        bad.append("jobs must contain only test")
        return bad
    job = jobs["test"]
    if not isinstance(job, dict):
        bad.append("test job must be a mapping")
        return bad
    extra_job = set(job) - ALLOWED_JOB_KEYS
    if extra_job:
        bad.append("unapproved test job keys: %s" % sorted(extra_job))
    if job.get("runs-on") != RUNS_ON:
        bad.append("runs-on must be exactly %s" % RUNS_ON)
    if job.get("timeout-minutes") != TIMEOUT_MINUTES:
        bad.append("timeout-minutes must be %d" % TIMEOUT_MINUTES)
    strategy = job.get("strategy")
    if not isinstance(strategy, dict):
        bad.append("strategy must be a mapping")
    else:
        extra_strategy = set(strategy) - ALLOWED_STRATEGY_KEYS
        if extra_strategy:
            bad.append("unapproved strategy keys: %s" % sorted(extra_strategy))
        matrix = strategy.get("matrix")
        if not isinstance(matrix, dict):
            bad.append("matrix must be a mapping")
        else:
            extra_matrix = set(matrix) - ALLOWED_MATRIX_KEYS
            if extra_matrix:
                bad.append("unapproved matrix keys: %s" % sorted(extra_matrix))
            if matrix.get("os") != list(CLAIMED_OSES):
                bad.append("matrix.os must be exactly the claimed OS list")
    steps = job.get("steps")
    if not isinstance(steps, list):
        bad.append("steps must be a list")
        return bad
    for i, step in enumerate(steps):
        bad.extend(_step_shape_violations(i, step))
    return bad


def _step_shape_violations(index: int, step) -> list[str]:
    if not isinstance(step, dict):
        return ["step %d is not a mapping" % index]
    uses, run = step.get("uses"), step.get("run")
    if uses and run:
        return ["step %d has both uses and run" % index]
    if isinstance(uses, str):
        extra = set(step) - ALLOWED_ACTION_STEP_KEYS
        if extra:
            return ["step %d has unapproved keys: %s" % (index, sorted(extra))]
        allowed_with = ALLOWED_ACTIONS.get(uses)
        if allowed_with is None:
            return ["step %d uses unapproved action %r" % (index, uses)]
        sha = uses.split("@", 1)[1] if "@" in uses else ""
        if not SHA_RE.match(sha):
            return ["step %d action is not SHA-pinned" % index]
        with_block = step.get("with")
        if with_block != allowed_with:
            return ["step %d with keys must be exactly %s" % (index, sorted(allowed_with))]
        return []
    if isinstance(run, str):
        extra = set(step) - ALLOWED_RUN_STEP_KEYS
        if extra:
            return ["step %d has unapproved keys: %s" % (index, sorted(extra))]
        if run not in ALLOWED_RUNS:
            return ["step %d run is not allowlisted" % index]
        if step.get("shell") != "bash":
            return ["step %d must set shell: bash" % index]
        return []
    return ["step %d is neither an approved action nor an approved run" % index]


class RepositoryCiContract(unittest.TestCase):
    def setUp(self):
        self.assertTrue(WORKFLOW.is_file(), f"missing CI workflow: {WORKFLOW}")
        self.text = WORKFLOW.read_text(encoding="utf-8")
        self.tree = parse_workflow_yaml(self.text)
        jobs = self.tree.get("jobs")
        self.assertIsInstance(jobs, dict)
        self.assertIn("test", jobs)
        self.job = jobs["test"]
        self.steps = self.job.get("steps")
        self.assertIsInstance(self.steps, list)

    def _mutated(self, old: str, new: str):
        self.assertIn(old, self.text)
        return parse_workflow_yaml(self.text.replace(old, new, 1))

    def test_workflow_matches_allowlisted_shape(self):
        self.assertEqual(workflow_shape_violations(self.tree), [])
        self.assertEqual(self.tree, ALLOWED_WORKFLOW)

    def test_runs_on_is_exactly_matrix_os(self):
        self.assertEqual(self.job.get("runs-on"), RUNS_ON)
        mutated = self._mutated("runs-on: ${{ matrix.os }}", "runs-on: ubuntu-latest")
        self.assertIn("runs-on must be exactly %s" % RUNS_ON,
                      workflow_shape_violations(mutated))

    def test_permissions_are_exactly_contents_read(self):
        self.assertEqual(self.tree.get("permissions"), ALLOWED_PERMISSIONS)
        mutated = self._mutated("contents: read", "contents: write")
        self.assertIn("permissions must be exactly {contents: read}",
                      workflow_shape_violations(mutated))

    def test_push_runs_ci_on_version_tags(self):
        self.assertEqual(self.tree.get("on"), REQUIRED_ON)
        self.assertEqual(self.tree["on"]["push"].get("tags"), ["v*"])
        removed = self._mutated("\n    tags: [v*]", "")
        hits = workflow_shape_violations(removed)
        self.assertTrue(any("push.tags" in v for v in hits), hits)
        changed = self._mutated("tags: [v*]", "tags: [v1.*]")
        hits = workflow_shape_violations(changed)
        self.assertTrue(any("push.tags" in v for v in hits), hits)

    def test_checkout_fetches_full_history_and_tags(self):
        checkout = next(
            s for s in self.steps
            if isinstance(s, dict) and str(s.get("uses", "")).startswith("%s@" % CHECKOUT_ACTION)
        )
        self.assertEqual(
            checkout.get("with"),
            {"persist-credentials": False, "fetch-depth": 0},
        )
        removed = self._mutated("\n          fetch-depth: 0", "")
        hits = workflow_shape_violations(removed)
        self.assertTrue(
            any("with keys must be exactly" in v for v in hits), hits
        )
        depth_one = self._mutated("fetch-depth: 0", "fetch-depth: 1")
        hits = workflow_shape_violations(depth_one)
        self.assertTrue(
            any("with keys must be exactly" in v for v in hits), hits
        )

    def test_unapproved_action_is_rejected(self):
        uses = [s.get("uses") for s in self.steps if isinstance(s, dict)]
        self.assertIn("%s@%s" % (CHECKOUT_ACTION, CHECKOUT_SHA), uses)
        self.assertTrue(all(
            u is None or u in ALLOWED_ACTIONS for u in uses
        ), uses)
        mutated = self._mutated(
            "uses: actions/checkout@%s" % CHECKOUT_SHA,
            "uses: actions/cache@%s" % CHECKOUT_SHA,
        )
        hits = [v for v in workflow_shape_violations(mutated) if "unapproved action" in v]
        self.assertEqual(len(hits), 1, hits)

    def test_shell_echo_noop_is_rejected(self):
        self.assertFalse(
            any(isinstance(s, dict) and s.get("run") == ECHO_NOOP_RUN for s in self.steps)
        )
        extra = (
            "      - name: Echo pinned Python version\n"
            "        shell: bash\n"
            "        run: %s\n" % ECHO_NOOP_RUN
        )
        mutated = parse_workflow_yaml(
            self.text.replace("      - name: Syntax compile\n", extra + "      - name: Syntax compile\n", 1)
        )
        hits = [v for v in workflow_shape_violations(mutated) if "run is not allowlisted" in v]
        self.assertEqual(len(hits), 1, hits)

    def test_arbitrary_if_on_job_or_required_step_is_rejected(self):
        self.assertNotIn("if", self.job)
        for step in self.steps:
            if isinstance(step, dict):
                self.assertNotIn("if", step)
        job_mutated = self._mutated(
            "    runs-on: ${{ matrix.os }}\n",
            "    if: github.event_name == 'push'\n    runs-on: ${{ matrix.os }}\n",
        )
        self.assertIn("unapproved test job keys: ['if']",
                      workflow_shape_violations(job_mutated))
        step_mutated = self._mutated(
            "      - name: Test\n        shell: bash\n",
            "      - name: Test\n        if: github.event_name == 'push'\n        shell: bash\n",
        )
        hits = [v for v in workflow_shape_violations(step_mutated) if "unapproved keys" in v]
        self.assertTrue(any("'if'" in v for v in hits), hits)

    def test_continue_on_error_presence_is_rejected(self):
        self.assertNotIn("continue-on-error", self.job)
        for step in self.steps:
            if isinstance(step, dict):
                self.assertNotIn("continue-on-error", step)
        mutated = self._mutated(
            "      - name: Test\n        shell: bash\n",
            "      - name: Test\n        continue-on-error: ${{ true }}\n        shell: bash\n",
        )
        hits = [v for v in workflow_shape_violations(mutated) if "unapproved keys" in v]
        self.assertTrue(any("continue-on-error" in v for v in hits), hits)

    def test_pip3_or_uv_install_step_is_rejected(self):
        runs = [s.get("run") for s in self.steps if isinstance(s, dict)]
        self.assertTrue(all(r is None or r in ALLOWED_RUNS for r in runs), runs)
        for cmd in ("pip3 install pytest", "uv pip install pytest"):
            extra = (
                "      - name: Install\n"
                "        shell: bash\n"
                "        run: %s\n" % cmd
            )
            mutated = parse_workflow_yaml(
                self.text.replace("      - name: Test\n", extra + "      - name: Test\n", 1)
            )
            hits = [v for v in workflow_shape_violations(mutated) if "run is not allowlisted" in v]
            self.assertEqual(len(hits), 1, (cmd, hits))


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


README = REPO_ROOT / "README.md"
RELEASE_PROCEDURE_BLOCK = (
    "Release procedure: move Unreleased notes into a dated CHANGELOG heading, "
    "set VERSION, merge only after the three-OS CI is green, create and push an "
    "annotated vVERSION tag on that merge SHA, require the tag-push CI green, "
    "then publish the GitHub Release. Quoting a version alone is not a release."
)


class ReadmeSupportAndReleaseDocs(unittest.TestCase):
    """README names the same matrix the workflow contract already pins."""

    def test_readme_names_the_claimed_ci_matrix(self):
        readme = README.read_text(encoding="utf-8")
        self.assertIn("CPython %s" % PYTHON_VERSION, readme)
        for os_name in CLAIMED_OSES:
            self.assertIn(os_name, readme)

    def test_readme_states_module_is_cross_platform_and_fcntl_runners_refuse(self):
        readme = README.read_text(encoding="utf-8")
        self.assertIn("The `module` runner is cross-platform.", readme)
        self.assertIn(
            "`process` and `batch` refuse where `fcntl` is unavailable.",
            readme,
        )

    def test_readme_states_the_release_procedure_as_one_line(self):
        readme = README.read_text(encoding="utf-8")
        self.assertTrue(
            any(line.strip() == RELEASE_PROCEDURE_BLOCK for line in readme.splitlines()),
            "README must contain the exact release-procedure block as one line",
        )


if __name__ == "__main__":
    unittest.main()
