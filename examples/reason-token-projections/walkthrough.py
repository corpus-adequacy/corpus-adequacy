#!/usr/bin/env python3
"""Run the three reason-token projections through the shipped CLI.

Inspects only produced report.v0 fields. A v0 manifest has no inventory;
absence is not printed as a measured zero. Changing selectors changes the
observational question; it does not improve a corpus.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

EXAMPLE_DIR = Path(__file__).resolve().parent
REPO_ROOT = EXAMPLE_DIR.parent.parent
CLI = REPO_ROOT / "corpus_adequacy.py"
CLI_TIMEOUT_SECONDS = 60
UNSUPPORTED = "unsupported-no-fcntl"
ORDINARY_LABEL = "reason-token"
ALLOWED_CLI_STATUSES = (0, 1)
COMPARISON_STATUS = "incomparable"
COMPARISON_REASON = (
    "the three reports are incomparable because their observation "
    "declarations differ"
)
SILENT_MEANS = (
    "diagnostic movement without declared-outcome movement and "
    "denominator-only"
)
PROJECTIONS = (
    ("outcome", "outcome.manifest.json"),
    ("decision-only", "decision-only.manifest.json"),
    ("diagnostic", "diagnostic.manifest.json"),
)


class WalkthroughError(Exception):
    """The run is not valid evidence, so no ordinary verdict is claimed."""


def process_supported() -> bool:
    try:
        import fcntl
    except ImportError:
        return False
    return fcntl is not None


def invoke_report(manifest_path: Path) -> dict:
    proc = subprocess.run(
        [sys.executable, str(CLI), str(manifest_path), "--json"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        timeout=CLI_TIMEOUT_SECONDS,
    )
    if proc.returncode not in ALLOWED_CLI_STATUSES:
        raise WalkthroughError(
            "cli status is not 0 or 1: %s" % proc.returncode)
    doc = json.loads(proc.stdout.decode("utf-8"))
    if doc.get("schema") != "corpus-adequacy.report.v0":
        raise WalkthroughError("cli stdout is not report.v0")
    adequate = doc.get("adequate")
    if proc.returncode == 0 and adequate is not True:
        raise WalkthroughError("exit 0 requires adequate true")
    if proc.returncode == 1 and adequate is not False:
        raise WalkthroughError("exit 1 requires adequate false")
    return doc


def require_valid_run(report: dict) -> None:
    """Control health and completeness before any ordinary verdict.

    report.adequate is the 100% in-scope bar. Survived and silent projections
    fail that bar on purpose. A valid run still needs control_status killed,
    unproved 0, a produced score, and both control rows.
    """
    if report.get("control_status") != "killed":
        raise WalkthroughError("control_status is not killed")
    if report.get("unproved") != 0:
        raise WalkthroughError("unproved is not 0")
    if report.get("score_percent") is None:
        raise WalkthroughError("no score; the run is not valid evidence")
    verdicts = [row.get("verdict") for row in report.get("mutants", [])]
    if verdicts.count("control-killed") != 1:
        raise WalkthroughError("need one control-killed row")
    if verdicts.count("control-unchanged") != 1:
        raise WalkthroughError("need one control-unchanged row")


def ordinary_verdict(report: dict) -> str:
    require_valid_run(report)
    matches = [row for row in report["mutants"]
               if row.get("label") == ORDINARY_LABEL]
    if len(matches) != 1:
        raise WalkthroughError("reason-token row missing")
    return matches[0]["verdict"]


def project(name: str, manifest_path: Path) -> dict:
    if not process_supported():
        return {"status": UNSUPPORTED}
    report = invoke_report(Path(manifest_path))
    verdict = ordinary_verdict(report)
    return {
        "status": "ok",
        "projection": name,
        "verdict": verdict,
        "adequate": report["adequate"],
        "control_status": report["control_status"],
        "unproved": report["unproved"],
        "killed": report["killed"],
        "survived": report["survived"],
        "silent": report["silent"],
    }


def main() -> int:
    if not process_supported():
        print(json.dumps({"status": UNSUPPORTED}, sort_keys=True))
        return 0
    rows = []
    for name, filename in PROJECTIONS:
        rows.append(project(name, EXAMPLE_DIR / filename))
    print(json.dumps({
        "status": "ok",
        "projections": rows,
        "comparison": {
            "status": COMPARISON_STATUS,
            "reason": COMPARISON_REASON,
        },
        "silent_means": SILENT_MEANS,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
