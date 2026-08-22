#!/usr/bin/env python3
"""Print a prefilled publication Issue Form URL from report+source bytes.

Local handoff recomputes prefills. Review must recompute those machine
fields before publication. Submitted query/form values stay untrusted.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from urllib.parse import urlencode

import render_publication_page as rpp

MACHINE_FIELD_IDS = (
    "source-url",
    "source-commit",
    "source-sha256",
    "adapter",
    "runner",
    "report-path",
    "report-digest",
    "manifest-sha256",
    "tool-commit",
    "tool-content-sha256",
    "tool-version",
    "killed",
    "survived",
    "silent",
    "unproved",
    "control-status",
)
USER_FIELD_IDS = (
    "display-name",
    "relationship",
    "public-evidence-url",
    "public-context",
    "scoping",
    "consent",
)
BASE = "https://github.com/corpus-adequacy/corpus-adequacy/issues/new?template=publish-measurement.yml&"


def machine_fields(report_path: Path) -> dict:
    record = rpp.load_record(Path(report_path))
    source_url = rpp._source_url(record)
    return {
        "source-url": source_url,
        "source-commit": record["source_commit"],
        "source-sha256": record["source_digest"],
        "adapter": record["adapter"],
        "runner": record["runner"],
        "report-path": record["report_rel"],
        "report-digest": record["digest"],
        "manifest-sha256": record["manifest_sha256"],
        "tool-commit": record["tool_commit"],
        "tool-content-sha256": record["tool_content_sha256"],
        "tool-version": record["tool_version"],
        "killed": "" if record["killed"] is None else str(record["killed"]),
        "survived": "" if record["survived"] is None else str(record["survived"]),
        "silent": "" if record["silent"] is None else str(record["silent"]),
        "unproved": "" if record["unproved"] is None else str(record["unproved"]),
        "control-status": "" if record["control_status"] is None else str(record["control_status"]),
    }


def handoff_url(report_path: Path, **_ignored) -> str:
    fields = machine_fields(report_path)
    query = urlencode(fields)
    return BASE + query


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Print a publication handoff URL")
    parser.add_argument("report")
    args = parser.parse_args(argv)
    sys.stdout.write(handoff_url(Path(args.report)) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
