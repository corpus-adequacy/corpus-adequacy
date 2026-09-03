#!/usr/bin/env python3
"""Bind the frozen AEE sequence into the sole generic process engine.

No scoring, mutation, comparison or report logic lives here. Public
non-claims: not MC/DC, not atomic-subcondition adequacy, not complete
mutation adequacy, not sandbox-efficacy, not certification, not ranking.
"""

from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import corpus_adequacy as ca  # noqa: E402
from aee_checker_sealed_authorize import (  # noqa: E402
    AuthorizeError,
    load_frozen_sites,
    require_authorized_sequence,
    required_sequence,
    validate_authorize,
)
from aee_checker_sealed_common import (  # noqa: E402
    PrepareError,
    load_strict,
    verify_file_digest,
)
from aee_checker_sealed_run import (  # noqa: E402
    PHASE_A_PIN_DIGESTS,
    PREPARE_V1_SCHEMA,
)

NON_CLAIMS = (
    "MC/DC",
    "atomic-subcondition adequacy",
    "complete mutation adequacy",
    "sandbox-efficacy",
    "certification",
    "ranking",
)


class ExecuteError(Exception):
    """The authorized execution funnel refused the run."""


def _same_mutation(got: dict, expected: dict) -> bool:
    keys = ("label", "anchor", "replacement")
    return all(got.get(key) == expected.get(key) for key in keys)


def bind_authorized_mutation_order(*, manifest: dict, sites: dict,
                                   control: dict, steps) -> tuple[str, ...]:
    """Resolve the authorized IDs to exact trusted manifest mutations."""
    try:
        steps = require_authorized_sequence(steps)
    except AuthorizeError as exc:
        raise ExecuteError(str(exc)) from exc
    if type(manifest) is not dict or set(manifest.get("mutants", {})) != {"sealed"}:
        raise ExecuteError("manifest mutation groups")
    rows = manifest["mutants"]["sealed"]
    if type(rows) is not list or len(rows) != len(steps) - 1:
        raise ExecuteError("manifest mutation count")
    by_id = {}
    for row in rows:
        row_id = row.get("id") if type(row) is dict else None
        if not isinstance(row_id, str) or row_id in by_id:
            raise ExecuteError("manifest mutation id")
        by_id[row_id] = row
    if set(by_id) != {step["id"] for step in steps[1:]}:
        raise ExecuteError("manifest mutation ids")
    expected_control = dict(control)
    if not by_id["control"].get("control") or not _same_mutation(
            by_id["control"], expected_control):
        raise ExecuteError("manifest control drift")
    site_rows = sites.get("sites") if type(sites) is dict else None
    if type(site_rows) is not list or len(site_rows) != 7:
        raise ExecuteError("manifest site sequence")
    for site in site_rows:
        expected = {
            "label": site.get("label"),
            "anchor": site.get("anchor"),
            "replacement": site.get("manifest_replacement"),
        }
        row = by_id.get(site.get("id"))
        if row is None or row.get("control") or not _same_mutation(row, expected):
            raise ExecuteError("manifest site drift")
    return tuple(by_id[step["id"]]["label"] for step in steps[1:])


def run_execution_funnel(*, authorize_raw: bytes, prepare_raw: bytes,
                         pins_dir: Path, manifest: dict, manifest_path: Path,
                         execution_backend,
                         execution_profile="contained-oci-v0") -> dict:
    try:
        validated = validate_authorize(authorize_raw, prepare_raw)
        if validated["prepare"].get("schema") != PREPARE_V1_SCHEMA:
            raise ExecuteError("production funnel requires prepare.v1")
        sites = load_frozen_sites(Path(pins_dir))
        control_raw = verify_file_digest(
            Path(pins_dir) / "control.json", PHASE_A_PIN_DIGESTS["control.json"])
        control = load_strict(control_raw)
        steps = required_sequence(sites)
        order = bind_authorized_mutation_order(
            manifest=manifest, sites=sites, control=control, steps=steps)
    except (AuthorizeError, PrepareError) as exc:
        raise ExecuteError(str(exc)) from exc
    return ca._run_process(
        manifest, Path(manifest_path),
        execution_backend=execution_backend,
        mutation_order=order,
        separate_build_phase=False,
        execution_profile=execution_profile,
    )


def main(argv: list[str]) -> int:
    sys.stderr.write("execution funnel is library-only; use the authorized driver\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
