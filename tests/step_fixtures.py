"""Authorized step objects for test collections (#185).

Test collections that reach the hosted gate or its publish readback must name authorized steps
in authorized order, as the sealed runtime does. The steps are derived from the same pinned sites
the gate reads, never restated.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for entry in (str(ROOT), str(ROOT / "measurements")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import contained_hosted_publication as hosted  # noqa: E402
from hosted_rail_contract import LEGACY_RAIL, OWNED_V1_RAIL  # noqa: E402


def authorized_step(rail, position: int) -> dict:
    """The engine step for the `position`-th authorized step of `rail`."""
    contract = rail.measurement
    step_id = hosted.expected_step_ids(rail)[position]
    if step_id == "baseline":
        return {"kind": "baseline", "group": contract.mutation_group, "id": None}
    controls = {contract.control_id, *contract.inert_control_ids}
    kind = "control" if step_id in controls else "mutant"
    return {"kind": kind, "group": contract.mutation_group, "id": step_id}


def sealed_step(position: int) -> dict:
    return authorized_step(LEGACY_RAIL, position)


def owned_step(position: int) -> dict:
    return authorized_step(OWNED_V1_RAIL, position)
