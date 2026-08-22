#!/usr/bin/env python3
"""Execution funnel for the frozen inverse-AEE experiment. Stdlib only.

Validates authorize+prepare, then walks load_frozen_sites ->
required_sequence. Each returned step is executed once by an injected
fake child and classified by classify_observation. This module does not
run the checker. Public non-claims: not MC/DC, not atomic-subcondition
adequacy, not complete mutation adequacy, not sandbox-efficacy, not
certification, not ranking.
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

from aee_checker_sealed_authorize import (  # noqa: E402
    KNOWN_DISPOSITIONS,
    SEALED_IDS,
    classify_observation,
    load_frozen_sites,
    required_sequence,
    validate_authorize,
)

FUNNEL_SCHEMA = "corpus-adequacy.aee-checker-sealed.execution-funnel.v0"
FUNNEL_PHASE = "execution-funnel"
EXPECTED_SEQUENCE_IDS = ("baseline", "control") + SEALED_IDS
NON_CLAIMS = (
    "MC/DC",
    "atomic-subcondition adequacy",
    "complete mutation adequacy",
    "sandbox-efficacy",
    "certification",
    "ranking",
)


class ExecuteError(Exception):
    """The execution funnel refused the run."""


def _require_sequence(steps) -> list:
    if type(steps) is not tuple and type(steps) is not list:
        raise ExecuteError("sequence")
    ids = [step.get("id") for step in steps]
    if ids != list(EXPECTED_SEQUENCE_IDS):
        raise ExecuteError("sequence")
    if len(set(ids)) != len(ids):
        raise ExecuteError("sequence")
    return list(steps)


def run_execution_funnel(*, authorize_raw: bytes, prepare_raw: bytes,
                         pins_dir: Path, child) -> dict:
    if child is None:
        raise ExecuteError("funnel-only; fake child required")
    validate_authorize(authorize_raw, prepare_raw)
    steps = _require_sequence(required_sequence(load_frozen_sites(Path(pins_dir))))
    observations = []
    dispositions = []
    executed = []
    closed = False
    close_reason = None
    for step in steps:
        observation = child(step)
        if type(observation) is not dict:
            raise ExecuteError("observation")
        disposition = classify_observation(step, observation)
        if disposition not in KNOWN_DISPOSITIONS:
            raise ExecuteError("unknown disposition")
        observations.append(observation)
        dispositions.append(disposition)
        executed.append(step["id"])
        if step.get("kind") in ("baseline", "must-die") and disposition == "void":
            closed = True
            close_reason = "void-before-scored"
            break
    return {
        "phase": FUNNEL_PHASE,
        "schema": FUNNEL_SCHEMA,
        "closed": closed,
        "close_reason": close_reason,
        "sequence": list(EXPECTED_SEQUENCE_IDS),
        "executed": executed,
        "observations": observations,
        "dispositions": dispositions,
        "non_claims": list(NON_CLAIMS),
    }


def main(argv: list[str]) -> int:
    sys.stderr.write(
        "execution-funnel is test-only; fake child required\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
