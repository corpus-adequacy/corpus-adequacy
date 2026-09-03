#!/usr/bin/env python3
"""Provenance-bound production driver for the frozen AEE measurement rail.

This module authorizes and materializes a candidate run. It does not score,
classify mutations, or construct reports. No experiment runs without explicit
PREPARE-v1 and authorize-v0 bytes supplied by the caller.
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
import aee_checker_sealed_execute as execute  # noqa: E402
import aee_checker_sealed_runtime as runtime  # noqa: E402
from aee_checker_sealed_authorize import (  # noqa: E402
    AuthorizeError,
    validate_authorize,
)
from aee_checker_sealed_common import (  # noqa: E402
    MaterializeBudget,
    PrepareError,
    verify_file_digest,
)
from aee_checker_sealed_materialize import materialize_pinned  # noqa: E402
from aee_checker_sealed_run import (  # noqa: E402
    MATERIALIZED_KEYS,
    PHASE_A_PIN_DIGESTS,
    PREPARE_V1_SCHEMA,
    execution_identity,
    verify_phase_a_frozen,
)


class DriverError(Exception):
    """The authorized driver refused before or during the bounded run."""


def _require_materialization(prepare: dict, materialized: dict,
                             dest: Path) -> None:
    expected = prepare["materialized"]
    for key in MATERIALIZED_KEYS:
        if materialized.get(key) != expected.get(key):
            raise DriverError("materialized %s drift" % key)
    if materialized.get("toolchain") != prepare.get("toolchain"):
        raise DriverError("materialized toolchain drift")
    for key in ("subject", "corpus", "vendor", "tool"):
        path = materialized.get(key)
        if not isinstance(path, Path) or path != Path(dest) / key or not path.is_dir():
            raise DriverError("materialized %s path" % key)


def run_authorized(*, authorize_raw: bytes, prepare_raw: bytes,
                   pins_dir: Path, materialize_dest: Path, root: Path,
                   transport=None) -> dict:
    """Validate, rematerialize, then invoke the sole generic process engine."""
    try:
        validated = validate_authorize(authorize_raw, prepare_raw)
        prepare = validated["prepare"]
        if prepare.get("schema") != PREPARE_V1_SCHEMA:
            raise DriverError("authorized driver requires prepare.v1")
        if execution_identity(Path(root)) != prepare.get("execution"):
            raise DriverError("execution identity drift")
        pins = verify_phase_a_frozen(Path(pins_dir))
    except (AuthorizeError, PrepareError, ca.ManifestError) as exc:
        raise DriverError(str(exc)) from exc

    try:
        budget = MaterializeBudget(prepare["materialize_ceilings"])
        dest = Path(materialize_dest)
        if dest.exists():
            raise DriverError("materialize destination already exists")
        dest.mkdir()
        materialized = materialize_pinned(
            pins, dest,
            template=Path(root) / "execution" / "aee-checker-sealed" / "cargo-config.toml",
            budget=budget,
        )
        _require_materialization(prepare, materialized, dest)
        manifest_path = Path(pins_dir) / "manifest.json"
        manifest_raw = verify_file_digest(
            manifest_path, PHASE_A_PIN_DIGESTS["manifest.json"])
        manifest = ca.load_manifest_bytes(
            manifest_raw, manifest_path, path_root=dest)
        backend = runtime.make_sealed_backend(
            prepare_raw=prepare_raw, materialized=materialized, transport=transport)
        return execute.run_execution_funnel(
            authorize_raw=authorize_raw,
            prepare_raw=prepare_raw,
            pins_dir=Path(pins_dir),
            manifest=manifest,
            manifest_path=manifest_path,
            execution_backend=backend,
            execution_profile="contained-oci-v0",
        )
    except (AuthorizeError, PrepareError, ca.ManifestError, execute.ExecuteError) as exc:
        raise DriverError(str(exc)) from exc


def main(argv: list[str]) -> int:
    sys.stderr.write(
        "driver requires explicit authorized inputs; no implicit experiment command\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
