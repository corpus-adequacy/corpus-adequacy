"""Adapter from the generic process engine to the sealed AEE candidate."""

from __future__ import annotations

from pathlib import Path

import corpus_adequacy as ca
import aee_checker_sealed_candidate as candidate
from aee_checker_sealed_common import PrepareError


def make_sealed_backend(*, prepare_raw: bytes, materialized: dict, transport=None):
    """Return a backend that executes only the PREPARE-bound sealed candidate."""
    required = ("corpus", "vendor", "tool")
    if type(prepare_raw) is not bytes or any(
            not isinstance(materialized.get(key), Path) for key in required):
        raise PrepareError("sealed runtime materialization")

    def backend(execution_manifest: dict, vectors, *, rebuild=True):
        if vectors is None or rebuild is not True:
            raise ca.ManifestError(
                "sealed runtime requires one combined build-and-run execution")
        subject = Path(execution_manifest["_repo_root"])
        mounts = {
            "input": materialized["corpus"],
            "vendor": materialized["vendor"],
            "tool": materialized["tool"],
            "subject": subject,
        }
        completed = candidate.run_sealed_candidate(
            prepare_raw=prepare_raw,
            mounts=mounts,
            execution_contract=execution_manifest,
            transport=transport,
        )
        outcome, diagnostic, kind = ca.child_outcome(execution_manifest, completed)
        seen = execution_manifest.get("_selector_keys_seen", {})
        reason = ca.sanitize_unproved_reason(getattr(completed, "unproved_reason", None))
        if kind is not None:
            detail = reason if (kind == "unproved" and reason) else "sealed candidate completed"
            return ca._ProcessExecution(
                True, detail, {}, {}, {"<batch>": kind}, seen)
        return ca._ProcessExecution(
            True, "sealed candidate completed",
            {"<batch>": outcome}, {"<batch>": diagnostic}, {}, seen)

    return backend
