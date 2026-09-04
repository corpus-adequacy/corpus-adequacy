"""Adapter from the generic process engine to the sealed AEE candidate."""

from __future__ import annotations

import hashlib
from pathlib import Path

import corpus_adequacy as ca
import aee_checker_sealed_candidate as candidate
from aee_checker_sealed_common import PrepareError
from aee_checker_sealed_run import load_prepare_v1


def make_sealed_backend(*, prepare_raw: bytes, materialized: dict, transport=None,
                        envelope_sink=None):
    """Return a backend that executes only the PREPARE-bound sealed candidate.

    `envelope_sink` receives the execution-envelope record for each contained
    run. The record is a sibling artifact: it never enters the report the
    generic engine builds, and it is not consulted for any verdict here.
    """
    required = ("corpus", "vendor", "tool")
    if type(prepare_raw) is not bytes or any(
            not isinstance(materialized.get(key), Path) for key in required):
        raise PrepareError("sealed runtime materialization")
    binding = None
    if envelope_sink is not None:
        prepare = load_prepare_v1(prepare_raw)
        binding = candidate.envelope_binding(
            prepare_sha256=hashlib.sha256(prepare_raw).hexdigest(),
            execution_commit=prepare["execution"]["commit"],
        )

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
            binding=binding,
        )
        record = getattr(completed, "envelope_record", None)
        if envelope_sink is not None and record is not None:
            envelope_sink(record)
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
