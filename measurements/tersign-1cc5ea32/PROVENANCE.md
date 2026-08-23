# Tersign CHECKS measurement provenance

Measured on `a51fc94c501bddd79678382083a9677338c533e8` (the source commit).
This later artifact-commit records the report; it is not the SHA the report
ran on. TOOL_SOURCE bytes on this head equal that source commit.

Re-measured under v0.1.2 to correct a misclassification, not to change a
result. Producer command, run on a clean tree at the source commit above:

    python3 corpus_adequacy.py measurements/tersign-1cc5ea32/manifest.json --json

## What changed, and why

The mutant `boundary_binding skips empty-attested coverage refusal` was scored
`survived` and is now declared `equivalent`. It replaces
`if attested <= 0 < covered:` with `if False and attested <= 0 < covered:`.
Reaching that guard requires `covered` to be a non-negative `int` and
`attested` an `int`, so the condition implies `covered > 0 >= attested`, which
implies `covered > attested` on the following line. Both branches return
`reject` / `boundary_reject` and differ only in the detail string, which
`tersign_checks.py` does not project. Applying the mutant and sweeping 140
inputs over the domain that reaches the line produced zero differences on
`(verdict, reason)`.

The equivalence is relative to this measurement's declared `outcome_from`
projection, not absolute: widening it to carry detail would make the mutant
distinguishable again. Stated that way because an equivalence claim with no
stated scope is the same defect this tool exists to find.

Two consequences are worth naming. The upstream corpus has no gap at this
rule: `n26-coverage-claimed-over-empty-attestation` pins it through the
subsuming guard, so the previous publication asserted an obligation
(`a future vector must distinguish this rule`) that no vector could ever
discharge. And the score moves from 83.3 to 90.9, over eleven non-equivalent
mutants rather than twelve, with one real survivor remaining and `adequate`
still false.

Re-measurement under v0.1.2 moved `tool_version`, `tool_commit` and
`tool_content_sha256`, and moved the survivor's row index from 0000 to 0002
because this version runs controls before ordinary mutants. Every mutant row
other than the reclassified one is byte-identical to the previous measurement.

Pin: `tersignhq/evidence-record-conformance@1cc5ea32b3da4f195b55782c8a3573d8564673a7`
tree `8003d51692a1e77d7bca8ec07015ca3c03c00242`
vectors_tree `d84527932ee96004b9cf6329d554eb7e039e5221`

## Identities (sha256 of committed bytes)

- wrapper `measurements/tersign_checks.py` and durable copy
  `f1347dc0738404490139d7f41dc605f6cb7fa72c6083948c66c7008127b20644` (3067 B)
- adapter `adapters/tersign_evidence_record.py`
  `ae8d69df38f16e24157b2de50522bfaae3e184a2524d5fb9b5cc92fc6acafaa1` (13472 B)
- `verify.py` `ec6a6fe6d5caa0e56a2a85b9b35557f2efb6aede7689b3e21c3466e6b7502a42` (36130 B)
- `keccak.py` `f541c8a43a288f61a147dd43accea048eb9f55a095ca3b9dbf3f88341d469190` (3208 B)
- Apache LICENSE `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`
- `UPSTREAM_TREE.txt` `0f29a02bc9175c867e26a91f89c0f1b167c5dc34c5dcdf81c997777f783cc16d`
  NOTICE is absent from this listing.
- durable `manifest.json` `8303d97632acbd1dd5722a9f881b84b02f280e36250a37f234799434b9918fd1`
  entrypoint `["python3","tersign_checks.py","{vector}"]`, `accepted_exit_codes` `[0]`
- `vectors.json` `678315a30887a5b899e8cc0cc36c4c8e8361cc4a587c7ed839b4f51ef717475d`
- `source.json` `bf7094942d119fc5b57c917423c5fb7b6de110c26589690a800fa448db441cf2`
- `report.v0.json` `d7c9039da10bd444a4861ef9d9d62565ab7bd4aa29186583335ac8c08dbc7f65` (5209 B)

## Report fields on the measured SHA

- schema `corpus-adequacy.report.v0`, runner `process`, tool_version `0.1.2`
- tool_commit `a51fc94c501bddd79678382083a9677338c533e8`, tool_source_state `exact`
- tool_content_sha256 `sha256:e903a76f0d27833df2fc9936d0c535b3cdabf273715371cb9ac71e5681900854`
- manifest_sha256 `sha256:8303d97632acbd1dd5722a9f881b84b02f280e36250a37f234799434b9918fd1`
- corpus_digest `null`
- killed=10, survived=1, silent=0, equivalent=1, declared_total=12,
  score=90.9, adequate=false
- control_status `killed` (2x `control-killed`, excluded from the score)
- moved sum 16
- exclusions: acknowledged_digests=0, known_holes=0, equivalent=1,
  unproved=0, unexercised_out_of_scope=0, hole_ratio=0.0, out_of_scope_ratio=0.0
- no non-claims field in report.v0; see below

## Non-claims

This measures only the reviewed declared mutants and the `(verdict, reason)`
projection at pin `1cc5ea32`. Not a complete inventory, not upstream
correctness or endorsement, not a claim that the one declared equivalence is
the only one present, not Assay RFC 8785 compatibility, not authenticity, not
a release, not #28. The remaining survivor, integer-valued floats serialized as
integers, is an ordinary survivor and is not claimed equivalent.
