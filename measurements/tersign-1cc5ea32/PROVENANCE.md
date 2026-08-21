# Tersign CHECKS measurement provenance

Measured on `7ec3caeab415064b88a7fd288f7ec8da096a77f4` (the source commit).
This later artifact-commit records the report; it is not the SHA the report
ran on. TOOL_SOURCE bytes on this head equal that source commit.

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
- durable `manifest.json` `9c4c9583ed7166cec9a26b24bc42ad5db32a4c744bce3d6b41128ff428a07487`
  entrypoint `["python3","tersign_checks.py","{vector}"]`, `accepted_exit_codes` `[0]`
- `vectors.json` `678315a30887a5b899e8cc0cc36c4c8e8361cc4a587c7ed839b4f51ef717475d`
- `source.json` `bf7094942d119fc5b57c917423c5fb7b6de110c26589690a800fa448db441cf2`
- `report.v0.json` `b1a10e8cafabb33969e3fcaa9f4bc65de005fbc3673ef297158cbb581746c043` (4539 B)

## Report fields on the measured SHA

- schema `corpus-adequacy.report.v0`, runner `process`, tool_version `0.1.0`
- tool_commit `7ec3caeab415064b88a7fd288f7ec8da096a77f4`, tool_source_state `exact`
- tool_content_sha256 `sha256:8c367574fc7be11d3eb0329bee861e58681c1b4ae0c5531a410e046654fb5b5b`
- manifest_sha256 `sha256:9c4c9583ed7166cec9a26b24bc42ad5db32a4c744bce3d6b41128ff428a07487`
- corpus_digest `null`
- killed=10, survived=2, silent=0, declared_total=12, score=83.3, adequate=false
- control_status `killed` (2× `control-killed`, excluded from the score)
- moved sum 16
- exclusions: acknowledged_digests=0, known_holes=0, equivalent=0,
  unproved=0, unexercised_out_of_scope=0, hole_ratio=0.0, out_of_scope_ratio=0.0
- no non-claims field in report.v0; see below

## Non-claims

This measures only the reviewed declared mutants and the `(verdict, reason)`
projection at pin `1cc5ea32`. Not a complete inventory, not upstream
correctness or endorsement, not semantic equivalence (integral-float is an
ordinary survivor), not Assay RFC 8785 compatibility, not authenticity, not
a release, not #28.
