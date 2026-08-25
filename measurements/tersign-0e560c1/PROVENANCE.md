# Tersign CHECKS measurement provenance

Measured on `b6f4e3fde79637bc809407bf8efd4c813dfe0959` (the clean producer
commit). This artifact commit records the resulting report; it is not the SHA
the report ran on. The report names the producer commit as `tool_commit` and
records `tool_source_state` as `exact`.

Producer command:

    python3 corpus_adequacy.py measurements/tersign-0e560c1/manifest.json --json

Pin: `tersignhq/evidence-record-conformance@0e560c1ad47f08177042c62754ebe6e0b482ad9a`
root tree `54314f6a4dc513b9356624f1f6d14e5228c1ad64`
manifest SHA-256 `40abdf703b3b731c685142aa24a2561f1cc4679a013d51fdcb9764a1658819c6`
vectors tree `fecf642073dd6b971aebba52bb67153efb1a1dfe`
vector-files aggregate SHA-256
`f4244e4bbcb86126f70cd4750d0a6ce8c729a0ef9baca428fdea9929dc97afd3`

## Identities (SHA-256 of committed bytes)

- producer commit `b6f4e3fde79637bc809407bf8efd4c813dfe0959`
- tool content `7a0f37f6c9f93daf88f96efc1f58f1f6f75264d150ab6eb72a0765d67c99037e`
- adapter `adapters/tersign_evidence_record.py`
  `50c53688f5598fa7b1a2e4097b445f538471cbe38d2c59330da1a46adf81fd1e`
  (16012 B)
- wrapper `tersign_checks.py`
  `f1347dc0738404490139d7f41dc605f6cb7fa72c6083948c66c7008127b20644`
  (3067 B)
- upstream `verify.py`
  `8041a3cb678e8777f6565551da2b258558030b31ee0e80bf1bb1a0bf49cb5f2e`
  (39656 B)
- upstream `keccak.py`
  `f541c8a43a288f61a147dd43accea048eb9f55a095ca3b9dbf3f88341d469190`
  (3208 B)
- upstream Apache LICENSE
  `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`
  (11358 B)
- `manifest.json`
  `8303d97632acbd1dd5722a9f881b84b02f280e36250a37f234799434b9918fd1`
  (4502 B)
- `vectors.json`
  `965bddad5118a9026470c4e409a8b877cc718000da1a1cdd55041f4b8cb0fd01`
  (14911 B)
- `source.json`
  `b9799f2205e4cc051a00bc1daa28f73cc255dff919469f1c036e1385822edd67`
  (1382 B)
- `report.v0.json`
  `6b8a49ce5f63c2b5a38a6b336a601b5ef7feabe6611c2e44bf5d481702e1f2ee`
  (5042 B)

## Recorded result

- schema `corpus-adequacy.report.v0`, runner `process`, tool version `0.1.2`
- manifest identity
  `sha256:8303d97632acbd1dd5722a9f881b84b02f280e36250a37f234799434b9918fd1`
- all 60 baseline typed outcomes reproduced (25 valid, 35 reject)
- controls ran first; both were `control-killed`; `control_status` is `killed`
- the integer-valued-float mutant was evaluated, moved one vector, and was
  `killed`
- killed=11, survived=0, silent=0, equivalent=1, declared_total=12,
  score_percent=100.0, adequate=true
- acknowledged_digests=0, known_holes=0, unproved=0,
  unexercised_out_of_scope=0, hole_ratio=0.0, out_of_scope_ratio=0.0

## Non-claims

This measurement covers only the declared mutant inventory and the
`(verdict, reason)` projection at the exact pin above. It is not a complete
inventory, not upstream correctness, not endorsement, not certification, not
authenticity, not Assay RFC 8785 compatibility, and not a release. The declared
equivalence remains relative to this projection; this record does not claim it
is the only equivalence present. The result does not establish provider,
deployment, or whole-system behavior.
