# Retained owned assessment: offline handoff

This is the byte-for-byte final package from one local owned assessment at
source `8c4034cabb7aac165ce4831b5191ae5cf315f23b`, retained on 20 September 2026.
It supplies the retrievable evidence missing from [issue #224](https://github.com/corpus-adequacy/corpus-adequacy/issues/224#issuecomment-5745973220).
The producer and reader were merged in PR #225. This handoff adds no execution.

## Verify offline

From the repository root, on a filesystem supporting the reader's safe descriptor
operations (Linux/macOS; Windows is currently unsupported):

```sh
python -I measurements/suggestion_readback.py verify \
  --package measurements/owned-assessment-8c4034c-20260920/package \
  --basis-dir fixtures/contained-v1-owned/corpus \
  --expected measurements/owned-assessment-8c4034c-20260920/expected.json
```

No Docker, candidate, image pull, model call or network access is needed for this
verification. Expected result: exit 0, `load=complete`, `expected_identity=match`,
`internal_consistency=match`, `reference_approval=accept`,
`replay_disposition=eligible-for-human-corpus-PR`, and `origin=unverified`.
This reproduces offline assessment, not the historical execution.

## Identity and trust inputs

The package receipt SHA-256 is
`b6bfce33e73bd2cb279aa2ecca0976a792a70028a5930bf7d8eb4af977dbc86c`;
the evidence-index SHA-256 is
`dd981f6d46b8b647558abda01d7bbe29419582f27f819697b6a7bdf3e73a2cef`.
`PACKAGE-SHA256.json` lists every retained package member. No package member was
sanitized, regenerated, finalized again or rewritten for this publication.
Git attributes preserve these bytes across checkout line-ending settings.

`pre-execution-expected.json` is the separately retained input used before
execution (SHA-256 `b99f87f778b60625d5a85ae97455c8cc02d02b18d83ab9a5270047ee6c51d97d`).
`expected.json` changes only its formerly null receipt digest to the final digest
already recorded in the issue comment. This is a publication-time handoff pin,
not a claim that the final receipt was known before execution. Both files stay
outside `package/`. The original basis is the repository's separately retained
`fixtures/contained-v1-owned/corpus`, not the derived corpus inside the package.

A reader must decide whether to trust these published expectations and the basis.
Their co-publication does not constitute an independent trust authority. Neither
hashes nor successful replay authenticate the producer, approval, reviewer or
execution origin. The package's authorization text is historical operator-reported
metadata; it grants no current execution permission.

## What was observed

The producer recorded eight invocations: baseline, positive control, inert control
and target for each of base and outer-whitespace variants. The added value 12 is
rejected by baseline (`above-maximum`) and accepted by
`upper-guard-first-overflow-only`; the four original rows agree. Positive controls
are killed and inert controls unchanged. Eight envelopes record completed
invocations and container removal. These are retained producer reports, not a new
independent execution observation.

The final semantic review identifies a non-building Codex agent; the reference
review identifies Muse. Rul1an publishes these records and is not thereby the
independent reviewer. Reviewer authentication, human review and independently
captured runtime origin are not established. Agent assistance is disclosed.

There was no separate pre-addition run. This record does not prove general model
effectiveness, overall corpus adequacy, hosted execution, or performance of an
external implementation. The later corpus revision in PR #227 remains separate;
it did not retroactively change this run's inputs. This directory is an offline
record, not a new measurement registration or release.
