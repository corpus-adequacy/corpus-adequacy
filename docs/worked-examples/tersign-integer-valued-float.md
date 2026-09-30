# Worked example: an integer-valued float the corpus could not see

Mutation-testing a conformance corpus isn't a new idea. This is two pinned runs of one tool against one corpus, written up because the interesting part turned out to sit underneath the result.

## The measurement

In August, corpus-adequacy measured Tersign's evidence-record conformance corpus ([tersignhq/evidence-record-conformance](https://github.com/tersignhq/evidence-record-conformance)) at `1cc5ea32` (54 vectors). The declared inventory had twelve mutants against the rules we read in its Python reference engine, `verify.py`, plus two controls that had to be killed first. A dispatch-only wrapper called `CHECKS[kind](input)` and compared verdict and reason, not the detail string. The run is public at https://corpus-adequacy.github.io/corpus-adequacy/runs/tersign-1cc5ea32/, and it vendors `verify.py`, `keccak.py` and the vectors under Apache-2.0 with per-file digests.

Result as now published: 10 killed, 1 survived, 1 declared equivalent (the August original scored that last one as a survivor; see the correction below).

## The survivor

The surviving mutant is a two-line insertion in `canonical()`:

```python
if isinstance(value, float):
    if value.is_integer():
        return canonical(int(value))
    raise ValueError("non-integer JSON number in the digest domain")
```

It survived because `n10-float-in-digest-domain` was the corpus's only fractional number token, and it carries `1.1`. On a fractional value the shipped engine and the mutant both reject with `number_domain_reject`, so nothing moves. An integer-valued float separates them: on `{"payload": {"amount": 2.0}, "claimed_canonical": "{\"amount\":2}"}` the shipped engine rejects and the mutant returns `valid`. That was reported in tersignhq/evidence-record-conformance#1 on 2026-08-23 ([5387273330](https://github.com/tersignhq/evidence-record-conformance/issues/1#issuecomment-5387273330)) and checked against Tersign's `main` at the time as well as the pin.

## What the survivor was hiding

This part is Tersign's finding, not ours ([5413072586](https://github.com/tersignhq/evidence-record-conformance/issues/1#issuecomment-5413072586)). Reproducing the survivor turned up a live divergence between the two reference engines. On the wire bytes `{"amount": 2.0}`, Python's `json` keeps the float and `canonical()` rejects, while `JSON.parse` collapses the token to the integer `2` and the TypeScript engine accepted. Two engines, two verdicts, identical bytes. Before `0e560c1` the differential harness had never exercised it: a value-carrying vector couldn't express the distinction to the TypeScript engine, because its loader erased the token before the engine ran. Python's `json` never erased it.

The fix is [`0e560c1`](https://github.com/tersignhq/evidence-record-conformance/commit/0e560c1) (2026-08-25). `canonical_bytes` takes the payload as raw text (`payload_text`, checked by key presence), and the TypeScript engine enforces the boundary at the token level through `JSON.parse` source access (Node 21 and later). `n35` rejects the token `2.0`, and `p25` accepts the plain integer token `2` through the same pathway, so an engine that simply refused the new pathway would fail too. The commit message records non-vacuity in both directions: with the TypeScript token guard disarmed, `n35` reads valid, and the weakened Python mutant is killed by `n35`. (The commit message cites issue tersignhq/evidence-record-conformance#4; the report is in tersignhq/evidence-record-conformance#1, as CONTRIBUTORS.md records at `1075ca6`.)

The same erasure on integer fields is pinned separately by `n38` in v0.5.1 ([`ba3145a`](https://github.com/tersignhq/evidence-record-conformance/commit/ba3145a)), which its commit describes as found by an adversarial review of v0.5.0, not by this run. That commit also made the TypeScript vector loader map any number whose token has a fraction or exponent part to `NaN`. So the value form of the input above no longer splits the engines (up to and including `0e560c1` the TypeScript engine still accepted it), and Tersign reports it rejecting in both at `1075ca6`.

## The re-pin

The same manifest (sha256 `8303d976…`) re-run at `0e560c1` (60 vectors): 11 killed, 0 survived, 1 declared equivalent, controls killed. Public at https://corpus-adequacy.github.io/corpus-adequacy/runs/tersign-0e560c1/. That result covers our twelve declared mutants only; it doesn't say the suite is complete or that either engine is correct.

## The correction

The first version of the `1cc5ea32` run also scored `boundary_binding skips empty-attested coverage refusal` as a survivor and printed an obligation to add a vector for it. No vector can: once control reaches `if attested <= 0 < covered:`, where `covered` is a non-negative int and `attested` an int, that condition implies `covered > attested` on the next line, both branches return `reject` with `boundary_reject`, and they differ only in the detail string the wrapper doesn't compare. `n26` already pins the rule through the subsuming guard. The finding was withdrawn on 2026-08-23 and the mutant is now declared equivalent, scoped to the verdict-and-reason projection. Our own test file had called that constant `MASKED_BOUNDARY` from the start, so the right suspicion existed in a name and never reached the declaration.

## Since then

Separately, we reported in [tersignhq/evidence-record-conformance#10](https://github.com/tersignhq/evidence-record-conformance/issues/10) that `payload_text` was parsed with plain `json.loads`, so the duplicate-name check in `_load_strict` didn't reach it. Tersign reproduced it at `0eda303` on both engines (the TypeScript engine also returned `valid`) and fixed it in both in [`ab7704d`](https://github.com/tersignhq/evidence-record-conformance/commit/ab7704d) (v0.5.4), where a duplicate name inside `payload_text` rejects with `canonicalization_reject`. It doesn't change anything above.

## What this does and doesn't show

It shows one declared mutant surviving a corpus, the input that separated it, and what the corpus owner found beneath it. It doesn't validate either engine, doesn't measure anything beyond our declared inventory, and doesn't claim the divergence as ours.

## Reproduce

From a checkout of corpus-adequacy at `b6f4e3f` (`git checkout b6f4e3f`, run from the repository root), both commands reproduce the published counts (10/1/1 with exit 1, and 11/0/1 with exit 0) against the same manifest (`8303d976…`); current main gives the same counts. The `1cc5ea32` report itself names `a51fc94` because it ran those tool bytes against the manifest corrected in `44661b9`; at `a51fc94` alone the older manifest gives 10/2/0, and its `PROVENANCE.md` explains why.

```sh
python3 corpus_adequacy.py measurements/tersign-1cc5ea32/manifest.json --json
python3 corpus_adequacy.py measurements/tersign-0e560c1/manifest.json --json
```

Each directory carries its own `PROVENANCE.md` with the pinned upstream commit and per-file digests from [`aa2ef19`](https://github.com/corpus-adequacy/corpus-adequacy/commit/aa2ef19) on; at `b6f4e3f` itself only the `1cc5ea32` directory has one.

---

Tersign checked every pin in an earlier draft against its commit ([tersignhq/evidence-record-conformance#1](https://github.com/tersignhq/evidence-record-conformance/issues/1#issuecomment-5907420541)). This version folds in their two corrections and their update on tersignhq/evidence-record-conformance#10. Drafted with AI assistance, human-reviewed.
