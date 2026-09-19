# G feasibility probe: `template-exhausted`

**This probe is not evidence.** No record derives from it, it is not a held-out mutant set, and it
says nothing about any model. It lives under `docs/design/`, not `measurements/`, on purpose.

## The question

Could an AI test-suggestion pilot (#200, and the admission harness in
[`docs/suggestion-admission-v0.md`](../../suggestion-admission-v0.md)) ever show *value* on the owned
fixture? For that, a held-out mutant would have to survive both the frozen corpus and a committed
boundary-value template. Only such a mutant leaves a model something a mechanical template could
not already find. The probe asks whether this fixture can carry even one such mutant.

## How it was run

`g_probe.py` builds the real Rust candidate in `fixtures/contained-v1-owned/candidate` with cargo
on the host, in scratch copies. It uses no Docker, no sealed route and no `report.v0`. It applies
eight guard perturbations to `src/check.rs` and compares each mutant's declared outcome
(`accepted`, `reason`) with the original on three sets of inputs:
- the frozen corpus `-1, 5, 10, 11`;
- the published counterexample `12`;
- a seven-vector boundary template (b-1, b, b+1 around `0`, the maximum `10`, `i64::MIN` and
  `i64::MAX`, minus values already covered).

For every mutant that survives the template, it then sweeps 409 values to classify it.

A Claude session wrote the mutants, and Claude may not author a real held-out set. They are
published here so that nobody mistakes them for one.

`PROBE-OUTPUT.txt` is the output at `6f42b1b78fefbb4da35c7b29cd3a68eaa85f8a6c`. It matches
byte for byte a first run on 2026-09-18.

## Result

Seven of the eight mutants survive the frozen corpus and the published counterexample. Of those
seven:
- five are killed by the template;
- one (`upper-interior-hole`) is killable only at an arbitrary interior value, which the authoring
  rules refuse as not a rule;
- one (`sentinel-removed`) is equivalent: no value in the sweep kills it.

The verdict is `template-exhausted`.

The reason is structural. The candidate's guards compare against exactly three things: `0`, the
maximum and `i64::MIN`. Perturbing a declared guard therefore changes behaviour either at one of
those boundaries, where the template already looks, or at an interior point the author picked,
which the rules refuse.

## Two facts about the fixture

- **The `minimum-sentinel` rule is dead code.** `value < 0` returns first for `i64::MIN`, so the
  `value == i64::MIN` guard can never fire, and removing it is an equivalent mutant. The fixture
  is frozen inside sealed execution identities and is not changed here.
- **A different author probably would not help.** A held-out author other than Claude would face
  the same twenty-line function and the same three comparison points. That is an argument, not
  something eight mutants prove. Room for value evidence more likely needs a subject with more
  comparisons, or a consented structured corpus.

## What this does not show

It shows nothing about any model's ability, about test-suggestion value in general, or about any
fixture other than this one. It does not claim the eight mutants are the only plausible ones. It
claims only that on this candidate, a boundary-value template killed every guard perturbation the
probe tried that the authoring rules admit.
