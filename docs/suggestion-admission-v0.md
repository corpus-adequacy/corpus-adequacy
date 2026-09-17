# suggestion-admission.v0

Deterministic admission for proposed test vectors (#200). `measurements/suggestion_admission.py`
is stdlib only and contacts no model or provider. It judges one proposal for one closed,
code-owned selection (`owned-independent-v0`) and writes a closed admission record. It changes no
corpus, selection, `report.v0` or score.

## Proposal: `corpus-adequacy.suggestion-proposal.v0`

Exact keys `schema`, `proposal_id`, `selection`, `target`, `vector`, `expected`, `authorship`.

- `target`: `{group, mutation_id}`, which must equal the selection's.
- `vector`: `{id, file, value_class, document}`, with `file == id + ".json"` and
  `document == {"value": <i64>}`.
- `expected`: exactly `{accepted, reason}`, the members of the declared outcome row. Expecting
  `detail`, a diagnostic, refuses as `proposal-expects-diagnostic`.
- `authorship`: `{author_kind, author, model_id, prompt_sha256, input_sha256, source_pin}`. A
  `model` author requires the model id and both digests; a `human` author requires all three to be
  null.
- Any key naming an equivalence judgement, anywhere, refuses as `model-equivalence-claim`.

## Gates

| # | Gate | Here | Refusal tokens |
|---|---|---|---|
| 0 | Proposal shape | implemented | `proposal-shape`, `proposal-selection`, `proposal-target`, `proposal-expects-diagnostic`, `proposal-authorship`, `model-equivalence-claim` |
| 1 | Freeze | implemented | `freeze-drift`, `freeze-drift:<path>` |
| 2 | Corpus separation | implemented | `proposal-corpus-exists`, `duplicate-vector-id`, `frozen-corpus-touched` |
| 3 | Reference pass | `not-run` | reserved: `reference-fail`, `reference-abnormal:<reason>` |
| 4 | Controls bite | `not-run` | reserved: `control-invalid` |
| 5 | Intended distinction | `not-run` | reserved: `witness-by-termination`, `no-distinction`, `silent-only`, `distinction-not-attributed` |
| 6 | Transformation robustness | `not-run` | reserved: `transformation-fragile:<T>` |
| 7 | Semantic review | implemented | `review-missing`, `review-shape`, `review-by-author`, `model-equivalence-claim` |
| 8 | Accounting | implemented | `accounting-gap` |

Gate 1 compares every file in the selection bundle's `candidate_freeze.sha256` with its current
bytes. Gate 2 builds a separate proposal corpus: the frozen vectors, the proposal's vector file and
a new `MANIFEST.json` whose `corpusDigest` uses the fixture's own formula (SHA-256 over
`file`, NUL, bytes, in manifest order). It refuses a vector id or file already present and
verifies that the frozen corpus tree is unchanged afterwards. Gate 7 takes a
`corpus-adequacy.suggestion-review.v0` record `{schema, proposal_id, reviewer, decision, minutes}`
whose reviewer is none of the proposal author, the model id or the packet author. That
comparison is exact-string over names the record itself calls unauthenticated: it catches an honest
self-review, not a different spelling of the same person.

## Record: `corpus-adequacy.suggestion-admission.v0`

Keys `schema`, `proposal_id`, `proposal_sha256`, `selection`, `gates` (nine rows of
`{gate, name, status, refusal}`), `decision`, `refusal`, `non_claims`. The bytes use the
class-artifact encoding. `decision` is `refused` (the first refusal is named) or
`pending-execution`. Execution gates are always `not-run`, and the encoder refuses a record whose
execution gates say anything else, so no record from this module is admitted.

`account()` checks a set of proposals: each reaches exactly one of `admitted`,
`refused:<token>` or `no-improvement`, and the counts add up. "No improvement over the
human baseline" is a complete result.

## Why termination is not a witness

Under the process and batch runners the engine scores a mutant that terminates abnormally as
`killed`, with the kind only in the row text. The execution gates will therefore read the
backend's `raised` observation, never the row text. A termination "kill" refuses as
`witness-by-termination`.

## Non-claims

No model output is evaluated. No suggestion value, real-fault detection, adequacy or provider
claim follows. The selection's one survivor has a public counterexample, so fixtures here exercise
the harness only. A pilot with model calls needs a separately approved execution packet.
