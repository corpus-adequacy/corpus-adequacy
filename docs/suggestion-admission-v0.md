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
`killed`, with the kind only in the row text. The execution gates therefore read the backend's
`raised` observation, never the row text. A termination "kill" refuses as
`witness-by-termination:<kind>`.

## Execution gates 3 to 6 (#205)

`measurements/suggestion_execution.py` judges the execution gates from a recording of the
engine's own backend calls. `RecordingBackend` wraps whatever backend the caller already trusts,
declares that it accepts a step, keeps what each call observed, and forwards the call unchanged.
A call that arrives without a step cannot be attributed and is refused rather than recorded. The
module imports no process, socket or HTTP machinery of its own, and a test reads its import list
to keep it that way. That is a tripwire on this module, not a sandbox: it imports
`corpus_adequacy`, which runs children by design.

| Gate | Passes when | Refusal |
|---|---|---|
| 3 `reference-pass` | the baseline over the proposal's corpus built, raised nothing, the proposal's row reads what the proposal declared, and every frozen row reads what the committed reference says | `reference-abnormal:<kind>`, `reference-fail` |
| 4 `controls-bite` | both controls raised nothing and cover the same row set; the positive control moves a row that was already frozen, not only the proposal's own; the inert control moves nothing; the engine's own control status agrees | `control-invalid` |
| 5 `intended-distinction` | the mutant built, raised nothing, and exactly the proposal's row moved | `mutant-unproved:<kind>`, `witness-by-termination:<kind>`, `distinction-not-attributed`, `silent-only`, `no-distinction` |
| 6 `transformation-robustness` | each declared transformation is first inert on rows, and then gates 3 and 5 hold under it | `transformation-invalid:<t>`, `transformation-fragile:<t>` |

A missing, duplicated or unattributable call refuses as `accounting-gap`, and so does a
judgement with no transformation at all: a robustness gate that checks nothing passes nothing.

The positive control has to move a frozen row because a control that only the new vector notices
says nothing about the corpus that was there before.

## Record: `corpus-adequacy.suggestion-admission.v1`

The v0 record stays exactly as it is, so nothing already written changes meaning. A run that
judged the execution gates writes v1 instead: the same keys plus `execution`, which names the
`route`, the `profile`, the `recording_sha256` and the `transformations` that were applied. In a
v1 record every gate must read `passed` or `refused`, because `not-run` belongs to v0, and
`decision` is `admitted` or `refused`.

The encoder refuses `admitted` unless the record's `route` is one that runs the candidate. The
`fake` route exists for tests, so a fake-route record can be built, can say `admitted`, and
cannot be encoded.

That is a check on the label the record carries, not proof that a run happened. A hand-built
record naming a real route encodes. What can bind a record to a run is `recording_sha256`: a
reader holding the recording recomputes it from `Recording.canonical()` and compares. The encoder
never sees the recording, and nothing here does that comparison for you.

## Non-claims

No model output is evaluated. No suggestion value, real-fault detection, adequacy or provider
claim follows. The selection's one survivor has a public counterexample, so fixtures here exercise
the harness only. A pilot with model calls needs a separately approved execution packet.
